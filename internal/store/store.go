// Package store owns the SQLite database: connection pools, write transactions, migrations, the process lock,
// integrity checks and the backup primitive (PLAN §4, ADR-0002).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	_ "modernc.org/sqlite" // database/sql driver "sqlite"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// File names inside the data directory.
const (
	DBFile        = "hallpass.db"
	LockFile      = "hallpass.lock"
	BackupsDir    = "backups"
	RecordingsDir = "recordings"
	QuarantineDir = "quarantine"
)

// Options configure Open.
type Options struct {
	DataDir string
	// Readers is the reader pool size (default max(4, GOMAXPROCS)).
	Readers int
	// AllowNetworkFS skips the network-filesystem refusal (development only).
	AllowNetworkFS bool
	// PreMigrationSnapshots is how many pre-migration snapshots to keep (default 3).
	PreMigrationSnapshots int
	// SkipMigrate opens without applying migrations (used by offline tools that only read).
	SkipMigrate bool
	Logger      *slog.Logger
	Clock       clock.Clock
	// TxObserver, if set, receives the duration and outcome of every write transaction.
	TxObserver TxObserver
	// Metrics, if set, records write transaction duration and results, busy retries and writer wait time
	// (HP-DB-003, HP-DB-004). Nil disables metrics.
	Metrics *metrics.Metrics
	// BusyTimeout overrides SQLite's busy_timeout (default 5s). Tests only.
	BusyTimeout time.Duration
	// migrations overrides the embedded migrations. Tests only.
	migrations fs.FS
}

// Store is an open Hallpass database owned exclusively by this process.
type Store struct {
	dir    string
	lock   *Lock
	wdb    *sql.DB
	rdb    *sql.DB
	writer *Writer
	reader *db.Queries
	log    *slog.Logger
	clock  clock.Clock
	health *Health

	closeOnce sync.Once
	closeErr  error
}

// Open prepares the data directory, takes the process lock, opens the pools, checks integrity and migrates.
func Open(ctx context.Context, opts Options) (*Store, error) {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Clock == nil {
		opts.Clock = clock.System{}
	}
	if opts.Readers <= 0 {
		opts.Readers = max(4, runtime.GOMAXPROCS(0))
	}
	if opts.PreMigrationSnapshots <= 0 {
		opts.PreMigrationSnapshots = 3
	}
	if opts.BusyTimeout <= 0 {
		opts.BusyTimeout = DefaultBusyTimeout
	}
	if opts.migrations == nil {
		sub, err := fs.Sub(migrationFS, "migrations")
		if err != nil {
			return nil, err
		}
		opts.migrations = sub
	}
	dir, err := filepath.Abs(opts.DataDir)
	if err != nil {
		return nil, fmt.Errorf("data dir: %w", err)
	}
	if err := PrepareDataDir(dir); err != nil {
		return nil, err
	}
	if !opts.AllowNetworkFS {
		if err := CheckLocalFilesystem(dir); err != nil {
			return nil, err
		}
	}
	lock, err := AcquireLock(filepath.Join(dir, LockFile))
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, lock: lock, log: opts.Logger, clock: opts.Clock, health: newHealth(opts.Clock)}
	if err := s.open(ctx, opts); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) open(ctx context.Context, opts Options) error {
	path := filepath.Join(s.dir, DBFile)
	var err error
	if s.wdb, err = sql.Open("sqlite", writerDSN(path, opts.BusyTimeout)); err != nil {
		return fmt.Errorf("open writer: %w", err)
	}
	s.wdb.SetMaxOpenConns(1)
	s.wdb.SetMaxIdleConns(1)
	s.wdb.SetConnMaxLifetime(0)
	s.wdb.SetConnMaxIdleTime(0)
	if err := s.wdb.PingContext(ctx); err != nil {
		return classify(fmt.Errorf("open database: %w", err))
	}
	if err := secureFiles(s.dir); err != nil {
		return err
	}
	if err := QuickCheck(ctx, s.wdb); err != nil {
		return err
	}
	if !opts.SkipMigrate {
		if err := migrate(ctx, s.wdb, opts.migrations, s.dir, opts.PreMigrationSnapshots, s.clock, s.log); err != nil {
			return err
		}
	} else if err := checkSchemaNotNewer(ctx, s.wdb, opts.migrations); err != nil {
		return err
	}
	if s.rdb, err = sql.Open("sqlite", readerDSN(path, opts.BusyTimeout)); err != nil {
		return fmt.Errorf("open readers: %w", err)
	}
	s.rdb.SetMaxOpenConns(opts.Readers)
	s.rdb.SetMaxIdleConns(opts.Readers)
	if err := VerifyPragmas(ctx, s.wdb, 1, false, opts.BusyTimeout); err != nil {
		return err
	}
	if err := VerifyPragmas(ctx, s.rdb, opts.Readers, true, opts.BusyTimeout); err != nil {
		return err
	}
	if err := secureFiles(s.dir); err != nil {
		return err
	}
	s.writer = &Writer{db: s.wdb, clock: s.clock, health: s.health, observer: opts.TxObserver, metrics: opts.Metrics}
	s.reader = db.New(s.rdb)
	opts.Metrics.SetStoreSizes(s.Sizes())
	return nil
}

// Close closes both pools (checkpointing the WAL) and releases the process lock.
func (s *Store) Close() error {
	s.closeOnce.Do(s.closeNow) //nolint:contextcheck // Close is called without a caller context
	return s.closeErr
}

func (s *Store) closeNow() {
	var errs []error
	if s.rdb != nil {
		errs = append(errs, s.rdb.Close())
	}
	if s.wdb != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, _ = s.wdb.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
		cancel()
		errs = append(errs, s.wdb.Close())
	}
	if s.lock != nil {
		errs = append(errs, s.lock.Release())
	}
	s.closeErr = errors.Join(errs...)
}

// W returns the single writer.
func (s *Store) W() *Writer { return s.writer }

// R returns typed queries over the read-only pool.
func (s *Store) R() *db.Queries { return s.reader }

// ReadDB returns the read-only pool for dynamic queries (filters, pagination).
func (s *Store) ReadDB() *sql.DB { return s.rdb }

// Dir returns the absolute data directory.
func (s *Store) Dir() string { return s.dir }

// Health returns the storage health tracker.
func (s *Store) Health() *Health { return s.health }

// Path returns the absolute path of a file inside the data directory.
func (s *Store) Path(elem ...string) string {
	return filepath.Join(append([]string{s.dir}, elem...)...)
}

// DefaultBusyTimeout is SQLite's busy_timeout for every connection.
const DefaultBusyTimeout = 5 * time.Second

func baseDSN(busy time.Duration) url.Values {
	q := url.Values{}
	for _, p := range []string{
		fmt.Sprintf("busy_timeout(%d)", busy.Milliseconds()),
		"foreign_keys(1)",
		"synchronous(FULL)",
		"trusted_schema(0)",
		"cache_size(-32000)",
		"temp_store(MEMORY)",
	} {
		q.Add("_pragma", p)
	}
	return q
}

func writerDSN(path string, busy time.Duration) string {
	q := baseDSN(busy)
	q.Set("_auto_vacuum", "INCREMENTAL") // only effective when the database is created
	q.Add("_pragma", "journal_mode(WAL)")
	q.Set("_txlock", "immediate") // BEGIN IMMEDIATE: take the write lock up front
	return "file:" + path + "?" + q.Encode()
}

func readerDSN(path string, busy time.Duration) string {
	q := baseDSN(busy)
	q.Add("_pragma", "query_only(1)")
	return "file:" + path + "?" + q.Encode()
}

// secureFiles tightens permissions of the database files to 0600 (HP-DB-010).
func secureFiles(dir string) error {
	for _, name := range []string{DBFile, DBFile + "-wal", DBFile + "-shm", LockFile} {
		p := filepath.Join(dir, name)
		fi, err := os.Stat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("stat %s: %w", p, err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			if err := os.Chmod(p, 0o600); err != nil {
				return fmt.Errorf("chmod %s: %w", p, err)
			}
		}
	}
	return nil
}

// ReadTx runs fn in a read-only transaction on the reader pool, giving fn a consistent snapshot of the database.
func (s *Store) ReadTx(ctx context.Context, fn func(q *db.Queries) error) error {
	tx, err := s.rdb.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return classify(err)
	}
	defer func() { _ = tx.Rollback() }()
	return classify(fn(db.New(tx)))
}
