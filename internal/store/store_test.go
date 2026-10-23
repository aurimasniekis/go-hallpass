package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

func openTest(t *testing.T, o Options) *Store {
	t.Helper()
	if o.DataDir == "" {
		o.DataDir = filepath.Join(t.TempDir(), "data")
	}
	s, err := Open(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func putSetting(ctx context.Context, s *Store, k, v string) error {
	return s.W().Tx(ctx, func(tx *Tx) error {
		return tx.Q.UpsertSetting(ctx, db.UpsertSettingParams{Key: k, Value: v, UpdatedAt: tx.NowMicros()})
	})
}

func TestOpenLayoutAndPermissions(t *testing.T) {
	s := openTest(t, Options{})
	fi, err := os.Stat(s.Dir())
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("data dir mode %v %v", fi.Mode().Perm(), err)
	}
	for _, sub := range []string{BackupsDir, RecordingsDir, QuarantineDir} {
		if fi, err := os.Stat(s.Path(sub)); err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v %v", sub, err, fi)
		}
	}
	if err := putSetting(context.Background(), s, "a", "b"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{DBFile, LockFile} {
		fi, err := os.Stat(s.Path(f))
		if err != nil || fi.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s mode %v %v", f, fi.Mode().Perm(), err)
		}
	}
}

// HP-DB-010: group/world-accessible data dirs are refused.
func TestRefusesOpenPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Open(context.Background(), Options{DataDir: dir})
	if err == nil || !strings.Contains(err.Error(), "must not be accessible") {
		t.Fatalf("expected permission refusal, got %v", err)
	}
}

// HP-DB-002: pragmas on every pooled connection; readers are read-only.
func TestPragmasEveryConnection(t *testing.T) {
	s := openTest(t, Options{Readers: 6})
	ctx := context.Background()
	if err := VerifyPragmas(ctx, s.rdb, 6, true, DefaultBusyTimeout); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPragmas(ctx, s.wdb, 1, false, DefaultBusyTimeout); err != nil {
		t.Fatal(err)
	}
	var av int
	if err := s.rdb.QueryRowContext(ctx, "PRAGMA auto_vacuum").Scan(&av); err != nil || av != 2 {
		t.Fatalf("auto_vacuum = %d (%v), want 2 (incremental)", av, err)
	}
	if _, err := s.ReadDB().ExecContext(ctx, "INSERT INTO settings (key, value, updated_at) VALUES ('x','y',0)"); err == nil {
		t.Fatal("reader pool accepted a write")
	}
}

// HP-DB-006: a second process owner is refused.
func TestSecondOwnerRefused(t *testing.T) {
	s := openTest(t, Options{})
	_, err := Open(context.Background(), Options{DataDir: s.Dir()})
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("expected ErrLocked, got %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(context.Background(), Options{DataDir: s.Dir()})
	if err != nil {
		t.Fatalf("reopen after release: %v", err)
	}
	_ = s2.Close()
}

// HP-DB-003: concurrent writers never surface SQLITE_BUSY.
func TestConcurrentWriters(t *testing.T) {
	s := openTest(t, Options{})
	ctx := context.Background()
	var wg sync.WaitGroup
	var failures atomic.Int64
	for g := range 100 {
		wg.Go(func() {
			for i := range 10 {
				if err := putSetting(ctx, s, fmt.Sprintf("k-%d-%d", g, i), "v"); err != nil {
					failures.Add(1)
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	rows, err := s.R().ListSettings(ctx)
	if err != nil || len(rows) != 1000 || failures.Load() != 0 {
		t.Fatalf("rows=%d err=%v failures=%d", len(rows), err, failures.Load())
	}
}

func TestTxRollbackAndHooks(t *testing.T) {
	s := openTest(t, Options{})
	ctx := context.Background()
	var hooks atomic.Int32
	boom := errors.New("boom")
	err := s.W().Tx(ctx, func(tx *Tx) error {
		tx.AfterCommit(func() { hooks.Add(1) })
		if err := tx.Q.UpsertSetting(ctx, db.UpsertSettingParams{Key: "r", Value: "1", UpdatedAt: tx.NowMicros()}); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) || hooks.Load() != 0 {
		t.Fatalf("err=%v hooks=%d", err, hooks.Load())
	}
	if _, err := s.R().GetSetting(ctx, "r"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("rolled-back row visible: %v", err)
	}
	err = s.W().Tx(ctx, func(tx *Tx) error {
		tx.AfterCommit(func() { hooks.Add(1) })
		return tx.Q.UpsertSetting(ctx, db.UpsertSettingParams{Key: "r", Value: "1", UpdatedAt: tx.NowMicros()})
	})
	if err != nil || hooks.Load() != 1 {
		t.Fatalf("err=%v hooks=%d", err, hooks.Load())
	}
}

func TestConstraintClassified(t *testing.T) {
	s := openTest(t, Options{})
	ctx := context.Background()
	err := s.W().Tx(ctx, func(tx *Tx) error {
		_, err := tx.SQL.ExecContext(ctx, "INSERT INTO keyring_keys (id, purpose, version, wrapped, wrap_kek_id, state, created_at, updated_at) VALUES ('a','bogus',1,x'00','k','active',0,0)")
		return err
	})
	if !errors.Is(err, ErrConstraint) || !IsConstraint(err) {
		t.Fatalf("expected constraint error, got %v", err)
	}
}

// holdWriteLock takes the database write lock from an independent connection for d.
func holdWriteLock(t *testing.T, path string, d time.Duration) (released chan struct{}) {
	t.Helper()
	other, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(0)")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := other.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	released = make(chan struct{})
	go func() {
		time.Sleep(d)
		_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		_ = conn.Close()
		_ = other.Close()
		close(released)
	}()
	return released
}

// HP-DB-003: bounded retries with backoff recover from short contention and give up with ErrBusy.
func TestBusyRetryAndGiveUp(t *testing.T) {
	s := openTest(t, Options{BusyTimeout: 5 * time.Millisecond})
	ctx := context.Background()
	<-holdWriteLock(t, s.Path(DBFile), 0) // warm up
	released := holdWriteLock(t, s.Path(DBFile), 15*time.Millisecond)
	if err := putSetting(ctx, s, "x", "1"); err != nil {
		t.Fatalf("short contention should be retried: %v", err)
	}
	<-released
	released = holdWriteLock(t, s.Path(DBFile), 3*time.Second)
	err := putSetting(ctx, s, "y", "1")
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("expected ErrBusy after bounded retries, got %v", err)
	}
	<-released
}

func TestSnapshotRoundTrip(t *testing.T) {
	s := openTest(t, Options{})
	ctx := context.Background()
	if err := putSetting(ctx, s, "snap", "value"); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "snap.db")
	if err := s.Snapshot(ctx, dest); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dest); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode %v %v", fi, err)
	}
	if err := s.Snapshot(ctx, dest); err == nil {
		t.Fatal("snapshot overwrote an existing file")
	}
	raw, err := sql.Open("sqlite", "file:"+dest+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	got, err := db.New(raw).GetSetting(ctx, "snap")
	if err != nil || got.Value != "value" {
		t.Fatalf("snapshot content: %v %v", got, err)
	}
	if err := QuickCheck(ctx, raw); err != nil {
		t.Fatal(err)
	}
}

func migFS(files map[string]string) fstest.MapFS {
	m := fstest.MapFS{}
	for name, body := range files {
		m[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return m
}

const (
	mig1 = "-- +goose Up\nCREATE TABLE t1 (id INTEGER PRIMARY KEY) STRICT;\n-- +goose Down\nSELECT 1;\n"
	mig2 = "-- +goose Up\nCREATE TABLE t2 (id INTEGER PRIMARY KEY) STRICT;\n-- +goose Down\nSELECT 1;\n"
	bad3 = "-- +goose Up\nCREATE TABLE t3 (id INTEGER PRIMARY KEY) STRICT;\nINSERT INTO nope VALUES (1);\n-- +goose Down\nSELECT 1;\n"
)

// HP-DB-005: failing migrations roll back, leave the prior version, and a pre-migration snapshot exists.
func TestMigrationFailureAndSnapshot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	ctx := context.Background()
	s, err := Open(ctx, Options{DataDir: dir, migrations: migFS(map[string]string{"0001_a.sql": mig1})})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	_, err = Open(ctx, Options{DataDir: dir, migrations: migFS(map[string]string{"0001_a.sql": mig1, "0002_b.sql": mig2, "0003_c.sql": bad3})})
	if err == nil || !strings.Contains(err.Error(), "migration failed") {
		t.Fatalf("expected migration failure, got %v", err)
	}
	s, err = Open(ctx, Options{DataDir: dir, SkipMigrate: true, migrations: migFS(map[string]string{"0001_a.sql": mig1, "0002_b.sql": mig2, "0003_c.sql": bad3})})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cur, latest, err := SchemaVersions(ctx, s.wdb, migFS(map[string]string{"0001_a.sql": mig1, "0002_b.sql": mig2, "0003_c.sql": bad3}))
	if err != nil || cur != 2 || latest != 3 {
		t.Fatalf("cur=%d latest=%d err=%v", cur, latest, err)
	}
	var n int
	if err := s.rdb.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE name = 't3'").Scan(&n); err != nil || n != 0 {
		t.Fatalf("failed migration left table t3: n=%d err=%v", n, err)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, BackupsDir))
	if len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "pre-migrate-0001-0003-") {
		t.Fatalf("expected one pre-migration snapshot, got %v", entries)
	}
}

// HP-DB-005: a database migrated by a newer binary is refused.
func TestSchemaTooNewRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	ctx := context.Background()
	s, err := Open(ctx, Options{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.W().Exec(ctx, "INSERT INTO goose_db_version (version_id, is_applied) VALUES (9999, 1)"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	_, err = Open(ctx, Options{DataDir: dir})
	if !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("expected ErrSchemaTooNew, got %v", err)
	}
	_, err = Open(ctx, Options{DataDir: dir, SkipMigrate: true})
	if !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("expected ErrSchemaTooNew with SkipMigrate, got %v", err)
	}
}

func TestPruneSnapshots(t *testing.T) {
	dir := t.TempDir()
	for _, ts := range []string{"20260101T000000Z", "20260102T000000Z", "20260103T000000Z", "20260104T000000Z"} {
		if err := os.WriteFile(filepath.Join(dir, "pre-migrate-0001-0002-"+ts+".db"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pruneSnapshots(dir, 2, nopLogger())
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 || !strings.Contains(entries[0].Name(), "20260103") {
		t.Fatalf("unexpected remaining: %v", entries)
	}
}

// HP-DB-008: corruption is detected at startup and the store refuses to open.
func TestCorruptionRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	ctx := context.Background()
	s, err := Open(ctx, Options{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 200 {
		if err := putSetting(ctx, s, fmt.Sprintf("key-%03d", i), strings.Repeat("v", 200)); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.Close()
	path := filepath.Join(dir, DBFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 4096 + 100; i < len(data) && i < 4096*6; i += 7 {
		data[i] ^= 0xA5
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Open(ctx, Options{DataDir: dir})
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("expected ErrCorrupt, got %v", err)
	}
}

func TestHealthTransitions(t *testing.T) {
	fc := clock.NewFake(time.Unix(1_800_000_000, 0))
	h := newHealth(fc)
	h.Observe(fmt.Errorf("%w: x", ErrBusy))
	fc.Advance(BusyDegradeAfter + time.Second)
	h.Observe(fmt.Errorf("%w: x", ErrBusy))
	if h.Status().State != HealthDegraded || h.AcceptsWrites() {
		t.Fatalf("sustained busy should degrade: %+v", h.Status())
	}
	h.Observe(nil)
	if h.Status().State != HealthOK {
		t.Fatal("success should recover from degraded")
	}
	h.Observe(fmt.Errorf("%w: x", ErrFull))
	if h.Status().State != HealthDegraded {
		t.Fatal("disk full should degrade")
	}
	for range ioFailThreshold {
		h.Observe(fmt.Errorf("%w: x", ErrIO))
	}
	if h.Status().State != HealthFailed {
		t.Fatal("repeated I/O errors should fail")
	}
	h.Observe(nil)
	if h.Status().State != HealthFailed {
		t.Fatal("failed must be sticky")
	}
	h2 := newHealth(fc)
	h2.Degrade("low disk")
	h2.Recover("other")
	if h2.Status().State != HealthDegraded {
		t.Fatal("recover with a different reason must not clear")
	}
	h2.Recover("low disk")
	if h2.Status().State != HealthOK {
		t.Fatal("recover failed")
	}
}

func TestTxObserverAndIncrementalVacuum(t *testing.T) {
	var calls atomic.Int32
	s := openTest(t, Options{TxObserver: func(string, time.Duration, error) { calls.Add(1) }})
	ctx := context.Background()
	if err := putSetting(ctx, s, "a", "b"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("observer calls = %d", calls.Load())
	}
	if err := s.IncrementalVacuum(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.Checkpoint(ctx, "TRUNCATE"); err != nil {
		t.Fatal(err)
	}
	if err := s.Checkpoint(ctx, "BOGUS"); err == nil {
		t.Fatal("invalid checkpoint mode accepted")
	}
	if err := s.IntegrityCheck(ctx); err != nil {
		t.Fatal(err)
	}
	if dbb, _ := s.Sizes(); dbb == 0 {
		t.Fatal("sizes not reported")
	}
}
