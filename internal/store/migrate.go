package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pressly/goose/v3"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// ErrSchemaTooNew means the database was migrated by a newer HallPass; downgrades are refused (HP-DB-005).
var ErrSchemaTooNew = errors.New("database schema is newer than this binary")

func newProvider(d *sql.DB, fsys fs.FS) (*goose.Provider, error) {
	return goose.NewProvider(goose.DialectSQLite3, d, fsys, goose.WithDisableGlobalRegistry(true))
}

// EmbeddedMigrations returns the migrations compiled into the binary.
func EmbeddedMigrations() fs.FS {
	sub, err := fs.Sub(migrationFS, "migrations")
	if err != nil {
		panic(err)
	}
	return sub
}

// SchemaVersions returns the current database version and the latest embedded version.
func SchemaVersions(ctx context.Context, d *sql.DB, fsys fs.FS) (current, latest int64, err error) {
	p, err := newProvider(d, fsys)
	if err != nil {
		return 0, 0, err
	}
	current, err = p.GetDBVersion(ctx)
	if err != nil {
		return 0, 0, classify(err)
	}
	srcs := p.ListSources()
	if len(srcs) > 0 {
		latest = srcs[len(srcs)-1].Version
	}
	return current, latest, nil
}

func checkSchemaNotNewer(ctx context.Context, d *sql.DB, fsys fs.FS) error {
	cur, latest, err := SchemaVersions(ctx, d, fsys)
	if err != nil {
		return err
	}
	if cur > latest {
		return fmt.Errorf("%w: database at version %d, binary supports up to %d; run a newer hallpass or restore a backup", ErrSchemaTooNew, cur, latest)
	}
	return nil
}

// migrate applies pending migrations under the process lock. Before applying any, a VACUUM INTO snapshot
// is written to <data>/backups so that a failed upgrade can be rolled back by restoring it.
func migrate(ctx context.Context, d *sql.DB, fsys fs.FS, dir string, keep int, c clock.Clock, log *slog.Logger) error {
	cur, latest, err := SchemaVersions(ctx, d, fsys)
	if err != nil {
		return err
	}
	if cur > latest {
		return fmt.Errorf("%w: database at version %d, binary supports up to %d; run a newer hallpass or restore a backup", ErrSchemaTooNew, cur, latest)
	}
	if cur == latest {
		return nil
	}
	if cur > 0 {
		name := fmt.Sprintf("pre-migrate-%04d-%04d-%s.db", cur, latest, c.Now().UTC().Format("20060102T150405Z"))
		path := filepath.Join(dir, BackupsDir, name)
		exec := func(ctx context.Context, q string, args ...any) error {
			_, err := d.ExecContext(ctx, q, args...)
			return classify(err)
		}
		if err := snapshot(ctx, exec, path); err != nil {
			return fmt.Errorf("pre-migration snapshot: %w", err)
		}
		log.Info("pre-migration snapshot written", slog.String("path", path), slog.Int64("from", cur), slog.Int64("to", latest))
		pruneSnapshots(filepath.Join(dir, BackupsDir), keep, log)
	}
	p, err := newProvider(d, fsys)
	if err != nil {
		return err
	}
	results, err := p.Up(ctx)
	for _, r := range results {
		if r.Error == nil {
			log.Info("migration applied", slog.Int64("version", r.Source.Version), slog.Duration("duration", r.Duration))
		}
	}
	if err != nil {
		return fmt.Errorf("migration failed (database left at the last successful version; pre-migration snapshot in %s): %w",
			filepath.Join(dir, BackupsDir), classify(err))
	}
	return nil
}

func pruneSnapshots(dir string, keep int, log *slog.Logger) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var snaps []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "pre-migrate-") && strings.HasSuffix(e.Name(), ".db") {
			snaps = append(snaps, e.Name())
		}
	}
	sort.Slice(snaps, func(i, j int) bool { return snapTime(snaps[i]) < snapTime(snaps[j]) })
	for len(snaps) > keep {
		p := filepath.Join(dir, snaps[0])
		if err := os.Remove(p); err == nil {
			log.Info("pruned old pre-migration snapshot", slog.String("path", p))
		}
		snaps = snaps[1:]
	}
}

// snapTime extracts the sortable timestamp suffix of a snapshot name.
func snapTime(name string) string {
	name = strings.TrimSuffix(name, ".db")
	if i := strings.LastIndexByte(name, '-'); i >= 0 {
		return name[i+1:]
	}
	return name
}
