package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// QuickCheck runs PRAGMA quick_check and returns ErrCorrupt with details when it does not report "ok" (HP-DB-008).
func QuickCheck(ctx context.Context, d *sql.DB) error { return check(ctx, d, "quick_check") }

// IntegrityCheck runs the slower full PRAGMA integrity_check.
func (s *Store) IntegrityCheck(ctx context.Context) error {
	err := check(ctx, s.rdb, "integrity_check")
	s.health.Observe(err)
	return err
}

func check(ctx context.Context, d *sql.DB, pragma string) error {
	rows, err := d.QueryContext(ctx, "PRAGMA "+pragma)
	if err != nil {
		return classify(fmt.Errorf("%s: %w", pragma, err))
	}
	defer rows.Close()
	var msgs []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return classify(err)
		}
		msgs = append(msgs, m)
	}
	if err := rows.Err(); err != nil {
		return classify(err)
	}
	if len(msgs) == 1 && msgs[0] == "ok" {
		return nil
	}
	if len(msgs) > 5 {
		msgs = append(msgs[:5], "…")
	}
	return fmt.Errorf("%w: %s reported: %s; restore from the latest verified backup (docs/operator/storage.md)", ErrCorrupt, pragma, strings.Join(msgs, "; "))
}

// expectedPragmas are asserted on every pooled connection (HP-DB-002).
var expectedPragmas = map[string]string{
	"journal_mode":   "wal",
	"synchronous":    "2", // FULL
	"foreign_keys":   "1",
	"trusted_schema": "0",
}

// VerifyPragmas checks out n connections concurrently and verifies each has the required settings.
func VerifyPragmas(ctx context.Context, d *sql.DB, n int, readOnly bool, busy time.Duration) error {
	conns := make([]*sql.Conn, 0, n)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	for range n {
		c, err := d.Conn(ctx)
		if err != nil {
			return classify(err)
		}
		conns = append(conns, c)
	}
	for i, c := range conns {
		for name, want := range expectedPragmas {
			var got string
			if err := c.QueryRowContext(ctx, "PRAGMA "+name).Scan(&got); err != nil {
				return classify(fmt.Errorf("pragma %s: %w", name, err))
			}
			if !strings.EqualFold(got, want) {
				return fmt.Errorf("connection %d: PRAGMA %s = %s, want %s", i, name, got, want)
			}
		}
		var bt int64
		if err := c.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&bt); err != nil {
			return classify(err)
		}
		if bt != busy.Milliseconds() {
			return fmt.Errorf("connection %d: PRAGMA busy_timeout = %d, want %d", i, bt, busy.Milliseconds())
		}
		var qo string
		if err := c.QueryRowContext(ctx, "PRAGMA query_only").Scan(&qo); err != nil {
			return classify(err)
		}
		if (qo == "1") != readOnly {
			return fmt.Errorf("connection %d: PRAGMA query_only = %s, want read-only=%v", i, qo, readOnly)
		}
	}
	return nil
}

// Checkpoint runs a WAL checkpoint (mode PASSIVE, FULL, RESTART or TRUNCATE) on the writer.
func (s *Store) Checkpoint(ctx context.Context, mode string) error {
	switch mode {
	case "PASSIVE", "FULL", "RESTART", "TRUNCATE":
	default:
		return fmt.Errorf("invalid checkpoint mode %q", mode)
	}
	err := s.writer.Exec(ctx, "PRAGMA wal_checkpoint("+mode+")")
	s.writer.metrics.SetStoreSizes(s.Sizes()) // HP-DB-011: export sizes after each checkpoint
	return err
}

// IncrementalVacuum returns up to pages free pages to the filesystem (0 = all).
func (s *Store) IncrementalVacuum(ctx context.Context, pages int) error {
	return s.writer.Exec(ctx, fmt.Sprintf("PRAGMA incremental_vacuum(%d)", max(pages, 0)))
}

// Sizes reports database and WAL file sizes in bytes (HP-DB-011).
func (s *Store) Sizes() (dbBytes, walBytes int64) {
	if fi, err := statFile(s.Path(DBFile)); err == nil {
		dbBytes = fi
	}
	if fi, err := statFile(s.Path(DBFile + "-wal")); err == nil {
		walBytes = fi
	}
	return dbBytes, walBytes
}
