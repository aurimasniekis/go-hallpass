package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Retry policy for SQLITE_BUSY on the writer (PLAN §4.2).
const (
	txMaxAttempts = 5
	txBaseBackoff = 10 * time.Millisecond
	txMaxBackoff  = time.Second
)

// TxObserver receives the duration and final error of each write transaction.
type TxObserver func(name string, d time.Duration, err error)

// Writer is the single write connection. All mutations go through Tx.
type Writer struct {
	db       *sql.DB
	clock    clock.Clock
	health   *Health
	observer TxObserver
}

// Tx is a write transaction. Its callback must only touch the database: no network, SSH, file fsync,
// channel operations or waits (enforced by the txscope analyzer, HP-DB-004).
type Tx struct {
	// Q runs typed queries inside the transaction.
	Q *db.Queries
	// SQL is the raw transaction for dynamic statements.
	SQL *sql.Tx
	// Now is the transaction's timestamp, taken after BEGIN IMMEDIATE acquired the write lock.
	Now time.Time

	afterCommit []func()
}

// AfterCommit registers fn to run after a successful commit (e.g. publishing events). Hooks from failed or
// retried attempts never run.
func (t *Tx) AfterCommit(fn func()) { t.afterCommit = append(t.afterCommit, fn) }

// NowMicros is Now as persisted Unix microseconds.
func (t *Tx) NowMicros() int64 { return t.Now.UnixMicro() }

// Tx runs fn in a BEGIN IMMEDIATE transaction, retrying the whole callback on SQLITE_BUSY with jittered backoff.
// fn must be safe to re-run. Returned errors are classified (ErrBusy, ErrFull, ErrIO, ErrCorrupt, ErrConstraint).
func (w *Writer) Tx(ctx context.Context, fn func(tx *Tx) error) error {
	return w.TxNamed(ctx, "", fn)
}

// TxNamed is Tx with a name for observability.
func (w *Writer) TxNamed(ctx context.Context, name string, fn func(tx *Tx) error) error {
	start := time.Now()
	var err error
	for attempt := 1; ; attempt++ {
		var hooks []func()
		hooks, err = w.attempt(ctx, fn)
		if err == nil {
			w.health.Observe(nil)
			if w.observer != nil {
				w.observer(name, time.Since(start), nil)
			}
			for _, h := range hooks {
				h()
			}
			return nil
		}
		w.health.Observe(err)
		if !errors.Is(err, ErrBusy) || attempt >= txMaxAttempts || ctx.Err() != nil {
			break
		}
		if serr := sleepCtx(ctx, backoff(attempt)); serr != nil {
			err = errors.Join(err, serr)
			break
		}
	}
	if w.observer != nil {
		w.observer(name, time.Since(start), err)
	}
	return err
}

func (w *Writer) attempt(ctx context.Context, fn func(tx *Tx) error) (hooks []func(), err error) {
	sqlTx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, classify(fmt.Errorf("begin: %w", err))
	}
	tx := &Tx{Q: db.New(sqlTx), SQL: sqlTx, Now: w.clock.Now().UTC()}
	defer func() {
		if p := recover(); p != nil {
			_ = sqlTx.Rollback()
			panic(p)
		}
	}()
	if err := fn(tx); err != nil {
		_ = sqlTx.Rollback()
		return nil, classify(err)
	}
	if err := sqlTx.Commit(); err != nil {
		_ = sqlTx.Rollback()
		return nil, classify(fmt.Errorf("commit: %w", err))
	}
	return tx.afterCommit, nil
}

// Exec runs a statement outside an explicit transaction on the writer (maintenance: VACUUM, checkpoints).
func (w *Writer) Exec(ctx context.Context, query string, args ...any) error {
	_, err := w.db.ExecContext(ctx, query, args...)
	err = classify(err)
	w.health.Observe(err)
	return err
}

func backoff(attempt int) time.Duration {
	ceiling := min(txBaseBackoff<<(attempt-1), txMaxBackoff)
	var b [8]byte
	_, _ = rand.Read(b[:])
	return time.Duration(binary.LittleEndian.Uint64(b[:]) % uint64(ceiling)) //nolint:gosec // ceiling > 0
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
