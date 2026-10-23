package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics/metricstest"
)

// HP-DB-003/004/011: write transactions, busy retries, writer wait and DB/WAL sizes are exported.
func TestWriterMetrics(t *testing.T) {
	m := metrics.New()
	s := openTest(t, Options{Metrics: m, BusyTimeout: 5 * time.Millisecond})
	ctx := context.Background()
	if v := metricstest.Value(t, m, "hallpass_store_db_bytes"); v == 0 {
		t.Error("db size not exported at open")
	}
	if err := s.W().TxNamed(ctx, "test.put", func(tx *Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.W().TxNamed(ctx, "test.fail", func(tx *Tx) error { return fmt.Errorf("x: %w", ErrConflict) }); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	<-holdWriteLock(t, s.Path(DBFile), 0) // warm up
	released := holdWriteLock(t, s.Path(DBFile), 3*time.Second)
	if err := s.W().TxNamed(ctx, "test.busy", func(tx *Tx) error { return nil }); !errors.Is(err, ErrBusy) {
		t.Fatalf("want busy, got %v", err)
	}
	<-released
	for _, c := range []struct{ name, result string }{{"test.put", "ok"}, {"test.fail", "conflict"}, {"test.busy", "busy"}} {
		if v := metricstest.Value(t, m, "hallpass_store_tx_total", "name", c.name, "result", c.result); v != 1 {
			t.Errorf("%s/%s = %v", c.name, c.result, v)
		}
	}
	if v := metricstest.Value(t, m, "hallpass_store_tx_busy_retries_total"); v != txMaxAttempts-1 {
		t.Errorf("busy retries = %v, want %d", v, txMaxAttempts-1)
	}
	if v := metricstest.Value(t, m, "hallpass_store_writer_wait_seconds"); v < 3 {
		t.Errorf("writer wait samples = %v", v)
	}
	if err := s.Checkpoint(ctx, "TRUNCATE"); err != nil {
		t.Fatal(err)
	}
}

func TestTxResultClassification(t *testing.T) {
	for err, want := range map[error]metrics.TxResult{
		nil: metrics.TxOK, context.Canceled: metrics.TxCanceled, ErrBusy: metrics.TxBusy, ErrFull: metrics.TxFull, ErrIO: metrics.TxIO,
		ErrCorrupt: metrics.TxCorrupt, ErrConstraint: metrics.TxConstraint, ErrConflict: metrics.TxConflict, sql.ErrNoRows: metrics.TxNotFound,
		ErrNotFound: metrics.TxNotFound, errors.New("other"): metrics.TxError,
	} {
		if got := TxResult(err); got != want {
			t.Errorf("TxResult(%v) = %s, want %s", err, got, want)
		}
	}
}
