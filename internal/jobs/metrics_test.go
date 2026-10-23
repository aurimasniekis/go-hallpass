package jobs

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics/metricstest"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
)

func TestJobMetrics(t *testing.T) {
	s := storetest.Open(t)
	m := metrics.New()
	r := NewRunner(s, Options{PollInterval: 10 * time.Millisecond, BaseBackoff: 5 * time.Millisecond, MaxBackoff: 20 * time.Millisecond,
		Lease: time.Second, Metrics: m})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	r.Register("demo.retry", 3, 0, func(context.Context, Job) error {
		if calls.Add(1) == 1 {
			return errors.New("transient")
		}
		return nil
	})
	go r.Run(ctx)
	waitState(t, s, enqueue(t, s, r, "demo.retry", EnqueueOptions{}), "done")
	deadline := time.Now().Add(5 * time.Second)
	for metricstest.Value(t, m, "hallpass_job_runs_total", "job", "demo.retry") < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if e, o := metricstest.Value(t, m, "hallpass_job_runs_total", "job", "demo.retry", "result", "error"),
		metricstest.Value(t, m, "hallpass_job_runs_total", "job", "demo.retry", "result", "ok"); e != 1 || o != 1 {
		t.Errorf("runs error=%v ok=%v", e, o)
	}
}

func TestPeriodicWithMetrics(t *testing.T) {
	m := metrics.New()
	ctx, cancel := context.WithCancel(context.Background())
	var n atomic.Int32
	done := make(chan struct{})
	go func() {
		PeriodicWithMetrics(ctx, nopLogger(), m, "store.wal_checkpoint", 5*time.Millisecond, true, func(context.Context) error {
			switch n.Add(1) {
			case 1:
				return errors.New("busy")
			case 2:
				panic("survives")
			}
			return nil
		})
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for n.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if e := metricstest.Value(t, m, "hallpass_job_runs_total", "job", "store.wal_checkpoint", "result", "error"); e != 2 {
		t.Errorf("errors = %v (failure + panic)", e)
	}
	if o := metricstest.Value(t, m, "hallpass_job_runs_total", "job", "store.wal_checkpoint", "result", "ok"); o < 1 {
		t.Errorf("ok = %v", o)
	}
}
