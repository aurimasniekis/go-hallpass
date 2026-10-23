package jobs

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
)

func newRunner(t *testing.T) (*store.Store, *Runner, context.Context) {
	t.Helper()
	s := storetest.Open(t)
	r := NewRunner(s, Options{PollInterval: 10 * time.Millisecond, BaseBackoff: 5 * time.Millisecond, MaxBackoff: 20 * time.Millisecond, Lease: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return s, r, ctx
}

func enqueue(t *testing.T, s *store.Store, r *Runner, kind string, o EnqueueOptions) string {
	t.Helper()
	var id string
	err := s.W().Tx(context.Background(), func(tx *store.Tx) error {
		var err error
		id, err = r.Enqueue(context.Background(), tx, kind, map[string]string{"k": "v"}, o)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func waitState(t *testing.T, s *store.Store, id, state string) db.Job {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		j, err := s.R().GetJob(context.Background(), id)
		if err == nil && j.State == state {
			return j
		}
		time.Sleep(5 * time.Millisecond)
	}
	j, _ := s.R().GetJob(context.Background(), id)
	t.Fatalf("job %s did not reach %s: %+v", id, state, j)
	return j
}

func TestRunsJob(t *testing.T) {
	s, r, ctx := newRunner(t)
	var got atomic.Value
	r.Register("demo", 3, 0, func(_ context.Context, j Job) error {
		got.Store(string(j.Payload))
		return nil
	})
	go r.Run(ctx)
	id := enqueue(t, s, r, "demo", EnqueueOptions{})
	j := waitState(t, s, id, "done")
	if got.Load() != `{"k":"v"}` || j.Attempts != 1 {
		t.Fatalf("payload=%v attempts=%d", got.Load(), j.Attempts)
	}
}

func TestRetryThenSucceed(t *testing.T) {
	s, r, ctx := newRunner(t)
	var calls atomic.Int32
	r.Register("flaky", 5, 0, func(context.Context, Job) error {
		if calls.Add(1) < 3 {
			return errors.New("transient")
		}
		return nil
	})
	go r.Run(ctx)
	j := waitState(t, s, enqueue(t, s, r, "flaky", EnqueueOptions{}), "done")
	if j.Attempts != 3 || calls.Load() != 3 {
		t.Fatalf("attempts=%d calls=%d", j.Attempts, calls.Load())
	}
}

func TestDeadAfterMaxAttemptsAndPermanent(t *testing.T) {
	s, r, ctx := newRunner(t)
	r.Register("always", 3, 0, func(context.Context, Job) error { return errors.New("nope") })
	r.Register("perm", 5, 0, func(context.Context, Job) error { return Permanent(errors.New("bad input")) })
	r.Register("panics", 2, 0, func(context.Context, Job) error { panic("boom") })
	go r.Run(ctx)
	if j := waitState(t, s, enqueue(t, s, r, "always", EnqueueOptions{}), "dead"); j.Attempts != 3 || j.LastError.String != "nope" {
		t.Fatalf("%+v", j)
	}
	if j := waitState(t, s, enqueue(t, s, r, "perm", EnqueueOptions{}), "dead"); j.Attempts != 1 {
		t.Fatalf("permanent retried: %+v", j)
	}
	if j := waitState(t, s, enqueue(t, s, r, "panics", EnqueueOptions{}), "dead"); j.Attempts != 2 {
		t.Fatalf("%+v", j)
	}
}

func TestDedupAndDelay(t *testing.T) {
	s, r, _ := newRunner(t)
	r.Register("d", 1, 0, func(context.Context, Job) error { return nil })
	a := enqueue(t, s, r, "d", EnqueueOptions{DedupKey: "x", RunAt: time.Now().Add(time.Hour)})
	b := enqueue(t, s, r, "d", EnqueueOptions{DedupKey: "x"})
	if a == "" || b != "" {
		t.Fatalf("dedup failed: %q %q", a, b)
	}
	due, _ := s.R().DueJobs(context.Background(), db.DueJobsParams{Now: time.Now().UnixMicro(), Lim: 10})
	if len(due) != 0 {
		t.Fatal("delayed job is due early")
	}
}

// HP-OPS-014: a job whose lease expired (process crashed mid-run) is reclaimed and completed.
func TestExpiredLeaseReclaimed(t *testing.T) {
	s, r, ctx := newRunner(t)
	var calls atomic.Int32
	r.Register("crash", 3, 0, func(context.Context, Job) error { calls.Add(1); return nil })
	id := enqueue(t, s, r, "crash", EnqueueOptions{})
	// Simulate a crashed owner: running with a lease that already expired.
	if err := s.W().Exec(context.Background(), "UPDATE jobs SET state='running', attempts=1, lease_until=? WHERE id=?",
		time.Now().Add(-time.Second).UnixMicro(), id); err != nil {
		t.Fatal(err)
	}
	go r.Run(ctx)
	j := waitState(t, s, id, "done")
	if calls.Load() != 1 || j.Attempts != 2 {
		t.Fatalf("calls=%d attempts=%d", calls.Load(), j.Attempts)
	}
}

func TestUnregisteredKindStaysQueued(t *testing.T) {
	s, r, ctx := newRunner(t)
	go r.Run(ctx)
	id := enqueue(t, s, r, "unknown", EnqueueOptions{})
	time.Sleep(50 * time.Millisecond)
	if j, _ := s.R().GetJob(context.Background(), id); j.State != "queued" {
		t.Fatalf("state %s", j.State)
	}
}

func TestBackoffBounds(t *testing.T) {
	for attempt := 1; attempt < 20; attempt++ {
		d := Backoff(time.Second, 5*time.Minute, attempt)
		if d < 0 || d > 5*time.Minute {
			t.Fatalf("attempt %d: %s", attempt, d)
		}
	}
}

func TestPeriodic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var n atomic.Int32
	done := make(chan struct{})
	go func() {
		Periodic(ctx, nopLogger(), "t", 5*time.Millisecond, true, func(context.Context) error {
			if n.Add(1) == 2 {
				panic("survives")
			}
			return nil
		})
		close(done)
	}()
	time.Sleep(40 * time.Millisecond)
	cancel()
	<-done
	if n.Load() < 3 {
		t.Fatalf("ran %d times", n.Load())
	}
}
