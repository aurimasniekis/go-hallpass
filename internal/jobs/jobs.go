// Package jobs runs durable background work stored in SQLite (HP-OPS-014).
//
// One-off jobs are enqueued inside the caller's transaction, claimed with a lease, executed outside any transaction
// and retried with exponential backoff up to MaxAttempts before becoming dead. A crashed process's leases expire and
// the jobs are reclaimed. Periodic tasks (sweeps) are idempotent and restart-safe; they are scheduled in memory.
package jobs

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Job is a claimed unit of work.
type Job struct {
	ID       string
	Kind     string
	Attempt  int
	Payload  json.RawMessage
	Deadline time.Time
}

// Handler executes a job. Returning an error schedules a retry (or marks the job dead after the last attempt);
// wrap with Permanent to stop retrying immediately.
type Handler func(ctx context.Context, job Job) error

type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }

// Permanent marks err as non-retryable.
func Permanent(err error) error { return permanentError{err: err} }

// Kind configuration.
type kindConfig struct {
	handler     Handler
	maxAttempts int
	timeout     time.Duration
}

// Options configure a Runner.
type Options struct {
	Concurrency  int           // parallel job executions (default 4)
	PollInterval time.Duration // idle poll interval (default 500ms)
	Lease        time.Duration // lease per execution; also the reclaim window after a crash (default 2m)
	BaseBackoff  time.Duration // first retry delay (default 2s)
	MaxBackoff   time.Duration // retry delay cap (default 5m)
	Logger       *slog.Logger
	Clock        clock.Clock
}

// Runner claims and executes jobs.
type Runner struct {
	s     *store.Store
	opts  Options
	log   *slog.Logger
	mu    sync.RWMutex
	kinds map[string]kindConfig
	wake  chan struct{}
}

// NewRunner returns a runner over s.
func NewRunner(s *store.Store, opts Options) *Runner {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 500 * time.Millisecond
	}
	if opts.Lease <= 0 {
		opts.Lease = 2 * time.Minute
	}
	if opts.BaseBackoff <= 0 {
		opts.BaseBackoff = 2 * time.Second
	}
	if opts.MaxBackoff <= 0 {
		opts.MaxBackoff = 5 * time.Minute
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Clock == nil {
		opts.Clock = clock.System{}
	}
	return &Runner{s: s, opts: opts, log: obs.Component(opts.Logger, "jobs"), kinds: map[string]kindConfig{}, wake: make(chan struct{}, 1)}
}

// Register installs the handler for kind. maxAttempts ≥ 1; timeout bounds each execution (≤ lease).
func (r *Runner) Register(kind string, maxAttempts int, timeout time.Duration, h Handler) {
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	if timeout <= 0 || timeout > r.opts.Lease {
		timeout = r.opts.Lease
	}
	r.mu.Lock()
	r.kinds[kind] = kindConfig{handler: h, maxAttempts: maxAttempts, timeout: timeout}
	r.mu.Unlock()
}

// EnqueueOptions control scheduling.
type EnqueueOptions struct {
	RunAt time.Time // default: now
	// DedupKey prevents enqueueing a second queued/running job with the same key.
	DedupKey    string
	MaxAttempts int // default: the kind's registered value, else 5
}

// Enqueue adds a job inside tx and wakes the runner after commit. It returns ("", nil) when deduplicated.
func (r *Runner) Enqueue(ctx context.Context, tx *store.Tx, kind string, payload any, o EnqueueOptions) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("job payload: %w", err)
	}
	maxAttempts := o.MaxAttempts
	if maxAttempts <= 0 {
		r.mu.RLock()
		maxAttempts = r.kinds[kind].maxAttempts
		r.mu.RUnlock()
		if maxAttempts <= 0 {
			maxAttempts = 5
		}
	}
	runAt := o.RunAt
	if runAt.IsZero() {
		runAt = tx.Now
	}
	id := ids.New(ids.Job)
	n, err := tx.Q.InsertJob(ctx, db.InsertJobParams{
		ID: id, Kind: kind, RunAt: runAt.UnixMicro(), MaxAttempts: int64(maxAttempts), PayloadJson: string(data),
		DedupKey: sql.NullString{String: o.DedupKey, Valid: o.DedupKey != ""}, CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros(),
	})
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", nil
	}
	tx.AfterCommit(r.Wake)
	return id, nil
}

// Wake prompts the runner to poll immediately.
func (r *Runner) Wake() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Run processes jobs until ctx is canceled, then waits for in-flight jobs.
func (r *Runner) Run(ctx context.Context) {
	sem := make(chan struct{}, r.opts.Concurrency)
	var wg sync.WaitGroup
	defer wg.Wait()
	t := time.NewTicker(r.opts.PollInterval)
	defer t.Stop()
	for {
		claimed, err := r.claim(ctx, cap(sem)-len(sem))
		if err != nil && ctx.Err() == nil {
			r.log.Warn("claiming jobs failed", obs.Err(err))
		}
		for _, j := range claimed {
			sem <- struct{}{}
			wg.Go(func() {
				defer func() { <-sem }()
				r.execute(ctx, j)
			})
		}
		if len(claimed) > 0 && len(sem) < cap(sem) {
			continue // more may be due
		}
		select {
		case <-ctx.Done():
			return
		case <-r.wake:
		case <-t.C:
		}
	}
}

type claimedJob struct {
	Job
	cfg         kindConfig
	maxAttempts int
}

func (r *Runner) claim(ctx context.Context, slots int) ([]claimedJob, error) {
	if slots <= 0 {
		return nil, nil
	}
	now := r.opts.Clock.Now()
	due, err := r.s.R().DueJobs(ctx, db.DueJobsParams{Now: now.UnixMicro(), Lim: int64(slots)})
	if err != nil || len(due) == 0 {
		return nil, err
	}
	var out []claimedJob
	err = r.s.W().TxNamed(ctx, "jobs.claim", func(tx *store.Tx) error {
		out = out[:0]
		lease := tx.Now.Add(r.opts.Lease)
		for _, d := range due {
			r.mu.RLock()
			cfg, ok := r.kinds[d.Kind]
			r.mu.RUnlock()
			if !ok {
				continue // another component may register it later; leave queued
			}
			n, err := tx.Q.ClaimJob(ctx, db.ClaimJobParams{
				LeaseUntil: sql.NullInt64{Int64: lease.UnixMicro(), Valid: true}, Now: tx.NowMicros(), ID: d.ID,
			})
			if err != nil {
				return err
			}
			if n == 1 {
				out = append(out, claimedJob{
					Job: Job{ID: d.ID, Kind: d.Kind, Attempt: int(d.Attempts) + 1, Payload: json.RawMessage(d.PayloadJson), Deadline: lease},
					cfg: cfg, maxAttempts: int(d.MaxAttempts),
				})
			}
		}
		return nil
	})
	return out, err
}

func (r *Runner) execute(parent context.Context, j claimedJob) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), j.cfg.timeout)
	defer cancel()
	err := safeRun(ctx, j.cfg.handler, j.Job)
	state, runAt, lastErr := "done", r.opts.Clock.Now(), sql.NullString{}
	if err != nil {
		lastErr = sql.NullString{String: truncate(err.Error(), 1000), Valid: true}
		var perm permanentError
		if errors.As(err, &perm) || j.Attempt >= j.maxAttempts {
			state = "dead"
			r.log.Error("job failed permanently", slog.String("job.kind", j.Kind), slog.String("job.id", j.ID), slog.Int("attempt", j.Attempt), obs.Err(err))
		} else {
			state = "queued"
			runAt = runAt.Add(backoff(r.opts.BaseBackoff, r.opts.MaxBackoff, j.Attempt))
			r.log.Warn("job failed; will retry", slog.String("job.kind", j.Kind), slog.String("job.id", j.ID), slog.Int("attempt", j.Attempt), obs.Err(err))
		}
	}
	ferr := r.s.W().TxNamed(context.WithoutCancel(parent), "jobs.finish", func(tx *store.Tx) error {
		return tx.Q.FinishJob(context.WithoutCancel(parent), db.FinishJobParams{
			State: state, RunAt: runAt.UnixMicro(), LastError: lastErr, UpdatedAt: tx.NowMicros(), ID: j.ID,
		})
	})
	if ferr != nil {
		r.log.Error("recording job result failed; lease expiry will retry it", slog.String("job.id", j.ID), obs.Err(ferr))
	}
}

func safeRun(ctx context.Context, h Handler, j Job) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("job panicked: %v", p)
		}
	}()
	return h(ctx, j)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Backoff returns an exponential delay with full jitter for attempt (1-based), capped at maxDelay.
func backoff(base, maxDelay time.Duration, attempt int) time.Duration {
	d := base
	for i := 1; i < attempt && d < maxDelay; i++ {
		d *= 2
	}
	d = min(d, maxDelay)
	var b [8]byte
	_, _ = rand.Read(b[:])
	half := d / 2
	return half + time.Duration(binary.LittleEndian.Uint64(b[:])%uint64(half+1)) //nolint:gosec // half ≥ 0
}

// Backoff is exported for other retry loops (outbox).
func Backoff(base, maxDelay time.Duration, attempt int) time.Duration {
	return backoff(base, maxDelay, attempt)
}

// Periodic runs fn every interval until ctx is canceled (first run after one interval, or immediately if now).
// Panics and errors are logged; fn must be idempotent.
func Periodic(ctx context.Context, log *slog.Logger, name string, interval time.Duration, now bool, fn func(context.Context) error) {
	t := time.NewTicker(interval)
	defer t.Stop()
	run := func() {
		defer func() {
			if p := recover(); p != nil {
				log.Error("periodic task panicked", slog.String("task", name), slog.Any("panic", p))
			}
		}()
		if err := fn(ctx); err != nil && ctx.Err() == nil {
			log.Warn("periodic task failed", slog.String("task", name), obs.Err(err))
		}
	}
	if now {
		run()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
