package events

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/aurimasniekis/go-pulse/pkg/pulse"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Publisher is the part of the Pulse client the relay uses.
type Publisher interface {
	Publish(ctx context.Context, subject, typ string, data any, opts ...pulse.PublishOption) (*pulse.PubAck, error)
}

// Limits of the retry policy.
const (
	MaxAttempts = 50
	MaxAge      = 24 * time.Hour
	MaxBackoff  = 5 * time.Minute
	batch       = 100
)

// Relay publishes due outbox rows.
type Relay struct {
	Store   *store.Store
	Pub     Publisher
	Clock   clock.Clock
	Metrics *metrics.Metrics
	Log     *slog.Logger

	lastBacklog time.Time
}

// Backoff is the delay before attempt n+1 (n ≥ 1): 2^(n-1) s with ±50 % jitter, capped at MaxBackoff.
func Backoff(attempts int64, jitter float64) time.Duration {
	d := time.Second << min(attempts-1, 20)
	d = time.Duration(float64(d) * (0.5 + jitter))
	return min(d, MaxBackoff)
}

// Once publishes up to one batch of due events and returns how many were published and how many failed.
func (r *Relay) Once(ctx context.Context) (published, failed int, err error) {
	now := r.Clock.Now()
	r.refreshBacklog(ctx, now)
	rows, err := r.Store.R().DueEventOutbox(ctx, db.DueEventOutboxParams{NextAttemptAt: now.UnixMicro(), Limit: batch})
	if err != nil {
		return 0, 0, err
	}
	for _, row := range rows {
		created := time.UnixMicro(row.CreatedAt)
		pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, perr := r.Pub.Publish(pctx, row.Subject, row.Type, json.RawMessage(row.PayloadJson), pulse.WithID(row.ID), pulse.WithTime(created))
		cancel()
		if ctx.Err() != nil {
			return published, failed, ctx.Err()
		}
		if perr == nil {
			published++
			r.Metrics.EventPublish(metrics.EventPublished)
			if err := r.mark(ctx, func(tx *store.Tx) error {
				_, err := tx.Q.MarkEventPublished(ctx, db.MarkEventPublishedParams{PublishedAt: micros(tx.NowMicros()), ID: row.ID})
				return err
			}); err != nil {
				return published, failed, err
			}
			continue
		}
		failed++
		msg := perr.Error()
		if len(msg) > 500 {
			msg = msg[:500]
		}
		attempts := row.Attempts + 1
		dead := attempts >= MaxAttempts || now.Sub(created) >= MaxAge
		if dead {
			r.Metrics.EventPublish(metrics.EventDead)
			r.Log.Error("event dead-lettered", slog.String("event.id", row.ID), slog.String("event.type", row.Type),
				slog.Int64("attempts", attempts), slog.String("error.message", msg))
		} else {
			r.Metrics.EventPublish(metrics.EventRetry)
		}
		next := now.Add(Backoff(attempts, jitter()))
		if err := r.mark(ctx, func(tx *store.Tx) error {
			reason := sql.NullString{String: msg, Valid: true}
			if dead {
				_, err := tx.Q.MarkEventDead(ctx, db.MarkEventDeadParams{DeadAt: micros(tx.NowMicros()), LastError: reason, ID: row.ID})
				return err
			}
			_, err := tx.Q.MarkEventRetry(ctx, db.MarkEventRetryParams{NextAttemptAt: next.UnixMicro(), LastError: reason, ID: row.ID})
			return err
		}); err != nil {
			return published, failed, err
		}
		// One failure usually means Pulse is unreachable: stop this round instead of timing out on every row.
		break
	}
	return published, failed, nil
}

// refreshBacklog updates the pending and dead-letter gauges at most every 30 seconds.
func (r *Relay) refreshBacklog(ctx context.Context, now time.Time) {
	if r.Metrics == nil || now.Sub(r.lastBacklog) < 30*time.Second {
		return
	}
	r.lastBacklog = now
	if c, err := r.Store.R().CountEventOutbox(ctx); err == nil {
		r.Metrics.SetEventBacklog(c.Pending, c.Dead)
	}
}

func micros(v int64) sql.NullInt64 { return sql.NullInt64{Int64: v, Valid: true} }

// jitter returns a uniform value in [0, 1).
func jitter() float64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return float64(binary.BigEndian.Uint64(b[:])>>11) / (1 << 53)
}

func (r *Relay) mark(ctx context.Context, fn func(tx *store.Tx) error) error {
	return r.Store.W().TxNamed(context.WithoutCancel(ctx), "events.mark", fn)
}

// Run publishes until ctx ends, polling every interval and draining backlogs without waiting.
func (r *Relay) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		for {
			n, failed, err := r.Once(ctx)
			if err != nil && !errors.Is(err, context.Canceled) {
				r.Log.Warn("event relay", obs.Err(err))
			}
			if err != nil || failed > 0 || n < batch {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
