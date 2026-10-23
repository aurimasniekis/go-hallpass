// Package outbox delivers notifications durably (HP-NTF-001).
//
// Messages are written inside the transaction that caused them, encrypted at rest, and delivered by a worker with
// leases, bounded exponential retries, a dead-letter state and a per-attempt delivery history. Delivery failures never
// change the business state that produced the message (HP-NTF-010).
package outbox

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/jobs"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// DefaultMaxAttempts bounds delivery retries.
const DefaultMaxAttempts = 8

// Message is a notification to deliver.
type Message struct {
	Provider    string // "slack", "telegram", "web", …
	Destination string // provider-specific address (channel ID, chat ID)
	Kind        string // e.g. "request.pending", "request.decided"
	SubjectType string
	SubjectID   string
	Body        []byte // provider-specific payload; encrypted at rest
	MaxAttempts int
	NotBefore   time.Time
}

// Delivery is a claimed message handed to a provider.
type Delivery struct {
	ID          string
	Provider    string
	Destination string
	Kind        string
	SubjectType string
	SubjectID   string
	Body        []byte
	Attempt     int
	ProviderRef string // reference returned by an earlier delivery of a related message, if any
}

// Result is a provider's delivery outcome.
type Result struct {
	ProviderRef string
	HTTPStatus  int
}

// ErrPermanent marks a delivery error that must not be retried (e.g. invalid destination).
var ErrPermanent = errors.New("permanent delivery failure")

// Provider delivers messages for one provider name.
type Provider interface {
	Deliver(ctx context.Context, d Delivery) (Result, error)
}

// Outbox enqueues and delivers messages.
type Outbox struct {
	s     *store.Store
	kr    *keyring.Keyring
	log   *slog.Logger
	clock clock.Clock
	m     *metrics.Metrics

	lastBacklog time.Time // last backlog gauge refresh (Run goroutine only)

	mu        sync.RWMutex
	providers map[string]Provider
	wake      chan struct{}

	lease       time.Duration
	timeout     time.Duration
	baseBackoff time.Duration
	maxBackoff  time.Duration
	poll        time.Duration
}

// Options configure an Outbox.
type Options struct {
	Logger       *slog.Logger
	Clock        clock.Clock
	Lease        time.Duration // default 30s
	Timeout      time.Duration // per-delivery timeout, default 10s
	BaseBackoff  time.Duration // default 2s
	MaxBackoff   time.Duration // default 5m
	PollInterval time.Duration // default 1s
	// Metrics records delivery outcomes and the pending/dead-letter backlog (HP-OBS-004). Nil disables.
	Metrics *metrics.Metrics
}

// New returns an outbox.
func New(s *store.Store, kr *keyring.Keyring, o Options) *Outbox {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Clock == nil {
		o.Clock = clock.System{}
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&o.Lease, 30*time.Second)
	def(&o.Timeout, 10*time.Second)
	def(&o.BaseBackoff, 2*time.Second)
	def(&o.MaxBackoff, 5*time.Minute)
	def(&o.PollInterval, time.Second)
	return &Outbox{
		s: s, kr: kr, log: obs.Component(o.Logger, "outbox"), clock: o.Clock, m: o.Metrics, providers: map[string]Provider{},
		wake: make(chan struct{}, 1), lease: o.Lease, timeout: min(o.Timeout, o.Lease), baseBackoff: o.BaseBackoff,
		maxBackoff: o.MaxBackoff, poll: o.PollInterval,
	}
}

// RegisterProvider installs the deliverer for a provider name.
func (o *Outbox) RegisterProvider(name string, p Provider) {
	o.mu.Lock()
	o.providers[name] = p
	o.mu.Unlock()
}

func bodyAAD(id string) []byte { return keyring.FieldAAD("outbox_messages", "body_enc", id) }

// Enqueue writes m inside tx and wakes the worker after commit.
func (o *Outbox) Enqueue(ctx context.Context, tx *store.Tx, m Message) (string, error) {
	if m.Provider == "" || m.Destination == "" || m.Kind == "" {
		return "", errors.New("outbox: provider, destination and kind are required")
	}
	id := ids.New(ids.Outbox)
	body, err := o.kr.Seal(keyring.PurposeField, bodyAAD(id), m.Body)
	if err != nil {
		return "", err
	}
	maxAttempts := m.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxAttempts
	}
	next := m.NotBefore
	if next.IsZero() {
		next = tx.Now
	}
	err = tx.Q.InsertOutboxMessage(ctx, db.InsertOutboxMessageParams{
		ID: id, Provider: m.Provider, Destination: m.Destination, Kind: m.Kind,
		SubjectType: sql.NullString{String: m.SubjectType, Valid: m.SubjectType != ""},
		SubjectID:   sql.NullString{String: m.SubjectID, Valid: m.SubjectID != ""},
		BodyEnc:     body, MaxAttempts: int64(maxAttempts), NextAt: next.UnixMicro(), CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros(),
	})
	if err != nil {
		return "", err
	}
	tx.AfterCommit(o.Wake)
	return id, nil
}

// Wake prompts the worker to poll immediately.
func (o *Outbox) Wake() {
	select {
	case o.wake <- struct{}{}:
	default:
	}
}

// Run delivers due messages until ctx is canceled.
func (o *Outbox) Run(ctx context.Context, concurrency int) {
	if concurrency <= 0 {
		concurrency = 4
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	defer wg.Wait()
	t := time.NewTicker(o.poll)
	defer t.Stop()
	for {
		if o.m != nil && time.Since(o.lastBacklog) >= BacklogRefresh {
			o.lastBacklog = time.Now()
			o.RefreshBacklog(ctx)
		}
		claimed, err := o.claim(ctx, cap(sem)-len(sem))
		if err != nil && ctx.Err() == nil {
			o.log.Warn("claiming outbox messages failed", obs.Err(err))
		}
		for _, d := range claimed {
			sem <- struct{}{}
			wg.Go(func() {
				defer func() { <-sem }()
				o.deliver(ctx, d)
			})
		}
		if len(claimed) > 0 && len(sem) < cap(sem) {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-o.wake:
		case <-t.C:
		}
	}
}

type claimed struct {
	Delivery
	maxAttempts int
}

func (o *Outbox) claim(ctx context.Context, slots int) ([]claimed, error) {
	if slots <= 0 {
		return nil, nil
	}
	due, err := o.s.R().DueOutboxMessages(ctx, db.DueOutboxMessagesParams{Now: o.clock.Now().UnixMicro(), Lim: int64(slots)})
	if err != nil || len(due) == 0 {
		return nil, err
	}
	var out []claimed
	err = o.s.W().TxNamed(ctx, "outbox.claim", func(tx *store.Tx) error {
		out = out[:0]
		for _, m := range due {
			n, err := tx.Q.ClaimOutboxMessage(ctx, db.ClaimOutboxMessageParams{
				LeaseUntil: sql.NullInt64{Int64: tx.Now.Add(o.lease).UnixMicro(), Valid: true}, Now: tx.NowMicros(), ID: m.ID,
			})
			if err != nil {
				return err
			}
			if n == 1 {
				out = append(out, claimed{Delivery: Delivery{
					ID: m.ID, Provider: m.Provider, Destination: m.Destination, Kind: m.Kind, SubjectType: m.SubjectType.String,
					SubjectID: m.SubjectID.String, Attempt: int(m.Attempts) + 1, ProviderRef: m.ProviderRef.String,
				}, maxAttempts: int(m.MaxAttempts)})
				out[len(out)-1].Body = m.BodyEnc
			}
		}
		return nil
	})
	return out, err
}

func (o *Outbox) deliver(parent context.Context, c claimed) {
	start := time.Now()
	var res Result
	body, err := o.kr.Open(keyring.PurposeField, bodyAAD(c.ID), c.Body)
	if err != nil {
		err = fmt.Errorf("%w: cannot decrypt message body: %w", ErrPermanent, err)
	} else {
		c.Body = body
		o.mu.RLock()
		p, ok := o.providers[c.Provider]
		o.mu.RUnlock()
		if !ok {
			err = fmt.Errorf("%w: no provider %q registered", ErrPermanent, c.Provider)
		} else {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), o.timeout)
			res, err = safeDeliver(ctx, p, c.Delivery)
			cancel()
		}
	}
	elapsed := time.Since(start)
	state, outcome := "delivered", "delivered"
	next := o.clock.Now()
	var lastErr, errCode sql.NullString
	if err != nil {
		lastErr = sql.NullString{String: truncate(err.Error(), 500), Valid: true}
		errCode = sql.NullString{String: errorCode(err), Valid: true}
		if errors.Is(err, ErrPermanent) || c.Attempt >= c.maxAttempts {
			state, outcome = "dead", "failed"
			o.log.Error("notification delivery failed permanently", slog.String("outbox.id", c.ID),
				slog.String("provider", c.Provider), slog.Int("attempt", c.Attempt), obs.Err(err))
		} else {
			state, outcome = "queued", "retry"
			next = next.Add(jobs.Backoff(o.baseBackoff, o.maxBackoff, c.Attempt))
			o.log.Warn("notification delivery failed; will retry", slog.String("outbox.id", c.ID),
				slog.String("provider", c.Provider), slog.Int("attempt", c.Attempt), obs.Err(err))
		}
	}
	ctx := context.WithoutCancel(parent)
	ferr := o.s.W().TxNamed(ctx, "outbox.finish", func(tx *store.Tx) error {
		if err := tx.Q.InsertDeliveryAttempt(ctx, db.InsertDeliveryAttemptParams{
			OutboxID: c.ID, At: tx.NowMicros(), Outcome: outcome,
			HttpStatus: sql.NullInt64{Int64: int64(res.HTTPStatus), Valid: res.HTTPStatus != 0},
			ErrorCode:  errCode, DurationMs: elapsed.Milliseconds(),
		}); err != nil {
			return err
		}
		return tx.Q.FinishOutboxMessage(ctx, db.FinishOutboxMessageParams{
			State: state, NextAt: next.UnixMicro(), ProviderRef: sql.NullString{String: res.ProviderRef, Valid: res.ProviderRef != ""},
			LastError: lastErr, UpdatedAt: tx.NowMicros(), ID: c.ID,
		})
	})
	if ferr != nil {
		o.log.Error("recording delivery result failed; lease expiry will retry it", slog.String("outbox.id", c.ID), obs.Err(ferr))
		return
	}
	mo := metrics.DeliveryDelivered
	switch state {
	case "dead":
		mo = metrics.DeliveryDead
	case "queued":
		mo = metrics.DeliveryRetry
	}
	o.m.NotificationDelivery(metrics.Provider(c.Provider), mo)
}

// BacklogRefresh is how often Run re-reads the pending and dead-letter counts for metrics.
const BacklogRefresh = 15 * time.Second

// RefreshBacklog sets the outbox pending (queued or sending) and dead-letter gauges from the database.
func (o *Outbox) RefreshBacklog(ctx context.Context) {
	if o.m == nil {
		return
	}
	rows, err := o.s.ReadDB().QueryContext(ctx,
		`SELECT state, count(*) FROM outbox_messages WHERE state IN ('queued', 'sending', 'dead') GROUP BY state`)
	if err != nil {
		return
	}
	defer rows.Close()
	var pending, dead int
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return
		}
		if st == "dead" {
			dead = n
		} else {
			pending += n
		}
	}
	if rows.Err() == nil {
		o.m.SetOutboxBacklog(pending, dead)
	}
}

func safeDeliver(ctx context.Context, p Provider, d Delivery) (res Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("provider panicked: %v", r)
		}
	}()
	return p.Deliver(ctx, d)
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, ErrPermanent):
		return "permanent"
	default:
		return "error"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
