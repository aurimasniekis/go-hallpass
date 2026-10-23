package access

import (
	"context"
	"database/sql"
	"log/slog"
	"sync"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
)

// EnforcementBound is the documented maximum delay between access ending and termination of affected channels
// (HP-GRT-008, ADR-0018).
const EnforcementBound = 5 * time.Second

// Live is a registered, running destination channel.
type Live struct {
	ChannelID     string
	ConnectionID  string
	AgentID       string
	KeyID         string
	GrantID       string
	CredentialRef string
	ExpiresAt     time.Time
	// Terminate ends the channel; it must return promptly (run any blocking work in its own goroutine) and be
	// idempotent. reason is one of the Reason* constants.
	Terminate func(reason string)

	once sync.Once
}

func (l *Live) kill(reason string) { l.once.Do(func() { go l.Terminate(reason) }) }

// Enforcer terminates live channels when their grant ends, their key or credential is revoked, or lockdown starts.
// Inputs: in-process events (fast path), a ticker over grant expiries, and a periodic database reconciliation of
// grants, keys and credentials changed since the last pass (safety net for lost events).
type Enforcer struct {
	svc  *Service
	bus  *eventbus.Bus
	tick time.Duration
	log  *slog.Logger

	mu      sync.Mutex
	byID    map[string]*Live
	ended   map[string]endedGrant // recently ended grants → reason (guards registration races)
	revKeys map[string]time.Time
	revCred map[string]time.Time

	grantCursor, keyCursor, credCursor int64
}

type endedGrant struct {
	reason string
	at     time.Time
}

// NewEnforcer returns an enforcer ticking every tick (≤ 1s recommended).
func NewEnforcer(svc *Service, bus *eventbus.Bus, tick time.Duration) *Enforcer {
	if tick <= 0 {
		tick = time.Second
	}
	now := svc.opts.Clock.Now().UnixMicro()
	return &Enforcer{
		svc: svc, bus: bus, tick: tick, log: obs.Component(svc.opts.Logger, "enforcer"),
		byID: map[string]*Live{}, ended: map[string]endedGrant{}, revKeys: map[string]time.Time{}, revCred: map[string]time.Time{},
		grantCursor: now, keyCursor: now, credCursor: now,
	}
}

// Register adds a live channel. It fails with ErrAccessEnded if the grant already ended, its expiry passed, or
// its key or credential was revoked after RegisterChannel's transaction (closing the revocation race, PLAN §5.6).
func (e *Enforcer) Register(l *Live) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.ended[l.GrantID]; ok {
		return ErrAccessEnded
	}
	if _, ok := e.revKeys[l.KeyID]; ok {
		return ErrAccessEnded
	}
	if _, ok := e.revCred[l.CredentialRef]; ok && l.CredentialRef != "" {
		return ErrAccessEnded
	}
	if !e.svc.opts.Clock.Now().Before(l.ExpiresAt) {
		return ErrAccessEnded
	}
	e.byID[l.ChannelID] = l
	return nil
}

// Unregister removes a channel (on normal close).
func (e *Enforcer) Unregister(channelID string) {
	e.mu.Lock()
	delete(e.byID, channelID)
	e.mu.Unlock()
}

// Count returns the number of live channels.
func (e *Enforcer) Count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.byID)
}

// TerminateAll ends every live channel (shutdown).
func (e *Enforcer) TerminateAll(reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, l := range e.byID {
		l.kill(reason)
		e.m().EnforcerTerminated(metrics.EndReason(reason))
		delete(e.byID, id)
	}
}

func (e *Enforcer) m() *metrics.Metrics { return e.svc.opts.Metrics }

// endedNow is the access end time for terminations detected at the moment access ended.
func (e *Enforcer) endedNow() func(*Live) time.Time {
	now := e.svc.opts.Clock.Now()
	return func(*Live) time.Time { return now }
}

func endedAt(t time.Time) func(*Live) time.Time { return func(*Live) time.Time { return t } }

// Terminate ends one live channel (operator action); it reports whether the channel was live in this process.
func (e *Enforcer) Terminate(channelID, reason string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.terminateWhere(reason, e.endedNow(), func(l *Live) bool { return l.ChannelID == channelID }) > 0
}

// terminateWhere kills matching live channels. ended returns when access ended for a channel; the delay until
// termination is the enforcement latency (HP-GRT-008, bound EnforcementBound).
func (e *Enforcer) terminateWhere(reason string, ended func(*Live) time.Time, match func(*Live) bool) int {
	n := 0
	now := e.svc.opts.Clock.Now()
	for id, l := range e.byID {
		if match(l) {
			l.kill(reason)
			delete(e.byID, id)
			e.m().EnforcerTerminated(metrics.EndReason(reason))
			e.m().EnforcementLatency(now.Sub(ended(l)))
			n++
		}
	}
	return n
}

// grantEnded handles a grant that is no longer active.
// at is when the grant ended (zero: now).
func (e *Enforcer) grantEnded(grantID, reason string, at time.Time) {
	if reason == "" {
		reason = ReasonExpired
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.svc.opts.Clock.Now()
	e.ended[grantID] = endedGrant{reason: reason, at: now}
	ended := endedAt(now)
	if !at.IsZero() && !at.After(now) {
		ended = endedAt(at)
	}
	if n := e.terminateWhere(reason, ended, func(l *Live) bool { return l.GrantID == grantID }); n > 0 {
		e.log.Info("terminated channels", slog.String(obs.FieldGrantID, grantID), slog.String("end_reason", reason), slog.Int("channels", n))
	}
}

func (e *Enforcer) grantExpiry(grantID string, expires time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, l := range e.byID {
		if l.GrantID == grantID && expires.Before(l.ExpiresAt) {
			l.ExpiresAt = expires
		}
	}
}

// at is when the key was revoked (zero: now).
func (e *Enforcer) keyRevoked(keyID string, at time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.svc.opts.Clock.Now()
	e.revKeys[keyID] = now
	e.terminateWhere(ReasonKeyRevoked, endedAt(earliest(at, now)), func(l *Live) bool { return l.KeyID == keyID })
}

// at is when the credential was revoked (zero: now).
func (e *Enforcer) credentialRevoked(credID string, at time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.svc.opts.Clock.Now()
	e.revCred[credID] = now
	e.terminateWhere(ReasonCredentialRevoked, endedAt(earliest(at, now)), func(l *Live) bool { return l.CredentialRef == credID })
}

// earliest returns at unless it is zero or in the future.
func earliest(at, now time.Time) time.Time {
	if at.IsZero() || at.After(now) {
		return now
	}
	return at
}

// expire terminates channels whose (time-authoritative) expiry has passed and prunes old tombstones.
func (e *Enforcer) expire(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.terminateWhere(ReasonExpired, func(l *Live) time.Time { return l.ExpiresAt }, func(l *Live) bool { return !now.Before(l.ExpiresAt) })
	for id, g := range e.ended {
		if now.Sub(g.at) > 10*time.Minute {
			delete(e.ended, id)
		}
	}
	for id, at := range e.revKeys {
		if now.Sub(at) > 10*time.Minute {
			delete(e.revKeys, id)
		}
	}
	for id, at := range e.revCred {
		if now.Sub(at) > 10*time.Minute {
			delete(e.revCred, id)
		}
	}
}

// overlap re-reads a window before each cursor to tolerate commit/clock ordering skew; handling is idempotent.
const overlap = 5 * time.Second

// reconcile reads grants, keys and credentials changed since the last pass.
func (e *Enforcer) reconcile(ctx context.Context) error {
	q := e.svc.s.R()
	// Cursors are wall-clock timestamps. After a backward clock step new rows are stamped earlier than rows already
	// seen, so a cursor ahead of now would skip them (lost revocations, HP-GRT-008): never let a cursor exceed now.
	// Rows committed since the step are within the overlap window of now.
	now := e.svc.Clock().Now().UnixMicro()
	e.grantCursor, e.keyCursor, e.credCursor = min(e.grantCursor, now), min(e.keyCursor, now), min(e.credCursor, now)
	grants, err := q.GrantsChangedSince(ctx, e.grantCursor-overlap.Microseconds())
	if err != nil {
		return err
	}
	for _, g := range grants {
		if g.State != GrantActive {
			reason, at := ReasonExpired, time.Time{}
			if full, err := q.GetGrant(ctx, g.ID); err == nil {
				if full.EndReason.Valid {
					reason = full.EndReason.String
				}
				if full.EndedAt.Valid {
					at = time.UnixMicro(full.EndedAt.Int64)
				}
			}
			e.grantEnded(g.ID, reason, at)
		} else {
			e.grantExpiry(g.ID, ts(g.ExpiresAt))
		}
		e.grantCursor = max(e.grantCursor, g.UpdatedAt)
	}
	keys, err := q.RevokedKeysSince(ctx, nullMicros(e.keyCursor-overlap.Microseconds()))
	if err != nil {
		return err
	}
	for _, k := range keys {
		e.keyRevoked(k.ID, time.UnixMicro(k.RevokedAt.Int64))
		e.keyCursor = max(e.keyCursor, k.RevokedAt.Int64)
	}
	creds, err := q.RevokedCredentialsSince(ctx, nullMicros(e.credCursor-overlap.Microseconds()))
	if err != nil {
		return err
	}
	for _, c := range creds {
		e.credentialRevoked(c.ID, time.UnixMicro(c.RevokedAt.Int64))
		e.credCursor = max(e.credCursor, c.RevokedAt.Int64)
	}
	return nil
}

// Run processes events and ticks until ctx is canceled. With lost events, the reconciliation pass still terminates
// affected channels within one tick plus query time, inside the 5 s bound.
func (e *Enforcer) Run(ctx context.Context) {
	var sub *eventbus.Subscription
	if e.bus != nil {
		sub = e.bus.Subscribe(1024, eventbus.TopicGrantUpdated, eventbus.TopicAgentKeyRevoked, eventbus.TopicCredentialChange, eventbus.TopicLockdown)
		defer sub.Close()
	}
	t := time.NewTicker(e.tick)
	defer t.Stop()
	var events <-chan eventbus.Event
	if sub != nil {
		events = sub.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-events:
			e.handle(ctx, ev)
		case <-t.C:
			e.expire(e.svc.opts.Clock.Now())
			if err := e.reconcile(ctx); err != nil && ctx.Err() == nil {
				e.log.Warn("enforcer reconciliation failed", obs.Err(err))
			}
		}
	}
}

func (e *Enforcer) handle(ctx context.Context, ev eventbus.Event) {
	switch ev.Topic {
	case eventbus.TopicGrantUpdated:
		if g, ok := ev.Payload.(*Grant); ok {
			if g.State != GrantActive {
				var at time.Time
				if g.EndedAt != nil {
					at = *g.EndedAt
				}
				e.grantEnded(g.ID, g.EndReason, at)
			} else {
				e.grantExpiry(g.ID, g.ExpiresAt)
			}
		}
	case eventbus.TopicAgentKeyRevoked:
		e.keyRevoked(ev.Key, time.Time{})
	case eventbus.TopicCredentialChange:
		// Key is a credential ID for revocations; reconciliation confirms the state from the database.
		if ev.Key != "" {
			if c, err := e.svc.s.R().GetLoginCredential(ctx, ev.Key); err == nil && c.State == "revoked" {
				e.credentialRevoked(ev.Key, time.Time{})
			}
		}
	case eventbus.TopicLockdown:
		if on, _ := ev.Payload.(bool); on {
			e.mu.Lock()
			e.terminateWhere(ReasonLockdown, e.endedNow(), func(*Live) bool { return true })
			e.mu.Unlock()
		}
	}
}

func nullMicros(v int64) sql.NullInt64 { return sql.NullInt64{Int64: v, Valid: true} }
