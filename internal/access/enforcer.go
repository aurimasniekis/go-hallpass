package access

import (
	"context"
	"database/sql"
	"log/slog"
	"sync"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
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
		delete(e.byID, id)
	}
}

func (e *Enforcer) terminateWhere(reason string, match func(*Live) bool) int {
	n := 0
	for id, l := range e.byID {
		if match(l) {
			l.kill(reason)
			delete(e.byID, id)
			n++
		}
	}
	return n
}

// grantEnded handles a grant that is no longer active.
func (e *Enforcer) grantEnded(grantID, reason string) {
	if reason == "" {
		reason = ReasonExpired
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ended[grantID] = endedGrant{reason: reason, at: e.svc.opts.Clock.Now()}
	if n := e.terminateWhere(reason, func(l *Live) bool { return l.GrantID == grantID }); n > 0 {
		e.log.Info("terminated channels", slog.String(obs.FieldGrantID, grantID), slog.String("reason", reason), slog.Int("channels", n))
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

func (e *Enforcer) keyRevoked(keyID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.revKeys[keyID] = e.svc.opts.Clock.Now()
	e.terminateWhere(ReasonKeyRevoked, func(l *Live) bool { return l.KeyID == keyID })
}

func (e *Enforcer) credentialRevoked(credID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.revCred[credID] = e.svc.opts.Clock.Now()
	e.terminateWhere(ReasonCredentialRevoked, func(l *Live) bool { return l.CredentialRef == credID })
}

// expire terminates channels whose (time-authoritative) expiry has passed and prunes old tombstones.
func (e *Enforcer) expire(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.terminateWhere(ReasonExpired, func(l *Live) bool { return !now.Before(l.ExpiresAt) })
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
	grants, err := q.GrantsChangedSince(ctx, e.grantCursor-overlap.Microseconds())
	if err != nil {
		return err
	}
	for _, g := range grants {
		if g.State != GrantActive {
			reason := ReasonExpired
			if full, err := q.GetGrant(ctx, g.ID); err == nil && full.EndReason.Valid {
				reason = full.EndReason.String
			}
			e.grantEnded(g.ID, reason)
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
		e.keyRevoked(k.ID)
		e.keyCursor = max(e.keyCursor, k.RevokedAt.Int64)
	}
	creds, err := q.RevokedCredentialsSince(ctx, nullMicros(e.credCursor-overlap.Microseconds()))
	if err != nil {
		return err
	}
	for _, c := range creds {
		e.credentialRevoked(c.ID)
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
				e.grantEnded(g.ID, g.EndReason)
			} else {
				e.grantExpiry(g.ID, g.ExpiresAt)
			}
		}
	case eventbus.TopicAgentKeyRevoked:
		e.keyRevoked(ev.Key)
	case eventbus.TopicCredentialChange:
		// Key is a credential ID for revocations; reconciliation confirms the state from the database.
		if ev.Key != "" {
			if c, err := e.svc.s.R().GetLoginCredential(ctx, ev.Key); err == nil && c.State == "revoked" {
				e.credentialRevoked(ev.Key)
			}
		}
	case eventbus.TopicLockdown:
		if on, _ := ev.Payload.(bool); on {
			e.mu.Lock()
			e.terminateWhere(ReasonLockdown, func(*Live) bool { return true })
			e.mu.Unlock()
		}
	}
}

func nullMicros(v int64) sql.NullInt64 { return sql.NullInt64{Int64: v, Valid: true} }
