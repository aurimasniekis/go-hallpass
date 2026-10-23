package access

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Options configure the access service.
type Options struct {
	PendingExpiry         time.Duration // default 30m
	RequestsPerAgentHour  int           // default 30
	MaxPendingPerAgent    int           // default 10
	MinRemainingToConnect time.Duration // default 2s
	DefaultRetention      time.Duration // default 90d
	BootID                string
	Clock                 clock.Clock
	Logger                *slog.Logger
	// Metrics records request transitions, decisions, grants and enforcer terminations (HP-OBS-004). Nil disables.
	Metrics *metrics.Metrics
	// StorageReserve, if set, is called before admitting a new channel; a non-nil result (free space below the
	// storage reserve, HP-OPS-006) refuses the channel with ErrStorageUnavailable. Nil skips the check.
	StorageReserve func() error
}

// RequestHook runs inside the transaction that creates a pending request or records a decision, so notifications
// are enqueued atomically with the state change (WP16).
type RequestHook func(ctx context.Context, tx *store.Tx, ev RequestEvent) error

// RequestEvent describes a request state change for hooks.
type RequestEvent struct {
	Kind     string // "created", "decided", "canceled", "expired"
	Request  *Request
	Decision *Decision
	Grant    *Grant
}

// Service owns access state transitions. Every transition is a compare-and-set in a single writer transaction.
type Service struct {
	s      *store.Store
	kr     *keyring.Keyring
	audit  *audit.Writer
	bus    *eventbus.Bus
	engine *policy.Engine
	opts   Options
	log    *slog.Logger
	seq    *Sequencer

	mu    sync.RWMutex
	hooks []RequestHook
}

// New returns an access service.
func New(s *store.Store, kr *keyring.Keyring, aw *audit.Writer, bus *eventbus.Bus, e *policy.Engine, o Options) *Service {
	if o.PendingExpiry <= 0 {
		o.PendingExpiry = 30 * time.Minute
	}
	if o.RequestsPerAgentHour <= 0 {
		o.RequestsPerAgentHour = 30
	}
	if o.MaxPendingPerAgent <= 0 {
		o.MaxPendingPerAgent = 10
	}
	if o.MinRemainingToConnect < 0 {
		o.MinRemainingToConnect = 0
	} else if o.MinRemainingToConnect == 0 {
		o.MinRemainingToConnect = 2 * time.Second
	}
	if o.DefaultRetention <= 0 {
		o.DefaultRetention = 90 * 24 * time.Hour
	}
	if o.BootID == "" {
		o.BootID = ids.New(ids.Boot)
	}
	if o.Clock == nil {
		o.Clock = clock.System{}
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return &Service{s: s, kr: kr, audit: aw, bus: bus, engine: e, opts: o, log: obs.Component(o.Logger, "access"), seq: NewSequencer(s)}
}

// BootID identifies this process run (connections and channels from other boots are reconciled as interrupted).
func (svc *Service) BootID() string { return svc.opts.BootID }

// Engine returns the policy engine.
func (svc *Service) Engine() *policy.Engine { return svc.engine }

// Sequencer returns the per-session event sequencer.
func (svc *Service) Sequencer() *Sequencer { return svc.seq }

// OnRequestEvent registers a transactional hook for request events.
func (svc *Service) OnRequestEvent(h RequestHook) {
	svc.mu.Lock()
	svc.hooks = append(svc.hooks, h)
	svc.mu.Unlock()
}

func (svc *Service) runHooks(ctx context.Context, tx *store.Tx, ev RequestEvent) error {
	svc.mu.RLock()
	hooks := append([]RequestHook(nil), svc.hooks...)
	svc.mu.RUnlock()
	for _, h := range hooks {
		if err := h(ctx, tx, ev); err != nil {
			return err
		}
	}
	return nil
}

func (svc *Service) publish(tx *store.Tx, topic, key string, payload any) {
	tx.AfterCommit(func() {
		if svc.bus != nil {
			svc.bus.Publish(eventbus.Event{Topic: topic, Key: key, Payload: payload})
		}
	})
}

// errPolicyMoved signals that policy changed between snapshot load and the transaction; the caller retries.
var errPolicyMoved = errors.New("policy version changed")

// withPolicy runs fn in a writer transaction with a policy snapshot that is current inside that transaction. The
// snapshot is loaded outside the transaction (cached per version); if the version moved, it reloads and retries.
func (svc *Service) withPolicy(ctx context.Context, name string, fn func(tx *store.Tx, snap *policy.Snapshot) error) error {
	if !svc.s.Health().AcceptsWrites() {
		return ErrStorageUnavailable
	}
	for range 5 {
		snap, err := svc.engine.Current(ctx)
		if err != nil {
			return err
		}
		err = svc.s.W().TxNamed(ctx, name, func(tx *store.Tx) error {
			ps, err := tx.Q.GetPolicyState(ctx)
			if err != nil {
				return err
			}
			if ps.Version != snap.Version || (ps.Lockdown == 1) != snap.Lockdown {
				return errPolicyMoved
			}
			return fn(tx, snap)
		})
		if !errors.Is(err, errPolicyMoved) {
			return err
		}
	}
	return apperr.New(apperr.CodeConflict, "policy is changing rapidly; retry")
}

// Timeline event types (schema version 1).
const (
	EvRequestCreated  = "request.created"
	EvRequestApproved = "request.approved"
	EvRequestDenied   = "request.denied"
	EvRequestExpired  = "request.expired"
	EvRequestCanceled = "request.canceled"
	EvGrantActivated  = "grant.activated"
	EvGrantExpired    = "grant.expired"
	EvGrantRevoked    = "grant.revoked"
	EvGrantClamped    = "grant.clamped"
	EvConnOpened      = "connection.opened"
	EvConnClosed      = "connection.closed"
	EvChannelOpened   = "channel.opened"
	EvChannelExited   = "channel.exited"
	EvChannelFailed   = "channel.failed"
	EvExecRequested   = "exec.requested"
	EvRecordingFailed = "recording.failed"
	EvSessionClosed   = "access_session.closed"
	// EvDestinationExec is a destination-reported exec record ingested from a signed collector (WP25, HP-REC-012).
	// It is never verified by Hallpass; its data carries provenance "destination-audit" and verified=false.
	EvDestinationExec = "destination.exec"
)

// TimelineEvent is one lifecycle event (payloads here are non-sensitive; terminal data lives in recordings).
type TimelineEvent struct {
	ID           string // optional; generated when empty
	SessionID    string
	RequestID    string
	Seq          int64 // 0 = unsequenced (request events before a session exists)
	Type         string
	ConnectionID string
	ChannelID    string
	SegmentID    string
	Data         map[string]any
	// IdempotencyKey defaults to type + subject IDs; retries with the same key do not duplicate (HP-REC-003).
	IdempotencyKey string
}

// AppendTimeline writes ev inside tx (for packages that attach their own events to a session timeline, such as
// internal/destaudit). Sequence numbers must come from the session's Sequencer, reserved before the transaction.
func AppendTimeline(ctx context.Context, tx *store.Tx, ev TimelineEvent) error {
	return appendTimeline(ctx, tx, ev)
}

func appendTimeline(ctx context.Context, tx *store.Tx, ev TimelineEvent) error {
	data := "{}"
	if len(ev.Data) > 0 {
		b, err := json.Marshal(ev.Data)
		if err != nil {
			return err
		}
		data = string(b)
	}
	key := ev.IdempotencyKey
	if key == "" {
		key = fmt.Sprintf("%s|%s|%s|%s|%s|%d", ev.Type, ev.RequestID, ev.SessionID, ev.ConnectionID, ev.ChannelID, ev.Seq)
	}
	id := ev.ID
	if id == "" {
		id = ids.New(ids.Event)
	}
	return tx.Q.InsertTimelineEvent(ctx, db.InsertTimelineEventParams{
		ID:              id,
		AccessSessionID: sql.NullString{String: ev.SessionID, Valid: ev.SessionID != ""},
		RequestID:       sql.NullString{String: ev.RequestID, Valid: ev.RequestID != ""},
		Seq:             sql.NullInt64{Int64: ev.Seq, Valid: ev.Seq > 0},
		Type:            ev.Type, SchemaVersion: 1, At: tx.NowMicros(),
		ConnectionID:   sql.NullString{String: ev.ConnectionID, Valid: ev.ConnectionID != ""},
		ChannelID:      sql.NullString{String: ev.ChannelID, Valid: ev.ChannelID != ""},
		SegmentID:      sql.NullString{String: ev.SegmentID, Valid: ev.SegmentID != ""},
		DataJson:       data,
		IdempotencyKey: key,
	})
}

// Sequencer assigns per-access-session sequence numbers (HP-REC-002). Numbers come from blocks reserved in the
// database before use, so they are never reused after a crash; unused numbers leave gaps, which are allowed.
type Sequencer struct {
	s     *store.Store
	block int64
	mu    sync.Mutex
	state map[string]*seqBlock
}

type seqBlock struct{ next, limit int64 }

// NewSequencer returns a sequencer reserving 4096 numbers at a time.
func NewSequencer(s *store.Store) *Sequencer {
	return &Sequencer{s: s, block: 4096, state: map[string]*seqBlock{}}
}

// Next returns the first of n consecutive sequence numbers for a session. It must not be called inside a writer
// transaction (it may reserve a block in its own transaction).
func (q *Sequencer) Next(ctx context.Context, sessionID string, n int64) (int64, error) {
	if n <= 0 {
		n = 1
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	b := q.state[sessionID]
	if b == nil || b.next+n-1 > b.limit {
		size := max(q.block, n)
		var limit int64
		err := q.s.W().TxNamed(ctx, "access.reserve_seq", func(tx *store.Tx) error {
			var err error
			limit, err = tx.Q.ReserveSeq(ctx, db.ReserveSeqParams{N: size, ID: sessionID})
			return err
		})
		if err != nil {
			return 0, err
		}
		b = &seqBlock{next: limit - size + 1, limit: limit}
		q.state[sessionID] = b
	}
	first := b.next
	b.next += n
	return first, nil
}

// Forget drops cached state for a closed session.
func (q *Sequencer) Forget(sessionID string) {
	q.mu.Lock()
	delete(q.state, sessionID)
	q.mu.Unlock()
}

func reasonAAD(requestID string) []byte {
	return keyring.FieldAAD("access_requests", "reason_enc", requestID)
}

// Reason decrypts a request's reason. Callers must enforce requests.reason.read permission; the text is untrusted.
func (svc *Service) Reason(ctx context.Context, requestID string) (string, error) {
	r, err := svc.s.R().GetRequest(ctx, requestID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", apperr.New(apperr.CodeNotFound, "request not found")
	}
	if err != nil || len(r.ReasonEnc) == 0 {
		return "", err
	}
	pt, err := svc.kr.Open(keyring.PurposeField, reasonAAD(requestID), r.ReasonEnc)
	return string(pt), err
}

func actorRef(a audit.Actor) string {
	if a.ID == "" {
		return a.Type
	}
	return a.Type + ":" + a.ID
}
