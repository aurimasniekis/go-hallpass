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
	"github.com/aurimasniekis/go-hallpass/internal/events"
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
	// Events publishes session lifecycle events to Pulse (ADR-0057). Nil disables.
	Events *events.Recorder
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
	if !svc.s.Health().AcceptsWrites(ctx) {
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
	// EvApprovalRecorded is one approval of a request that needs several distinct approvers.
	EvApprovalRecorded = "request.approval_recorded"
	EvGrantActivated   = "grant.activated"
	EvGrantExpired     = "grant.expired"
	EvGrantRevoked     = "grant.revoked"
	EvGrantClamped     = "grant.clamped"
	EvConnOpened       = "connection.opened"
	EvConnClosed       = "connection.closed"
	EvChannelOpened    = "channel.opened"
	EvChannelExited    = "channel.exited"
	EvChannelFailed    = "channel.failed"
	EvExecRequested    = "exec.requested"
	EvRecordingFailed  = "recording.failed"
	EvSessionClosed    = "access_session.closed"
	// Git operations on git remotes record metadata only (no pack data): the service and repository, the ref updates
	// of a push (allowed or refused), and the bytes transferred.
	EvGitRequested   = "git.requested"
	EvGitPush        = "git.push"
	EvGitPushRefused = "git.push_refused"
	EvGitTransferred = "git.transferred"
	// File transfers (SFTP) record one event per file operation and a summary; no file content.
	EvFileOperation = "file.operation"
	EvFileSummary   = "file.summary"
	// EvDestinationExec is a destination-reported exec record ingested from a signed collector (WP25, HP-REC-012).
	// It is never verified by HallPass; its data carries provenance "destination-audit" and verified=false.
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
	_, err := insertTimeline(ctx, tx, ev)
	return err
}

// sessionEvents names the timeline events published to Pulse as evt.hallpass.session.<name> (ADR-0057). Request and
// grant events are not among them: the audit log publishes those. Per-file operations and destination audit records
// stay in HallPass.
var sessionEvents = map[string]string{
	EvConnOpened:      "connection.opened",
	EvConnClosed:      "connection.closed",
	EvChannelOpened:   "channel.opened",
	EvChannelExited:   "channel.exited",
	EvChannelFailed:   "channel.failed",
	EvExecRequested:   "exec.requested",
	EvGitRequested:    "git.requested",
	EvGitPush:         "git.push",
	EvGitPushRefused:  "git.push_refused",
	EvGitTransferred:  "git.transferred",
	EvFileSummary:     "file.summary",
	EvRecordingFailed: "recording.failed",
	EvSessionClosed:   "closed",
}

// SessionEvent is the payload of a session event published to Pulse: the timeline event (whose data never holds
// command text or file contents) with the grant's agent, server and role.
type SessionEvent struct {
	ID           string         `json:"id"`
	Type         string         `json:"type"`
	At           int64          `json:"at"`
	SessionID    string         `json:"session_id"`
	GrantID      string         `json:"grant_id"`
	AgentID      string         `json:"agent_id"`
	ServerID     string         `json:"server_id"`
	RoleID       string         `json:"role_id"`
	OperatorID   string         `json:"operator_id,omitempty"`
	ConnectionID string         `json:"connection_id,omitempty"`
	ChannelID    string         `json:"channel_id,omitempty"`
	SegmentID    string         `json:"segment_id,omitempty"`
	Data         map[string]any `json:"data,omitempty"`
}

// appendTimeline writes ev and, for session lifecycle events, records it for Pulse in the same transaction.
func (svc *Service) appendTimeline(ctx context.Context, tx *store.Tx, ev TimelineEvent) error {
	name, publish := sessionEvents[ev.Type]
	if !publish || svc.opts.Events == nil || ev.SessionID == "" {
		return appendTimeline(ctx, tx, ev)
	}
	if ev.ID == "" {
		ev.ID = ids.New(ids.Event)
	}
	if added, err := insertTimeline(ctx, tx, ev); err != nil || !added {
		return err
	}
	sub, err := tx.Q.SessionSubjects(ctx, ev.SessionID)
	if err != nil {
		return fmt.Errorf("session event: %w", err)
	}
	return svc.opts.Events.Record(ctx, tx, events.Event{ID: ev.ID, Name: "session." + name, Payload: SessionEvent{
		ID: ev.ID, Type: ev.Type, At: tx.NowMicros(), SessionID: ev.SessionID, GrantID: sub.GrantID, AgentID: sub.AgentID,
		ServerID: sub.ServerID, RoleID: sub.RoleID, OperatorID: sub.OperatorID.String, ConnectionID: ev.ConnectionID,
		ChannelID: ev.ChannelID, SegmentID: ev.SegmentID, Data: ev.Data,
	}})
}

// insertTimeline writes ev and reports whether it was new (false: an event with its idempotency key exists).
func insertTimeline(ctx context.Context, tx *store.Tx, ev TimelineEvent) (bool, error) {
	data := "{}"
	if len(ev.Data) > 0 {
		b, err := json.Marshal(ev.Data)
		if err != nil {
			return false, err
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
	n, err := tx.Q.InsertTimelineEvent(ctx, db.InsertTimelineEventParams{
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
	return n > 0, err
}

// Sequencer assigns per-access-session sequence numbers (HP-REC-002). Numbers come from blocks reserved in the
// database before use, so they are never reused after a crash; unused numbers leave gaps, which are allowed.
//
// The global mutex guards only the session map and is never held across I/O: a reservation waits for the database
// under that session's own lock, so a storage stall cannot delay other sessions served from cached blocks, and
// every waiter honours its context (HP-REC-011, SR-21).
type Sequencer struct {
	s     *store.Store
	block int64
	mu    sync.Mutex
	state map[string]*seqBlock
}

type seqBlock struct {
	lock        chan struct{} // one slot: serializes this session's allocations and reservations
	next, limit int64         // limit 0: no block reserved yet
}

// seqReserveTimeout bounds a block reservation for callers whose context has no deadline (connection and channel
// close paths run with context.WithoutCancel). It covers the writer's busy-retry budget.
const seqReserveTimeout = 30 * time.Second

// NewSequencer returns a sequencer reserving 4096 numbers at a time.
func NewSequencer(s *store.Store) *Sequencer {
	return &Sequencer{s: s, block: 4096, state: map[string]*seqBlock{}}
}

func (q *Sequencer) entry(sessionID string) *seqBlock {
	q.mu.Lock()
	defer q.mu.Unlock()
	b := q.state[sessionID]
	if b == nil {
		b = &seqBlock{lock: make(chan struct{}, 1)}
		q.state[sessionID] = b
	}
	return b
}

// Next returns the first of n consecutive sequence numbers for a session. It must not be called inside a writer
// transaction (it may reserve a block in its own transaction).
func (q *Sequencer) Next(ctx context.Context, sessionID string, n int64) (int64, error) {
	if n <= 0 {
		n = 1
	}
	b := q.entry(sessionID)
	select {
	case b.lock <- struct{}{}:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	defer func() { <-b.lock }()
	if b.limit == 0 || b.next+n-1 > b.limit {
		size := max(q.block, n)
		rctx := ctx
		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			rctx, cancel = context.WithTimeout(ctx, seqReserveTimeout)
			defer cancel()
		}
		var limit int64
		err := q.s.W().TxNamed(rctx, "access.reserve_seq", func(tx *store.Tx) error {
			var err error
			limit, err = tx.Q.ReserveSeq(rctx, db.ReserveSeqParams{N: size, ID: sessionID})
			return err
		})
		if err != nil {
			return 0, err
		}
		b.next, b.limit = limit-size+1, limit
	}
	first := b.next
	b.next += n
	return first, nil
}

// Forget drops cached state for a closed session. A later Next reserves a fresh block (numbers stay unique).
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
