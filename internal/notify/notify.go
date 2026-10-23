// Package notify is the approval notification core (PLAN §10, WP16): integrations and routes, action tokens,
// provider identity links, outbox delivery through the chat adapters, and the inbound sink that turns verified
// provider callbacks into decisions through the single decision service (HP-NTF-008). Notification failure never
// changes a request (HP-NTF-010).
package notify

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
	"github.com/aurimasniekis/go-hallpass/internal/outbox"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Outbox provider name and message kinds.
const (
	OutboxProvider = "chat"
	KindPending    = "request.pending"
	KindUpdate     = "request.update"
)

// Options configure the core.
type Options struct {
	// PublicURL builds the "Details" link (<public_url>/requests/<id>).
	PublicURL string
	// ChatRequiresMFA requires chat approvers to have MFA (local TOTP enrolled, or an SSO identity whose IdP
	// enforces it) before a chat callback can decide (PLAN §10.1, R-10). Default true.
	ChatRequiresMFA *bool
	// DecisionsPerMinute limits chat decisions per operator (HP-NTF-012). Default 30.
	DecisionsPerMinute int
	// SlackBaseURL and TelegramBaseURL override provider API endpoints (tests).
	SlackBaseURL, TelegramBaseURL, SlackResponseURLBase string
	Clock                                               clock.Clock
	Logger                                              *slog.Logger
}

// Service is the notification core.
type Service struct {
	s         *store.Store
	kr        *keyring.Keyring
	audit     *audit.Writer
	access    *access.Service
	engine    *policy.Engine
	agents    *agents.Service
	inventory *inventory.Service
	auth      *opauth.Service
	out       *outbox.Outbox
	opts      Options
	log       *slog.Logger

	mu       sync.Mutex
	clients  map[string]cachedProvider // integration ID → provider client (per version)
	limiter  map[string][]time.Time    // operator ID → recent chat decisions
	rejected map[string]time.Time      // rejection audit rate limit
}

type cachedProvider struct {
	version int64
	p       chat.Provider
}

// Deps are the services the core uses.
type Deps struct {
	Store     *store.Store
	Keyring   *keyring.Keyring
	Audit     *audit.Writer
	Access    *access.Service
	Engine    *policy.Engine
	Agents    *agents.Service
	Inventory *inventory.Service
	Auth      *opauth.Service
	Outbox    *outbox.Outbox
}

// New wires the core: it registers the outbox provider and the transactional request hook.
func New(d Deps, o Options) *Service {
	if o.ChatRequiresMFA == nil {
		t := true
		o.ChatRequiresMFA = &t
	}
	if o.DecisionsPerMinute <= 0 {
		o.DecisionsPerMinute = 30
	}
	if o.Clock == nil {
		o.Clock = clock.System{}
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	o.PublicURL = strings.TrimRight(o.PublicURL, "/")
	svc := &Service{s: d.Store, kr: d.Keyring, audit: d.Audit, access: d.Access, engine: d.Engine, agents: d.Agents, inventory: d.Inventory,
		auth: d.Auth, out: d.Outbox, opts: o, log: obs.Component(o.Logger, "notify"), clients: map[string]cachedProvider{},
		limiter: map[string][]time.Time{}, rejected: map[string]time.Time{}}
	if d.Outbox != nil {
		d.Outbox.RegisterProvider(OutboxProvider, svc)
	}
	if d.Access != nil {
		d.Access.OnRequestEvent(svc.onRequestEvent)
	}
	return svc
}

// ---- action tokens (HP-NTF-007)

func newTokenID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// tokenHash is HMAC-SHA-256 with the token purpose key: possession of the database alone does not reveal tokens.
func (svc *Service) tokenHash(id string) ([]byte, error) {
	return svc.kr.MAC(keyring.PurposeToken, []byte("hallpass/action-token/v1|"+id))
}

// pendingBody is the outbox payload of a new approval message. Content is rendered at delivery time from the
// current request; only the token IDs (needed for the buttons) are carried, encrypted at rest by the outbox.
type pendingBody struct {
	IntegrationID string        `json:"integration_id"`
	Destination   string        `json:"destination"`
	RequestID     string        `json:"request_id"`
	Actions       []chat.Action `json:"actions"`
}

// updateBody edits a delivered approval message to show the outcome (best effort).
type updateBody struct {
	IntegrationID string            `json:"integration_id"`
	OriginalID    string            `json:"original_outbox_id"`
	Update        chat.StatusUpdate `json:"update"`
}

// onRequestEvent runs in the request transaction (access.RequestHook): new pending requests get an approval
// message per matching route; decisions, cancellations and expiry update the delivered messages.
func (svc *Service) onRequestEvent(ctx context.Context, tx *store.Tx, ev access.RequestEvent) error {
	switch ev.Kind {
	case "created":
		if ev.Request.State != access.ReqPending {
			return nil
		}
		return svc.enqueuePending(ctx, tx, ev.Request)
	case "decided", "canceled", "expired":
		return svc.enqueueUpdates(ctx, tx, ev)
	}
	return nil
}

func (svc *Service) enqueuePending(ctx context.Context, tx *store.Tx, r *access.Request) error {
	routes, err := tx.Q.EnabledRoutes(ctx)
	if err != nil || len(routes) == 0 {
		return err
	}
	snap, err := svc.engine.SnapshotAt(ctx, tx.Q)
	if err != nil {
		return err
	}
	srv := snap.Server(r.ServerID)
	if srv == nil {
		return nil
	}
	dec := snap.Evaluate(r.AgentID, r.ServerID, r.RoleID)
	durations := approvalDurations(dec, r.RequestedDuration)
	for _, rt := range routes {
		var targets policy.TargetSelector
		if json.Unmarshal([]byte(rt.TargetsJson), &targets) != nil || !targets.Matches(srv.Object) {
			continue
		}
		var actions []chat.Action
		add := func(kind chat.ActionKind, d time.Duration) error {
			id, err := newTokenID()
			if err != nil {
				return err
			}
			h, err := svc.tokenHash(id)
			if err != nil {
				return err
			}
			act := "approve"
			if kind == chat.ActionDeny {
				act = "deny"
			}
			if err := tx.Q.InsertActionToken(ctx, db.InsertActionTokenParams{Hash: h, RequestID: r.ID, Action: act,
				DurationS: sql.NullInt64{Int64: int64(d / time.Second), Valid: kind == chat.ActionApprove}, Provider: rt.Provider,
				IntegrationID: rt.IntegrationID, ExpiresAt: r.ExpiresAt.UnixMicro(), CreatedAt: tx.NowMicros()}); err != nil {
				return err
			}
			actions = append(actions, chat.Action{Kind: kind, Duration: d, TokenID: id})
			return nil
		}
		for _, d := range durations {
			if err := add(chat.ActionApprove, d); err != nil {
				return err
			}
		}
		if err := add(chat.ActionDeny, 0); err != nil {
			return err
		}
		body, _ := json.Marshal(pendingBody{IntegrationID: rt.IntegrationID, Destination: rt.Destination, RequestID: r.ID, Actions: actions})
		if _, err := svc.out.Enqueue(ctx, tx, outbox.Message{Provider: OutboxProvider, Destination: rt.ID, Kind: KindPending,
			SubjectType: "request", SubjectID: r.ID, Body: body}); err != nil {
			return err
		}
	}
	return nil
}

// approvalDurations returns up to five allowed durations, smallest first, always including the requested one when
// it is allowed.
func approvalDurations(d policy.Decision, requested time.Duration) []time.Duration {
	var out []time.Duration
	for _, a := range d.AllowedDurations {
		if d.MaxDuration > 0 && a > d.MaxDuration {
			continue
		}
		out = append(out, a)
	}
	if len(out) == 0 && requested > 0 {
		out = []time.Duration{requested}
	}
	if len(out) > chat.MaxApproveActions {
		out = out[:chat.MaxApproveActions]
	}
	return out
}

func decisionState(r *access.Request) chat.DecisionState {
	switch r.State {
	case access.ReqApproved:
		return "approved"
	case access.ReqDenied:
		return "denied"
	case access.ReqExpired:
		return "expired"
	}
	return "canceled"
}

func (svc *Service) enqueueUpdates(ctx context.Context, tx *store.Tx, ev access.RequestEvent) error {
	msgs, err := tx.Q.PendingMessagesForRequest(ctx, sql.NullString{String: ev.Request.ID, Valid: true})
	if err != nil || len(msgs) == 0 {
		return err
	}
	decidedBy := ""
	var dur time.Duration
	if ev.Decision != nil {
		decidedBy = svc.operatorName(ctx, tx.Q, ev.Decision.ActorID)
	}
	if ev.Grant != nil {
		dur = ev.Grant.ExpiresAt.Sub(ev.Grant.StartsAt)
	}
	state := decisionState(ev.Request)
	for _, m := range msgs {
		integrationID, err := tx.Q.GetRouteIntegration(ctx, m.Destination)
		if err != nil {
			continue // route deleted since: nothing to update
		}
		body, _ := json.Marshal(updateBody{IntegrationID: integrationID, OriginalID: m.ID,
			Update: chat.StatusUpdate{RequestID: ev.Request.ID, State: state, DecidedBy: decidedBy, Duration: dur, At: tx.Now}})
		if _, err := svc.out.Enqueue(ctx, tx, outbox.Message{Provider: OutboxProvider, Destination: m.Destination, Kind: KindUpdate,
			SubjectType: "request", SubjectID: ev.Request.ID, Body: body}); err != nil {
			return err
		}
	}
	return nil
}

func (svc *Service) operatorName(ctx context.Context, q *db.Queries, id string) string {
	if op, err := q.GetOperator(ctx, id); err == nil {
		return op.DisplayName
	}
	return ""
}

// ---- replay cache (chat.ReplayCache, durable across restarts)

type replayCache struct {
	svc      *Service
	provider string
}

func (r replayCache) Remember(ctx context.Context, key string, expiresAt time.Time) (bool, error) {
	var n int64
	err := r.svc.s.W().TxNamed(ctx, "notify.replay", func(tx *store.Tx) error {
		var err error
		n, err = tx.Q.RememberReplay(ctx, db.RememberReplayParams{Provider: r.provider, Fingerprint: key, ExpiresAt: expiresAt.UnixMicro()})
		return err
	})
	return n > 0, err
}

// Purge removes expired replay-cache entries and link codes (background job).
func (svc *Service) Purge(ctx context.Context) error {
	return svc.s.W().TxNamed(ctx, "notify.purge", func(tx *store.Tx) error {
		if err := tx.Q.PurgeNotify(ctx, tx.NowMicros()); err != nil {
			return err
		}
		return tx.Q.PurgeLinkCodes(ctx, tx.NowMicros())
	})
}

func invalid(format string, a ...any) error { return apperr.New(apperr.CodeInvalid, format, a...) }
