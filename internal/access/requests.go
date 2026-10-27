package access

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// CreateRequestInput is an agent's request for access.
type CreateRequestInput struct {
	AgentID        string
	KeyID          string
	ServerID       string
	RoleID         string
	Reason         string
	Duration       time.Duration // 0 = policy default
	IdempotencyKey string
	// AgentSession is the agent session asking ("" = the agent's shared default session); the grant belongs to it.
	AgentSession string
}

// CreateResult is the outcome of CreateRequest.
type CreateResult struct {
	Request      *Request
	Grant        *Grant // set when auto-approved
	Deduplicated bool
	AutoApproved bool
}

// ErrReasonRequired is returned when policy requires a reason and none was given.
var ErrReasonRequired = apperr.New(apperr.CodeInvalid, "a reason is required for this role")

// CreateRequest creates (or reuses) a pending request. A pending request for the same agent, server and role is
// returned instead of creating a second one (HP-REQ-003); an idempotency key returns the original result. Requests
// within the auto-approve limit are approved by policy in the same transaction (HP-POL-013).
func (svc *Service) CreateRequest(ctx context.Context, in CreateRequestInput) (*CreateResult, error) {
	reason, err := SanitizeReason(in.Reason)
	if err != nil {
		return nil, err
	}
	if !ValidAgentSession(in.AgentSession) {
		return nil, apperr.New(apperr.CodeInvalid, "invalid agent session")
	}
	if in.IdempotencyKey != "" && (len(in.IdempotencyKey) < 8 || len(in.IdempotencyKey) > 128) {
		return nil, apperr.New(apperr.CodeInvalid, "idempotency key must be 8-128 characters")
	}
	var res *CreateResult
	err = svc.withPolicy(ctx, "access.create_request", func(tx *store.Tx, snap *policy.Snapshot) error {
		res = nil
		// The authenticating key must still be active and belong to the agent, and the agent enabled: a connection
		// authenticated before a revocation must not file requests or receive auto-approved grants (HP-AGT-005, SR-15).
		if err := activeKey(ctx, tx, in.AgentID, in.KeyID); err != nil {
			return err
		}
		if in.IdempotencyKey != "" {
			r, err := tx.Q.GetRequestByIdempotencyKey(ctx, db.GetRequestByIdempotencyKeyParams{
				AgentID: in.AgentID, IdempotencyKey: sql.NullString{String: in.IdempotencyKey, Valid: true}})
			if err == nil {
				if r.ServerID != in.ServerID || r.RoleID != in.RoleID || r.AgentSession != in.AgentSession {
					return apperr.New(apperr.CodeConflict, "idempotency key was used for a different request")
				}
				res = &CreateResult{Request: requestFromRow(r), Deduplicated: true}
				if g, err := tx.Q.GetGrantByRequest(ctx, r.ID); err == nil {
					res.Grant = grantFromRow(g)
				}
				return nil
			} else if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		if snap.Lockdown {
			return ErrLockdown
		}
		d := snap.Evaluate(in.AgentID, in.ServerID, in.RoleID)
		if !d.Requestable() {
			return ErrNotFoundOrForbidden
		}
		if existing, err := tx.Q.GetPendingRequest(ctx, db.GetPendingRequestParams{AgentID: in.AgentID, AgentSession: in.AgentSession,
			ServerID: in.ServerID, RoleID: in.RoleID}); err == nil {
			res = &CreateResult{Request: requestFromRow(existing), Deduplicated: true}
			return nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if d.RequireReason && reason == "" {
			return ErrReasonRequired
		}
		dur := in.Duration
		if dur == 0 {
			dur = snap.DefaultDuration(in.RoleID, d)
		}
		if !d.DurationAllowed(dur) {
			return apperr.New(apperr.CodeInvalid, "duration %s is not allowed; choose one of %s", dur, fmtDurations(d.AllowedDurations))
		}
		recent, err := tx.Q.CountRecentRequests(ctx, db.CountRecentRequestsParams{AgentID: in.AgentID, CreatedAt: tx.Now.Add(-time.Hour).UnixMicro()})
		if err != nil {
			return err
		}
		if recent >= int64(svc.opts.RequestsPerAgentHour) {
			return apperr.New(apperr.CodeRateLimited, "too many access requests in the last hour")
		}
		pending, err := tx.Q.CountPendingRequests(ctx, in.AgentID)
		if err != nil {
			return err
		}
		if pending >= int64(svc.opts.MaxPendingPerAgent) {
			return apperr.New(apperr.CodeRateLimited, "too many pending requests; cancel or wait for some to complete")
		}
		id := ids.New(ids.Request)
		var reasonEnc []byte
		if reason != "" {
			if reasonEnc, err = svc.kr.Seal(keyring.PurposeField, reasonAAD(id), []byte(reason)); err != nil {
				return err
			}
		}
		if err := tx.Q.InsertRequest(ctx, db.InsertRequestParams{
			ID: id, AgentID: in.AgentID, AgentKeyID: in.KeyID, ServerID: in.ServerID, RoleID: in.RoleID, ReasonEnc: reasonEnc,
			RequestedDurationS: int64(dur / time.Second), IdempotencyKey: sql.NullString{String: in.IdempotencyKey, Valid: in.IdempotencyKey != ""},
			PolicyVersion: snap.Version, CreatedAt: tx.NowMicros(), ExpiresAt: tx.Now.Add(svc.opts.PendingExpiry).UnixMicro(), UpdatedAt: tx.NowMicros(),
			AgentSession: in.AgentSession,
		}); err != nil {
			return err
		}
		tx.AfterCommit(func() { svc.opts.Metrics.AccessRequest(metrics.RequestPending) })
		if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorAgent, ID: in.AgentID}, Action: "request.created",
			Target: audit.Target{Type: "request", ID: id}, Details: map[string]any{"server_id": in.ServerID, "role_id": in.RoleID,
				"duration": dur.String(), "key_id": in.KeyID, "policy_version": snap.Version, "agent_session": in.AgentSession}}); err != nil {
			return err
		}
		if err := svc.appendTimeline(ctx, tx, TimelineEvent{RequestID: id, Type: EvRequestCreated,
			Data: map[string]any{"duration": dur.String(), "has_reason": reason != "", "agent_session": in.AgentSession}}); err != nil {
			return err
		}
		row, err := tx.Q.GetRequest(ctx, id)
		if err != nil {
			return err
		}
		res = &CreateResult{Request: requestFromRow(row)}
		roleRow, err := tx.Q.GetRole(ctx, in.RoleID)
		if err != nil {
			return err
		}
		// A role that needs several approvers is never approved by policy alone.
		if d.AutoApproves(dur) && inventory.RoleFromRow(roleRow).ApprovalsRequired <= 1 {
			out, err := svc.decideTx(ctx, tx, snap, row, decideParams{
				approve: true, duration: dur, actorType: "policy", actorID: d.DecidingRule, channel: "policy",
			})
			if err != nil {
				return err
			}
			res.Request, res.Grant, res.AutoApproved = out.request, out.grant, true
			return nil
		}
		if err := svc.runHooks(ctx, tx, RequestEvent{Kind: "created", Request: res.Request}); err != nil {
			return err
		}
		svc.publish(tx, eventbus.TopicRequestCreated, id, nil)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// activeKey returns ErrAccessEnded unless keyID is an active key of an enabled agent agentID.
func activeKey(ctx context.Context, tx *store.Tx, agentID, keyID string) error {
	key, err := tx.Q.GetAgentKey(ctx, keyID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (key.State != "active" || key.AgentID != agentID)) {
		return ErrAccessEnded
	} else if err != nil {
		return err
	}
	a, err := tx.Q.GetAgent(ctx, agentID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && a.Enabled != 1) {
		return ErrAccessEnded
	}
	return err
}

func fmtDurations(ds []time.Duration) string {
	out := ""
	for i, d := range ds {
		if i > 0 {
			out += ", "
		}
		out += shortDuration(d)
	}
	return out
}

// shortDuration renders presets the way agents type them (5m, 1h, 24h).
func shortDuration(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return itoa(int64(d/time.Hour)) + "h"
	case d%time.Minute == 0:
		return itoa(int64(d/time.Minute)) + "m"
	}
	return d.String()
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// GetRequest returns a request.
func (svc *Service) GetRequest(ctx context.Context, id string) (*Request, error) {
	r, err := svc.s.R().GetRequest(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeNotFound, "request not found")
	}
	if err != nil {
		return nil, err
	}
	return requestFromRow(r), nil
}

// GetRequestForAgent returns a request only if the agent owns it; any other case is ErrNotFoundOrForbidden (HP-REQ-009).
func (svc *Service) GetRequestForAgent(ctx context.Context, agentID, id string) (*Request, *Grant, error) {
	if !ids.Valid(ids.Request, id) {
		return nil, nil, ErrNotFoundOrForbidden
	}
	r, err := svc.s.R().GetRequest(ctx, id)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && r.AgentID != agentID) {
		return nil, nil, ErrNotFoundOrForbidden
	}
	if err != nil {
		return nil, nil, err
	}
	var g *Grant
	if gr, err := svc.s.R().GetGrantByRequest(ctx, id); err == nil {
		g = grantFromRow(gr)
	}
	return requestFromRow(r), g, nil
}

// CancelByAgent cancels the agent's own pending request (HP-REQ-006).
func (svc *Service) CancelByAgent(ctx context.Context, agentID, id string) (*Request, error) {
	if _, _, err := svc.GetRequestForAgent(ctx, agentID, id); err != nil {
		return nil, err
	}
	return svc.cancel(ctx, audit.Actor{Type: audit.ActorAgent, ID: agentID}, id, ReasonAgent, nil)
}

// CancelByOperator cancels a pending request; the operator must be an administrator or hold approval authority for it.
func (svc *Service) CancelByOperator(ctx context.Context, op policy.OperatorInfo, id string) (*Request, error) {
	return svc.cancel(ctx, audit.Actor{Type: audit.ActorOperator, ID: op.ID}, id, ReasonOperator, &op)
}

func (svc *Service) cancel(ctx context.Context, actor audit.Actor, id, reason string, op *policy.OperatorInfo) (*Request, error) {
	var out *Request
	err := svc.withPolicy(ctx, "access.cancel_request", func(tx *store.Tx, snap *policy.Snapshot) error {
		r, err := tx.Q.GetRequest(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeNotFound, "request not found")
		} else if err != nil {
			return err
		}
		if op != nil {
			cur, err := withdrawingOperator(ctx, tx.Q, *op) // re-read in the transaction (SR-23)
			if err != nil {
				return err
			}
			if !slices.Contains(cur.Roles, "administrator") {
				if c := snap.CanAct(cur, r.AgentID, r.ServerID, r.RoleID, 0); !c.Allowed {
					return apperr.New(apperr.CodeForbidden, "not permitted to cancel this request: %s", c.Reason)
				}
			}
		}
		if r.State != ReqPending {
			out = requestFromRow(r)
			return nil // idempotent: already terminal
		}
		var err2 error
		out, err2 = svc.endRequestTx(ctx, tx, r, ReqCanceled, reason, actor)
		return err2
	})
	return out, err
}

// endRequestTx moves a pending request to canceled or expired inside tx.
func (svc *Service) endRequestTx(ctx context.Context, tx *store.Tx, r db.AccessRequest, state, reason string, actor audit.Actor) (*Request, error) {
	n, err := tx.Q.TransitionRequest(ctx, db.TransitionRequestParams{State: state, StateReason: sql.NullString{String: reason, Valid: true},
		DecidedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, Now: tx.NowMicros(), ID: r.ID})
	if err != nil {
		return nil, err
	}
	row, err := tx.Q.GetRequest(ctx, r.ID)
	if err != nil {
		return nil, err
	}
	req := requestFromRow(row)
	if n == 0 {
		return req, nil
	}
	evType, kind := EvRequestCanceled, "canceled"
	if state == ReqExpired {
		evType, kind = EvRequestExpired, "expired"
	}
	if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "request." + kind, Target: audit.Target{Type: "request", ID: r.ID},
		Details: map[string]any{"reason": reason, "agent_id": r.AgentID}}); err != nil {
		return nil, err
	}
	if err := svc.appendTimeline(ctx, tx, TimelineEvent{RequestID: r.ID, Type: evType, Data: map[string]any{"reason": reason}}); err != nil {
		return nil, err
	}
	if err := svc.runHooks(ctx, tx, RequestEvent{Kind: kind, Request: req}); err != nil {
		return nil, err
	}
	tx.AfterCommit(func() { svc.opts.Metrics.AccessRequest(metrics.RequestState(state)) })
	svc.publish(tx, eventbus.TopicRequestUpdated, r.ID, req.State)
	return req, nil
}

// ExpireDue expires pending requests and grants whose time has passed and closes finished sessions (periodic sweep;
// every check is also time-authoritative, so the sweep only records what is already true).
func (svc *Service) ExpireDue(ctx context.Context) (requests, grants int, err error) {
	now := svc.opts.Clock.Now()
	reqIDs, err := svc.s.R().DuePendingRequests(ctx, db.DuePendingRequestsParams{ExpiresAt: now.UnixMicro(), Limit: 500})
	if err != nil {
		return 0, 0, err
	}
	if len(reqIDs) > 0 {
		err = svc.s.W().TxNamed(ctx, "access.expire_requests", func(tx *store.Tx) error {
			requests = 0
			for _, id := range reqIDs {
				r, err := tx.Q.GetRequest(ctx, id)
				if err != nil {
					return err
				}
				if r.State != ReqPending {
					continue
				}
				if _, err := svc.endRequestTx(ctx, tx, r, ReqExpired, ReasonExpired, audit.System); err != nil {
					return err
				}
				requests++
			}
			return nil
		})
		if err != nil {
			return 0, 0, err
		}
	}
	gIDs, err := svc.s.R().DueGrants(ctx, db.DueGrantsParams{ExpiresAt: now.UnixMicro(), Limit: 500})
	if err != nil {
		return requests, 0, err
	}
	for _, gid := range gIDs {
		ok, err := svc.endGrant(ctx, gid, GrantExpired, ReasonExpired, audit.System)
		if err != nil {
			return requests, grants, err
		}
		if ok {
			grants++
		}
	}
	_, err = svc.CloseFinishedSessions(ctx)
	return requests, grants, err
}
