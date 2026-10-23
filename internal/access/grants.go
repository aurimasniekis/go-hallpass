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
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// FindActiveGrant returns the grant to use for activity: among active grants for agent+server+role with at least
// MinRemainingToConnect left, the latest expiry wins and ties go to the lowest ID (HP-GRT-005).
func (svc *Service) FindActiveGrant(ctx context.Context, agentID, serverID, roleID string) (*Grant, error) {
	cutoff := svc.opts.Clock.Now().Add(svc.opts.MinRemainingToConnect)
	r, err := svc.s.R().FindActiveGrant(ctx, db.FindActiveGrantParams{AgentID: agentID, ServerID: serverID, RoleID: roleID, ExpiresAt: cutoff.UnixMicro()})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	g := grantFromRow(r)
	if sess, err := svc.s.R().GetSessionByGrant(ctx, g.ID); err == nil {
		g.SessionID = sess.ID
	}
	return g, nil
}

// GetGrant returns a grant with its session ID.
func (svc *Service) GetGrant(ctx context.Context, id string) (*Grant, error) {
	r, err := svc.s.R().GetGrant(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeNotFound, "grant not found")
	}
	if err != nil {
		return nil, err
	}
	g := grantFromRow(r)
	if sess, err := svc.s.R().GetSessionByGrant(ctx, id); err == nil {
		g.SessionID = sess.ID
	}
	return g, nil
}

// ActiveGrantsForAgent lists an agent's active grants (for `sessions`).
func (svc *Service) ActiveGrantsForAgent(ctx context.Context, agentID string) ([]*Grant, error) {
	rows, err := svc.s.R().ActiveGrantsForAgent(ctx, agentID)
	if err != nil {
		return nil, err
	}
	now := svc.opts.Clock.Now()
	var out []*Grant
	for _, r := range rows {
		g := grantFromRow(r)
		if !g.ActiveAt(now) {
			continue
		}
		if sess, err := svc.s.R().GetSessionByGrant(ctx, g.ID); err == nil {
			g.SessionID = sess.ID
		}
		out = append(out, g)
	}
	return out, nil
}

// RevokeGrant revokes an active grant (HP-GRT-009). Operators need the administrator role or approval authority
// for the grant's target; channels are terminated by the enforcer within the enforcement bound.
func (svc *Service) RevokeGrant(ctx context.Context, op policy.OperatorInfo, grantID, reason string) (*Grant, error) {
	if _, err := SanitizeReason(reason); err != nil {
		return nil, err
	}
	snap, err := svc.engine.Current(ctx)
	if err != nil {
		return nil, err
	}
	g, err := svc.GetGrant(ctx, grantID)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(op.Roles, "administrator") {
		if c := snap.CanApprove(op, g.AgentID, g.ServerID, g.RoleID, 0); !c.Allowed {
			return nil, apperr.New(apperr.CodeForbidden, "not permitted to revoke this grant: %s", c.Reason)
		}
	}
	actor := audit.Actor{Type: audit.ActorOperator, ID: op.ID}
	if _, err := svc.endGrantWith(ctx, grantID, GrantRevoked, ReasonOperator, actor, reason); err != nil {
		return nil, err
	}
	return svc.GetGrant(ctx, grantID)
}

func (svc *Service) endGrant(ctx context.Context, grantID, state, reason string, actor audit.Actor) (bool, error) {
	return svc.endGrantWith(ctx, grantID, state, reason, actor, "")
}

func (svc *Service) endGrantWith(ctx context.Context, grantID, state, reason string, actor audit.Actor, note string) (bool, error) {
	sessID := ""
	if s, err := svc.s.R().GetSessionByGrant(ctx, grantID); err == nil {
		sessID = s.ID
	}
	var seq int64
	if sessID != "" {
		var err error
		if seq, err = svc.seq.Next(ctx, sessID, 1); err != nil {
			return false, err
		}
	}
	ended := false
	err := svc.s.W().TxNamed(ctx, "access.end_grant", func(tx *store.Tx) error {
		var err error
		ended, err = svc.endGrantTx(ctx, tx, grantID, sessID, seq, state, reason, actor, note)
		return err
	})
	return ended, err
}

// endGrantTx moves an active grant to expired or revoked, marks its session closing and records the events.
func (svc *Service) endGrantTx(ctx context.Context, tx *store.Tx, grantID, sessID string, seq int64, state, reason string, actor audit.Actor, note string) (bool, error) {
	n, err := tx.Q.EndGrant(ctx, db.EndGrantParams{State: state, Now: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, EndReason: sql.NullString{String: reason, Valid: true},
		RevokedBy: sql.NullString{String: actorRef(actor), Valid: state == GrantRevoked}, ID: grantID})
	if err != nil || n == 0 {
		return false, err
	}
	ev := audit.Event{Actor: actor, Action: "grant." + state, Target: audit.Target{Type: "grant", ID: grantID}, Details: map[string]any{"reason": reason}}
	if note != "" {
		ev.Sensitive = map[string]any{"note": note}
	}
	if _, err := svc.audit.Append(ctx, tx, ev); err != nil {
		return false, err
	}
	if sessID != "" {
		if _, err := tx.Q.SetSessionState(ctx, db.SetSessionStateParams{State: "closing", ID: sessID}); err != nil {
			return false, err
		}
		evType := EvGrantExpired
		if state == GrantRevoked {
			evType = EvGrantRevoked
		}
		if err := appendTimeline(ctx, tx, TimelineEvent{SessionID: sessID, Seq: seq, Type: evType, Data: map[string]any{"grant_id": grantID, "reason": reason}}); err != nil {
			return false, err
		}
	}
	row, err := tx.Q.GetGrant(ctx, grantID)
	if err != nil {
		return false, err
	}
	g := grantFromRow(row)
	g.SessionID = sessID
	svc.publish(tx, eventbus.TopicGrantUpdated, grantID, g)
	return true, nil
}

// endGrantsTx ends many grants inside an existing transaction (cascades). Sequence numbers are not assigned because
// a writer transaction cannot reserve them; these timeline events are ordered by time.
func (svc *Service) endGrantsTx(ctx context.Context, tx *store.Tx, grantIDs []string, reason string, actor audit.Actor) error {
	for _, gid := range grantIDs {
		sessID := ""
		if s, err := tx.Q.GetSessionByGrant(ctx, gid); err == nil {
			sessID = s.ID
		}
		if _, err := svc.endGrantTx(ctx, tx, gid, sessID, 0, GrantRevoked, reason, actor, ""); err != nil {
			return err
		}
	}
	return nil
}

func (svc *Service) cancelRequestsTx(ctx context.Context, tx *store.Tx, ids []string, reason string, actor audit.Actor) error {
	for _, id := range ids {
		r, err := tx.Q.GetRequest(ctx, id)
		if err != nil {
			return err
		}
		if r.State != ReqPending {
			continue
		}
		if _, err := svc.endRequestTx(ctx, tx, r, ReqCanceled, reason, actor); err != nil {
			return err
		}
	}
	return nil
}

// AgentDisabledHook is registered with agents.Service.OnDisable (HP-AGT-008).
func (svc *Service) AgentDisabledHook(ctx context.Context, tx *store.Tx, agentID, _, _ string) error {
	reqs, err := tx.Q.PendingRequestsForAgent(ctx, agentID)
	if err != nil {
		return err
	}
	if err := svc.cancelRequestsTx(ctx, tx, reqs, ReasonAgentDisabled, audit.System); err != nil {
		return err
	}
	grants, err := tx.Q.ActiveGrantIDsForAgent(ctx, agentID)
	if err != nil {
		return err
	}
	return svc.endGrantsTx(ctx, tx, grants, ReasonAgentDisabled, audit.System)
}

// KeyRevokedHook is registered with agents.Service.OnKeyRevoke. When the agent has no other active key its access
// ends; otherwise only connections authenticated with the revoked key are terminated (by the enforcer).
func (svc *Service) KeyRevokedHook(ctx context.Context, tx *store.Tx, agentID, _, _ string) error {
	n, err := tx.Q.CountActiveAgentKeys(ctx, agentID)
	if err != nil || n > 0 {
		return err
	}
	reqs, err := tx.Q.PendingRequestsForAgent(ctx, agentID)
	if err != nil {
		return err
	}
	if err := svc.cancelRequestsTx(ctx, tx, reqs, ReasonKeyRevoked, audit.System); err != nil {
		return err
	}
	grants, err := tx.Q.ActiveGrantIDsForAgent(ctx, agentID)
	if err != nil {
		return err
	}
	return svc.endGrantsTx(ctx, tx, grants, ReasonKeyRevoked, audit.System)
}

// TargetDisabledHook is registered with inventory.Service.OnDisable (HP-SRV-008).
func (svc *Service) TargetDisabledHook(ctx context.Context, tx *store.Tx, kind, id string) error {
	var reqs, grants []string
	var err error
	switch kind {
	case "server":
		if reqs, err = tx.Q.PendingRequestsForServer(ctx, id); err != nil {
			return err
		}
		grants, err = tx.Q.ActiveGrantIDsForServer(ctx, id)
	case "role":
		if reqs, err = tx.Q.PendingRequestsForRole(ctx, id); err != nil {
			return err
		}
		grants, err = tx.Q.ActiveGrantIDsForRole(ctx, id)
	default:
		return nil
	}
	if err != nil {
		return err
	}
	if err := svc.cancelRequestsTx(ctx, tx, reqs, ReasonTargetDisabled, audit.System); err != nil {
		return err
	}
	return svc.endGrantsTx(ctx, tx, grants, ReasonTargetDisabled, audit.System)
}

// SetLockdown enables or lifts emergency lockdown (HP-GRT-011). Enabling revokes every active grant and cancels every
// pending request; while enabled, no request, decision or channel is accepted.
func (svc *Service) SetLockdown(ctx context.Context, actor audit.Actor, enabled bool) error {
	return svc.s.W().TxNamed(ctx, "access.lockdown", func(tx *store.Tx) error {
		n, err := tx.Q.SetLockdown(ctx, db.SetLockdownParams{
			Lockdown: b2i(enabled), LockdownBy: sql.NullString{String: actorRef(actor), Valid: enabled},
			LockdownAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: enabled}, UpdatedAt: tx.NowMicros(),
		})
		if err != nil || n == 0 {
			return err
		}
		if _, err := tx.Q.BumpPolicyVersion(ctx, tx.NowMicros()); err != nil {
			return err
		}
		action := "lockdown.lifted"
		if enabled {
			action = "lockdown.enabled"
			reqs, err := tx.Q.PendingRequests(ctx)
			if err != nil {
				return err
			}
			ids := make([]string, len(reqs))
			for i, r := range reqs {
				ids[i] = r.ID
			}
			if err := svc.cancelRequestsTx(ctx, tx, ids, ReasonLockdown, actor); err != nil {
				return err
			}
			grants, err := tx.Q.ActiveGrants(ctx)
			if err != nil {
				return err
			}
			gids := make([]string, len(grants))
			for i, g := range grants {
				gids[i] = g.ID
			}
			if err := svc.endGrantsTx(ctx, tx, gids, ReasonLockdown, actor); err != nil {
				return err
			}
		}
		if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: action}); err != nil {
			return err
		}
		svc.publish(tx, eventbus.TopicLockdown, "", enabled)
		svc.publish(tx, eventbus.TopicPolicyChanged, "", nil)
		return nil
	})
}

// ReconcilePolicy applies the current policy to pending requests and active grants (HP-POL-008): requests that are
// no longer requestable are canceled, grants that are no longer requestable are revoked, and grants whose maximum
// shrank are shortened. It runs after every policy.changed event and periodically as a safety net.
func (svc *Service) ReconcilePolicy(ctx context.Context) (canceled, revoked, clamped int, err error) {
	err = svc.withPolicy(ctx, "access.reconcile_policy", func(tx *store.Tx, snap *policy.Snapshot) error {
		canceled, revoked, clamped = 0, 0, 0
		reqs, err := tx.Q.PendingRequests(ctx)
		if err != nil {
			return err
		}
		for _, r := range reqs {
			if snap.Evaluate(r.AgentID, r.ServerID, r.RoleID).Requestable() {
				continue
			}
			reason := ReasonPolicyChanged
			if snap.Lockdown {
				reason = ReasonLockdown
			}
			if _, err := svc.endRequestTx(ctx, tx, r, ReqCanceled, reason, audit.System); err != nil {
				return err
			}
			canceled++
		}
		grants, err := tx.Q.ActiveGrants(ctx)
		if err != nil {
			return err
		}
		for _, g := range grants {
			d := snap.Evaluate(g.AgentID, g.ServerID, g.RoleID)
			if !d.Requestable() {
				sessID := ""
				if s, err := tx.Q.GetSessionByGrant(ctx, g.ID); err == nil {
					sessID = s.ID
				}
				reason := ReasonPolicyChanged
				if d.Reason == "disabled" {
					reason = ReasonTargetDisabled
				}
				ok, err := svc.endGrantTx(ctx, tx, g.ID, sessID, 0, GrantRevoked, reason, audit.System, "")
				if err != nil {
					return err
				}
				if ok {
					revoked++
				}
				continue
			}
			limit := time.UnixMicro(g.StartsAt).Add(d.MaxDuration)
			if limit.UnixMicro() < g.ExpiresAt {
				n, err := tx.Q.ClampGrant(ctx, db.ClampGrantParams{ExpiresAt: limit.UnixMicro(), Now: tx.NowMicros(), ID: g.ID})
				if err != nil {
					return err
				}
				if n == 1 {
					clamped++
					if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.System, Action: "grant.clamped", Target: audit.Target{Type: "grant", ID: g.ID},
						Details: map[string]any{"expires_at": limit.UTC().Format(time.RFC3339), "reason": ReasonPolicyChanged}}); err != nil {
						return err
					}
					row, _ := tx.Q.GetGrant(ctx, g.ID)
					svc.publish(tx, eventbus.TopicGrantUpdated, g.ID, grantFromRow(row))
				}
			}
		}
		return nil
	})
	return canceled, revoked, clamped, err
}

// CloseFinishedSessions closes access sessions whose grant ended and that have no live channels.
func (svc *Service) CloseFinishedSessions(ctx context.Context) (int, error) {
	rows, err := svc.s.R().ClosableSessions(ctx, db.ClosableSessionsParams{ExpiresAt: svc.opts.Clock.Now().UnixMicro(), Limit: 500})
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	n := 0
	for _, r := range rows {
		seq, err := svc.seq.Next(ctx, r.ID, 1)
		if err != nil {
			return n, err
		}
		err = svc.s.W().TxNamed(ctx, "access.close_session", func(tx *store.Tx) error {
			g, err := tx.Q.GetGrant(ctx, r.GrantID)
			if err != nil {
				return err
			}
			reason := g.EndReason.String
			if reason == "" {
				reason = ReasonExpired
			}
			c, err := tx.Q.SetSessionState(ctx, db.SetSessionStateParams{State: "closed", ClosedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
				CloseReason: sql.NullString{String: reason, Valid: true}, ID: r.ID})
			if err != nil || c == 0 {
				return err
			}
			n++
			svc.publish(tx, eventbus.TopicSessionUpdated, r.ID, "closed")
			return appendTimeline(ctx, tx, TimelineEvent{SessionID: r.ID, Seq: seq, Type: EvSessionClosed, Data: map[string]any{"reason": reason}})
		})
		if err != nil {
			return n, err
		}
		svc.seq.Forget(r.ID)
	}
	return n, nil
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
