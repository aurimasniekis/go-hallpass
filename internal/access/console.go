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
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Web terminals (ADR-0055): an administrator opens a recorded shell on a server role from the console. It is an
// ordinary request → decision → grant → session, so recording, the timeline, expiry, revocation, lockdown and the
// enforcer apply unchanged, but the agent is the built-in ConsoleAgentID, the operator is named on the request, grant
// and connection, the operator approves it themselves (in the web console, without approver rules or notifications),
// and agent policy rules do not apply (Snapshot.EvaluateConsole).

// ChannelConsole is the decision channel of a web terminal: the web console. The request's operator_id is what
// marks a decision as a web terminal's own approval.
const ChannelConsole = ChannelWeb

// MaxConsoleChannelsPerOperator bounds the web terminals one administrator has open at once.
const MaxConsoleChannelsPerOperator = 8

// ErrConsoleOperator refuses a web terminal for an operator who is not an enabled administrator.
var ErrConsoleOperator = apperr.New(apperr.CodeForbidden, "only enabled administrators can open a web terminal")

// OpenConsoleInput describes a web terminal to open.
type OpenConsoleInput struct {
	Operator policy.OperatorInfo
	ServerID string
	RoleID   string
	// Duration is one of the allowed presets up to the role maximum; 0 uses the role default.
	Duration time.Duration
}

// consoleOperator re-reads the operator inside tx and requires an enabled administrator. Roles the caller states
// (a web session's) can only narrow what is assigned; without them the administrator role itself is checked.
func consoleOperator(ctx context.Context, q *db.Queries, op policy.OperatorInfo) error {
	if len(op.Roles) == 0 {
		op.Roles = []string{opauth.RoleAdministrator}
	}
	cur, err := currentOperator(ctx, q, op)
	if err != nil {
		if errors.Is(err, ErrOperatorUnavailable) {
			return ErrConsoleOperator
		}
		return err
	}
	if !slices.Contains(cur.Roles, opauth.RoleAdministrator) {
		return ErrConsoleOperator
	}
	return nil
}

// OpenConsole creates the approved request, the decision, the grant and the access session of a web terminal in one
// transaction. The role must allow an interactive shell (shell and pty).
func (svc *Service) OpenConsole(ctx context.Context, in OpenConsoleInput) (*Grant, error) {
	var g *Grant
	err := svc.withPolicy(ctx, "access.open_console", func(tx *store.Tx, snap *policy.Snapshot) error {
		g = nil
		if err := consoleOperator(ctx, tx.Q, in.Operator); err != nil {
			return err
		}
		d := snap.EvaluateConsole(in.ServerID, in.RoleID)
		if d.Denied {
			if d.Reason == "lockdown" {
				return ErrLockdown
			}
			return ErrNotFoundOrForbidden
		}
		roleRow, err := tx.Q.GetRole(ctx, in.RoleID)
		if err != nil {
			return ErrNotFoundOrForbidden
		}
		role := inventory.RoleFromRow(roleRow)
		if !role.Has(inventory.CapShell) || !role.Has(inventory.CapPTY) {
			return apperr.New(apperr.CodeForbidden, "this role does not allow an interactive shell (it needs the shell and pty capabilities)")
		}
		dur := in.Duration
		if dur == 0 {
			dur = snap.DefaultDuration(in.RoleID, d)
		}
		if !slices.Contains(d.AllowedDurations, dur) {
			return apperr.New(apperr.CodeInvalid, "duration %s is not allowed; choose one of %s", dur, fmtDurations(d.AllowedDurations))
		}
		reqID := ids.New(ids.Request)
		opID := sql.NullString{String: in.Operator.ID, Valid: true}
		if err := tx.Q.InsertRequest(ctx, db.InsertRequestParams{
			ID: reqID, AgentID: ConsoleAgentID, AgentKeyID: ConsoleKeyID, ServerID: in.ServerID, RoleID: in.RoleID,
			RequestedDurationS: int64(dur / time.Second), PolicyVersion: snap.Version, CreatedAt: tx.NowMicros(),
			ExpiresAt: tx.Now.Add(svc.opts.PendingExpiry).UnixMicro(), UpdatedAt: tx.NowMicros(), OperatorID: opID,
		}); err != nil {
			return err
		}
		if _, err := tx.Q.TransitionRequest(ctx, db.TransitionRequestParams{State: ReqApproved, DecidedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
			Now: tx.NowMicros(), ID: reqID}); err != nil {
			return err
		}
		decID := ids.New(ids.Decision)
		if err := tx.Q.InsertDecision(ctx, db.InsertDecisionParams{
			ID: decID, RequestID: reqID, Outcome: "approved", ActorType: "operator", ActorID: in.Operator.ID, Channel: ChannelConsole,
			ApprovedDurationS: sql.NullInt64{Int64: int64(dur / time.Second), Valid: true}, PolicyVersion: snap.Version, DecidedAt: tx.NowMicros(),
		}); err != nil {
			return err
		}
		r, err := tx.Q.GetRequest(ctx, reqID)
		if err != nil {
			return err
		}
		if g, err = svc.createGrantTx(ctx, tx, snap, r, decID, dur); err != nil {
			return err
		}
		if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorOperator, ID: in.Operator.ID}, Action: "terminal.opened",
			Target: audit.Target{Type: "grant", ID: g.ID}, Details: map[string]any{"server_id": in.ServerID, "role_id": in.RoleID,
				"remote_user": g.RemoteUser, "duration": dur.String(), "session_id": g.SessionID, "request_id": reqID}}); err != nil {
			return err
		}
		if err := appendTimeline(ctx, tx, TimelineEvent{RequestID: reqID, Type: EvRequestCreated, Data: map[string]any{"duration": dur.String(),
			"has_reason": false, "operator_id": in.Operator.ID, "web_terminal": true}}); err != nil {
			return err
		}
		if err := appendTimeline(ctx, tx, TimelineEvent{RequestID: reqID, SessionID: g.SessionID, Seq: 1, Type: EvRequestApproved,
			Data: map[string]any{"actor_type": "operator", "actor_id": in.Operator.ID, "channel": ChannelConsole, "duration": dur.String()}}); err != nil {
			return err
		}
		if err := appendTimeline(ctx, tx, TimelineEvent{RequestID: reqID, SessionID: g.SessionID, Seq: 2, Type: EvGrantActivated,
			Data: map[string]any{"grant_id": g.ID, "starts_at": g.StartsAt, "expires_at": g.ExpiresAt}}); err != nil {
			return err
		}
		tx.AfterCommit(func() {
			svc.opts.Metrics.AccessRequest(metrics.RequestState(ReqApproved))
			svc.opts.Metrics.GrantStarted()
		})
		svc.publish(tx, eventbus.TopicGrantUpdated, g.ID, g)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return g, nil
}

// CloseConsole ends a web terminal's grant when its browser connection closes.
func (svc *Service) CloseConsole(ctx context.Context, grantID, operatorID string) error {
	g, err := svc.GetGrant(ctx, grantID)
	if err != nil {
		return err
	}
	if g.OperatorID != operatorID || g.State != GrantActive {
		return nil
	}
	_, err = svc.endGrant(ctx, grantID, GrantRevoked, ReasonTerminalClosed, audit.Actor{Type: audit.ActorOperator, ID: operatorID})
	return err
}

// RevokeIneligibleConsoleGrants ends web terminals whose administrator was disabled or lost the administrator role
// (run every few seconds; channel opens check the operator too).
func (svc *Service) RevokeIneligibleConsoleGrants(ctx context.Context) (int, error) {
	ids, err := svc.s.R().ActiveConsoleGrantsOfIneligibleOperators(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		ok, err := svc.endGrant(ctx, id, GrantRevoked, ReasonOperatorIneligible, audit.System)
		if err != nil {
			return n, err
		}
		if ok {
			n++
		}
	}
	return n, nil
}
