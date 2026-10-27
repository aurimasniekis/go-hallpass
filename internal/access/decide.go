package access

import (
	"context"
	"database/sql"
	"encoding/json"
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

// Approval channels.
const (
	ChannelWeb      = "web"
	ChannelSlack    = "slack"
	ChannelTelegram = "telegram"
	ChannelAPI      = "api"
)

// DecideInput is an operator decision from any channel (HP-NTF-008): web, Slack and Telegram all call Decide.
type DecideInput struct {
	RequestID      string
	Approve        bool
	Duration       time.Duration // approvals only; 0 = requested duration
	Operator       policy.OperatorInfo
	Channel        string
	Comment        string
	IdempotencyKey string
}

// DecideResult is the outcome of a decision.
type DecideResult struct {
	Request  *Request
	Decision *Decision
	Grant    *Grant
	// Replayed is true when an identical earlier decision was returned instead of applying a new one (HP-NTF-009).
	Replayed bool
	// Pending is true when the approval was recorded but the role needs more distinct approvers; Request is still
	// pending and Decision and Grant are nil.
	Pending           bool
	Approvals         []Approval
	ApprovalsRequired int
}

// Approval is one approver's approval of a request whose role needs several distinct approvers.
type Approval struct {
	OperatorID string        `json:"operator_id"`
	Channel    string        `json:"channel"`
	Duration   time.Duration `json:"-"`
	ApprovedAt time.Time     `json:"approved_at"`
}

func approvalFromRow(a db.RequestApproval) Approval {
	return Approval{OperatorID: a.OperatorID, Channel: a.Channel, Duration: time.Duration(a.ApprovedDurationS) * time.Second,
		ApprovedAt: time.UnixMicro(a.ApprovedAt).UTC()}
}

// Approvals lists the approvals recorded for a request (only roles that need several approvers record them).
func (svc *Service) Approvals(ctx context.Context, requestID string) ([]Approval, error) {
	rows, err := svc.s.R().ListRequestApprovals(ctx, requestID)
	if err != nil {
		return nil, err
	}
	out := make([]Approval, len(rows))
	for i, r := range rows {
		out[i] = approvalFromRow(r)
	}
	return out, nil
}

// ErrConflict reports that the request was already decided, canceled or expired.
type ErrConflict struct{ Current *Request }

func (e *ErrConflict) Error() string { return "request is already " + e.Current.State }

// Is lets errors.Is(err, apperr.ErrConflict) match.
func (e *ErrConflict) Is(target error) bool { return target == apperr.ErrConflict } //nolint:errorlint // sentinel identity

// Decide approves or denies a pending request. Inside one transaction it re-checks the request state and expiry,
// lockdown, the operator's role and approver rule, self-approval, the current policy and the duration, then writes the
// decision and (on approval) the grant and access session (HP-GRT-001, HP-GRT-007).
func (svc *Service) Decide(ctx context.Context, in DecideInput) (*DecideResult, error) {
	if !slices.Contains([]string{ChannelWeb, ChannelSlack, ChannelTelegram, ChannelAPI}, in.Channel) {
		return nil, apperr.New(apperr.CodeInvalid, "unknown decision channel")
	}
	comment, err := SanitizeReason(in.Comment)
	if err != nil {
		return nil, err
	}
	var res *DecideResult
	err = svc.withPolicy(ctx, "access.decide", func(tx *store.Tx, snap *policy.Snapshot) error {
		res = nil
		r, err := tx.Q.GetRequest(ctx, in.RequestID)
		if errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeNotFound, "request not found")
		} else if err != nil {
			return err
		}
		if r.State != ReqPending {
			// Idempotent replay: the same operator repeating the same decision gets the recorded outcome.
			if d, err := tx.Q.GetDecisionByRequest(ctx, r.ID); err == nil && d.ActorID == in.Operator.ID &&
				(d.Outcome == "approved") == in.Approve {
				res = &DecideResult{Request: requestFromRow(r), Decision: decisionFromRow(d), Replayed: true}
				if g, err := tx.Q.GetGrantByRequest(ctx, r.ID); err == nil {
					res.Grant = grantFromRow(g)
				}
				return nil
			}
			return &ErrConflict{Current: requestFromRow(r)}
		}
		if !tx.Now.Before(time.UnixMicro(r.ExpiresAt)) {
			// Expiry is time-authoritative; the sweep records the transition. Report it as expired now.
			cur := requestFromRow(r)
			cur.State, cur.StateReason = ReqExpired, ReasonExpired
			return &ErrConflict{Current: cur}
		}
		if snap.Lockdown {
			return ErrLockdown
		}
		dur := in.Duration
		if dur == 0 {
			dur = time.Duration(r.RequestedDurationS) * time.Second
		}
		op, err := currentOperator(ctx, tx.Q, in.Operator)
		if err != nil {
			return err
		}
		check := snap.CanAct(op, r.AgentID, r.ServerID, r.RoleID, dur)
		if in.Approve {
			check = snap.CanApprove(op, r.AgentID, r.ServerID, r.RoleID, dur) // self-approval rule (HP-POL-012)
		}
		if !check.Allowed {
			return apperr.New(apperr.CodeForbidden, "not permitted to decide this request: %s", check.Reason)
		}
		if role := snap.Role(r.RoleID); role != nil && len(role.ApprovalChannels) > 0 && !slices.Contains(role.ApprovalChannels, in.Channel) && in.Channel != ChannelAPI {
			return apperr.New(apperr.CodeForbidden, "this role cannot be decided via %s", in.Channel)
		}
		if in.Approve {
			d := snap.Evaluate(r.AgentID, r.ServerID, r.RoleID)
			if !d.Requestable() {
				// Policy reconciliation cancels it (policy_changed); never approve against current policy.
				return apperr.New(apperr.CodePrecondition, "policy no longer permits this request")
			}
			if !d.DurationAllowed(dur) {
				return apperr.New(apperr.CodeInvalid, "duration %s is not allowed; choose one of %s", dur, fmtDurations(d.AllowedDurations))
			}
		}
		var approvers []string
		if in.Approve {
			roleRow, err := tx.Q.GetRole(ctx, r.RoleID)
			if err != nil {
				return err
			}
			if need := inventory.RoleFromRow(roleRow).ApprovalsRequired; need > 1 {
				approvals, err := svc.recordApproval(ctx, tx, r, in, op.ID, dur, comment, check.RuleID, need)
				if err != nil {
					return err
				}
				if len(approvals) < need {
					res = &DecideResult{Request: requestFromRow(r), Pending: true, Approvals: approvals, ApprovalsRequired: need}
					return nil
				}
				// The last approval completes the request: the grant gets the shortest duration any approver chose.
				for _, a := range approvals {
					dur = min(dur, a.Duration)
					approvers = append(approvers, a.OperatorID)
				}
			}
		}
		out, err := svc.decideTx(ctx, tx, snap, r, decideParams{
			approve: in.Approve, duration: dur, actorType: "operator", actorID: in.Operator.ID, channel: in.Channel,
			comment: comment, approverRule: check.RuleID, idempotencyKey: in.IdempotencyKey, approvers: approvers,
		})
		if err != nil {
			return err
		}
		res = &DecideResult{Request: out.request, Decision: out.decision, Grant: out.grant}
		if len(approvers) > 0 {
			res.Approvals, _ = svc.approvalsTx(ctx, tx, r.ID)
			res.ApprovalsRequired = len(approvers)
		}
		return nil
	})
	svc.observeDecision(in, res, err)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// observeDecision counts a decision attempt by channel and outcome (replays are not new decisions).
func (svc *Service) observeDecision(in DecideInput, res *DecideResult, err error) {
	var o metrics.DecisionOutcome
	switch {
	case err == nil && res != nil && res.Replayed:
		return
	case err == nil && in.Approve:
		o = metrics.DecisionApproved
	case err == nil:
		o = metrics.DecisionDenied
	case errors.Is(err, apperr.ErrConflict):
		o = metrics.DecisionConflict
	case errors.Is(err, apperr.ErrForbidden):
		o = metrics.DecisionForbidden
	default:
		o = metrics.DecisionError
	}
	svc.opts.Metrics.Decision(metrics.DecisionChannel(in.Channel), o)
}

type decideParams struct {
	approve        bool
	duration       time.Duration
	actorType      string // operator | policy
	actorID        string
	channel        string
	comment        string
	approverRule   string
	idempotencyKey string
	approvers      []string // every approver, for requests that needed several
}

// recordApproval stores one operator's approval of a request that needs several distinct approvers and returns all
// approvals so far. An operator approves at most once; the caller has checked authority, policy and duration.
func (svc *Service) recordApproval(ctx context.Context, tx *store.Tx, r db.AccessRequest, in DecideInput, operatorID string,
	dur time.Duration, comment, approverRule string, need int) ([]Approval, error) {
	var commentEnc []byte
	if comment != "" {
		var err error
		aad := keyring.FieldAAD("request_approvals", "comment_enc", r.ID+"/"+operatorID)
		if commentEnc, err = svc.kr.Seal(keyring.PurposeField, aad, []byte(comment)); err != nil {
			return nil, err
		}
	}
	n, err := tx.Q.InsertRequestApproval(ctx, db.InsertRequestApprovalParams{
		RequestID: r.ID, OperatorID: operatorID, Channel: in.Channel, ApprovedDurationS: int64(dur / time.Second), CommentEnc: commentEnc,
		ApproverRuleID: sql.NullString{String: approverRule, Valid: approverRule != ""}, ApprovedAt: tx.NowMicros(),
	})
	if err != nil {
		return nil, err
	}
	approvals, err := svc.approvalsTx(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, apperr.New(apperr.CodeConflict, "you already approved this request; it needs %d more approver(s)", need-len(approvals))
	}
	if len(approvals) >= need {
		return approvals, nil
	}
	if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorOperator, ID: operatorID},
		Action: "request.approval_recorded", Target: audit.Target{Type: "request", ID: r.ID},
		Details: map[string]any{"channel": in.Channel, "duration": dur.String(), "approver_rule_id": approverRule,
			"approvals": len(approvals), "approvals_required": need}}); err != nil {
		return nil, err
	}
	if err := svc.appendTimeline(ctx, tx, TimelineEvent{RequestID: r.ID, Type: EvApprovalRecorded,
		Data: map[string]any{"actor_id": operatorID, "channel": in.Channel, "duration": dur.String(), "approvals": len(approvals),
			"approvals_required": need}}); err != nil {
		return nil, err
	}
	svc.publish(tx, eventbus.TopicRequestUpdated, r.ID, ReqPending)
	return approvals, nil
}

func (svc *Service) approvalsTx(ctx context.Context, tx *store.Tx, requestID string) ([]Approval, error) {
	rows, err := tx.Q.ListRequestApprovals(ctx, requestID)
	if err != nil {
		return nil, err
	}
	out := make([]Approval, len(rows))
	for i, a := range rows {
		out[i] = approvalFromRow(a)
	}
	return out, nil
}

type decideOut struct {
	request  *Request
	decision *Decision
	grant    *Grant
}

// decideTx records the decision and, for approvals, creates the grant (starting at commit time) and its access
// session. The caller has validated authority and policy.
func (svc *Service) decideTx(ctx context.Context, tx *store.Tx, snap *policy.Snapshot, r db.AccessRequest, p decideParams) (*decideOut, error) {
	outcome, state := "denied", ReqDenied
	if p.approve {
		outcome, state = "approved", ReqApproved
	}
	n, err := tx.Q.TransitionRequest(ctx, db.TransitionRequestParams{State: state, DecidedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
		Now: tx.NowMicros(), ID: r.ID})
	if err != nil {
		return nil, err
	}
	if n != 1 {
		row, _ := tx.Q.GetRequest(ctx, r.ID)
		return nil, &ErrConflict{Current: requestFromRow(row)}
	}
	decID := ids.New(ids.Decision)
	var commentEnc []byte
	if p.comment != "" {
		if commentEnc, err = svc.kr.Seal(keyring.PurposeField, keyring.FieldAAD("approval_decisions", "comment_enc", decID), []byte(p.comment)); err != nil {
			return nil, err
		}
	}
	if err := tx.Q.InsertDecision(ctx, db.InsertDecisionParams{
		ID: decID, RequestID: r.ID, Outcome: outcome, ActorType: p.actorType, ActorID: p.actorID, Channel: p.channel,
		ApprovedDurationS: sql.NullInt64{Int64: int64(p.duration / time.Second), Valid: p.approve}, CommentEnc: commentEnc,
		PolicyVersion: snap.Version, ApproverRuleID: sql.NullString{String: p.approverRule, Valid: p.approverRule != ""},
		IdempotencyKey: sql.NullString{String: p.idempotencyKey, Valid: p.idempotencyKey != ""}, DecidedAt: tx.NowMicros(),
	}); err != nil {
		return nil, err
	}
	actor := audit.Actor{Type: audit.ActorOperator, ID: p.actorID}
	if p.actorType == "policy" {
		actor = audit.Actor{Type: audit.ActorPolicy, ID: p.actorID}
	}
	if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "request." + outcome, Target: audit.Target{Type: "request", ID: r.ID},
		Details: map[string]any{"decision_id": decID, "channel": p.channel, "duration": p.duration.String(), "approver_rule_id": p.approverRule,
			"agent_id": r.AgentID, "server_id": r.ServerID, "role_id": r.RoleID, "policy_version": snap.Version, "approvers": p.approvers}}); err != nil {
		return nil, err
	}
	out := &decideOut{}
	evType := EvRequestDenied
	if p.approve {
		evType = EvRequestApproved
		g, err := svc.createGrantTx(ctx, tx, snap, r, decID, p.duration)
		if err != nil {
			return nil, err
		}
		out.grant = g
	}
	if err := svc.appendTimeline(ctx, tx, TimelineEvent{RequestID: r.ID, SessionID: sessionOf(out.grant), Seq: seqIf(out.grant, 1), Type: evType,
		Data: map[string]any{"actor_type": p.actorType, "actor_id": p.actorID, "channel": p.channel, "duration": p.duration.String(),
			"approvers": p.approvers}}); err != nil {
		return nil, err
	}
	if out.grant != nil {
		if err := svc.appendTimeline(ctx, tx, TimelineEvent{RequestID: r.ID, SessionID: out.grant.SessionID, Seq: 2, Type: EvGrantActivated,
			Data: map[string]any{"grant_id": out.grant.ID, "starts_at": out.grant.StartsAt, "expires_at": out.grant.ExpiresAt}}); err != nil {
			return nil, err
		}
	}
	row, err := tx.Q.GetRequest(ctx, r.ID)
	if err != nil {
		return nil, err
	}
	out.request = requestFromRow(row)
	d, err := tx.Q.GetDecisionByRequest(ctx, r.ID)
	if err != nil {
		return nil, err
	}
	out.decision = decisionFromRow(d)
	if err := svc.runHooks(ctx, tx, RequestEvent{Kind: "decided", Request: out.request, Decision: out.decision, Grant: out.grant}); err != nil {
		return nil, err
	}
	started := out.grant != nil
	tx.AfterCommit(func() {
		svc.opts.Metrics.AccessRequest(metrics.RequestState(state))
		if started {
			svc.opts.Metrics.GrantStarted()
		}
	})
	svc.publish(tx, eventbus.TopicRequestUpdated, r.ID, out.request.State)
	if out.grant != nil {
		svc.publish(tx, eventbus.TopicGrantUpdated, out.grant.ID, out.grant)
	}
	return out, nil
}

func sessionOf(g *Grant) string {
	if g == nil {
		return ""
	}
	return g.SessionID
}

func seqIf(g *Grant, n int64) int64 {
	if g == nil {
		return 0
	}
	return n
}

// createGrantTx inserts the grant (start = transaction time, HP-GRT-001) and its 1:1 access session. The first two
// session sequence numbers are used inline for request.approved and grant.activated.
func (svc *Service) createGrantTx(ctx context.Context, tx *store.Tx, snap *policy.Snapshot, r db.AccessRequest, decisionID string, dur time.Duration) (*Grant, error) {
	roleRow, err := tx.Q.GetRole(ctx, r.RoleID)
	if err != nil {
		return nil, err
	}
	role := inventory.RoleFromRow(roleRow)
	caps, _ := json.Marshal(role.Capabilities)
	gid, sid := ids.New(ids.Grant), ids.New(ids.Session)
	start := tx.Now
	if err := tx.Q.InsertGrant(ctx, db.InsertGrantParams{
		ID: gid, RequestID: r.ID, DecisionID: decisionID, AgentID: r.AgentID, ServerID: r.ServerID, RoleID: r.RoleID,
		RemoteUser: role.RemoteUser, CapabilitiesJson: string(caps), PolicyVersion: snap.Version, StartsAt: start.UnixMicro(),
		ExpiresAt: start.Add(dur).UnixMicro(), UpdatedAt: tx.NowMicros(), OperatorID: r.OperatorID, AgentSession: r.AgentSession,
	}); err != nil {
		return nil, err
	}
	if err := tx.Q.InsertSession(ctx, db.InsertSessionParams{ID: sid, GrantID: gid, SeqReserved: 2, OpenedAt: tx.NowMicros(),
		RetentionClass: role.RetentionClass}); err != nil {
		return nil, err
	}
	if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.System, Action: "grant.activated", Target: audit.Target{Type: "grant", ID: gid},
		Details: map[string]any{"request_id": r.ID, "session_id": sid, "expires_at": start.Add(dur).UTC().Format(time.RFC3339)}}); err != nil {
		return nil, err
	}
	row, err := tx.Q.GetGrant(ctx, gid)
	if err != nil {
		return nil, err
	}
	g := grantFromRow(row)
	g.SessionID = sid
	return g, nil
}

// ErrOperatorUnavailable refuses decisions by operators that no longer exist or are disabled.
var ErrOperatorUnavailable = apperr.New(apperr.CodeForbidden, "operator not found or disabled")

// currentOperator re-reads the deciding operator from q (inside the decision transaction where one exists): a
// deleted or disabled operator is refused, and roles and groups are limited to those still assigned. Caller-supplied
// roles and groups can only narrow the result (a password session drops SSO-sourced roles), never widen it
// (G-5, HP-NTF-008, SR-23).
func currentOperator(ctx context.Context, q *db.Queries, in policy.OperatorInfo) (policy.OperatorInfo, error) {
	return rereadOperator(ctx, q, in, false)
}

// withdrawingOperator is currentOperator for withdrawing access (cancel, revoke): a disabled operator is refused and
// roles are narrowed to those still assigned, but a caller that is not an operator row (gateway-internal actors such
// as the soak and fault harnesses' system administrator) keeps its stated authority, because withdrawing access can
// never widen it.
func withdrawingOperator(ctx context.Context, q *db.Queries, in policy.OperatorInfo) (policy.OperatorInfo, error) {
	return rereadOperator(ctx, q, in, true)
}

func rereadOperator(ctx context.Context, q *db.Queries, in policy.OperatorInfo, allowInternal bool) (policy.OperatorInfo, error) {
	row, err := q.GetOperator(ctx, in.ID)
	if errors.Is(err, sql.ErrNoRows) {
		if allowInternal && in.Enabled {
			return in, nil
		}
		return policy.OperatorInfo{}, ErrOperatorUnavailable
	} else if err != nil {
		return policy.OperatorInfo{}, err
	}
	if row.Enabled != 1 {
		return policy.OperatorInfo{}, ErrOperatorUnavailable
	}
	assigned, err := q.ListOperatorRoles(ctx, in.ID)
	if err != nil {
		return policy.OperatorInfo{}, err
	}
	groups, err := q.ListOperatorGroupNames(ctx, in.ID)
	if err != nil {
		return policy.OperatorInfo{}, err
	}
	out := policy.OperatorInfo{ID: in.ID, Enabled: true, MFAPassed: in.MFAPassed, Roles: []string{}, Groups: []string{}}
	for _, r := range in.Roles {
		if slices.ContainsFunc(assigned, func(a db.ListOperatorRolesRow) bool { return a.Role == r }) && !slices.Contains(out.Roles, r) {
			out.Roles = append(out.Roles, r)
		}
	}
	for _, g := range in.Groups {
		if slices.Contains(groups, g) && !slices.Contains(out.Groups, g) {
			out.Groups = append(out.Groups, g)
		}
	}
	return out, nil
}
