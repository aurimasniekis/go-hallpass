// Package access implements the request → decision → grant → access session lifecycle, channel registration with
// revalidation and concurrency limits, the session timeline, and the enforcer that terminates activity when access
// ends (PLAN §5, ADR-0007, ADR-0018).
package access

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Request states (HP-REQ-001).
const (
	ReqPending  = "pending"
	ReqApproved = "approved"
	ReqDenied   = "denied"
	ReqExpired  = "expired"
	ReqCanceled = "canceled"
)

// Grant states.
const (
	GrantActive  = "active"
	GrantExpired = "expired"
	GrantRevoked = "revoked"
)

// End and cancel reasons.
const (
	ReasonExpired           = "expired"
	ReasonOperator          = "operator"
	ReasonAgent             = "agent"
	ReasonPolicyChanged     = "policy_changed"
	ReasonAgentDisabled     = "agent_disabled"
	ReasonKeyRevoked        = "key_revoked"
	ReasonTargetDisabled    = "target_disabled"
	ReasonCredentialRevoked = "credential_revoked" //nolint:gosec // G101 false positive: reason code
	ReasonLockdown          = "lockdown"
	ReasonShutdown          = "shutdown"
	// ReasonTerminalClosed ends a web terminal grant when its browser connection closes.
	ReasonTerminalClosed = "terminal_closed"
	// ReasonOperatorIneligible ends a web terminal whose administrator was disabled or lost the role.
	ReasonOperatorIneligible = "operator_ineligible"
)

// The built-in agent and key that web terminals run as (migration 0029). The agent is disabled and deleted and the
// key revoked, so neither ever authenticates over SSH or appears in lists and policy.
const (
	ConsoleAgentID = "agt_00000000000000000000000000"
	ConsoleKeyID   = "key_00000000000000000000000000"
)

// Errors with stable meaning for the SSH front end and API.
var (
	// ErrNotFoundOrForbidden is returned for unknown, hidden or unrequestable targets and other agents' requests
	// (HP-POL-010); its message is identical in every case.
	ErrNotFoundOrForbidden = apperr.New(apperr.CodeNotFound, "server or role not found or not permitted")
	ErrLockdown            = apperr.New(apperr.CodeUnavailable, "access is temporarily suspended (lockdown)")
	ErrAccessEnded         = apperr.New(apperr.CodePrecondition, "access has ended")
	ErrConcurrencyLimit    = apperr.New(apperr.CodeRateLimited, "concurrency limit reached for this role")
	ErrRateLimited         = apperr.New(apperr.CodeRateLimited, "too many requests")
	ErrStorageUnavailable  = apperr.New(apperr.CodeUnavailable, "storage unavailable; access fails closed")
)

// IsNotFoundOrForbidden reports whether err is the uniform not-found-or-forbidden error.
func IsNotFoundOrForbidden(err error) bool { return errors.Is(err, ErrNotFoundOrForbidden) }

// Request is an access request (reason excluded; see Service.Reason).
type Request struct {
	ID                string        `json:"id"`
	AgentID           string        `json:"agent_id"`
	AgentKeyID        string        `json:"agent_key_id"`
	ServerID          string        `json:"server_id"`
	RoleID            string        `json:"role_id"`
	RequestedDuration time.Duration `json:"requested_duration"`
	State             string        `json:"state"`
	StateReason       string        `json:"state_reason,omitempty"`
	PolicyVersion     int64         `json:"policy_version"`
	CreatedAt         time.Time     `json:"created_at"`
	ExpiresAt         time.Time     `json:"expires_at"`
	DecidedAt         *time.Time    `json:"decided_at,omitempty"`
	HasReason         bool          `json:"has_reason"`
	// OperatorID names the administrator of a web terminal (agent is ConsoleAgentID); empty for agent access.
	OperatorID string `json:"operator_id,omitempty"`
}

// Terminal reports whether the request can no longer change.
func (r *Request) Terminal() bool { return r.State != ReqPending }

// Grant is an authoritative permission window.
type Grant struct {
	ID            string     `json:"id"`
	RequestID     string     `json:"request_id"`
	DecisionID    string     `json:"decision_id"`
	AgentID       string     `json:"agent_id"`
	ServerID      string     `json:"server_id"`
	RoleID        string     `json:"role_id"`
	RemoteUser    string     `json:"remote_user"`
	Capabilities  []string   `json:"capabilities"`
	PolicyVersion int64      `json:"policy_version"`
	StartsAt      time.Time  `json:"starts_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	State         string     `json:"state"`
	EndedAt       *time.Time `json:"ended_at,omitempty"`
	EndReason     string     `json:"end_reason,omitempty"`
	SessionID     string     `json:"session_id,omitempty"`
	// OperatorID names the administrator of a web terminal (agent is ConsoleAgentID); empty for agent access.
	OperatorID string `json:"operator_id,omitempty"`
}

// Console reports whether the grant is a web terminal of an administrator (ADR-0055).
func (g *Grant) Console() bool { return g.OperatorID != "" }

// ActiveAt reports whether the grant permits activity at t (expiry is time-authoritative).
func (g *Grant) ActiveAt(t time.Time) bool { return g.State == GrantActive && t.Before(g.ExpiresAt) }

// Decision is a recorded approval or denial.
type Decision struct {
	ID              string        `json:"id"`
	RequestID       string        `json:"request_id"`
	Outcome         string        `json:"outcome"`
	ActorType       string        `json:"actor_type"`
	ActorID         string        `json:"actor_id"`
	Channel         string        `json:"channel"`
	ApprovedDuraton time.Duration `json:"approved_duration,omitempty"`
	PolicyVersion   int64         `json:"policy_version"`
	ApproverRuleID  string        `json:"approver_rule_id,omitempty"`
	DecidedAt       time.Time     `json:"decided_at"`
}

func ts(us int64) time.Time { return time.UnixMicro(us).UTC() }

func tsPtr(us int64, valid bool) *time.Time {
	if !valid {
		return nil
	}
	t := ts(us)
	return &t
}

func requestFromRow(r db.AccessRequest) *Request {
	return &Request{
		ID: r.ID, AgentID: r.AgentID, AgentKeyID: r.AgentKeyID, ServerID: r.ServerID, RoleID: r.RoleID,
		RequestedDuration: time.Duration(r.RequestedDurationS) * time.Second, State: r.State, StateReason: r.StateReason.String,
		PolicyVersion: r.PolicyVersion, CreatedAt: ts(r.CreatedAt), ExpiresAt: ts(r.ExpiresAt),
		DecidedAt: tsPtr(r.DecidedAt.Int64, r.DecidedAt.Valid), HasReason: len(r.ReasonEnc) > 0, OperatorID: r.OperatorID.String,
	}
}

func grantFromRow(r db.Grant) *Grant {
	g := &Grant{
		ID: r.ID, RequestID: r.RequestID, DecisionID: r.DecisionID, AgentID: r.AgentID, ServerID: r.ServerID, RoleID: r.RoleID,
		RemoteUser: r.RemoteUser, PolicyVersion: r.PolicyVersion, StartsAt: ts(r.StartsAt), ExpiresAt: ts(r.ExpiresAt),
		State: r.State, EndedAt: tsPtr(r.EndedAt.Int64, r.EndedAt.Valid), EndReason: r.EndReason.String,
		OperatorID: r.OperatorID.String,
	}
	_ = json.Unmarshal([]byte(r.CapabilitiesJson), &g.Capabilities)
	return g
}

func decisionFromRow(r db.ApprovalDecision) *Decision {
	return &Decision{
		ID: r.ID, RequestID: r.RequestID, Outcome: r.Outcome, ActorType: r.ActorType, ActorID: r.ActorID, Channel: r.Channel,
		ApprovedDuraton: time.Duration(r.ApprovedDurationS.Int64) * time.Second, PolicyVersion: r.PolicyVersion,
		ApproverRuleID: r.ApproverRuleID.String, DecidedAt: ts(r.DecidedAt),
	}
}
