package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/httpapi/gen"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/oidc"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/rbac"
	"github.com/aurimasniekis/go-hallpass/internal/recording/hprec"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// API DTOs: domain JSON with durations as integer seconds (outer fields shadow the embedded ones) and sensitive
// fields filtered by permission.

type meDTO struct {
	Operator    *opauth.Operator  `json:"operator"`
	Permissions []rbac.Permission `json:"permissions"`
	CSRFToken   string            `json:"csrf_token"`
	Session     meSession         `json:"session"`
}

type meSession struct {
	ID          string     `json:"id"`
	Method      string     `json:"method"`
	AuthAt      time.Time  `json:"auth_at"`
	MFAAt       *time.Time `json:"mfa_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	Limited     bool       `json:"limited"`
	NeedsEnroll bool       `json:"needs_enroll"`
}

func (s *Server) me(p *opauth.Principal) meDTO {
	perms := []rbac.Permission{}
	if !p.Limited {
		perms = s.d.Matrix.Permissions(p.Operator.Roles)
	}
	return meDTO{Operator: p.Operator, Permissions: perms, CSRFToken: p.CSRFToken,
		Session: meSession{ID: p.SessionID, Method: p.Method, AuthAt: p.AuthAt, MFAAt: p.MFAAt, ExpiresAt: p.ExpiresAt, Limited: p.Limited, NeedsEnroll: p.NeedsEnroll}}
}

// serverDTO redacts the destination address and port without inventory.address.read (HP-SRV-010, HP-RBAC-002).
type serverDTO struct {
	*inventory.Server
	Address         string `json:"address"`
	Port            int    `json:"port"`
	AddressRedacted bool   `json:"address_redacted"`
}

func (s *Server) canSeeAddress(c *gen.Call) bool {
	return c.Principal != nil && s.d.Matrix.Has(c.Principal.Operator.Roles, rbac.InventoryAddressRead)
}

func (s *Server) server(c *gen.Call, v *inventory.Server) serverDTO {
	if s.canSeeAddress(c) {
		return serverDTO{Server: v, Address: v.Address, Port: v.Port}
	}
	return serverDTO{Server: v, AddressRedacted: true}
}

type roleDTO struct {
	*inventory.Role
	DefaultDuration seconds `json:"default_duration"`
	MaxDuration     seconds `json:"max_duration"`
}

func role(r *inventory.Role) roleDTO {
	return roleDTO{Role: r, DefaultDuration: secs(r.DefaultDuration), MaxDuration: secs(r.MaxDuration)}
}

// roleInputDTO accepts durations in seconds.
type roleInputDTO struct {
	inventory.RoleInput
	DefaultDuration *int64 `json:"default_duration,omitempty"`
	MaxDuration     *int64 `json:"max_duration,omitempty"`
}

func (r roleInputDTO) input() inventory.RoleInput {
	in := r.RoleInput
	in.DefaultDuration = durPtr(r.DefaultDuration)
	in.MaxDuration = durPtr(r.MaxDuration)
	return in
}

type hostCADTO struct {
	*inventory.HostCA
	MaxValidity seconds `json:"max_validity"`
}

type ruleDTO struct {
	policy.Rule
	MaxDuration     seconds `json:"max_duration,omitempty"`
	AutoMaxDuration seconds `json:"auto_max_duration,omitempty"`
}

func rule(r policy.Rule) ruleDTO {
	return ruleDTO{Rule: r, MaxDuration: secs(r.MaxDuration), AutoMaxDuration: secs(r.AutoMaxDuration)}
}

// ruleInputDTO accepts a rule with durations in seconds.
type ruleInputDTO struct {
	policy.Rule
	MaxDuration     int64 `json:"max_duration,omitempty"`
	AutoMaxDuration int64 `json:"auto_max_duration,omitempty"`
}

func (r ruleInputDTO) rule() policy.Rule {
	out := r.Rule
	out.MaxDuration = time.Duration(r.MaxDuration) * time.Second
	out.AutoMaxDuration = time.Duration(r.AutoMaxDuration) * time.Second
	return out
}

type approverRuleDTO struct {
	policy.ApproverRule
	MaxDuration seconds `json:"max_duration,omitempty"`
}

type approverRuleInputDTO struct {
	policy.ApproverRule
	MaxDuration int64 `json:"max_duration,omitempty"`
}

func (r approverRuleInputDTO) rule() policy.ApproverRule {
	out := r.ApproverRule
	out.MaxDuration = time.Duration(r.MaxDuration) * time.Second
	return out
}

type effectiveRow struct {
	AgentID         string   `json:"agent_id"`
	AgentName       string   `json:"agent_name"`
	ServerID        string   `json:"server_id"`
	ServerAlias     string   `json:"server_alias"`
	RoleID          string   `json:"role_id"`
	RoleAlias       string   `json:"role_alias"`
	Level           string   `json:"level"`
	RequireReason   bool     `json:"require_reason"`
	MaxDuration     seconds  `json:"max_duration"`
	AutoMaxDuration seconds  `json:"auto_max_duration"`
	Rules           []string `json:"rules"`
}

type effectiveDTO struct {
	PolicyVersion int64          `json:"policy_version"`
	Items         []effectiveRow `json:"items"`
}

func effective(version int64, rows []policy.Access) effectiveDTO {
	out := effectiveDTO{PolicyVersion: version, Items: []effectiveRow{}}
	for _, a := range rows {
		level := a.Decision.Level
		if a.Decision.Denied {
			level = "denied"
		} else if level == "" {
			level = "none"
		}
		rules := a.Decision.MatchedRules
		if rules == nil {
			rules = []string{}
		}
		out.Items = append(out.Items, effectiveRow{AgentID: a.AgentID, AgentName: a.AgentName, ServerID: a.ServerID, ServerAlias: a.ServerAlias,
			RoleID: a.RoleID, RoleAlias: a.RoleAlias, Level: level, RequireReason: a.Decision.RequireReason,
			MaxDuration: secs(a.Decision.MaxDuration), AutoMaxDuration: secs(a.Decision.AutoMaxDuration), Rules: rules})
	}
	return out
}

// requestDTO carries the reason only for requests.reason.read (HP-RBAC-001; reasons are untrusted agent text).
type requestDTO struct {
	*access.Request
	RequestedDuration seconds `json:"requested_duration"`
	Reason            *string `json:"reason"`
}

func (s *Server) request(c *gen.Call, r *access.Request) requestDTO {
	out := requestDTO{Request: r, RequestedDuration: secs(r.RequestedDuration)}
	if r.HasReason && s.d.Matrix.Has(c.Principal.Operator.Roles, rbac.RequestsReasonRead) {
		if reason, err := s.d.Access.Reason(c.R.Context(), r.ID); err == nil {
			out.Reason = &reason
		}
	}
	return out
}

func requestFromRow(r db.AccessRequest) *access.Request {
	out := &access.Request{ID: r.ID, AgentID: r.AgentID, AgentKeyID: r.AgentKeyID, ServerID: r.ServerID, RoleID: r.RoleID,
		RequestedDuration: time.Duration(r.RequestedDurationS) * time.Second, State: r.State, StateReason: r.StateReason.String,
		PolicyVersion: r.PolicyVersion, CreatedAt: micros(r.CreatedAt), ExpiresAt: micros(r.ExpiresAt), HasReason: len(r.ReasonEnc) > 0}
	out.DecidedAt = nullTime(r.DecidedAt)
	return out
}

func grantFromRow(g db.Grant) *access.Grant {
	var caps []string
	_ = json.Unmarshal([]byte(g.CapabilitiesJson), &caps)
	return &access.Grant{ID: g.ID, RequestID: g.RequestID, DecisionID: g.DecisionID, AgentID: g.AgentID, ServerID: g.ServerID, RoleID: g.RoleID,
		RemoteUser: g.RemoteUser, Capabilities: caps, PolicyVersion: g.PolicyVersion, StartsAt: micros(g.StartsAt), ExpiresAt: micros(g.ExpiresAt),
		State: g.State, EndedAt: nullTime(g.EndedAt), EndReason: g.EndReason.String}
}

type sessionDTO struct {
	ID             string     `json:"id"`
	GrantID        string     `json:"grant_id"`
	State          string     `json:"state"`
	OpenedAt       time.Time  `json:"opened_at"`
	ClosedAt       *time.Time `json:"closed_at"`
	CloseReason    string     `json:"close_reason,omitempty"`
	RetentionClass string     `json:"retention_class"`
	DeleteAfter    *time.Time `json:"delete_after"`
	AgentID        string     `json:"agent_id"`
	ServerID       string     `json:"server_id"`
	RoleID         string     `json:"role_id"`
	RemoteUser     string     `json:"remote_user"`
	GrantExpiresAt time.Time  `json:"grant_expires_at"`
	GrantState     string     `json:"grant_state"`
	ChannelsTotal  *int       `json:"channels_total,omitempty"`
	ChannelsLive   *int       `json:"channels_live,omitempty"`
}

func sessionFromRow(r db.ListSessionsPageRow) sessionDTO {
	return sessionDTO{ID: r.ID, GrantID: r.GrantID, State: r.State, OpenedAt: micros(r.OpenedAt), ClosedAt: nullTime(r.ClosedAt),
		CloseReason: r.CloseReason.String, RetentionClass: r.RetentionClass, DeleteAfter: nullTime(r.DeleteAfter), AgentID: r.AgentID,
		ServerID: r.ServerID, RoleID: r.RoleID, RemoteUser: r.RemoteUser, GrantExpiresAt: micros(r.ExpiresAt), GrantState: r.GrantState}
}

type channelDTO struct {
	ID           string     `json:"id"`
	SessionID    string     `json:"session_id"`
	ConnectionID string     `json:"connection_id"`
	GrantID      string     `json:"grant_id"`
	AgentID      string     `json:"agent_id"`
	RoleID       string     `json:"role_id"`
	Kind         string     `json:"kind"`
	PTY          bool       `json:"pty"`
	State        string     `json:"state"`
	OpenedAt     time.Time  `json:"opened_at"`
	ClosedAt     *time.Time `json:"closed_at"`
	CloseReason  string     `json:"close_reason,omitempty"`
	CloseDetail  string     `json:"close_detail,omitempty"`
	GatewayCode  *int64     `json:"gateway_exit_code"`
	ExitStatus   *int64     `json:"exit_status"`
	ExitSignal   string     `json:"exit_signal,omitempty"`
}

func channel(ch db.SshChannel) channelDTO {
	return channelDTO{ID: ch.ID, SessionID: ch.AccessSessionID, ConnectionID: ch.ConnectionID, GrantID: ch.GrantID, AgentID: ch.AgentID,
		RoleID: ch.RoleID, Kind: ch.Kind, PTY: ch.Pty == 1, State: ch.State, OpenedAt: micros(ch.OpenedAt), ClosedAt: nullTime(ch.ClosedAt),
		CloseReason: ch.CloseReason.String, CloseDetail: ch.CloseDetail.String, GatewayCode: nullInt(ch.GatewayExitCode),
		ExitStatus: nullInt(ch.ExitStatus), ExitSignal: ch.ExitSignal.String}
}

type timelineDTO struct {
	ID           string          `json:"id"`
	Seq          *int64          `json:"seq"`
	Type         string          `json:"type"`
	At           time.Time       `json:"at"`
	ConnectionID string          `json:"connection_id,omitempty"`
	ChannelID    string          `json:"channel_id,omitempty"`
	SegmentID    string          `json:"segment_id,omitempty"`
	Data         json.RawMessage `json:"data"`
}

func timeline(e db.TimelineEvent) timelineDTO {
	data := json.RawMessage(e.DataJson)
	if len(data) == 0 {
		data = json.RawMessage("{}")
	}
	return timelineDTO{ID: e.ID, Seq: nullInt(e.Seq), Type: e.Type, At: micros(e.At), ConnectionID: e.ConnectionID.String,
		ChannelID: e.ChannelID.String, SegmentID: e.SegmentID.String, Data: data}
}

type segmentDTO struct {
	ID           string     `json:"id"`
	SessionID    string     `json:"session_id"`
	ChannelID    string     `json:"channel_id"`
	Ordinal      int64      `json:"ordinal"`
	State        string     `json:"state"`
	Records      *int64     `json:"records"`
	Bytes        *int64     `json:"bytes"`
	FirstSeq     *int64     `json:"first_seq"`
	LastSeq      *int64     `json:"last_seq"`
	EndReason    string     `json:"end_reason,omitempty"`
	OpenedAt     time.Time  `json:"opened_at"`
	FinalizedAt  *time.Time `json:"finalized_at"`
	VerifyResult string     `json:"verify_result,omitempty"`
}

func segment(r db.RecordingSegment) segmentDTO {
	return segmentDTO{ID: r.ID, SessionID: r.AccessSessionID, ChannelID: r.ChannelID, Ordinal: r.Ordinal, State: r.State, Records: nullInt(r.Records),
		Bytes: nullInt(r.Bytes), FirstSeq: nullInt(r.FirstSeq), LastSeq: nullInt(r.LastSeq), EndReason: r.EndReason.String, OpenedAt: micros(r.OpenedAt),
		FinalizedAt: nullTime(r.FinalizedAt), VerifyResult: r.VerifyResult.String}
}

type recordDTO struct {
	Type     string    `json:"type"`
	Seq      uint64    `json:"seq"`
	Time     time.Time `json:"time"`
	OffsetMS int64     `json:"offset_ms"`
	Stream   string    `json:"stream"`
	Data     string    `json:"data"`
}

type recordPageDTO struct {
	SegmentID  string      `json:"segment_id"`
	Records    []recordDTO `json:"records"`
	NextSeq    uint64      `json:"next_seq"`
	More       bool        `json:"more"`
	Complete   bool        `json:"complete"`
	Incomplete bool        `json:"incomplete"`
}

func recordPage(segID string, p hprec.Page) recordPageDTO {
	out := recordPageDTO{SegmentID: segID, Records: []recordDTO{}, NextSeq: p.NextSeq, More: p.More, Complete: p.Complete, Incomplete: p.Incomplete}
	for _, r := range p.Records {
		out.Records = append(out.Records, recordDTO{Type: r.Type.Versioned(), Seq: r.Seq, Time: r.Time.UTC(), OffsetMS: r.Mono.Milliseconds(),
			Stream: streamName(r.Stream), Data: base64.StdEncoding.EncodeToString(r.Payload)})
	}
	return out
}

type auditDTO struct {
	ID            string          `json:"id"`
	Seq           int64           `json:"seq"`
	At            time.Time       `json:"at"`
	ActorType     string          `json:"actor_type"`
	ActorID       string          `json:"actor_id,omitempty"`
	Action        string          `json:"action"`
	TargetType    string          `json:"target_type,omitempty"`
	TargetID      string          `json:"target_id,omitempty"`
	Outcome       string          `json:"outcome"`
	SourceIP      string          `json:"source_ip,omitempty"`
	CorrelationID string          `json:"correlation_id,omitempty"`
	Details       json.RawMessage `json:"details"`
}

func auditEvent(e db.AuditEvent) auditDTO {
	d := json.RawMessage(e.DetailsJson)
	if len(d) == 0 {
		d = json.RawMessage("{}")
	}
	return auditDTO{ID: e.ID, Seq: e.Seq, At: micros(e.At), ActorType: e.ActorType, ActorID: e.ActorID.String, Action: e.Action,
		TargetType: e.TargetType.String, TargetID: e.TargetID.String, Outcome: e.Outcome, SourceIP: e.SourceIp.String,
		CorrelationID: e.CorrelationID.String, Details: d}
}

type providerDTO struct {
	*oidc.Provider
	RedirectURI string `json:"redirect_uri"`
}

func streamName(st hprec.Stream) string {
	switch st {
	case hprec.StreamPTY:
		return "pty"
	case hprec.StreamStdout:
		return "stdout"
	case hprec.StreamStderr:
		return "stderr"
	case hprec.StreamStdin:
		return "stdin"
	}
	return "meta"
}
