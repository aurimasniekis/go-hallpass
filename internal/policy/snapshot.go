package policy

import (
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
)

// Effects and levels.
const (
	EffectAllow = "allow"
	EffectDeny  = "deny"

	LevelNone        = ""
	LevelVisible     = "visible"
	LevelRequestable = "requestable"
	LevelAutoApprove = "auto_approve"
)

var levelRank = map[string]int{LevelNone: 0, LevelVisible: 1, LevelRequestable: 2, LevelAutoApprove: 3}

// AtLeast reports whether level a is at least b.
func AtLeast(a, b string) bool { return levelRank[a] >= levelRank[b] }

// Rule is a visibility/request rule.
type Rule struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	Effect          string          `json:"effect"`
	Level           string          `json:"level,omitempty"`
	Subjects        SubjectSelector `json:"subjects"`
	Targets         TargetSelector  `json:"targets"`
	Roles           RoleSelector    `json:"roles"`
	MaxDuration     time.Duration   `json:"max_duration,omitempty"`
	AutoMaxDuration time.Duration   `json:"auto_max_duration,omitempty"`
	RequireReason   bool            `json:"require_reason"`
	Enabled         bool            `json:"enabled"`
	Version         int64           `json:"version"`
}

// Validate checks a rule (HP-POL-002/003).
func (r *Rule) Validate(globalMax time.Duration) error {
	v := &apperr.Validation{}
	if r.Name == "" || len(r.Name) > 128 {
		v.Add("name", "required, at most 128 bytes")
	}
	if len(r.Description) > 2000 {
		v.Add("description", "at most 2000 bytes")
	}
	switch r.Effect {
	case EffectDeny:
		if r.Level != "" || r.MaxDuration != 0 || r.AutoMaxDuration != 0 {
			v.Add("effect", "deny rules take no level or durations")
		}
	case EffectAllow:
		if r.Level != LevelVisible && r.Level != LevelRequestable && r.Level != LevelAutoApprove {
			v.Add("level", "must be visible, requestable or auto_approve")
		}
	default:
		v.Add("effect", "must be allow or deny")
	}
	if r.MaxDuration < 0 || r.MaxDuration > globalMax || (r.MaxDuration != 0 && r.MaxDuration < time.Minute) {
		v.Add("max_duration", "must be between 1m and %s", globalMax)
	}
	if r.Level == LevelAutoApprove {
		if r.AutoMaxDuration < time.Minute || r.AutoMaxDuration > globalMax || (r.MaxDuration != 0 && r.AutoMaxDuration > r.MaxDuration) {
			v.Add("auto_max_duration", "auto_approve requires a duration between 1m and the rule's max_duration")
		}
	} else if r.AutoMaxDuration != 0 {
		v.Add("auto_max_duration", "only valid for auto_approve rules")
	}
	r.Subjects.validate(v, "subjects")
	r.Targets.validate(v, "targets")
	r.Roles.validate(v, "roles")
	return v.Err()
}

// ApproverRule grants approval authority (HP-POL-011).
type ApproverRule struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Operators   OperatorSelector `json:"operators"`
	Targets     TargetSelector   `json:"targets"`
	Roles       RoleSelector     `json:"roles"`
	MaxDuration time.Duration    `json:"max_duration,omitempty"`
	Enabled     bool             `json:"enabled"`
	Version     int64            `json:"version"`
}

// Validate checks an approver rule.
func (r *ApproverRule) Validate(globalMax time.Duration) error {
	v := &apperr.Validation{}
	if r.Name == "" || len(r.Name) > 128 {
		v.Add("name", "required, at most 128 bytes")
	}
	if r.MaxDuration < 0 || r.MaxDuration > globalMax || (r.MaxDuration != 0 && r.MaxDuration < time.Minute) {
		v.Add("max_duration", "must be between 1m and %s", globalMax)
	}
	r.Operators.validate(v, "operators")
	r.Targets.validate(v, "targets")
	r.Roles.validate(v, "roles")
	return v.Err()
}

// AgentInfo is the policy view of an agent.
type AgentInfo struct {
	Object
	Enabled bool
	Owners  []string
}

// ServerInfo is the policy view of a server.
type ServerInfo struct {
	Object
	Alias       string
	Description string
	Enabled     bool
}

// RoleInfo is the policy view of a role.
type RoleInfo struct {
	Object
	ServerID         string
	Description      string
	Capabilities     []string
	DefaultDuration  time.Duration
	MaxDuration      time.Duration
	ApprovalChannels []string
	Enabled          bool
}

// Settings are global policy parameters.
type Settings struct {
	MaxGrantDuration     time.Duration
	DurationPresets      []time.Duration
	ProhibitSelfApproval bool
}

// Snapshot is an immutable, compiled policy at one policy_version.
type Snapshot struct {
	Version   int64
	Lockdown  bool
	settings  Settings
	rules     []Rule
	approvers []ApproverRule
	agents    map[string]*AgentInfo
	servers   map[string]*ServerInfo
	byAlias   map[string]*ServerInfo
	roles     map[string]*RoleInfo
	rolesOf   map[string][]*RoleInfo // server ID → roles sorted by alias
}

// Data is the input to compile a snapshot.
type Data struct {
	Version   int64
	Lockdown  bool
	Settings  Settings
	Rules     []Rule
	Approvers []ApproverRule
	Agents    []AgentInfo
	Servers   []ServerInfo
	Roles     []RoleInfo
}

// Compile builds a snapshot.
func Compile(d Data) *Snapshot {
	s := &Snapshot{
		Version: d.Version, Lockdown: d.Lockdown, settings: d.Settings,
		agents: map[string]*AgentInfo{}, servers: map[string]*ServerInfo{}, byAlias: map[string]*ServerInfo{},
		roles: map[string]*RoleInfo{}, rolesOf: map[string][]*RoleInfo{},
	}
	for _, r := range d.Rules {
		if r.Enabled {
			s.rules = append(s.rules, r)
		}
	}
	for _, r := range d.Approvers {
		if r.Enabled {
			s.approvers = append(s.approvers, r)
		}
	}
	for i := range d.Agents {
		a := d.Agents[i]
		s.agents[a.ID] = &a
	}
	for i := range d.Servers {
		srv := d.Servers[i]
		s.servers[srv.ID] = &srv
		s.byAlias[srv.Alias] = &srv
	}
	for i := range d.Roles {
		r := d.Roles[i]
		s.roles[r.ID] = &r
		s.rolesOf[r.ServerID] = append(s.rolesOf[r.ServerID], &r)
	}
	for _, rs := range s.rolesOf {
		sort.Slice(rs, func(i, j int) bool { return rs[i].Name < rs[j].Name })
	}
	return s
}

// Settings returns global policy settings.
func (s *Snapshot) Settings() Settings { return s.settings }

// Decision is the effective policy for one agent × server × role.
type Decision struct {
	Level            string          `json:"level"` // "" means denied/invisible
	Denied           bool            `json:"denied"`
	DecidingRule     string          `json:"deciding_rule,omitempty"`
	MatchedRules     []string        `json:"matched_rules"`
	MaxDuration      time.Duration   `json:"max_duration,omitempty"`
	AutoMaxDuration  time.Duration   `json:"auto_max_duration,omitempty"`
	AllowedDurations []time.Duration `json:"allowed_durations,omitempty"`
	RequireReason    bool            `json:"require_reason"`
	Reason           string          `json:"reason,omitempty"`
}

// Visible reports level ≥ visible.
func (d Decision) Visible() bool { return AtLeast(d.Level, LevelVisible) }

// Requestable reports level ≥ requestable.
func (d Decision) Requestable() bool { return AtLeast(d.Level, LevelRequestable) }

// AutoApproves reports whether a request for dur is approved by policy without a human (HP-POL-013).
func (d Decision) AutoApproves(dur time.Duration) bool {
	return d.Level == LevelAutoApprove && d.AutoMaxDuration > 0 && dur <= d.AutoMaxDuration && dur <= d.MaxDuration
}

// DurationAllowed reports whether dur is one of the allowed presets.
func (d Decision) DurationAllowed(dur time.Duration) bool {
	return slices.Contains(d.AllowedDurations, dur)
}

// Evaluate computes the effective level for agent × server × role (PLAN §9.2). Disabled or unknown objects and
// lockdown yield a denied decision.
func (s *Snapshot) Evaluate(agentID, serverID, roleID string) Decision {
	a, srv, role := s.agents[agentID], s.servers[serverID], s.roles[roleID]
	switch {
	case a == nil || srv == nil || role == nil || role.ServerID != serverID:
		return Decision{Denied: true, Reason: "unknown"}
	case !a.Enabled || !srv.Enabled || !role.Enabled:
		return Decision{Denied: true, Reason: "disabled"}
	case s.Lockdown:
		return Decision{Denied: true, Reason: "lockdown"}
	}
	d := Decision{MatchedRules: []string{}}
	var ruleMax time.Duration
	hasRuleMax := false
	var autoMax time.Duration
	best := -1
	for i := range s.rules {
		r := &s.rules[i]
		if !r.Subjects.Matches(a.Object) || !r.Targets.Matches(srv.Object) || !r.Roles.Matches(role.Object) {
			continue
		}
		d.MatchedRules = append(d.MatchedRules, r.ID)
		if r.Effect == EffectDeny {
			return Decision{Denied: true, DecidingRule: r.ID, MatchedRules: d.MatchedRules, Reason: "deny rule"}
		}
		if best < 0 || levelRank[r.Level] > levelRank[s.rules[best].Level] {
			best = i
		}
		if AtLeast(r.Level, LevelRequestable) {
			if r.RequireReason {
				d.RequireReason = true
			}
			if r.MaxDuration > 0 && (!hasRuleMax || r.MaxDuration > ruleMax) {
				ruleMax, hasRuleMax = r.MaxDuration, true
			}
		}
		if r.Level == LevelAutoApprove && (autoMax == 0 || r.AutoMaxDuration < autoMax) {
			autoMax = r.AutoMaxDuration
		}
	}
	if best < 0 {
		return Decision{Denied: true, MatchedRules: d.MatchedRules, Reason: "no matching allow rule (default deny)"}
	}
	d.Level = s.rules[best].Level
	d.DecidingRule = s.rules[best].ID
	if d.Requestable() {
		maxDur := min(role.MaxDuration, s.settings.MaxGrantDuration)
		if hasRuleMax {
			maxDur = min(maxDur, ruleMax)
		}
		d.MaxDuration = maxDur
		for _, p := range s.settings.DurationPresets {
			if p <= maxDur {
				d.AllowedDurations = append(d.AllowedDurations, p)
			}
		}
		if d.Level == LevelAutoApprove {
			d.AutoMaxDuration = min(autoMax, maxDur)
		}
	}
	return d
}

// DefaultDuration returns the duration used when an agent does not specify one: the role default, clamped to
// the largest allowed preset not above it (or the smallest allowed preset).
func (s *Snapshot) DefaultDuration(roleID string, d Decision) time.Duration {
	role := s.roles[roleID]
	if role == nil || len(d.AllowedDurations) == 0 {
		return 0
	}
	want := role.DefaultDuration
	if d.Level == LevelAutoApprove && d.AutoMaxDuration > 0 && d.AutoMaxDuration < want {
		want = d.AutoMaxDuration
	}
	choice := d.AllowedDurations[0]
	for _, p := range d.AllowedDurations {
		if p <= want {
			choice = p
		}
	}
	return choice
}

// ErrNotFoundOrForbidden is the single response for unknown, hidden, disabled or unrequestable targets (HP-POL-010).
var ErrNotFoundOrForbidden = errors.New("server or role not found or not permitted")

// VisibleRole is a role visible to an agent with its decision.
type VisibleRole struct {
	Role     *RoleInfo
	Decision Decision
}

// VisibleServer is a server with at least one visible role.
type VisibleServer struct {
	Server *ServerInfo
	Roles  []VisibleRole
}

// Visible lists the servers and roles an agent can see, sorted by alias (HP-POL-005).
func (s *Snapshot) Visible(agentID string) []VisibleServer {
	var out []VisibleServer
	aliases := make([]string, 0, len(s.byAlias))
	for a := range s.byAlias {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)
	for _, alias := range aliases {
		srv := s.byAlias[alias]
		var roles []VisibleRole
		for _, r := range s.rolesOf[srv.ID] {
			if d := s.Evaluate(agentID, srv.ID, r.ID); d.Visible() {
				roles = append(roles, VisibleRole{Role: r, Decision: d})
			}
		}
		if len(roles) > 0 {
			out = append(out, VisibleServer{Server: srv, Roles: roles})
		}
	}
	return out
}

// ResolveServer returns a visible server by alias, or ErrNotFoundOrForbidden for every other case. It does no
// work that depends on whether the alias exists beyond in-memory evaluation.
func (s *Snapshot) ResolveServer(agentID, alias string) (VisibleServer, error) {
	srv, ok := s.byAlias[alias]
	if !ok {
		return VisibleServer{}, ErrNotFoundOrForbidden
	}
	var roles []VisibleRole
	for _, r := range s.rolesOf[srv.ID] {
		if d := s.Evaluate(agentID, srv.ID, r.ID); d.Visible() {
			roles = append(roles, VisibleRole{Role: r, Decision: d})
		}
	}
	if len(roles) == 0 {
		return VisibleServer{}, ErrNotFoundOrForbidden
	}
	return VisibleServer{Server: srv, Roles: roles}, nil
}

// ResolveRole returns a visible role on a visible server, or ErrNotFoundOrForbidden.
func (s *Snapshot) ResolveRole(agentID, serverAlias, roleAlias string) (VisibleServer, VisibleRole, error) {
	vs, err := s.ResolveServer(agentID, serverAlias)
	if err != nil {
		return VisibleServer{}, VisibleRole{}, err
	}
	for _, r := range vs.Roles {
		if r.Role.Name == roleAlias {
			return vs, r, nil
		}
	}
	return VisibleServer{}, VisibleRole{}, ErrNotFoundOrForbidden
}

// Agent returns the policy view of an agent.
func (s *Snapshot) Agent(id string) *AgentInfo { return s.agents[id] }

// Server returns the policy view of a server.
func (s *Snapshot) Server(id string) *ServerInfo { return s.servers[id] }

// Role returns the policy view of a role.
func (s *Snapshot) Role(id string) *RoleInfo { return s.roles[id] }

// Rules returns the enabled rules.
func (s *Snapshot) Rules() []Rule { return s.rules }

// OperatorInfo is what approval checks need about an operator.
type OperatorInfo struct {
	ID        string
	Roles     []string // internal roles: administrator, approver, auditor, viewer
	Groups    []string
	Enabled   bool
	MFAPassed bool
}

// ApprovalCheck is the outcome of an approval-authority check.
type ApprovalCheck struct {
	Allowed bool
	RuleID  string
	Reason  string
}

// CanApprove checks approval authority for a request (HP-POL-011/012, HP-RBAC-003): an enabled operator with the
// approver or administrator role, a matching enabled approver rule covering the duration, and not an owner of the
// requesting agent when self-approval is prohibited.
func (s *Snapshot) CanApprove(op OperatorInfo, agentID, serverID, roleID string, dur time.Duration) ApprovalCheck {
	return s.authority(op, agentID, serverID, roleID, dur, true)
}

// CanAct checks the authority to deny, cancel or revoke (and terminate activity under) a request or grant: the same
// role and approver-rule scope as CanApprove, but without the self-approval prohibition, which restricts only
// approving (HP-POL-012). Owners may always withdraw their own agent's access (HP-GRT-009, HP-REQ-006, SR-32).
func (s *Snapshot) CanAct(op OperatorInfo, agentID, serverID, roleID string, dur time.Duration) ApprovalCheck {
	return s.authority(op, agentID, serverID, roleID, dur, false)
}

func (s *Snapshot) authority(op OperatorInfo, agentID, serverID, roleID string, dur time.Duration, approving bool) ApprovalCheck {
	if !op.Enabled {
		return ApprovalCheck{Reason: "operator disabled"}
	}
	if !slices.Contains(op.Roles, "approver") && !slices.Contains(op.Roles, "administrator") {
		return ApprovalCheck{Reason: "operator lacks the approver or administrator role"}
	}
	srv, role := s.servers[serverID], s.roles[roleID]
	if srv == nil || role == nil {
		return ApprovalCheck{Reason: "unknown target"}
	}
	if a := s.agents[agentID]; approving && a != nil && s.settings.ProhibitSelfApproval && slices.Contains(a.Owners, op.ID) {
		return ApprovalCheck{Reason: "self-approval is prohibited for owners of the requesting agent"}
	}
	opObj := Object{ID: op.ID, Groups: op.Groups}
	tooLong := false
	for _, r := range s.approvers {
		if !r.Operators.Matches(opObj) || !r.Targets.Matches(srv.Object) || !r.Roles.Matches(role.Object) {
			continue
		}
		if r.MaxDuration > 0 && dur > r.MaxDuration {
			tooLong = true
			continue
		}
		return ApprovalCheck{Allowed: true, RuleID: r.ID}
	}
	if tooLong {
		return ApprovalCheck{Reason: "requested duration exceeds the approver rule's maximum"}
	}
	return ApprovalCheck{Reason: "no approver rule grants authority for this target and role"}
}

// ApproversFor lists approver rules matching a target (used to route notifications).
func (s *Snapshot) ApproversFor(serverID, roleID string) []ApproverRule {
	srv, role := s.servers[serverID], s.roles[roleID]
	if srv == nil || role == nil {
		return nil
	}
	var out []ApproverRule
	for _, r := range s.approvers {
		if r.Targets.Matches(srv.Object) && r.Roles.Matches(role.Object) {
			out = append(out, r)
		}
	}
	return out
}
