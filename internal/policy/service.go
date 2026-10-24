package policy

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
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Service manages policy rules, approver rules and agent owners. Every change increments policy_version in the
// same transaction and publishes policy.changed after commit (HP-POL-007).
type Service struct {
	s      *store.Store
	audit  *audit.Writer
	bus    *eventbus.Bus
	engine *Engine
}

// NewService returns a policy service.
func NewService(s *store.Store, aw *audit.Writer, bus *eventbus.Bus, e *Engine) *Service {
	return &Service{s: s, audit: aw, bus: bus, engine: e}
}

// Engine returns the snapshot engine.
func (svc *Service) Engine() *Engine { return svc.engine }

func (svc *Service) changed(ctx context.Context, tx *store.Tx) (int64, error) {
	v, err := tx.Q.BumpPolicyVersion(ctx, tx.NowMicros())
	if err != nil {
		return 0, err
	}
	tx.AfterCommit(func() {
		if svc.bus != nil {
			svc.bus.Publish(eventbus.Event{Topic: eventbus.TopicPolicyChanged, Payload: v})
		}
	})
	return v, nil
}

func durS(d time.Duration) sql.NullInt64 {
	return sql.NullInt64{Int64: int64(d / time.Second), Valid: d > 0}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func normalizeRule(r *Rule) {
	sortSel := func(s []string) []string { s = slices.Clone(s); slices.Sort(s); return slices.Compact(s) }
	r.Subjects.Agents, r.Subjects.AgentGroups = sortSel(r.Subjects.Agents), sortSel(r.Subjects.AgentGroups)
	r.Targets.Servers, r.Targets.ServerGroups = sortSel(r.Targets.Servers), sortSel(r.Targets.ServerGroups)
	r.Roles.Names, r.Roles.IDs = sortSel(r.Roles.Names), sortSel(r.Roles.IDs)
}

// CreateRule adds a policy rule.
func (svc *Service) CreateRule(ctx context.Context, actor audit.Actor, r Rule) (*Rule, error) {
	normalizeRule(&r)
	if err := r.Validate(svc.engine.globalMax); err != nil {
		return nil, err
	}
	r.ID = ids.New(ids.PolicyRule)
	err := svc.s.W().TxNamed(ctx, "policy.create_rule", func(tx *store.Tx) error {
		if err := tx.Q.InsertPolicyRule(ctx, db.InsertPolicyRuleParams{
			ID: r.ID, Name: r.Name, Description: r.Description, Effect: r.Effect, Level: sql.NullString{String: r.Level, Valid: r.Level != ""},
			SubjectsJson: mustJSON(r.Subjects), TargetsJson: mustJSON(r.Targets), RolesJson: mustJSON(r.Roles),
			MaxDurationS: durS(r.MaxDuration), AutoMaxDurationS: durS(r.AutoMaxDuration), RequireReason: b2i(r.RequireReason),
			Enabled: b2i(r.Enabled), CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros(), UpdatedBy: actorRef(actor),
		}); err != nil {
			if store.IsConstraint(err) {
				return apperr.New(apperr.CodeAlreadyExists, "a rule named %q already exists", r.Name)
			}
			return err
		}
		v, err := svc.changed(ctx, tx)
		if err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "policy.rule.created", Target: audit.Target{Type: "policy_rule", ID: r.ID},
			Details: map[string]any{"rule": r, "policy_version": v}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.GetRule(ctx, r.ID)
}

// UpdateRule replaces a rule (optimistic concurrency on Version).
func (svc *Service) UpdateRule(ctx context.Context, actor audit.Actor, id string, r Rule) (*Rule, error) {
	normalizeRule(&r)
	if err := r.Validate(svc.engine.globalMax); err != nil {
		return nil, err
	}
	err := svc.s.W().TxNamed(ctx, "policy.update_rule", func(tx *store.Tx) error {
		n, err := tx.Q.UpdatePolicyRule(ctx, db.UpdatePolicyRuleParams{
			Name: r.Name, Description: r.Description, Effect: r.Effect, Level: sql.NullString{String: r.Level, Valid: r.Level != ""},
			SubjectsJson: mustJSON(r.Subjects), TargetsJson: mustJSON(r.Targets), RolesJson: mustJSON(r.Roles),
			MaxDurationS: durS(r.MaxDuration), AutoMaxDurationS: durS(r.AutoMaxDuration), RequireReason: b2i(r.RequireReason),
			Enabled: b2i(r.Enabled), UpdatedAt: tx.NowMicros(), UpdatedBy: actorRef(actor), ID: id, Version: r.Version,
		})
		if err != nil {
			if store.IsConstraint(err) {
				return apperr.New(apperr.CodeAlreadyExists, "a rule named %q already exists", r.Name)
			}
			return err
		}
		if n == 0 {
			if _, err := tx.Q.GetPolicyRule(ctx, id); errors.Is(err, sql.ErrNoRows) {
				return apperr.New(apperr.CodeNotFound, "rule not found")
			}
			return apperr.New(apperr.CodeConflict, "rule was modified concurrently; reload and retry")
		}
		v, err := svc.changed(ctx, tx)
		if err != nil {
			return err
		}
		r.ID = id
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "policy.rule.updated", Target: audit.Target{Type: "policy_rule", ID: id},
			Details: map[string]any{"rule": r, "policy_version": v}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.GetRule(ctx, id)
}

// DeleteRule removes a rule.
func (svc *Service) DeleteRule(ctx context.Context, actor audit.Actor, id string) error {
	return svc.s.W().TxNamed(ctx, "policy.delete_rule", func(tx *store.Tx) error {
		row, err := tx.Q.GetPolicyRule(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeNotFound, "rule not found")
		} else if err != nil {
			return err
		}
		if _, err := tx.Q.DeletePolicyRule(ctx, id); err != nil {
			return err
		}
		v, err := svc.changed(ctx, tx)
		if err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "policy.rule.deleted", Target: audit.Target{Type: "policy_rule", ID: id},
			Details: map[string]any{"name": row.Name, "policy_version": v}})
		return err
	})
}

// GetRule returns a rule.
func (svc *Service) GetRule(ctx context.Context, id string) (*Rule, error) {
	r, err := svc.s.R().GetPolicyRule(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeNotFound, "rule not found")
	}
	if err != nil {
		return nil, err
	}
	rule, err := ruleFromRow(r)
	return &rule, err
}

// ListRules returns every rule (enabled and disabled).
func (svc *Service) ListRules(ctx context.Context) ([]Rule, error) { return loadRules(ctx, svc.s.R()) }

// CreateApproverRule adds an approver rule.
func (svc *Service) CreateApproverRule(ctx context.Context, actor audit.Actor, r ApproverRule) (*ApproverRule, error) {
	if err := r.Validate(svc.engine.globalMax); err != nil {
		return nil, err
	}
	r.ID = ids.New(ids.ApproverRule)
	err := svc.s.W().TxNamed(ctx, "policy.create_approver_rule", func(tx *store.Tx) error {
		if err := tx.Q.InsertApproverRule(ctx, db.InsertApproverRuleParams{
			ID: r.ID, Name: r.Name, Description: r.Description, OperatorsJson: mustJSON(r.Operators), TargetsJson: mustJSON(r.Targets),
			RolesJson: mustJSON(r.Roles), MaxDurationS: durS(r.MaxDuration), Enabled: b2i(r.Enabled),
			CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros(), UpdatedBy: actorRef(actor),
		}); err != nil {
			if store.IsConstraint(err) {
				return apperr.New(apperr.CodeAlreadyExists, "an approver rule named %q already exists", r.Name)
			}
			return err
		}
		v, err := svc.changed(ctx, tx)
		if err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "policy.approver_rule.created", Target: audit.Target{Type: "approver_rule", ID: r.ID},
			Details: map[string]any{"rule": r, "policy_version": v}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.GetApproverRule(ctx, r.ID)
}

// UpdateApproverRule replaces an approver rule.
func (svc *Service) UpdateApproverRule(ctx context.Context, actor audit.Actor, id string, r ApproverRule) (*ApproverRule, error) {
	if err := r.Validate(svc.engine.globalMax); err != nil {
		return nil, err
	}
	err := svc.s.W().TxNamed(ctx, "policy.update_approver_rule", func(tx *store.Tx) error {
		n, err := tx.Q.UpdateApproverRule(ctx, db.UpdateApproverRuleParams{
			Name: r.Name, Description: r.Description, OperatorsJson: mustJSON(r.Operators), TargetsJson: mustJSON(r.Targets),
			RolesJson: mustJSON(r.Roles), MaxDurationS: durS(r.MaxDuration), Enabled: b2i(r.Enabled), UpdatedAt: tx.NowMicros(),
			UpdatedBy: actorRef(actor), ID: id, Version: r.Version,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return apperr.New(apperr.CodeConflict, "approver rule not found or modified concurrently")
		}
		v, err := svc.changed(ctx, tx)
		if err != nil {
			return err
		}
		r.ID = id
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "policy.approver_rule.updated", Target: audit.Target{Type: "approver_rule", ID: id},
			Details: map[string]any{"rule": r, "policy_version": v}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.GetApproverRule(ctx, id)
}

// DeleteApproverRule removes an approver rule.
func (svc *Service) DeleteApproverRule(ctx context.Context, actor audit.Actor, id string) error {
	return svc.s.W().TxNamed(ctx, "policy.delete_approver_rule", func(tx *store.Tx) error {
		n, err := tx.Q.DeleteApproverRule(ctx, id)
		if err != nil {
			return err
		}
		if n == 0 {
			return apperr.New(apperr.CodeNotFound, "approver rule not found")
		}
		if _, err := svc.changed(ctx, tx); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "policy.approver_rule.deleted", Target: audit.Target{Type: "approver_rule", ID: id}})
		return err
	})
}

// GetApproverRule returns an approver rule.
func (svc *Service) GetApproverRule(ctx context.Context, id string) (*ApproverRule, error) {
	r, err := svc.s.R().GetApproverRule(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeNotFound, "approver rule not found")
	}
	if err != nil {
		return nil, err
	}
	ar, err := approverFromRow(r)
	return &ar, err
}

// ListApproverRules returns every approver rule.
func (svc *Service) ListApproverRules(ctx context.Context) ([]ApproverRule, error) {
	return loadApprovers(ctx, svc.s.R())
}

// MaxAgentOwners bounds the owner list of one agent.
const MaxAgentOwners = 64

// SetAgentOwners replaces the owners of an agent (used by the self-approval prohibition, HP-POL-012). Every owner
// must be an existing operator; the change bumps the policy version and is audited.
func (svc *Service) SetAgentOwners(ctx context.Context, actor audit.Actor, agentID string, operatorIDs []string) error {
	operatorIDs = slices.Compact(slices.Sorted(slices.Values(operatorIDs)))
	if len(operatorIDs) > MaxAgentOwners {
		return apperr.New(apperr.CodeInvalid, "at most %d owners", MaxAgentOwners)
	}
	for _, id := range operatorIDs {
		if !ids.Valid(ids.Operator, id) {
			return apperr.New(apperr.CodeInvalid, "invalid operator id %q", id)
		}
	}
	return svc.s.W().TxNamed(ctx, "policy.set_agent_owners", func(tx *store.Tx) error {
		if _, err := tx.Q.GetAgent(ctx, agentID); errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeNotFound, "agent not found")
		} else if err != nil {
			return err
		}
		for _, op := range operatorIDs {
			if _, err := tx.Q.GetOperator(ctx, op); errors.Is(err, sql.ErrNoRows) {
				return apperr.New(apperr.CodeInvalid, "operator %q not found", op)
			} else if err != nil {
				return err
			}
		}
		previous, err := tx.Q.ListOwnersForAgent(ctx, agentID)
		if err != nil {
			return err
		}
		if err := tx.Q.DeleteAgentOwners(ctx, agentID); err != nil {
			return err
		}
		for _, op := range operatorIDs {
			if err := tx.Q.InsertAgentOwner(ctx, db.InsertAgentOwnerParams{AgentID: agentID, OperatorID: op}); err != nil {
				return err
			}
		}
		if _, err := svc.changed(ctx, tx); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "agent.owners.set", Target: audit.Target{Type: "agent", ID: agentID},
			Details: map[string]any{"owners": operatorIDs, "previous": previous}})
		return err
	})
}

// AgentOwners returns the operator IDs owning an agent (sorted).
func (svc *Service) AgentOwners(ctx context.Context, agentID string) ([]string, error) {
	if _, err := svc.s.R().GetAgent(ctx, agentID); errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeNotFound, "agent not found")
	} else if err != nil {
		return nil, err
	}
	return svc.s.R().ListOwnersForAgent(ctx, agentID)
}

// ProhibitSelfApproval reports whether agent owners are barred from approving their agents' requests (default true,
// R-09).
func (svc *Service) ProhibitSelfApproval(ctx context.Context) (bool, error) {
	st, err := svc.s.R().GetSetting(ctx, SettingProhibitSelfApproval)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return st.Value != "false", nil
}

// SetProhibitSelfApproval toggles the self-approval prohibition (HP-POL-012).
func (svc *Service) SetProhibitSelfApproval(ctx context.Context, actor audit.Actor, prohibit bool) error {
	val := "true"
	if !prohibit {
		val = "false"
	}
	return svc.s.W().TxNamed(ctx, "policy.self_approval", func(tx *store.Tx) error {
		if err := tx.Q.UpsertSetting(ctx, db.UpsertSettingParams{Key: SettingProhibitSelfApproval, Value: val, UpdatedAt: tx.NowMicros(),
			UpdatedBy: sql.NullString{String: actorRef(actor), Valid: true}}); err != nil {
			return err
		}
		if _, err := svc.changed(ctx, tx); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "policy.self_approval.set", Details: map[string]any{"prohibit": prohibit}})
		return err
	})
}

// Access is one row of an effective-access preview.
type Access struct {
	AgentID     string   `json:"agent_id"`
	AgentName   string   `json:"agent_name"`
	ServerID    string   `json:"server_id"`
	ServerAlias string   `json:"server_alias"`
	RoleID      string   `json:"role_id"`
	RoleAlias   string   `json:"role_alias"`
	Decision    Decision `json:"decision"`
}

// PreviewAgent returns the decision for every server×role for one agent, including denied ones with the
// deciding rule, so operators can see why (HP-POL-009).
func PreviewAgent(s *Snapshot, agentID string) []Access {
	a := s.Agent(agentID)
	if a == nil {
		return nil
	}
	var out []Access
	for _, srv := range sortedServers(s) {
		for _, r := range s.rolesOf[srv.ID] {
			out = append(out, Access{AgentID: a.ID, AgentName: a.Name, ServerID: srv.ID, ServerAlias: srv.Alias, RoleID: r.ID, RoleAlias: r.Name,
				Decision: s.Evaluate(a.ID, srv.ID, r.ID)})
		}
	}
	return out
}

// PreviewServer returns, for one server, every agent×role decision that is at least visible or explicitly denied.
func PreviewServer(s *Snapshot, serverID string) []Access {
	srv := s.Server(serverID)
	if srv == nil {
		return nil
	}
	agentIDs := make([]string, 0, len(s.agents))
	for id := range s.agents {
		agentIDs = append(agentIDs, id)
	}
	slices.SortFunc(agentIDs, func(x, y string) int { return compare(s.agents[x].Name, s.agents[y].Name) })
	var out []Access
	for _, aid := range agentIDs {
		for _, r := range s.rolesOf[serverID] {
			d := s.Evaluate(aid, serverID, r.ID)
			if d.Visible() || d.DecidingRule != "" {
				out = append(out, Access{AgentID: aid, AgentName: s.agents[aid].Name, ServerID: serverID, ServerAlias: srv.Alias,
					RoleID: r.ID, RoleAlias: r.Name, Decision: d})
			}
		}
	}
	return out
}

func sortedServers(s *Snapshot) []*ServerInfo {
	out := make([]*ServerInfo, 0, len(s.servers))
	for _, srv := range s.servers {
		out = append(out, srv)
	}
	slices.SortFunc(out, func(a, b *ServerInfo) int { return compare(a.Alias, b.Alias) })
	return out
}

func compare(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func actorRef(a audit.Actor) string {
	if a.ID == "" {
		return a.Type
	}
	return a.Type + ":" + a.ID
}

// PreviewChange compiles a what-if snapshot of the current state with one rule change applied, without saving it
// (HP-POL-009): proposed replaces the rule with the same ID, or is added when its ID is empty or unknown;
// removeID drops a rule. The proposed rule is normalized and validated like a saved one.
func (svc *Service) PreviewChange(ctx context.Context, proposed *Rule, removeID string) (*Snapshot, error) {
	rules, err := svc.ListRules(ctx)
	if err != nil {
		return nil, err
	}
	approvers, err := svc.ListApproverRules(ctx)
	if err != nil {
		return nil, err
	}
	if proposed != nil {
		normalizeRule(proposed)
		if err := proposed.Validate(svc.engine.globalMax); err != nil {
			return nil, err
		}
	}
	out := make([]Rule, 0, len(rules)+1)
	replaced := false
	for _, r := range rules {
		switch {
		case removeID != "" && r.ID == removeID:
		case proposed != nil && proposed.ID != "" && r.ID == proposed.ID:
			replaced = true
			out = append(out, *proposed)
		default:
			out = append(out, r)
		}
	}
	if proposed != nil && !replaced {
		p := *proposed
		if p.ID == "" {
			p.ID = "pol_preview"
		}
		out = append(out, p)
	}
	return svc.engine.WhatIf(ctx, Override{Rules: out, Approvers: approvers})
}
