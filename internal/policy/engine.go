package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/groups"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// SettingProhibitSelfApproval is the settings key for the self-approval prohibition (default: prohibited, R-09).
const SettingProhibitSelfApproval = "policy.prohibit_self_approval"

// Engine serves compiled snapshots, rebuilding when policy_version changes (HP-POL-007).
type Engine struct {
	s         *store.Store
	globalMax time.Duration
	presets   []time.Duration

	mu  sync.Mutex
	cur *Snapshot
}

// NewEngine returns an engine.
func NewEngine(s *store.Store, globalMax time.Duration, presets []time.Duration) *Engine {
	return &Engine{s: s, globalMax: globalMax, presets: presets}
}

// GlobalMax returns the global grant ceiling.
func (e *Engine) GlobalMax() time.Duration { return e.globalMax }

// Current returns the snapshot for the current policy version.
func (e *Engine) Current(ctx context.Context) (*Snapshot, error) {
	ps, err := e.s.R().GetPolicyState(ctx)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cur != nil && e.cur.Version == ps.Version && e.cur.Lockdown == (ps.Lockdown == 1) {
		return e.cur, nil
	}
	snap, err := e.load(ctx, nil)
	if err != nil {
		return nil, err
	}
	e.cur = snap
	return snap, nil
}

// Override replaces rules for what-if previews.
type Override struct {
	Rules     []Rule
	Approvers []ApproverRule
}

// WhatIf compiles a snapshot of the current state with the given rule sets instead of the stored ones (HP-POL-009).
func (e *Engine) WhatIf(ctx context.Context, o Override) (*Snapshot, error) { return e.load(ctx, &o) }

// SnapshotAt loads a snapshot inside a write transaction (decision-time checks read their own transaction's view).
func (e *Engine) SnapshotAt(ctx context.Context, q *db.Queries) (*Snapshot, error) {
	d, err := e.loadData(ctx, q, nil)
	if err != nil {
		return nil, err
	}
	return Compile(*d), nil
}

func (e *Engine) load(ctx context.Context, o *Override) (*Snapshot, error) {
	var d *Data
	err := e.s.ReadTx(ctx, func(q *db.Queries) error {
		var err error
		d, err = e.loadData(ctx, q, o)
		return err
	})
	if err != nil {
		return nil, err
	}
	return Compile(*d), nil
}

func (e *Engine) loadData(ctx context.Context, q *db.Queries, o *Override) (*Data, error) {
	ps, err := q.GetPolicyState(ctx)
	if err != nil {
		return nil, err
	}
	d := &Data{Version: ps.Version, Lockdown: ps.Lockdown == 1, Settings: Settings{
		MaxGrantDuration: e.globalMax, DurationPresets: e.presets, ProhibitSelfApproval: true,
	}}
	if st, err := q.GetSetting(ctx, SettingProhibitSelfApproval); err == nil {
		d.Settings.ProhibitSelfApproval = st.Value != "false"
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if o != nil {
		d.Rules, d.Approvers = o.Rules, o.Approvers
	} else {
		if d.Rules, err = loadRules(ctx, q); err != nil {
			return nil, err
		}
		if d.Approvers, err = loadApprovers(ctx, q); err != nil {
			return nil, err
		}
	}
	if err := loadAgents(ctx, q, d); err != nil {
		return nil, err
	}
	if err := loadServers(ctx, q, d); err != nil {
		return nil, err
	}
	return d, loadRoles(ctx, q, d)
}

func loadRules(ctx context.Context, q *db.Queries) ([]Rule, error) {
	rows, err := q.ListPolicyRules(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Rule, 0, len(rows))
	for _, r := range rows {
		rule, err := ruleFromRow(r)
		if err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, nil
}

func ruleFromRow(r db.PolicyRule) (Rule, error) {
	rule := Rule{
		ID: r.ID, Name: r.Name, Description: r.Description, Effect: r.Effect, Level: r.Level.String,
		MaxDuration: time.Duration(r.MaxDurationS.Int64) * time.Second, AutoMaxDuration: time.Duration(r.AutoMaxDurationS.Int64) * time.Second,
		RequireReason: r.RequireReason == 1, Enabled: r.Enabled == 1, Version: r.Version,
	}
	if err := json.Unmarshal([]byte(r.SubjectsJson), &rule.Subjects); err != nil {
		return rule, err
	}
	if err := json.Unmarshal([]byte(r.TargetsJson), &rule.Targets); err != nil {
		return rule, err
	}
	return rule, json.Unmarshal([]byte(r.RolesJson), &rule.Roles)
}

func loadApprovers(ctx context.Context, q *db.Queries) ([]ApproverRule, error) {
	rows, err := q.ListApproverRules(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ApproverRule, 0, len(rows))
	for _, r := range rows {
		ar, err := approverFromRow(r)
		if err != nil {
			return nil, err
		}
		out = append(out, ar)
	}
	return out, nil
}

func approverFromRow(r db.ApproverRule) (ApproverRule, error) {
	ar := ApproverRule{ID: r.ID, Name: r.Name, Description: r.Description, MaxDuration: time.Duration(r.MaxDurationS.Int64) * time.Second,
		Enabled: r.Enabled == 1, Version: r.Version}
	if err := json.Unmarshal([]byte(r.OperatorsJson), &ar.Operators); err != nil {
		return ar, err
	}
	if err := json.Unmarshal([]byte(r.TargetsJson), &ar.Targets); err != nil {
		return ar, err
	}
	return ar, json.Unmarshal([]byte(r.RolesJson), &ar.Roles)
}

func loadAgents(ctx context.Context, q *db.Queries, d *Data) error {
	rows, err := q.ListAgents(ctx)
	if err != nil {
		return err
	}
	gs, err := q.ListAllAgentGroups(ctx)
	if err != nil {
		return err
	}
	byAgent := map[string][]string{}
	for _, g := range gs {
		byAgent[g.AgentID] = append(byAgent[g.AgentID], g.Name)
	}
	labels, err := groups.AllLabels(ctx, q, groups.EntityAgent)
	if err != nil {
		return err
	}
	owners, err := q.ListAgentOwners(ctx)
	if err != nil {
		return err
	}
	byOwner := map[string][]string{}
	for _, o := range owners {
		byOwner[o.AgentID] = append(byOwner[o.AgentID], o.OperatorID)
	}
	for _, r := range rows {
		d.Agents = append(d.Agents, AgentInfo{
			Object:  Object{ID: r.ID, Name: r.Name, Groups: byAgent[r.ID], Labels: labels[r.ID]},
			Enabled: r.Enabled == 1, Owners: byOwner[r.ID],
		})
	}
	return nil
}

func loadServers(ctx context.Context, q *db.Queries, d *Data) error {
	rows, err := q.ListServers(ctx)
	if err != nil {
		return err
	}
	gs, err := q.ListAllServerGroups(ctx)
	if err != nil {
		return err
	}
	byServer := map[string][]string{}
	for _, g := range gs {
		byServer[g.ServerID] = append(byServer[g.ServerID], g.Name)
	}
	labels, err := groups.AllLabels(ctx, q, groups.EntityServer)
	if err != nil {
		return err
	}
	for _, r := range rows {
		d.Servers = append(d.Servers, ServerInfo{
			Object: Object{ID: r.ID, Name: r.Alias, Groups: byServer[r.ID], Labels: labels[r.ID]},
			Alias:  r.Alias, Description: r.Description, Enabled: r.Enabled == 1,
		})
	}
	return nil
}

func loadRoles(ctx context.Context, q *db.Queries, d *Data) error {
	rows, err := q.ListAllRoles(ctx)
	if err != nil {
		return err
	}
	labels, err := groups.AllLabels(ctx, q, groups.EntityRole)
	if err != nil {
		return err
	}
	for _, r := range rows {
		role := inventory.RoleFromRow(r)
		d.Roles = append(d.Roles, RoleInfo{
			Object:   Object{ID: r.ID, Name: r.Alias, Labels: labels[r.ID]},
			ServerID: r.ServerID, Description: r.Description, Capabilities: role.Capabilities,
			DefaultDuration: role.DefaultDuration, MaxDuration: role.MaxDuration, ApprovalChannels: role.ApprovalChannels,
			Enabled: role.Enabled,
		})
	}
	return nil
}
