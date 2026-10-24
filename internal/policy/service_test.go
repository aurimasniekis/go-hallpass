package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/egress"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/keyring/keyringtest"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
)

var admin = audit.Actor{Type: audit.ActorOperator, ID: "opr_admin"}

type fixture struct {
	s      *store.Store
	svc    *Service
	agents *agents.Service
	inv    *inventory.Service
	bus    *eventbus.Bus
	agent  *agents.Agent
	srv    *inventory.Server
	role   *inventory.Role
}

func ptr[T any](v T) *T { return &v }

func setup(t *testing.T) *fixture {
	t.Helper()
	s := storetest.Open(t)
	kr := keyringtest.Load(t, s)
	aw := audit.NewWriter(kr)
	bus := eventbus.New()
	g, _ := egress.New([]string{"10.0.0.0/8"}, nil, nil, time.Second)
	f := &fixture{s: s, bus: bus, agents: agents.New(s, kr, aw, bus, nil),
		inv: inventory.New(s, aw, bus, inventory.Options{Guard: g, MaxGrantDuration: 24 * time.Hour})}
	f.svc = NewService(s, aw, bus, NewEngine(s, 24*time.Hour, presets))
	ctx := context.Background()
	var err error
	if f.agent, err = f.agents.Create(ctx, admin, agents.CreateInput{Name: "sre-bot", Groups: []string{"sre"}}); err != nil {
		t.Fatal(err)
	}
	if f.srv, err = f.inv.CreateServer(ctx, admin, inventory.ServerInput{Alias: ptr("web1"), Address: ptr("10.0.0.1"), Groups: ptr([]string{"prod"})}); err != nil {
		t.Fatal(err)
	}
	if f.role, err = f.inv.CreateRole(ctx, admin, f.srv.ID, inventory.RoleInput{Alias: ptr("inspect"), RemoteUser: ptr("ro")}); err != nil {
		t.Fatal(err)
	}
	return f
}

func sreRule() Rule {
	return Rule{Name: "sre-inspect", Effect: EffectAllow, Level: LevelRequestable, RequireReason: true, Enabled: true,
		Subjects: SubjectSelector{AgentGroups: []string{"sre"}}, Targets: TargetSelector{ServerGroups: []string{"prod"}}, Roles: RoleSelector{Names: []string{"inspect"}}}
}

func TestRuleCRUDAndEngine(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	sub := f.bus.Subscribe(10, eventbus.TopicPolicyChanged)
	snap0, err := f.svc.Engine().Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d := snap0.Evaluate(f.agent.ID, f.srv.ID, f.role.ID); !d.Denied {
		t.Fatal("default deny violated")
	}
	r, err := f.svc.CreateRule(ctx, admin, sreRule())
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.C) != 1 {
		t.Fatal("policy.changed not published")
	}
	snap1, _ := f.svc.Engine().Current(ctx)
	if snap1.Version <= snap0.Version {
		t.Fatal("policy version not bumped")
	}
	if d := snap1.Evaluate(f.agent.ID, f.srv.ID, f.role.ID); d.Level != LevelRequestable || d.DecidingRule != r.ID {
		t.Fatalf("%+v", d)
	}
	if again, _ := f.svc.Engine().Current(ctx); again != snap1 {
		t.Fatal("snapshot not cached for an unchanged version")
	}
	if _, err := f.svc.CreateRule(ctx, admin, sreRule()); !errors.Is(err, apperr.ErrAlreadyExists) {
		t.Fatal(err)
	}
	upd := *r
	upd.Effect, upd.Level = EffectDeny, ""
	if _, err := f.svc.UpdateRule(ctx, admin, r.ID, upd); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.UpdateRule(ctx, admin, r.ID, upd); !errors.Is(err, apperr.ErrConflict) {
		t.Fatalf("stale version accepted: %v", err)
	}
	snap2, _ := f.svc.Engine().Current(ctx)
	if d := snap2.Evaluate(f.agent.ID, f.srv.ID, f.role.ID); !d.Denied || d.DecidingRule != r.ID {
		t.Fatalf("%+v", d)
	}
	rules, _ := f.svc.ListRules(ctx)
	if len(rules) != 1 || rules[0].Effect != EffectDeny {
		t.Fatalf("%+v", rules)
	}
	if err := f.svc.DeleteRule(ctx, admin, r.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.DeleteRule(ctx, admin, r.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatal(err)
	}
	if res, err := audit.Verify(ctx, f.s.R()); err != nil || !res.OK {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestRuleValidation(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	bad := []Rule{
		{Name: "empty", Effect: EffectAllow, Level: LevelVisible, Enabled: true},
		{Name: "level", Effect: EffectAllow, Level: "bogus", Subjects: SubjectSelector{All: true}, Targets: TargetSelector{All: true}, Roles: RoleSelector{All: true}},
		{Name: "deny-level", Effect: EffectDeny, Level: LevelVisible, Subjects: SubjectSelector{All: true}, Targets: TargetSelector{All: true}, Roles: RoleSelector{All: true}},
		{Name: "auto-no-max", Effect: EffectAllow, Level: LevelAutoApprove, Subjects: SubjectSelector{All: true}, Targets: TargetSelector{All: true}, Roles: RoleSelector{All: true}},
		{Name: "too-long", Effect: EffectAllow, Level: LevelVisible, MaxDuration: 48 * time.Hour, Subjects: SubjectSelector{All: true}, Targets: TargetSelector{All: true}, Roles: RoleSelector{All: true}},
		{Name: "bad-id", Effect: EffectAllow, Level: LevelVisible, Subjects: SubjectSelector{Agents: []string{"nope"}}, Targets: TargetSelector{All: true}, Roles: RoleSelector{All: true}},
		{Name: "bad-op", Effect: EffectAllow, Level: LevelVisible, Subjects: SubjectSelector{AgentLabels: &LabelSelector{MatchExpressions: []Requirement{{Key: "a", Operator: "Gt"}}}}, Targets: TargetSelector{All: true}, Roles: RoleSelector{All: true}},
		{Name: "empty-labels", Effect: EffectAllow, Level: LevelVisible, Subjects: SubjectSelector{AgentLabels: &LabelSelector{}}, Targets: TargetSelector{All: true}, Roles: RoleSelector{All: true}},
	}
	for _, r := range bad {
		if _, err := f.svc.CreateRule(ctx, admin, r); !errors.Is(err, apperr.ErrInvalid) {
			t.Errorf("%s accepted: %v", r.Name, err)
		}
	}
}

// HP-POL-007: membership and inventory changes produce a new snapshot.
func TestMembershipChangeRebuildsSnapshot(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, err := f.svc.CreateRule(ctx, admin, sreRule()); err != nil {
		t.Fatal(err)
	}
	snap, _ := f.svc.Engine().Current(ctx)
	if !snap.Evaluate(f.agent.ID, f.srv.ID, f.role.ID).Requestable() {
		t.Fatal("expected access")
	}
	if _, err := f.agents.Update(ctx, admin, f.agent.ID, agents.UpdateInput{Version: f.agent.Version, Groups: ptr([]string{"dev"})}); err != nil {
		t.Fatal(err)
	}
	snap2, _ := f.svc.Engine().Current(ctx)
	if snap2.Evaluate(f.agent.ID, f.srv.ID, f.role.ID).Visible() {
		t.Fatal("stale snapshot after group change")
	}
}

func TestApproverRulesOwnersAndSelfApproval(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	other := ids.New(ids.Operator)
	ar, err := f.svc.CreateApproverRule(ctx, admin, ApproverRule{Name: "oncall", Enabled: true,
		Operators: OperatorSelector{Operators: []string{other}}, Targets: TargetSelector{All: true}, Roles: RoleSelector{All: true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CreateApproverRule(ctx, admin, ApproverRule{Name: "bad", Operators: OperatorSelector{Operators: []string{"x"}}, Targets: TargetSelector{All: true}, Roles: RoleSelector{All: true}}); !errors.Is(err, apperr.ErrInvalid) {
		t.Fatal(err)
	}
	owner := insertOperator(t, f.s)
	ar.Operators = OperatorSelector{Operators: []string{owner}}
	if _, err := f.svc.UpdateApproverRule(ctx, admin, ar.ID, *ar); err != nil {
		t.Fatal(err)
	}
	op := OperatorInfo{ID: owner, Roles: []string{"approver"}, Enabled: true}
	snap, _ := f.svc.Engine().Current(ctx)
	if !snap.CanApprove(op, f.agent.ID, f.srv.ID, f.role.ID, time.Hour).Allowed {
		t.Fatal("approver rule not applied")
	}
	if err := f.svc.SetAgentOwners(ctx, admin, f.agent.ID, []string{owner}); err != nil {
		t.Fatal(err)
	}
	snap, _ = f.svc.Engine().Current(ctx)
	if snap.CanApprove(op, f.agent.ID, f.srv.ID, f.role.ID, time.Hour).Allowed {
		t.Fatal("self-approval allowed by default (R-09 proposes prohibited)")
	}
	if err := f.svc.SetProhibitSelfApproval(ctx, admin, false); err != nil {
		t.Fatal(err)
	}
	snap, _ = f.svc.Engine().Current(ctx)
	if !snap.CanApprove(op, f.agent.ID, f.srv.ID, f.role.ID, time.Hour).Allowed {
		t.Fatal("self-approval setting ignored")
	}
	if err := f.svc.SetAgentOwners(ctx, admin, f.agent.ID, []string{"bogus"}); !errors.Is(err, apperr.ErrInvalid) {
		t.Fatal(err)
	}
	list, _ := f.svc.ListApproverRules(ctx)
	if len(list) != 1 {
		t.Fatal(list)
	}
	if err := f.svc.DeleteApproverRule(ctx, admin, ar.ID); err != nil {
		t.Fatal(err)
	}
}

// HP-POL-009: effective-access preview and what-if evaluation of unsaved rules.
func TestPreviewAndWhatIf(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	snap, _ := f.svc.Engine().Current(ctx)
	rows := PreviewAgent(snap, f.agent.ID)
	if len(rows) != 1 || !rows[0].Decision.Denied {
		t.Fatalf("%+v", rows)
	}
	r := sreRule()
	r.ID = "pol_whatif"
	wi, err := f.svc.Engine().WhatIf(ctx, Override{Rules: []Rule{r}})
	if err != nil {
		t.Fatal(err)
	}
	if rows := PreviewAgent(wi, f.agent.ID); !rows[0].Decision.Requestable() || rows[0].Decision.DecidingRule != "pol_whatif" {
		t.Fatalf("%+v", rows)
	}
	if rows := PreviewServer(wi, f.srv.ID); len(rows) != 1 || rows[0].AgentName != "sre-bot" {
		t.Fatalf("%+v", rows)
	}
	if cur, _ := f.svc.Engine().Current(ctx); cur.Evaluate(f.agent.ID, f.srv.ID, f.role.ID).Visible() {
		t.Fatal("what-if leaked into the live snapshot")
	}
	if PreviewAgent(wi, "agt_missing") != nil || PreviewServer(wi, "srv_missing") != nil {
		t.Fatal("unknown preview targets returned rows")
	}
}

func TestLockdownHidesEverything(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, err := f.svc.CreateRule(ctx, admin, sreRule()); err != nil {
		t.Fatal(err)
	}
	if err := f.s.W().Tx(ctx, func(tx *store.Tx) error {
		_, err := tx.SQL.ExecContext(ctx, "UPDATE policy_state SET lockdown = 1")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	snap, _ := f.svc.Engine().Current(ctx)
	if !snap.Lockdown || snap.Evaluate(f.agent.ID, f.srv.ID, f.role.ID).Visible() {
		t.Fatal("lockdown not applied")
	}
}
