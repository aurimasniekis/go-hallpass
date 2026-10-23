package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"time"
)

var presets = []time.Duration{5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour, 3 * time.Hour, 6 * time.Hour, 24 * time.Hour}

func world() Data {
	return Data{
		Version:  7,
		Settings: Settings{MaxGrantDuration: 24 * time.Hour, DurationPresets: presets, ProhibitSelfApproval: true},
		Agents: []AgentInfo{
			{Object: Object{ID: "agt_sre", Name: "sre-bot", Groups: []string{"sre"}, Labels: map[string]string{"team": "sre", "env": "prod"}}, Enabled: true, Owners: []string{"opr_owner"}},
			{Object: Object{ID: "agt_dev", Name: "dev-bot", Groups: []string{"dev"}, Labels: map[string]string{"team": "dev"}}, Enabled: true},
			{Object: Object{ID: "agt_off", Name: "off-bot", Groups: []string{"sre"}}, Enabled: false},
		},
		Servers: []ServerInfo{
			{Object: Object{ID: "srv_web", Groups: []string{"prod-web"}, Labels: map[string]string{"tier": "web"}}, Alias: "web1", Enabled: true},
			{Object: Object{ID: "srv_db", Groups: []string{"prod-db"}, Labels: map[string]string{"tier": "db"}}, Alias: "db1", Enabled: true},
			{Object: Object{ID: "srv_off", Groups: []string{"prod-web"}}, Alias: "old1", Enabled: false},
		},
		Roles: []RoleInfo{
			{Object: Object{ID: "rol_web_inspect", Name: "inspect", Labels: map[string]string{"class": "readonly"}}, ServerID: "srv_web", DefaultDuration: 30 * time.Minute, MaxDuration: 6 * time.Hour, Enabled: true},
			{Object: Object{ID: "rol_web_deploy", Name: "deploy"}, ServerID: "srv_web", DefaultDuration: time.Hour, MaxDuration: 3 * time.Hour, Enabled: true},
			{Object: Object{ID: "rol_db_inspect", Name: "inspect", Labels: map[string]string{"class": "readonly"}}, ServerID: "srv_db", DefaultDuration: 30 * time.Minute, MaxDuration: 24 * time.Hour, Enabled: true},
			{Object: Object{ID: "rol_db_admin", Name: "admin-x"}, ServerID: "srv_db", DefaultDuration: 15 * time.Minute, MaxDuration: time.Hour, Enabled: false},
			{Object: Object{ID: "rol_off", Name: "inspect"}, ServerID: "srv_off", DefaultDuration: 15 * time.Minute, MaxDuration: time.Hour, Enabled: true},
		},
	}
}

func allow(id, level string, subj SubjectSelector, tgt TargetSelector, roles RoleSelector) Rule {
	return Rule{ID: id, Name: id, Effect: EffectAllow, Level: level, Subjects: subj, Targets: tgt, Roles: roles, RequireReason: true, Enabled: true}
}

// HP-POL-001: default deny.
func TestDefaultDeny(t *testing.T) {
	s := Compile(world())
	if d := s.Evaluate("agt_sre", "srv_web", "rol_web_inspect"); !d.Denied || d.Visible() {
		t.Fatalf("%+v", d)
	}
	if len(s.Visible("agt_sre")) != 0 {
		t.Fatal("something visible without rules")
	}
}

// HP-POL-002/004/005: levels, deny override, union of groups, disabled objects invisible.
func TestLevelsAndDeny(t *testing.T) {
	d := world()
	d.Rules = []Rule{
		allow("r-vis", LevelVisible, SubjectSelector{AgentGroups: []string{"sre"}}, TargetSelector{All: true}, RoleSelector{All: true}),
		allow("r-req", LevelRequestable, SubjectSelector{AgentLabels: &LabelSelector{MatchLabels: map[string]string{"team": "sre"}}},
			TargetSelector{ServerGroups: []string{"prod-web"}}, RoleSelector{RoleLabels: &LabelSelector{MatchLabels: map[string]string{"class": "readonly"}}}),
		{ID: "r-deny", Name: "r-deny", Effect: EffectDeny, Subjects: SubjectSelector{Agents: []string{"agt_sre"}}, Targets: TargetSelector{Servers: []string{"srv_db"}}, Roles: RoleSelector{All: true}, Enabled: true},
		{ID: "r-disabled", Name: "x", Effect: EffectDeny, Subjects: SubjectSelector{All: true}, Targets: TargetSelector{All: true}, Roles: RoleSelector{All: true}, Enabled: false},
	}
	s := Compile(d)
	if got := s.Evaluate("agt_sre", "srv_web", "rol_web_inspect"); got.Level != LevelRequestable || got.DecidingRule != "r-req" || len(got.MatchedRules) != 2 {
		t.Fatalf("%+v", got)
	}
	if got := s.Evaluate("agt_sre", "srv_web", "rol_web_deploy"); got.Level != LevelVisible {
		t.Fatalf("deploy: %+v", got)
	}
	if got := s.Evaluate("agt_sre", "srv_db", "rol_db_inspect"); !got.Denied || got.DecidingRule != "r-deny" {
		t.Fatalf("deny did not override: %+v", got)
	}
	if got := s.Evaluate("agt_off", "srv_web", "rol_web_inspect"); !got.Denied {
		t.Fatal("disabled agent has access")
	}
	if got := s.Evaluate("agt_sre", "srv_off", "rol_off"); !got.Denied {
		t.Fatal("disabled server visible")
	}
	if got := s.Evaluate("agt_dev", "srv_web", "rol_web_inspect"); !got.Denied {
		t.Fatal("unmatched agent visible")
	}
	if got := s.Evaluate("agt_sre", "srv_web", "rol_db_inspect"); !got.Denied {
		t.Fatal("role/server mismatch accepted")
	}
	vis := s.Visible("agt_sre")
	if len(vis) != 1 || vis[0].Server.Alias != "web1" || len(vis[0].Roles) != 2 {
		t.Fatalf("visible %+v", vis)
	}
}

// HP-POL-003: selector semantics incl. empty label selectors and expressions.
func TestSelectorSemantics(t *testing.T) {
	o := Object{ID: "x", Name: "inspect", Groups: []string{"a"}, Labels: map[string]string{"env": "prod", "team": "sre"}}
	cases := []struct {
		ls   *LabelSelector
		want bool
	}{
		{nil, false},
		{&LabelSelector{}, false},
		{&LabelSelector{MatchLabels: map[string]string{"env": "prod"}}, true},
		{&LabelSelector{MatchLabels: map[string]string{"env": "prod", "team": "dev"}}, false},
		{&LabelSelector{MatchExpressions: []Requirement{{Key: "env", Operator: OpIn, Values: []string{"prod", "stage"}}}}, true},
		{&LabelSelector{MatchExpressions: []Requirement{{Key: "env", Operator: OpNotIn, Values: []string{"prod"}}}}, false},
		{&LabelSelector{MatchExpressions: []Requirement{{Key: "missing", Operator: OpNotIn, Values: []string{"x"}}}}, true},
		{&LabelSelector{MatchExpressions: []Requirement{{Key: "team", Operator: OpExists}}}, true},
		{&LabelSelector{MatchExpressions: []Requirement{{Key: "team", Operator: OpDoesNotExist}}}, false},
		{&LabelSelector{MatchLabels: map[string]string{"env": "prod"}, MatchExpressions: []Requirement{{Key: "team", Operator: OpIn, Values: []string{"dev"}}}}, false},
		{&LabelSelector{MatchExpressions: []Requirement{{Key: "team", Operator: "Bogus"}}}, false},
	}
	for i, c := range cases {
		if got := c.ls.Matches(o.Labels); got != c.want {
			t.Errorf("case %d: got %v", i, got)
		}
	}
	if (SubjectSelector{}).Matches(o) || (TargetSelector{}).Matches(o) || (RoleSelector{}).Matches(o) || (OperatorSelector{}).Matches(o) {
		t.Fatal("empty selector matched")
	}
	if !(SubjectSelector{AgentGroups: []string{"z", "a"}}).Matches(o) || !(RoleSelector{Names: []string{"inspect"}}).Matches(o) {
		t.Fatal("union semantics broken")
	}
}

// HP-POL-003: all: true includes objects created after the rule.
func TestAllIncludesFutureObjects(t *testing.T) {
	d := world()
	d.Rules = []Rule{allow("r", LevelRequestable, SubjectSelector{All: true}, TargetSelector{All: true}, RoleSelector{All: true})}
	d.Servers = append(d.Servers, ServerInfo{Object: Object{ID: "srv_new"}, Alias: "new1", Enabled: true})
	d.Roles = append(d.Roles, RoleInfo{Object: Object{ID: "rol_new", Name: "inspect"}, ServerID: "srv_new", DefaultDuration: time.Minute * 30, MaxDuration: time.Hour, Enabled: true})
	if got := Compile(d).Evaluate("agt_dev", "srv_new", "rol_new"); got.Level != LevelRequestable {
		t.Fatalf("%+v", got)
	}
}

// Durations: role max, global max, rule max; presets; auto-approve only within the auto max (HP-POL-013).
func TestDurations(t *testing.T) {
	d := world()
	r1 := allow("r1", LevelRequestable, SubjectSelector{All: true}, TargetSelector{All: true}, RoleSelector{All: true})
	r1.MaxDuration = 3 * time.Hour
	r2 := allow("r2", LevelAutoApprove, SubjectSelector{Agents: []string{"agt_sre"}}, TargetSelector{Servers: []string{"srv_db"}}, RoleSelector{All: true})
	r2.AutoMaxDuration, r2.RequireReason = 15*time.Minute, false
	r3 := allow("r3", LevelAutoApprove, SubjectSelector{All: true}, TargetSelector{Servers: []string{"srv_db"}}, RoleSelector{All: true})
	r3.AutoMaxDuration = time.Hour
	d.Rules = []Rule{r1, r2, r3}
	s := Compile(d)
	got := s.Evaluate("agt_sre", "srv_db", "rol_db_inspect")
	if got.Level != LevelAutoApprove || got.MaxDuration != 3*time.Hour || got.AutoMaxDuration != 15*time.Minute {
		t.Fatalf("%+v", got)
	}
	if !got.AutoApproves(15*time.Minute) || got.AutoApproves(30*time.Minute) {
		t.Fatal("auto-approval bounds wrong: longer requests must need a human")
	}
	if !got.RequireReason {
		t.Fatal("reason requirement must hold if any matching rule requires it")
	}
	if !slices.Equal(got.AllowedDurations, presets[:5]) || got.DurationAllowed(6*time.Hour) {
		t.Fatalf("allowed %v", got.AllowedDurations)
	}
	if def := s.DefaultDuration("rol_db_inspect", got); def != 15*time.Minute {
		t.Fatalf("default duration %s", def)
	}
	web := s.Evaluate("agt_sre", "srv_web", "rol_web_deploy")
	if web.MaxDuration != 3*time.Hour || web.Level != LevelRequestable {
		t.Fatalf("%+v", web)
	}
}

// HP-POL-010: every not-visible case yields the identical error.
func TestResolveNonDisclosure(t *testing.T) {
	d := world()
	d.Rules = []Rule{allow("r", LevelRequestable, SubjectSelector{All: true}, TargetSelector{Servers: []string{"srv_web"}}, RoleSelector{Names: []string{"inspect"}})}
	s := Compile(d)
	if _, r, err := s.ResolveRole("agt_dev", "web1", "inspect"); err != nil || r.Role.ID != "rol_web_inspect" {
		t.Fatal(err)
	}
	for _, c := range [][2]string{{"nope", "inspect"}, {"db1", "inspect"}, {"old1", "inspect"}, {"web1", "deploy"}, {"web1", "nope"}} {
		if _, _, err := s.ResolveRole("agt_dev", c[0], c[1]); !errors.Is(err, ErrNotFoundOrForbidden) {
			t.Errorf("%v: %v", c, err)
		}
	}
	if _, err := s.ResolveServer("agt_off", "web1"); !errors.Is(err, ErrNotFoundOrForbidden) {
		t.Fatal("disabled agent resolved a server")
	}
	d.Lockdown = true
	if _, err := Compile(d).ResolveServer("agt_dev", "web1"); !errors.Is(err, ErrNotFoundOrForbidden) {
		t.Fatal("lockdown must hide everything")
	}
}

// HP-POL-011/012: approver authority.
func TestCanApprove(t *testing.T) {
	d := world()
	d.Approvers = []ApproverRule{
		{ID: "a1", Name: "a1", Operators: OperatorSelector{OperatorGroups: []string{"oncall"}}, Targets: TargetSelector{ServerGroups: []string{"prod-web"}}, Roles: RoleSelector{All: true}, MaxDuration: time.Hour, Enabled: true},
		{ID: "a2", Name: "a2", Operators: OperatorSelector{Operators: []string{"opr_owner"}}, Targets: TargetSelector{All: true}, Roles: RoleSelector{All: true}, Enabled: true},
	}
	s := Compile(d)
	approver := OperatorInfo{ID: "opr_a", Roles: []string{"approver"}, Groups: []string{"oncall"}, Enabled: true}
	if c := s.CanApprove(approver, "agt_sre", "srv_web", "rol_web_inspect", 30*time.Minute); !c.Allowed || c.RuleID != "a1" {
		t.Fatalf("%+v", c)
	}
	if c := s.CanApprove(approver, "agt_sre", "srv_web", "rol_web_inspect", 3*time.Hour); c.Allowed {
		t.Fatal("approver max duration ignored")
	}
	if c := s.CanApprove(approver, "agt_sre", "srv_db", "rol_db_inspect", time.Minute); c.Allowed {
		t.Fatal("out-of-scope approval allowed")
	}
	viewer := approver
	viewer.Roles = []string{"viewer"}
	if s.CanApprove(viewer, "agt_sre", "srv_web", "rol_web_inspect", time.Minute).Allowed {
		t.Fatal("viewer approved")
	}
	owner := OperatorInfo{ID: "opr_owner", Roles: []string{"administrator"}, Enabled: true}
	if c := s.CanApprove(owner, "agt_sre", "srv_web", "rol_web_inspect", time.Minute); c.Allowed {
		t.Fatal("self-approval allowed while prohibited")
	}
	if !s.CanApprove(owner, "agt_dev", "srv_web", "rol_web_inspect", time.Minute).Allowed {
		t.Fatal("owner of another agent blocked")
	}
	noRule := OperatorInfo{ID: "opr_admin", Roles: []string{"administrator"}, Enabled: true}
	if s.CanApprove(noRule, "agt_dev", "srv_web", "rol_web_inspect", time.Minute).Allowed {
		t.Fatal("administrators must also need an approver rule (ADR-0008)")
	}
	d.Settings.ProhibitSelfApproval = false
	if !Compile(d).CanApprove(owner, "agt_sre", "srv_web", "rol_web_inspect", time.Minute).Allowed {
		t.Fatal("self-approval setting ignored")
	}
}

// randomWorld builds a random but valid world for property tests.
func randomWorld(rng *rand.Rand) Data {
	d := Data{Settings: Settings{MaxGrantDuration: 24 * time.Hour, DurationPresets: presets}}
	grps := []string{"a", "b", "c"}
	pick := func() []string {
		var out []string
		for _, g := range grps {
			if rng.IntN(2) == 0 {
				out = append(out, g)
			}
		}
		return out
	}
	lab := func() map[string]string { return map[string]string{"k": grps[rng.IntN(3)]} }
	for i := range 6 {
		d.Agents = append(d.Agents, AgentInfo{Object: Object{ID: fmt.Sprintf("agt_%d", i), Groups: pick(), Labels: lab()}, Enabled: rng.IntN(5) > 0})
	}
	for i := range 5 {
		id := fmt.Sprintf("srv_%d", i)
		d.Servers = append(d.Servers, ServerInfo{Object: Object{ID: id, Groups: pick(), Labels: lab()}, Alias: fmt.Sprintf("s%d", i), Enabled: rng.IntN(5) > 0})
		for j := range 2 {
			d.Roles = append(d.Roles, RoleInfo{Object: Object{ID: fmt.Sprintf("rol_%d_%d", i, j), Name: []string{"inspect", "deploy"}[j], Labels: lab()},
				ServerID: id, DefaultDuration: 30 * time.Minute, MaxDuration: 6 * time.Hour, Enabled: rng.IntN(5) > 0})
		}
	}
	for i := range rng.IntN(6) {
		d.Rules = append(d.Rules, randomRule(rng, fmt.Sprintf("r%d", i), grps))
	}
	return d
}

func randomRule(rng *rand.Rand, id string, grps []string) Rule {
	levels := []string{LevelVisible, LevelRequestable, LevelAutoApprove}
	r := Rule{ID: id, Name: id, Effect: EffectAllow, Level: levels[rng.IntN(3)], Enabled: true}
	if rng.IntN(5) == 0 {
		r.Effect, r.Level = EffectDeny, ""
	}
	if r.Level == LevelAutoApprove {
		r.AutoMaxDuration = 15 * time.Minute
	}
	switch rng.IntN(3) {
	case 0:
		r.Subjects.All = true
	case 1:
		r.Subjects.AgentGroups = []string{grps[rng.IntN(3)]}
	default:
		r.Subjects.AgentLabels = &LabelSelector{MatchLabels: map[string]string{"k": grps[rng.IntN(3)]}}
	}
	switch rng.IntN(3) {
	case 0:
		r.Targets.All = true
	case 1:
		r.Targets.ServerGroups = []string{grps[rng.IntN(3)]}
	default:
		r.Targets.ServerLabels = &LabelSelector{MatchExpressions: []Requirement{{Key: "k", Operator: OpIn, Values: []string{grps[rng.IntN(3)]}}}}
	}
	if rng.IntN(2) == 0 {
		r.Roles.All = true
	} else {
		r.Roles.Names = []string{"inspect"}
	}
	return r
}

func forAll(d Data, fn func(a, s, r string)) {
	for _, a := range d.Agents {
		for _, rl := range d.Roles {
			fn(a.ID, rl.ServerID, rl.ID)
		}
	}
}

// Property: a matching deny rule always denies; adding an allow rule never lowers any level.
func TestPolicyProperties(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewPCG(seed, 42))
	for range 300 {
		d := randomWorld(rng)
		base := Compile(d)
		extra := randomRule(rng, "extra", []string{"a", "b", "c"})
		d2 := d
		d2.Rules = append(slices.Clone(d.Rules), extra)
		after := Compile(d2)
		forAll(d, func(a, s, r string) {
			before, now := base.Evaluate(a, s, r), after.Evaluate(a, s, r)
			if extra.Effect == EffectAllow && !now.Denied && levelRank[now.Level] < levelRank[before.Level] {
				t.Fatalf("adding an allow lowered %s/%s/%s: %v → %v", a, s, r, before.Level, now.Level)
			}
			if extra.Effect == EffectAllow && before.Denied && before.DecidingRule != "" && !now.Denied {
				t.Fatalf("allow overrode a deny for %s/%s/%s", a, s, r)
			}
			ag, sv, rl := after.agents[a], after.servers[s], after.roles[r]
			if extra.Effect == EffectDeny && extra.Subjects.Matches(ag.Object) && extra.Targets.Matches(sv.Object) && extra.Roles.Matches(rl.Object) && !now.Denied {
				t.Fatalf("matching deny did not deny %s/%s/%s", a, s, r)
			}
			if now.Visible() && (!ag.Enabled || !sv.Enabled || !rl.Enabled) {
				t.Fatal("disabled object visible")
			}
			if now.Requestable() && (now.MaxDuration <= 0 || now.MaxDuration > 6*time.Hour) {
				t.Fatalf("max duration out of bounds: %s", now.MaxDuration)
			}
		})
	}
}

func FuzzRuleJSON(f *testing.F) {
	seed, _ := json.Marshal(allow("r", LevelRequestable, SubjectSelector{AgentGroups: []string{"sre"}}, TargetSelector{All: true},
		RoleSelector{RoleLabels: &LabelSelector{MatchExpressions: []Requirement{{Key: "class", Operator: OpIn, Values: []string{"ro"}}}}}))
	f.Add(seed)
	f.Add([]byte(`{"effect":"deny","subjects":{"all":true},"targets":{},"roles":{"names":["x"]}}`))
	w := world()
	f.Fuzz(func(t *testing.T, data []byte) {
		var r Rule
		if json.Unmarshal(data, &r) != nil {
			return
		}
		r.Enabled = true
		valid := r.Validate(24*time.Hour) == nil
		d := w
		d.Rules = []Rule{r}
		s := Compile(d)
		forAll(d, func(a, sv, rl string) {
			dec := s.Evaluate(a, sv, rl)
			if !valid && (r.Subjects.Empty() || r.Targets.Empty() || r.Roles.Empty()) && dec.Visible() {
				t.Fatal("rule with an empty selector granted access")
			}
		})
	})
}

func BenchmarkEvaluateVisible(b *testing.B) {
	d := Data{Settings: Settings{MaxGrantDuration: 24 * time.Hour, DurationPresets: presets}}
	d.Agents = []AgentInfo{{Object: Object{ID: "agt_x", Groups: []string{"g1"}, Labels: map[string]string{"team": "sre"}}, Enabled: true}}
	for i := range 2000 {
		id := fmt.Sprintf("srv_%d", i)
		d.Servers = append(d.Servers, ServerInfo{Object: Object{ID: id, Groups: []string{fmt.Sprintf("g%d", i%50)}, Labels: map[string]string{"tier": fmt.Sprint(i % 7)}}, Alias: fmt.Sprintf("s%04d", i), Enabled: true})
		for j := range 3 {
			d.Roles = append(d.Roles, RoleInfo{Object: Object{ID: fmt.Sprintf("rol_%d_%d", i, j), Name: fmt.Sprintf("r%d", j)}, ServerID: id, DefaultDuration: time.Hour, MaxDuration: 6 * time.Hour, Enabled: true})
		}
	}
	for i := range 100 {
		d.Rules = append(d.Rules, allow(fmt.Sprintf("r%d", i), LevelRequestable, SubjectSelector{AgentGroups: []string{fmt.Sprintf("g%d", i%5)}},
			TargetSelector{ServerGroups: []string{fmt.Sprintf("g%d", i%50)}}, RoleSelector{All: true}))
	}
	s := Compile(d)
	b.Run("evaluate", func(b *testing.B) {
		for b.Loop() {
			s.Evaluate("agt_x", "srv_10", "rol_10_1")
		}
	})
	b.Run("visible-2000-servers", func(b *testing.B) {
		for b.Loop() {
			s.Visible("agt_x")
		}
	})
}
