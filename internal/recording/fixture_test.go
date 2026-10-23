package recording

import (
	"context"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/egress"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/keyring/keyringtest"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshkeys"
)

var admin = audit.Actor{Type: audit.ActorOperator, ID: "opr_admin"}

type fx struct {
	t      *testing.T
	ctx    context.Context
	clk    *clock.Fake
	s      *store.Store
	kr     *keyring.Keyring
	access *access.Service
	agent  *agents.Agent
	keyID  string
	grant  *access.Grant
	conn   string
	opID   string
}

func ptr[T any](v T) *T { return &v }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// newFx builds a store with an approved grant and an open connection so channels can be registered.
func newFx(t *testing.T) *fx {
	t.Helper()
	clk := clock.NewFake(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
	s := storetest.Open(t, storetest.WithClock(clk))
	kr := keyringtest.Load(t, s)
	aw := audit.NewWriter(kr)
	bus := eventbus.New()
	g, _ := egress.New([]string{"10.0.0.0/8"}, nil, nil, time.Second)
	presets := []time.Duration{5 * time.Minute, time.Hour, 24 * time.Hour}
	ag := agents.New(s, kr, aw, bus, clk)
	inv := inventory.New(s, aw, bus, inventory.Options{Guard: g, MaxGrantDuration: 24 * time.Hour, Clock: clk})
	engine := policy.NewEngine(s, 24*time.Hour, presets)
	pol := policy.NewService(s, aw, bus, engine)
	acc := access.New(s, kr, aw, bus, engine, access.Options{Clock: clk, PendingExpiry: 30 * time.Minute})
	f := &fx{t: t, ctx: context.Background(), clk: clk, s: s, kr: kr, access: acc}

	var err error
	f.agent, err = ag.Create(f.ctx, admin, agents.CreateInput{Name: "sre-bot", Groups: []string{"sre"}, PublicKeys: []string{sshkeys.Ed25519(t).AuthorizedLine("")}})
	must(t, err)
	keys, _ := ag.Keys(f.ctx, f.agent.ID)
	f.keyID = keys[0].ID
	srv, err := inv.CreateServer(f.ctx, admin, inventory.ServerInput{Alias: ptr("web1"), Address: ptr("10.0.0.1")})
	must(t, err)
	role, err := inv.CreateRole(f.ctx, admin, srv.ID, inventory.RoleInput{Alias: ptr("inspect"), RemoteUser: ptr("ro"), MaxConcurrent: ptr(10), MaxConcurrentPerAgent: ptr(10)})
	must(t, err)
	_, err = pol.CreateRule(f.ctx, admin, policy.Rule{Name: "sre", Effect: policy.EffectAllow, Level: policy.LevelRequestable, Enabled: true,
		Subjects: policy.SubjectSelector{AgentGroups: []string{"sre"}}, Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}})
	must(t, err)
	f.opID = ids.New(ids.Operator)
	_, err = pol.CreateApproverRule(f.ctx, admin, policy.ApproverRule{Name: "oncall", Enabled: true,
		Operators: policy.OperatorSelector{Operators: []string{f.opID}}, Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}})
	must(t, err)
	req, err := acc.CreateRequest(f.ctx, access.CreateRequestInput{AgentID: f.agent.ID, KeyID: f.keyID, ServerID: srv.ID, RoleID: role.ID, Reason: "debug", Duration: time.Hour})
	must(t, err)
	dec, err := acc.Decide(f.ctx, access.DecideInput{RequestID: req.Request.ID, Approve: true, Operator: policy.OperatorInfo{ID: f.opID, Roles: []string{"approver"}, Enabled: true}, Channel: access.ChannelWeb})
	must(t, err)
	f.grant = dec.Grant
	f.conn, err = acc.OpenConnection(f.ctx, access.ConnectionInfo{AgentID: f.agent.ID, KeyID: f.keyID, ClientUser: "x", ClientVersion: "SSH-2.0-test", SourceIP: "10.9.9.9"})
	must(t, err)
	return f
}

func (f *fx) channel(kind string) *access.ChannelReg {
	f.t.Helper()
	reg, err := f.access.RegisterChannel(f.ctx, access.RegisterInput{ConnectionID: f.conn, AgentID: f.agent.ID, KeyID: f.keyID, GrantID: f.grant.ID, Kind: kind, PTY: kind == access.KindShell})
	must(f.t, err)
	return reg
}

func (f *fx) service(o Options) *Service {
	o.Clock = f.clk
	return New(f.s, f.kr, f.access.Sequencer(), o)
}
