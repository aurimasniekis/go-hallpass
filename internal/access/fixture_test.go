package access

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/egress"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/keyring/keyringtest"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshkeys"
)

var (
	admin   = audit.Actor{Type: audit.ActorOperator, ID: "opr_admin"}
	presets = []time.Duration{5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour, 3 * time.Hour, 6 * time.Hour, 24 * time.Hour}
)

type fx struct {
	t        *testing.T
	ctx      context.Context
	clk      *clock.Fake
	s        *store.Store
	bus      *eventbus.Bus
	agents   *agents.Service
	inv      *inventory.Service
	pol      *policy.Service
	svc      *Service
	agent    *agents.Agent
	keyID    string
	srv      *inventory.Server
	role     *inventory.Role
	approver policy.OperatorInfo
}

func ptr[T any](v T) *T { return &v }

func newFx(t *testing.T) *fx {
	t.Helper()
	return newFxWith(t, nil)
}

// newFxWith builds the fixture; opt (if non-nil) adjusts the access Options.
func newFxWith(t *testing.T, opt func(*Options)) *fx {
	t.Helper()
	clk := clock.NewFake(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
	s := storetest.Open(t, storetest.WithClock(clk))
	kr := keyringtest.Load(t, s)
	aw := audit.NewWriter(kr)
	bus := eventbus.New()
	g, _ := egress.New([]string{"10.0.0.0/8"}, nil, nil, time.Second)
	f := &fx{t: t, ctx: context.Background(), clk: clk, s: s, bus: bus,
		agents: agents.New(s, kr, aw, bus, clk),
		inv:    inventory.New(s, aw, bus, inventory.Options{Guard: g, MaxGrantDuration: 24 * time.Hour, Clock: clk})}
	engine := policy.NewEngine(s, 24*time.Hour, presets)
	f.pol = policy.NewService(s, aw, bus, engine)
	o := Options{Clock: clk, PendingExpiry: 30 * time.Minute}
	if opt != nil {
		opt(&o)
	}
	f.svc = New(s, kr, aw, bus, engine, o)
	f.agents.OnDisable(f.svc.AgentDisabledHook)
	f.agents.OnKeyRevoke(f.svc.KeyRevokedHook)
	f.inv.OnDisable(f.svc.TargetDisabledHook)

	var err error
	f.agent, err = f.agents.Create(f.ctx, admin, agents.CreateInput{Name: "sre-bot", Groups: []string{"sre"}, PublicKeys: []string{sshkeys.Ed25519(t).AuthorizedLine("")}})
	must(t, err)
	keys, _ := f.agents.Keys(f.ctx, f.agent.ID)
	f.keyID = keys[0].ID
	f.srv, err = f.inv.CreateServer(f.ctx, admin, inventory.ServerInput{Alias: ptr("web1"), Address: ptr("10.0.0.1")})
	must(t, err)
	f.role, err = f.inv.CreateRole(f.ctx, admin, f.srv.ID, inventory.RoleInput{Alias: ptr("inspect"), RemoteUser: ptr("ro"),
		MaxConcurrent: ptr(3), MaxConcurrentPerAgent: ptr(2)})
	must(t, err)
	_, err = f.pol.CreateRule(f.ctx, admin, policy.Rule{Name: "sre", Effect: policy.EffectAllow, Level: policy.LevelRequestable, RequireReason: true, Enabled: true,
		Subjects: policy.SubjectSelector{AgentGroups: []string{"sre"}}, Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}})
	must(t, err)
	opID := insertOperator(t, s, "approver")
	_, err = f.pol.CreateApproverRule(f.ctx, admin, policy.ApproverRule{Name: "oncall", Enabled: true,
		Operators: policy.OperatorSelector{Operators: []string{opID}}, Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}})
	must(t, err)
	f.approver = policy.OperatorInfo{ID: opID, Roles: []string{"approver"}, Enabled: true}
	return f
}

// insertOperator creates an enabled operator with roles (decisions re-read operators from the database, SR-23).
func insertOperator(t *testing.T, s *store.Store, roles ...string) string {
	t.Helper()
	id := ids.New(ids.Operator)
	must(t, s.W().Tx(context.Background(), func(tx *store.Tx) error {
		if _, err := tx.SQL.ExecContext(context.Background(), `INSERT INTO operators (id, email, display_name, enabled, provisioned_via,
			created_at, created_by, updated_at) VALUES (?, ?, 'op', 1, 'admin', ?, 'test', ?)`, id, id+"@example.com", tx.NowMicros(), tx.NowMicros()); err != nil {
			return err
		}
		for _, r := range roles {
			if _, err := tx.SQL.ExecContext(context.Background(), `INSERT INTO operator_roles (operator_id, role, source) VALUES (?, ?, 'manual')`, id, r); err != nil {
				return err
			}
		}
		return nil
	}))
	return id
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fx) request(reason string, dur time.Duration) *CreateResult {
	f.t.Helper()
	res, err := f.svc.CreateRequest(f.ctx, CreateRequestInput{AgentID: f.agent.ID, KeyID: f.keyID, ServerID: f.srv.ID, RoleID: f.role.ID, Reason: reason, Duration: dur})
	must(f.t, err)
	return res
}

func (f *fx) approve(reqID string, dur time.Duration) *DecideResult {
	f.t.Helper()
	res, err := f.svc.Decide(f.ctx, DecideInput{RequestID: reqID, Approve: true, Duration: dur, Operator: f.approver, Channel: ChannelWeb})
	must(f.t, err)
	return res
}

func (f *fx) grant(dur time.Duration) *Grant {
	f.t.Helper()
	r := f.request("investigate errors", dur)
	return f.approve(r.Request.ID, 0).Grant
}

func (f *fx) conn() string {
	f.t.Helper()
	id, err := f.svc.OpenConnection(f.ctx, ConnectionInfo{AgentID: f.agent.ID, KeyID: f.keyID, ClientUser: "anything", ClientVersion: "SSH-2.0-OpenSSH_9.6", SourceIP: "10.9.9.9"})
	must(f.t, err)
	return id
}

func inventoryServer(alias, addr string) inventory.ServerInput {
	return inventory.ServerInput{Alias: ptr(alias), Address: ptr(addr)}
}

func roleInput(alias string) inventory.RoleInput {
	return inventory.RoleInput{Alias: ptr(alias), RemoteUser: ptr("ro")}
}

func nullStr(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func nullInt(v int64) sql.NullInt64 { return sql.NullInt64{Int64: v, Valid: true} }

func newKeyLine(t *testing.T) string { return sshkeys.Ed25519(t).AuthorizedLine("") }

func roleChannels(f *fx, channels []string) inventory.RoleInput {
	r, _ := f.inv.GetRole(f.ctx, f.role.ID)
	return inventory.RoleInput{Version: r.Version, ApprovalChannels: ptr(channels)}
}
