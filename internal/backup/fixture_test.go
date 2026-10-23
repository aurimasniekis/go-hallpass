package backup

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/app"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/sshproxy"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshkeys"
)

var admin = audit.Actor{Type: audit.ActorOperator, ID: "opr_admin"}

func ptr[T any](v T) *T { return &v }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// writeKEK generates a KEK file outside any data directory (test-time key, never committed).
func writeKEK(t *testing.T) string {
	t.Helper()
	k, err := keyring.GenerateKEK()
	must(t, err)
	p := filepath.Join(t.TempDir(), "kek")
	must(t, keyring.WriteKEKFile(p, k))
	return p
}

func testConfig(dataDir, kekFile string) *config.Config {
	cfg := config.Default()
	cfg.Mode = "development"
	cfg.DataDir = dataDir
	cfg.KEK.File = kekFile
	cfg.Egress.AllowCIDRs = []string{"10.0.0.0/8"}
	cfg.Recording.Durability = "strict"
	return cfg
}

func openApp(t *testing.T, cfg *config.Config) *app.App {
	t.Helper()
	a, err := app.New(context.Background(), cfg, slog.New(slog.DiscardHandler))
	must(t, err)
	return a
}

// fixture is a running App with an approved grant and an open connection, so channels can be recorded.
type fixture struct {
	t     *testing.T
	ctx   context.Context
	cfg   *config.Config
	a     *app.App
	agent string
	keyID string
	grant string
	conn  string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, ctx: context.Background()}
	f.cfg = testConfig(filepath.Join(t.TempDir(), "data"), writeKEK(t))
	f.a = openApp(t, f.cfg)
	t.Cleanup(func() { _ = f.a.Close() })
	a, ctx := f.a, f.ctx
	ag, err := a.Agents.Create(ctx, admin, agents.CreateInput{Name: "sre-bot", Groups: []string{"sre"}, PublicKeys: []string{sshkeys.Ed25519(t).AuthorizedLine("")}})
	must(t, err)
	f.agent = ag.ID
	keys, err := a.Agents.Keys(ctx, ag.ID)
	must(t, err)
	f.keyID = keys[0].ID
	srv, err := a.Inventory.CreateServer(ctx, admin, inventory.ServerInput{Alias: ptr("web1"), Address: ptr("10.0.0.1")})
	must(t, err)
	role, err := a.Inventory.CreateRole(ctx, admin, srv.ID, inventory.RoleInput{Alias: ptr("inspect"), RemoteUser: ptr("ro"), MaxConcurrent: ptr(50), MaxConcurrentPerAgent: ptr(50)})
	must(t, err)
	_, err = a.Policy.CreateRule(ctx, admin, policy.Rule{Name: "sre", Effect: policy.EffectAllow, Level: policy.LevelRequestable, Enabled: true,
		Subjects: policy.SubjectSelector{AgentGroups: []string{"sre"}}, Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}})
	must(t, err)
	opID := ids.New(ids.Operator)
	_, err = a.Policy.CreateApproverRule(ctx, admin, policy.ApproverRule{Name: "oncall", Enabled: true,
		Operators: policy.OperatorSelector{Operators: []string{opID}}, Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}})
	must(t, err)
	req, err := a.Access.CreateRequest(ctx, access.CreateRequestInput{AgentID: ag.ID, KeyID: f.keyID, ServerID: srv.ID, RoleID: role.ID, Reason: "debug", Duration: time.Hour})
	must(t, err)
	dec, err := a.Access.Decide(ctx, access.DecideInput{RequestID: req.Request.ID, Approve: true,
		Operator: policy.OperatorInfo{ID: opID, Roles: []string{"approver"}, Enabled: true}, Channel: access.ChannelWeb})
	must(t, err)
	f.grant = dec.Grant.ID
	f.conn, err = a.Access.OpenConnection(ctx, access.ConnectionInfo{AgentID: ag.ID, KeyID: f.keyID, ClientUser: "x", ClientVersion: "SSH-2.0-test", SourceIP: "10.9.9.9"})
	must(t, err)
	return f
}

// record opens a channel recording and writes a few records. The caller finalizes or leaves it open.
func (f *fixture) record(cmd string) sshproxy.Recorder {
	f.t.Helper()
	reg, err := f.a.Access.RegisterChannel(f.ctx, access.RegisterInput{ConnectionID: f.conn, AgentID: f.agent, KeyID: f.keyID, GrantID: f.grant, Kind: access.KindExec})
	must(f.t, err)
	rec, err := f.a.Recording.Open(f.ctx, reg, access.KindExec, false)
	must(f.t, err)
	must(f.t, rec.ExecRequested(cmd))
	must(f.t, rec.Output(sshproxy.StreamStdout, []byte("output of "+cmd+"\n")))
	return rec
}

// finished records and finalizes one channel.
func (f *fixture) finished(cmd string) {
	f.t.Helper()
	rec := f.record(cmd)
	status := 0
	must(f.t, rec.Exit(&status, ""))
	must(f.t, rec.Finalize("exit_status"))
}
