package destaudit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/destaudit/wire"
	"github.com/aurimasniekis/go-hallpass/internal/egress"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/keyring/keyringtest"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
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

type agentFx struct {
	agent *agents.Agent
	keyID string
}

type fx struct {
	t        *testing.T
	ctx      context.Context
	clk      *clock.Fake
	s        *store.Store
	bus      *eventbus.Bus
	agents   *agents.Service
	inv      *inventory.Service
	acc      *access.Service
	svc      *Service
	srv      *inventory.Server
	role     *inventory.Role
	approver policy.OperatorInfo
	a1, a2   agentFx

	collector *Collector
	priv      ed25519.PrivateKey
	nextSeq   int64
}

func newFx(t *testing.T) *fx {
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
	presets := []time.Duration{5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour, 3 * time.Hour}
	engine := policy.NewEngine(s, 24*time.Hour, presets)
	pol := policy.NewService(s, aw, bus, engine)
	f.acc = access.New(s, kr, aw, bus, engine, access.Options{Clock: clk})
	f.svc = New(s, kr, aw, f.acc.Sequencer(), Options{Clock: clk, Bus: bus})

	var err error
	f.srv, err = f.inv.CreateServer(f.ctx, admin, inventory.ServerInput{Alias: ptr("web1"), Address: ptr("10.0.0.1")})
	must(t, err)
	f.role, err = f.inv.CreateRole(f.ctx, admin, f.srv.ID, inventory.RoleInput{Alias: ptr("inspect"), RemoteUser: ptr("ro"),
		MaxConcurrent: ptr(5), MaxConcurrentPerAgent: ptr(3)})
	must(t, err)
	_, err = pol.CreateRule(f.ctx, admin, policy.Rule{Name: "sre", Effect: policy.EffectAllow, Level: policy.LevelRequestable, Enabled: true,
		Subjects: policy.SubjectSelector{AgentGroups: []string{"sre"}}, Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}})
	must(t, err)
	opID := ids.New(ids.Operator)
	_, err = pol.CreateApproverRule(f.ctx, admin, policy.ApproverRule{Name: "oncall", Enabled: true,
		Operators: policy.OperatorSelector{Operators: []string{opID}}, Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}})
	must(t, err)
	f.approver = policy.OperatorInfo{ID: opID, Roles: []string{"approver"}, Enabled: true}
	f.a1 = f.newAgent("bot-one")
	f.a2 = f.newAgent("bot-two")
	f.collector, f.priv = f.register(f.srv.ID, "web1-auditd")
	return f
}

func (f *fx) newAgent(name string) agentFx {
	f.t.Helper()
	a, err := f.agents.Create(f.ctx, admin, agents.CreateInput{Name: name, Groups: []string{"sre"}, PublicKeys: []string{sshkeys.Ed25519(f.t).AuthorizedLine("")}})
	must(f.t, err)
	keys, err := f.agents.Keys(f.ctx, a.ID)
	must(f.t, err)
	return agentFx{agent: a, keyID: keys[0].ID}
}

func authorizedLine(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	pk, err := ssh.NewPublicKey(pub)
	must(t, err)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
}

func (f *fx) register(serverID, name string) (*Collector, ed25519.PrivateKey) {
	f.t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	must(f.t, err)
	c, err := f.svc.RegisterCollector(f.ctx, admin, RegisterInput{ServerID: serverID, Name: name, PublicKey: authorizedLine(f.t, pub) + " collector@web1"})
	must(f.t, err)
	return c, priv
}

// activity opens a grant, connection and active exec channel for agent a, using credentialRef as the destination
// login credential (a login credential ID, or "ca:<id>" for certificates).
type activity struct {
	grant  *access.Grant
	connID string
	reg    *access.ChannelReg
}

func (f *fx) activity(a agentFx, credentialRef string) activity {
	f.t.Helper()
	req, err := f.acc.CreateRequest(f.ctx, access.CreateRequestInput{AgentID: a.agent.ID, KeyID: a.keyID, ServerID: f.srv.ID, RoleID: f.role.ID,
		Reason: "investigate", Duration: time.Hour})
	must(f.t, err)
	dec, err := f.acc.Decide(f.ctx, access.DecideInput{RequestID: req.Request.ID, Approve: true, Operator: f.approver, Channel: access.ChannelWeb})
	must(f.t, err)
	conn, err := f.acc.OpenConnection(f.ctx, access.ConnectionInfo{AgentID: a.agent.ID, KeyID: a.keyID, ClientUser: "x", ClientVersion: "SSH-2.0-test", SourceIP: "10.9.9.9"})
	must(f.t, err)
	reg, err := f.acc.RegisterChannel(f.ctx, access.RegisterInput{ConnectionID: conn, AgentID: a.agent.ID, KeyID: a.keyID, GrantID: dec.Grant.ID, Kind: access.KindExec})
	must(f.t, err)
	must(f.t, f.acc.ActivateChannel(f.ctx, reg, credentialRef, nil))
	return activity{grant: dec.Grant, connID: conn, reg: reg}
}

func (a activity) keyID() string {
	return wire.CertKeyIDPrefix + a.grant.RoleID + ":" + a.grant.ID + ":" + a.connID
}

// loginCredential inserts an active managed login key for the role and returns its ID and fingerprint.
func (f *fx) loginCredential(roleID string) (string, string) {
	f.t.Helper()
	k := sshkeys.Ed25519(f.t)
	id := ids.New(ids.Credential)
	must(f.t, f.s.W().Tx(f.ctx, func(tx *store.Tx) error {
		return tx.Q.InsertLoginCredential(f.ctx, db.InsertLoginCredentialParams{ID: id, RoleID: roleID, Kind: "managed_key", Algorithm: "ssh-ed25519",
			PublicKey: k.AuthorizedLine(""), FingerprintSha256: k.Fingerprint(), PrivateEnc: []byte("not-used"), CreatedAt: tx.NowMicros(),
			CreatedBy: "test", UpdatedAt: tx.NowMicros()})
	}))
	return id, k.Fingerprint()
}

var recCounter int

func (f *fx) record(login wire.Login, at time.Time) wire.Record {
	recCounter++
	return wire.Record{ID: fmt.Sprintf("%d.%03d:%d", at.Unix(), at.Nanosecond()/1e6, recCounter), Source: wire.SourceAuditd, Time: at,
		Login: login, PID: 4242, PPID: 4200, UID: 1001, AUID: 1001, Success: true,
		Exe: "/usr/bin/cat", Argv: []string{"cat", "/etc/secret-config"}, CWD: "/home/ro"}
}

// envelope signs a batch from the fixture collector with the next sequence number.
func (f *fx) envelope(recs ...wire.Record) *wire.Envelope {
	f.t.Helper()
	f.nextSeq++
	env, err := wire.Sign(f.priv, &wire.Batch{V: wire.Version, CollectorID: f.collector.ID, Seq: f.nextSeq, SentAt: f.clk.Now(), Records: recs})
	must(f.t, err)
	return env
}

func body(t *testing.T, env *wire.Envelope) []byte {
	t.Helper()
	b, err := json.Marshal(env)
	must(t, err)
	return b
}

func (f *fx) ingest(recs ...wire.Record) *IngestResult {
	f.t.Helper()
	res, err := f.svc.Ingest(f.ctx, f.collector.ID, body(f.t, f.envelope(recs...)))
	must(f.t, err)
	return res
}

func (f *fx) timeline(sessionID string) []db.TimelineEvent {
	f.t.Helper()
	evs, err := f.s.R().TimelineForSession(f.ctx, db.TimelineForSessionParams{AccessSessionID: sql.NullString{String: sessionID, Valid: true}, Seq: sql.NullInt64{Valid: true}, Limit: 1000})
	must(f.t, err)
	return evs
}

func destExecEvents(evs []db.TimelineEvent) []db.TimelineEvent {
	var out []db.TimelineEvent
	for _, e := range evs {
		if e.Type == access.EvDestinationExec {
			out = append(out, e)
		}
	}
	return out
}
