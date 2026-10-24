package sshfront

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/keyring/keyringtest"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshkeys"
)

type frontFx struct {
	t     *testing.T
	ctx   context.Context
	s     *store.Store
	ag    *agents.Service
	srv   *Server
	agent *agents.Agent
	keyID string
	key   sshkeys.Key
	host  sshkeys.Key
	addr  string
}

var opAdmin = audit.Actor{Type: audit.ActorOperator, ID: "opr_admin"}

// newFrontFx starts a server; withBus=false simulates lost events (only the periodic re-check runs).
func newFrontFx(t *testing.T, withBus bool, revalidate time.Duration) *frontFx {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := storetest.Open(t)
	kr := keyringtest.Load(t, s)
	aw := audit.NewWriter(kr)
	bus := eventbus.New()
	ag := agents.New(s, kr, aw, bus, clock.System{})
	engine := policy.NewEngine(s, 24*time.Hour, []time.Duration{time.Hour})
	acc := access.New(s, kr, aw, bus, engine, access.Options{})
	key := sshkeys.Ed25519(t)
	a, err := ag.Create(ctx, opAdmin, agents.CreateInput{Name: "bot", PublicKeys: []string{key.AuthorizedLine("")}})
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := ag.Keys(ctx, a.ID)
	cfg := config.Default().SSH
	cfg.KeepaliveInterval = 0
	host := sshkeys.Ed25519(t)
	o := Options{Config: cfg, Agents: ag, Access: acc, Audit: aw, Store: s, Hosts: staticHosts{host.Signer},
		Handler: closingHandler{&Handler{}}, Revalidate: revalidate}
	if withBus {
		o.Bus = bus
	}
	srv := New(o)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(srv.Shutdown)
	return &frontFx{t: t, ctx: ctx, s: s, ag: ag, srv: srv, agent: a, keyID: keys[0].ID, key: key, host: host, addr: ln.Addr().String()}
}

func (f *frontFx) dial() *ssh.Client {
	f.t.Helper()
	c, err := ssh.Dial("tcp", f.addr, &ssh.ClientConfig{User: "agent", Auth: []ssh.AuthMethod{ssh.PublicKeys(f.key.Signer)},
		HostKeyCallback: ssh.FixedHostKey(f.host.Public), Timeout: 5 * time.Second})
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = c.Close() })
	return c
}

func waitClosed(t *testing.T, c *ssh.Client, within time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() { _ = c.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(within):
		t.Fatalf("connection still open after %s", within)
	}
}

func (f *frontFx) auditCount(action string) int {
	f.t.Helper()
	var n int
	if err := f.s.ReadDB().QueryRowContext(f.ctx, `SELECT count(*) FROM audit_events WHERE action = ?`, action).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// SR-15 (HP-AGT-005): revoking the authenticating key closes the agent's established connection at once.
func TestKeyRevocationClosesConnection(t *testing.T) {
	f := newFrontFx(t, true, time.Hour)
	c := f.dial()
	if _, err := f.ag.RevokeKey(f.ctx, opAdmin, f.agent.ID, f.keyID, ""); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, c, time.Second)
}

// SR-15: with the revocation event lost, the periodic re-check still closes the connection within the bound.
func TestRevokedKeyConnectionClosedWithoutEvents(t *testing.T) {
	f := newFrontFx(t, false, 100*time.Millisecond)
	c := f.dial()
	if _, err := f.ag.RevokeKey(f.ctx, opAdmin, f.agent.ID, f.keyID, ""); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, c, access.EnforcementBound)
}

// SR-15: disabling the agent closes its connections.
func TestAgentDisableClosesConnection(t *testing.T) {
	f := newFrontFx(t, true, time.Hour)
	c := f.dial()
	if _, err := f.ag.SetEnabled(f.ctx, opAdmin, f.agent.ID, false, ""); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, c, time.Second)
}

// SR-20 (T-01, T-22): refused requests are audited at a bounded rate (the rest summarized as suppressed), and a
// connection that keeps sending them is closed.
func TestRefusalAuditsBoundedAndConnectionClosed(t *testing.T) {
	f := newFrontFx(t, true, time.Hour)
	c := f.dial()
	for range MaxRefusalsPerConn + 5 {
		if ok, _, err := c.SendRequest("tcpip-forward", true, nil); err != nil {
			break // closed by the gateway
		} else if ok {
			t.Fatal("tcpip-forward accepted")
		}
	}
	waitClosed(t, c, 2*time.Second)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && f.auditCount("ssh.denied.suppressed") == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if n := f.auditCount("ssh.global_request.denied"); n > deniedAuditsPerConn {
		t.Fatalf("%d refusal audit rows, want at most %d", n, deniedAuditsPerConn)
	}
	if f.auditCount("ssh.denied.suppressed") != 1 {
		t.Fatal("suppressed refusals were not summarized at connection close")
	}
}

// SR-22 (HP-SSH-013): the pre-auth per-source limit treats an IPv6 /64 as one source, and one /48 cannot take
// more than wideTierFactor times that limit.
func TestPreAuthLimitKeysIPv6ByPrefix(t *testing.T) {
	cfg := config.Default().SSH
	cfg.MaxUnauthenticated, cfg.MaxUnauthenticatedPerIP = 256, 4
	srv := New(Options{Config: cfg})
	base := netip.MustParseAddr("2001:db8:1:1::1").As16()
	n := 0
	for i := range 32 {
		a := base
		a[15] = byte(i + 1) // same /64, different addresses
		if srv.acquirePreAuth(netip.AddrFrom16(a)) {
			n++
		}
	}
	if n != cfg.MaxUnauthenticatedPerIP {
		t.Fatalf("one /64 got %d pre-auth slots, want %d", n, cfg.MaxUnauthenticatedPerIP)
	}
	wide := 0
	for i := range 64 {
		a := base
		a[7] = byte(i + 2) // different /64s inside one /48
		for range cfg.MaxUnauthenticatedPerIP {
			if srv.acquirePreAuth(netip.AddrFrom16(a)) {
				wide++
			}
		}
	}
	if total := n + wide; total != wideTierFactor*cfg.MaxUnauthenticatedPerIP {
		t.Fatalf("one /48 got %d pre-auth slots, want %d", total, wideTierFactor*cfg.MaxUnauthenticatedPerIP)
	}
	if !srv.acquirePreAuth(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("unrelated IPv4 source refused")
	}
	srv.releasePreAuth(netip.AddrFrom16(base)) // frees one slot of the /64 and of the /48
	if !srv.acquirePreAuth(netip.AddrFrom16(base)) {
		t.Fatal("released slot not reusable")
	}
	if got, want := len(srv.unauth), n+wide+1; got != want {
		t.Fatalf("global slots in use %d, want %d", got, want)
	}
}

type fakeMeta struct{ addr net.Addr }

func (m fakeMeta) User() string          { return "agent" }
func (m fakeMeta) SessionID() []byte     { return nil }
func (m fakeMeta) ClientVersion() []byte { return []byte("SSH-2.0-test") }
func (m fakeMeta) ServerVersion() []byte { return []byte(ServerVersion) }
func (m fakeMeta) RemoteAddr() net.Addr  { return m.addr }
func (m fakeMeta) LocalAddr() net.Addr   { return m.addr }

// SR-44 (HP-SSH-003): auth-failure audit rows are rate limited per IPv6 /64, not per address.
func TestAuthFailureAuditKeyedByPrefix(t *testing.T) {
	f := newFrontFx(t, true, time.Hour)
	base := netip.MustParseAddr("2001:db8:2:2::1").As16()
	for i := range 60 {
		a := base
		a[14], a[15] = byte(i>>8), byte(i)
		ip := netip.AddrFrom16(a)
		f.srv.recordAuthFailure(f.ctx, ip, fakeMeta{&net.TCPAddr{IP: ip.AsSlice(), Port: 22}}, &agents.AuthError{Reason: agents.FailUnknownKey})
	}
	if n := f.auditCount("ssh.auth.failed"); n != 20 {
		t.Fatalf("%d auth-failure audit rows from one /64, want 20", n)
	}
}
