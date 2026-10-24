package sshfront

import (
	"context"
	"net"
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
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics/metricstest"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshkeys"
)

type staticHosts struct{ s ssh.Signer }

func (h staticHosts) GatewayHostSigners(context.Context) ([]ssh.Signer, error) {
	return []ssh.Signer{h.s}, nil
}

// closingHandler serves a session by refusing an x11 request and closing it.
type closingHandler struct{ h *Handler }

func (c closingHandler) HandleSession(ctx context.Context, conn *Conn, ch ssh.Channel, reqs <-chan *ssh.Request) {
	s := &session{h: c.h, c: conn, ch: ch, reqs: reqs}
	_, _ = s.awaitStart(ctx)
	_ = ch.Close()
}

func waitValue(t *testing.T, m *metrics.Metrics, want float64, name string, labels ...string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if metricstest.Value(t, m, name, labels...) == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s%v = %v, want %v", name, labels, metricstest.Value(t, m, name, labels...), want)
}

// HP-OBS-004: connection results, authentication failures, active connections and refused requests are exported.
func TestServerMetrics(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clk := clock.System{}
	s := storetest.Open(t)
	kr := keyringtest.Load(t, s)
	aw := audit.NewWriter(kr)
	bus := eventbus.New()
	ag := agents.New(s, kr, aw, bus, clk)
	engine := policy.NewEngine(s, 24*time.Hour, []time.Duration{time.Hour})
	acc := access.New(s, kr, aw, bus, engine, access.Options{})
	key := sshkeys.Ed25519(t)
	if _, err := ag.Create(ctx, audit.Actor{Type: audit.ActorOperator, ID: "opr_admin"},
		agents.CreateInput{Name: "bot", PublicKeys: []string{key.AuthorizedLine("")}}); err != nil {
		t.Fatal(err)
	}
	m := metrics.New()
	cfg := config.Default().SSH
	cfg.KeepaliveInterval = 0
	h := &Handler{Metrics: m}
	hostKey := sshkeys.Ed25519(t)
	srv := New(Options{Config: cfg, Agents: ag, Access: acc, Audit: aw, Store: s, Hosts: staticHosts{hostKey.Signer},
		Handler: closingHandler{h}, Metrics: m})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ctx, ln) }()
	addr := ln.Addr().String()
	dial := func(k sshkeys.Key) (*ssh.Client, error) {
		return ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "agent", Auth: []ssh.AuthMethod{ssh.PublicKeys(k.Signer)},
			HostKeyCallback: ssh.FixedHostKey(hostKey.Public), Timeout: 5 * time.Second})
	}

	if _, err := dial(sshkeys.Ed25519(t)); err == nil {
		t.Fatal("unknown key authenticated")
	}
	waitValue(t, m, 1, "hallpass_ssh_connections_total", "result", "auth_failed")
	waitValue(t, m, 1, "hallpass_ssh_auth_failures_total", "reason", "unknown_key")

	c, err := dial(key)
	if err != nil {
		t.Fatal(err)
	}
	waitValue(t, m, 1, "hallpass_ssh_connections_total", "result", "accepted")
	waitValue(t, m, 1, "hallpass_ssh_connections_active")
	if _, _, err := c.OpenChannel("direct-tcpip", nil); err == nil {
		t.Fatal("direct-tcpip accepted")
	}
	if ok, _, _ := c.SendRequest("tcpip-forward", true, nil); ok {
		t.Fatal("tcpip-forward accepted")
	}
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestSubsystem("netconf"); err == nil { // only sftp is served
		t.Fatal("subsystem accepted")
	}
	_ = sess.Close()
	waitValue(t, m, 1, "hallpass_ssh_refused_requests_total", "type", "channel_type")
	waitValue(t, m, 1, "hallpass_ssh_refused_requests_total", "type", "port_forward")
	waitValue(t, m, 1, "hallpass_ssh_refused_requests_total", "type", "subsystem")
	_ = c.Close()
	waitValue(t, m, 0, "hallpass_ssh_connections_active")

	srv.Shutdown()
	if v := srv.refusal(metrics.ConnPreAuthLimit); v != metrics.ConnShuttingDown {
		t.Errorf("refusal while closing = %s", v)
	}
	for in, want := range map[string]metrics.RefusedRequest{"x11-req": metrics.RefusedX11, "auth-agent-req@openssh.com": metrics.RefusedAgentForward,
		"cancel-tcpip-forward": metrics.RefusedPortForward, "weird": metrics.Other} {
		if got := refusedType(in); got != want {
			t.Errorf("refusedType(%s) = %s", in, got)
		}
	}
}
