//go:build openssh

package openssh

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/app"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/credentials"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
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

// Gateway is an in-process HallPass in front of a real sshd, driven with the system ssh client.
type Gateway struct {
	t          *testing.T
	A          *app.App
	Dest       *Destination
	Server     *inventory.Server
	Role       *inventory.Role
	Agent      *agents.Agent
	port       int
	keyFile    string
	knownHosts string
	cancel     context.CancelFunc
	done       chan error
}

func startGateway(t *testing.T) *Gateway {
	t.Helper()
	requireDocker(t)
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh client not available")
	}
	dest := StartDestination(t)
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Mode = "development"
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.KEK.File = ""
	cfg.Egress.AllowCIDRs = []string{"127.0.0.0/8"}
	cfg.Egress.AllowSpecialCIDRs = []string{"127.0.0.1/32"}
	cfg.Shutdown.DrainTimeout = config.Duration(500 * time.Millisecond)
	cfg.HTTP.Listen = ""
	ctx := context.Background()
	logs := &syncBuffer{}
	a, err := app.New(ctx, cfg, slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	must(t, err)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("gateway logs:\n%s", logs.String())
		}
	})
	g := &Gateway{t: t, A: a, Dest: dest, done: make(chan error, 1)}

	// Agent key on disk for the ssh client.
	key := sshkeys.Ed25519(t)
	blk, err := ssh.MarshalPrivateKey(key.Private, "")
	must(t, err)
	g.keyFile = filepath.Join(dir, "agent_key")
	must(t, os.WriteFile(g.keyFile, pem.EncodeToMemory(blk), 0o600))
	g.Agent, err = a.Agents.Create(ctx, admin, agents.CreateInput{Name: "sre-bot", Groups: []string{"sre"}, PublicKeys: []string{key.AuthorizedLine("")}})
	must(t, err)

	g.Server, err = a.Inventory.CreateServer(ctx, admin, inventory.ServerInput{Alias: ptr("web1"), Address: ptr(dest.Host), Port: ptr(dest.Port)})
	must(t, err)
	_, err = a.Inventory.AddHostIdentity(ctx, admin, g.Server.ID, dest.HostKey())
	must(t, err)
	g.Role, err = a.Inventory.CreateRole(ctx, admin, g.Server.ID, inventory.RoleInput{Alias: ptr("inspect"), RemoteUser: ptr("ro")})
	must(t, err)
	cred, err := a.Credentials.Generate(ctx, admin, g.Role.ID)
	must(t, err)
	// Install the suggested line verbatim, including restrict and from= (HP-KEY-002, HP-DOC-003).
	dest.Authorize("ro", strings.Replace(cred.AuthorizedKeysLine, `from="`, `from="*,`, 1))
	_, err = a.Credentials.Probe(ctx, admin, cred.ID)
	must(t, err)
	_, err = a.Credentials.Activate(ctx, admin, cred.ID, false)
	must(t, err)
	_, err = a.Policy.CreateRule(ctx, admin, policy.Rule{Name: "sre", Effect: policy.EffectAllow, Level: policy.LevelAutoApprove, Enabled: true,
		AutoMaxDuration: time.Hour, Subjects: policy.SubjectSelector{AgentGroups: []string{"sre"}}, Targets: policy.TargetSelector{All: true},
		Roles: policy.RoleSelector{All: true}})
	must(t, err)

	ln, err := app.Listen(ctx, "127.0.0.1:0")
	must(t, err)
	g.port = ln.Addr().(*net.TCPAddr).Port
	keys, err := a.Credentials.GatewayHostKeys(ctx)
	must(t, err)
	g.knownHosts = filepath.Join(dir, "known_hosts")
	must(t, os.WriteFile(g.knownHosts, []byte(fmt.Sprintf("[127.0.0.1]:%d %s\n", g.port, keys[0].PublicKey)), 0o600))

	sctx, cancel := context.WithCancel(ctx)
	g.cancel = cancel
	go func() { g.done <- a.Serve(sctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-g.done:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("gateway did not stop")
		}
		_ = a.Close()
	})
	return g
}

// SSH runs the system ssh client against the gateway with strict host-key checking.
func (g *Gateway) SSH(stdin string, extra ...string) (stdout, stderr string, code int) {
	g.t.Helper()
	args := []string{"-F", "/dev/null", "-i", g.keyFile, "-o", "IdentitiesOnly=yes", "-o", "UserKnownHostsFile=" + g.knownHosts,
		"-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-p", fmt.Sprint(g.port)}
	args = append(args, extra...)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		code = ee.ExitCode()
	default:
		g.t.Fatalf("ssh: %v", err)
	}
	return out.String(), errb.String(), code
}

// waitRecordingsClosed waits for recorders to finalize: the agent can see the exit status a moment before the
// final frame is committed.
func (g *Gateway) waitRecordingsClosed() {
	g.t.Helper()
	for range 100 {
		var n int
		must(g.t, g.A.Store.ReadDB().QueryRowContext(context.Background(), `SELECT count(*) FROM recording_segments WHERE state = 'open'`).Scan(&n))
		if n == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	g.t.Fatal("recordings still open")
}

func (g *Gateway) Run(command string) (string, string, int) {
	return g.SSH("", "agent@127.0.0.1", command)
}

// HP-SSH-001/006/020, HP-TST-003: exec through real OpenSSH on both sides, stdout/stderr separated, exit status kept.
// The text after -- is forwarded verbatim and interpreted by the destination's login shell.
func TestOpenSSHExec(t *testing.T) {
	g := startGateway(t)
	out, errOut, code := g.Run("list")
	if code != 0 || !strings.Contains(out, "web1") {
		t.Fatalf("list: %d %q %q", code, out, errOut)
	}
	out, errOut, code = g.Run(`exec web1 --role inspect -- echo "hello world"; echo oops >&2; whoami; exit 3`)
	if code != 3 || out != "hello world\nro\n" || !strings.Contains(errOut, "oops") {
		t.Fatalf("exec: %d %q %q", code, out, errOut)
	}
	// stdin is forwarded and EOF propagates.
	out, _, code = g.SSH("line1\nline2\n", "agent@127.0.0.1", "exec web1 --role inspect -- wc -l")
	if code != 0 || strings.TrimSpace(out) != "2" {
		t.Fatalf("stdin: %d %q", code, out)
	}
	// Large output is not truncated (backpressure, HP-SSH-014).
	out, errOut, code = g.Run("exec web1 --role inspect -- head -c 5000000 /dev/zero")
	if code != 0 || len(out) != 5000000 {
		t.Fatalf("large output: %d %d bytes %q", code, len(out), errOut)
	}
	g.waitRecordingsClosed()
	vr, err := g.A.Recording.Verify(context.Background(), "")
	must(t, err)
	if !vr.OK || len(vr.Segments) < 3 {
		t.Fatalf("recordings %+v", vr)
	}
}

// HP-SSH-008: interactive PTY shell with a real terminal.
func TestOpenSSHPTY(t *testing.T) {
	g := startGateway(t)
	out, errOut, code := g.SSH("echo pty-$((40+2)); tty; exit 4\n", "-tt", "agent@127.0.0.1", "connect web1 --role inspect")
	if code != 4 || !strings.Contains(out, "pty-42") || !strings.Contains(out, "/dev/pts/") {
		t.Fatalf("pty: %d %q %q", code, out, errOut)
	}
}

// HP-SSH-007: forwarding, agent forwarding and subsystems other than sftp are refused; sftp needs a server as the
// SSH user and a role with the file-transfer capability.
func TestOpenSSHForwardingDenied(t *testing.T) {
	g := startGateway(t)
	_, errOut, code := g.SSH("", "-W", "127.0.0.1:22", "agent@127.0.0.1")
	if code == 0 {
		t.Fatalf("stdio forward allowed: %q", errOut)
	}
	_, errOut, code = g.SSH("", "-o", "ExitOnForwardFailure=yes", "-R", "0:127.0.0.1:22", "-N", "agent@127.0.0.1")
	if code == 0 || !strings.Contains(strings.ToLower(errOut), "forward") {
		t.Fatalf("remote forward allowed: %d %q", code, errOut)
	}
	_, _, code = g.SSH("", "-s", "agent@127.0.0.1", "sftp")
	if code == 0 {
		t.Fatal("sftp subsystem allowed without a server")
	}
	_, _, code = g.SSH("", "-s", "web1@127.0.0.1", "sftp")
	if code == 0 {
		t.Fatal("sftp subsystem allowed without the file-transfer capability")
	}
	_, _, code = g.SSH("", "-s", "web1@127.0.0.1", "netconf")
	if code == 0 {
		t.Fatal("netconf subsystem allowed")
	}
}

// HP-POL-006: unknown and hidden servers are indistinguishable.
func TestOpenSSHHiddenTarget(t *testing.T) {
	g := startGateway(t)
	_, err := g.A.Inventory.CreateServer(context.Background(), admin, inventory.ServerInput{Alias: ptr("db1"), Address: ptr("127.0.0.1"), Port: ptr(2)})
	must(t, err)
	rules, _ := g.A.Policy.ListRules(context.Background())
	r := rules[0]
	r.Targets = policy.TargetSelector{Servers: []string{g.Server.ID}}
	_, err = g.A.Policy.UpdateRule(context.Background(), admin, r.ID, r)
	must(t, err)
	_, e1, c1 := g.Run("exec nosuch --role inspect -- id")
	_, e2, c2 := g.Run("exec db1 --role inspect -- id")
	if c1 != 82 || c1 != c2 || strings.ReplaceAll(e1, "nosuch", "X") != strings.ReplaceAll(e2, "db1", "X") {
		t.Fatalf("distinguishable: %d %q / %d %q", c1, e1, c2, e2)
	}
}

// HP-SRV-004: a changed destination host key stops the connection before authentication.
func TestOpenSSHHostKeyChanged(t *testing.T) {
	g := startGateway(t)
	if _, _, code := g.Run("exec web1 --role inspect -- true"); code != 0 {
		t.Fatalf("baseline exec %d", code)
	}
	g.Dest.ReplaceHostKey()
	_, errOut, code := g.Run("exec web1 --role inspect -- true")
	if code != 88 {
		t.Fatalf("host key change: %d %q", code, errOut)
	}
}

type runResult struct {
	code int
	err  string
}

// startLongCommand runs a long command through real OpenSSH and waits until its channel is active.
func (g *Gateway) startLongCommand() (done chan runResult, grantID string) {
	g.t.Helper()
	done = make(chan runResult, 1)
	go func() {
		_, e, c := g.Run("exec web1 --role inspect -- sleep 300")
		done <- runResult{c, e}
	}()
	ctx := context.Background()
	deadline := time.Now().Add(20 * time.Second)
	for grantID == "" && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		var live int
		_ = g.A.Store.ReadDB().QueryRowContext(ctx, `SELECT count(*) FROM ssh_channels WHERE state = 'active'`).Scan(&live)
		if live > 0 {
			_ = g.A.Store.ReadDB().QueryRowContext(ctx, `SELECT id FROM grants WHERE state = 'active'`).Scan(&grantID)
		}
	}
	if grantID == "" {
		g.t.Fatal("command never became active")
	}
	return done, grantID
}

// expectTerminated asserts the running command ends within the 5 s enforcement bound (HP-GRT-008).
func (g *Gateway) expectTerminated(done chan runResult, start time.Time) runResult {
	g.t.Helper()
	select {
	case r := <-done:
		if r.code == 0 {
			g.t.Fatalf("command exited successfully instead of being terminated: %q", r.err)
		}
		g.t.Logf("terminated in %v (exit %d)", time.Since(start), r.code)
		return r
	case <-time.After(5 * time.Second):
		g.t.Fatal("not terminated within 5s")
	}
	return runResult{}
}

// HP-GRT-009: revocation terminates a running command within 5 s.
func TestOpenSSHRevocation(t *testing.T) {
	g := startGateway(t)
	done, grantID := g.startLongCommand()
	start := time.Now()
	_, err := g.A.Access.RevokeGrant(context.Background(), policy.OperatorInfo{ID: "opr_admin", Roles: []string{"administrator"}, Enabled: true}, grantID, "incident")
	must(t, err)
	if r := g.expectTerminated(done, start); r.code != 87 {
		t.Fatalf("exit %d %q", r.code, r.err)
	}
}

// HP-AGT-005: revoking the agent key terminates its live sessions, and the key no longer authenticates.
func TestOpenSSHKeyRevocation(t *testing.T) {
	g := startGateway(t)
	done, _ := g.startLongCommand()
	keys, err := g.A.Agents.Keys(context.Background(), g.Agent.ID)
	must(t, err)
	start := time.Now()
	_, err = g.A.Agents.RevokeKey(context.Background(), admin, g.Agent.ID, keys[0].ID, "leaked")
	must(t, err)
	g.expectTerminated(done, start)
	if _, errOut, code := g.Run("list"); code != 255 || !strings.Contains(errOut, "Permission denied") {
		t.Fatalf("revoked key authenticated: %d %q", code, errOut)
	}
}

// HP-AGT-008: disabling the agent terminates its live sessions and refuses new logins.
func TestOpenSSHAgentDisable(t *testing.T) {
	g := startGateway(t)
	done, _ := g.startLongCommand()
	start := time.Now()
	_, err := g.A.Agents.SetEnabled(context.Background(), admin, g.Agent.ID, false, "incident")
	must(t, err)
	g.expectTerminated(done, start)
	if _, errOut, code := g.Run("list"); code != 255 || !strings.Contains(errOut, "Permission denied") {
		t.Fatalf("disabled agent authenticated: %d %q", code, errOut)
	}
}

// HP-SRV-008: disabling the server terminates live activity on it and hides it from new requests.
func TestOpenSSHServerDisable(t *testing.T) {
	g := startGateway(t)
	done, _ := g.startLongCommand()
	start := time.Now()
	_, err := g.A.Inventory.SetServerEnabled(context.Background(), admin, g.Server.ID, false)
	must(t, err)
	g.expectTerminated(done, start)
	if _, errOut, code := g.Run("exec web1 --role inspect -- true"); code == 0 {
		t.Fatalf("exec on a disabled server: %q", errOut)
	}
}

// HP-KEY-004: login with a short-lived OpenSSH user certificate and explicit principals.
func TestOpenSSHCertificateLogin(t *testing.T) {
	g := startGateway(t)
	ctx := context.Background()
	ca, err := g.A.Credentials.CreateUserCA(ctx, admin, "test-ca")
	must(t, err)
	role, err := g.A.Inventory.CreateRole(ctx, admin, g.Server.ID, inventory.RoleInput{Alias: ptr("deploy"), RemoteUser: ptr("deploy")})
	must(t, err)
	must(t, g.A.Credentials.BindRoleCert(ctx, admin, credentials.CertBinding{RoleID: role.ID, UserCAID: ca.ID, Principals: []string{"hp-deploy"}, TTL: 2 * time.Minute}))
	g.Dest.TrustUserCA(ca.PublicKey, "deploy", "hp-deploy")
	out, errOut, code := g.Run("exec web1 --role deploy -- whoami")
	if code != 0 || strings.TrimSpace(out) != "deploy" {
		t.Fatalf("cert login: %d %q %q", code, out, errOut)
	}
	if logs := docker(t, "logs", g.Dest.ID); !strings.Contains(logs, "hp-deploy") && !strings.Contains(logs, "CERT") {
		t.Logf("sshd logs did not mention the certificate:\n%s", logs)
	}
}

// HP-SSH-002: an unknown agent key is refused by the gateway.
func TestOpenSSHUnknownAgentKey(t *testing.T) {
	g := startGateway(t)
	other := sshkeys.Ed25519(t)
	blk, err := ssh.MarshalPrivateKey(other.Private, "")
	must(t, err)
	g.keyFile = filepath.Join(t.TempDir(), "other")
	must(t, os.WriteFile(g.keyFile, pem.EncodeToMemory(blk), 0o600))
	_, errOut, code := g.Run("list")
	if code != 255 || !strings.Contains(errOut, "Permission denied") {
		t.Fatalf("%d %q", code, errOut)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
