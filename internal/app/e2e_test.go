package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/recording"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshkeys"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshtest"
)

var admin = audit.Actor{Type: audit.ActorOperator, ID: "opr_admin"}

func ptr[T any](v T) *T { return &v }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

type gw struct {
	t      *testing.T
	a      *App
	addr   string
	key    sshkeys.Key
	dest   *sshtest.Server
	hostPK ssh.PublicKey
	srv    *inventory.Server
	role   *inventory.Role
	cancel context.CancelFunc
	done   chan error
}

// startGateway runs a full in-process gateway in front of an in-process destination, with an agent allowed to
// auto-approve exec on web1/inspect.
func startGateway(t *testing.T, tweaks ...func(*config.Config)) *gw {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Mode = "development"
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.KEK.File = ""
	cfg.Egress.AllowCIDRs = []string{"127.0.0.0/8"}
	cfg.Egress.AllowSpecialCIDRs = []string{"127.0.0.1/32"}
	cfg.Shutdown.DrainTimeout = config.Duration(500 * time.Millisecond)
	cfg.HTTP.Listen = ""
	for _, tw := range tweaks {
		tw(cfg)
	}
	ctx := context.Background()
	a, err := New(ctx, cfg, slog.New(slog.DiscardHandler))
	must(t, err)
	g := &gw{t: t, a: a, key: sshkeys.Ed25519(t), dest: sshtest.Start(t), done: make(chan error, 1)}

	_, err = a.Agents.Create(ctx, admin, agents.CreateInput{Name: "sre-bot", Groups: []string{"sre"}, PublicKeys: []string{g.key.AuthorizedLine("")}})
	must(t, err)
	host, port := g.dest.Addr()
	g.srv, err = a.Inventory.CreateServer(ctx, admin, inventory.ServerInput{Alias: ptr("web1"), Address: ptr(host), Port: ptr(port)})
	must(t, err)
	_, err = a.Inventory.AddHostIdentity(ctx, admin, g.srv.ID, g.dest.KnownHostsLine(0))
	must(t, err)
	g.role, err = a.Inventory.CreateRole(ctx, admin, g.srv.ID, inventory.RoleInput{Alias: ptr("inspect"), RemoteUser: ptr("ro")})
	must(t, err)
	cred, err := a.Credentials.Generate(ctx, admin, g.role.ID)
	must(t, err)
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cred.PublicKey))
	must(t, err)
	g.dest.Authorize(pk)
	_, err = a.Credentials.Probe(ctx, admin, cred.ID)
	must(t, err)
	_, err = a.Credentials.Activate(ctx, admin, cred.ID, false)
	must(t, err)
	_, err = a.Policy.CreateRule(ctx, admin, policy.Rule{Name: "sre", Effect: policy.EffectAllow, Level: policy.LevelAutoApprove, Enabled: true,
		AutoMaxDuration: time.Hour, Subjects: policy.SubjectSelector{AgentGroups: []string{"sre"}}, Targets: policy.TargetSelector{All: true},
		Roles: policy.RoleSelector{All: true}})
	must(t, err)
	keys, err := a.Credentials.GatewayHostKeys(ctx)
	must(t, err)
	g.hostPK, _, _, _, err = ssh.ParseAuthorizedKey([]byte(keys[0].PublicKey))
	must(t, err)

	ln, err := Listen(ctx, "127.0.0.1:0")
	must(t, err)
	g.addr = ln.Addr().String()
	sctx, cancel := context.WithCancel(ctx)
	g.cancel = cancel
	go func() { g.done <- a.Serve(sctx, ln) }()
	t.Cleanup(func() {
		g.stop()
		_ = a.Close()
	})
	return g
}

func (g *gw) stop() {
	if g.cancel == nil {
		return
	}
	g.cancel()
	g.cancel = nil
	select {
	case err := <-g.done:
		if err != nil {
			g.t.Errorf("serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		g.t.Error("gateway did not stop")
	}
}

// recordingsFinalized waits until n segments exist and none is open, then verifies them: the agent sees the exit
// status a moment before the recorder commits the final frame.
func (g *gw) recordingsFinalized(n int) *recording.VerifyResult {
	g.t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var total, open int
		must(g.t, g.a.Store.ReadDB().QueryRowContext(ctx, `SELECT count(*), coalesce(sum(state = 'open'), 0) FROM recording_segments`).Scan(&total, &open))
		if total >= n && open == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	vr, err := g.a.Recording.Verify(ctx, "")
	must(g.t, err)
	return vr
}

func (g *gw) client(key sshkeys.Key) (*ssh.Client, error) {
	return ssh.Dial("tcp", g.addr, &ssh.ClientConfig{User: "agent", Auth: []ssh.AuthMethod{ssh.PublicKeys(key.Signer)},
		HostKeyCallback: ssh.FixedHostKey(g.hostPK), Timeout: 5 * time.Second})
}

// run executes one gateway command and returns stdout, stderr and the exit status.
func (g *gw) run(cmd string) (string, string, int) {
	g.t.Helper()
	c, err := g.client(g.key)
	must(g.t, err)
	defer c.Close()
	s, err := c.NewSession()
	must(g.t, err)
	defer s.Close()
	var out, errb bytes.Buffer
	s.Stdout, s.Stderr = &out, &errb
	err = s.Run(cmd)
	code := 0
	var ee *ssh.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitStatus()
	case err != nil:
		g.t.Fatalf("%s: %v", cmd, err)
	}
	return out.String(), errb.String(), code
}

// HP-SSH-001/020/021, HP-REC-001: list, exec with auto-approval, exit status passthrough and a verified recording.
func TestGatewayExecEndToEnd(t *testing.T) {
	g := startGateway(t)
	out, errOut, code := g.run("list --json")
	if code != 0 || !strings.Contains(out, `"web1"`) {
		t.Fatalf("list: %d %q %q", code, out, errOut)
	}
	g.dest.Exec = func(cmd string, _ io.Reader, stdout, stderr io.Writer) uint32 {
		_, _ = io.WriteString(stdout, "out:"+cmd+"\n")
		_, _ = io.WriteString(stderr, "err line\n")
		return 7
	}
	out, errOut, code = g.run("exec web1 --role inspect --duration 5m --reason 'check disk' -- df -h '/var'")
	if code != 7 || out != "out:df -h '/var'\n" || !strings.Contains(errOut, "err line") {
		t.Fatalf("exec: %d %q %q", code, out, errOut)
	}
	if l := g.dest.Logins(); len(l) == 0 || l[len(l)-1].User != "ro" {
		t.Fatalf("destination logins %+v", l)
	}
	// The grant is reused for a second exec without a new request.
	_, _, code = g.run("exec web1 --role inspect -- true")
	if code != 7 {
		t.Fatalf("second exec %d", code)
	}
	if vr := g.recordingsFinalized(2); !vr.OK || len(vr.Segments) != 2 {
		t.Fatalf("recordings: %+v", vr)
	}
}

// HP-POL-006, HP-SSH-018: hidden and unknown targets look identical.
func TestGatewayHiddenTarget(t *testing.T) {
	g := startGateway(t)
	_, err := g.a.Inventory.CreateServer(context.Background(), admin, inventory.ServerInput{Alias: ptr("db1"), Address: ptr("127.0.0.1"), Port: ptr(2222)})
	must(t, err)
	_, e1, c1 := g.run("exec nosuch -- id")
	_, e2, c2 := g.run("exec db1 -- id")
	if c1 != c2 || c1 == 0 || strings.ReplaceAll(e1, "nosuch", "X") != strings.ReplaceAll(e2, "db1", "X") {
		t.Fatalf("distinguishable: %d %q / %d %q", c1, e1, c2, e2)
	}
}

// HP-SSH-001/003: unknown keys are rejected at authentication.
func TestGatewayRejectsUnknownKey(t *testing.T) {
	g := startGateway(t)
	if _, err := g.client(sshkeys.Ed25519(t)); err == nil {
		t.Fatal("unknown key authenticated")
	}
}

// HP-SSH-007: port forwarding, non-session channels and subsystems other than sftp are refused; sftp itself fails
// unless the SSH user names a server with a file-transfer role.
func TestGatewayDeniesForwarding(t *testing.T) {
	g := startGateway(t)
	c, err := g.client(g.key)
	must(t, err)
	defer c.Close()
	if _, err := c.Dial("tcp", "127.0.0.1:22"); err == nil {
		t.Fatal("direct-tcpip allowed")
	}
	if _, err := c.Listen("tcp", "127.0.0.1:0"); err == nil {
		t.Fatal("tcpip-forward allowed")
	}
	s, err := c.NewSession()
	must(t, err)
	if err := s.RequestSubsystem("netconf"); err == nil {
		t.Fatal("netconf subsystem allowed")
	}
	_ = s.Close()
	s, err = c.NewSession()
	must(t, err)
	stderr, err := s.StderrPipe()
	must(t, err)
	must(t, s.RequestSubsystem("sftp"))
	// ssh.Session cannot Wait after RequestSubsystem; the gateway's refusal on stderr ends with the channel.
	if msg, _ := io.ReadAll(stderr); !strings.Contains(string(msg), "not found or not permitted") {
		t.Fatalf("sftp with an SSH user that is not a server: %q", msg)
	}
}

// HP-GRT-009, HP-SES-004: revoking a grant terminates the running channel within the enforcement bound.
func TestGatewayRevocationTerminates(t *testing.T) {
	g := startGateway(t)
	started := make(chan struct{})
	var once sync.Once
	g.dest.Exec = func(_ string, stdin io.Reader, stdout, _ io.Writer) uint32 {
		once.Do(func() { close(started) })
		_, _ = io.Copy(io.Discard, stdin) // runs until the gateway closes the channel
		return 0
	}
	c, err := g.client(g.key)
	must(t, err)
	defer c.Close()
	s, err := c.NewSession()
	must(t, err)
	pr, pw := io.Pipe() // stdin that stays open
	defer pw.Close()
	s.Stdin = pr
	done := make(chan error, 1)
	go func() { done <- s.Run("exec web1 --role inspect -- sleep 1000") }()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("exec never started")
	}
	ags, err := g.a.Agents.List(context.Background())
	must(t, err)
	grants, err := g.a.Access.ActiveGrantsForAgent(context.Background(), ags[0].ID)
	must(t, err)
	if len(grants) != 1 {
		t.Fatalf("grants %d", len(grants))
	}
	t0 := time.Now()
	_, err = g.a.Access.RevokeGrant(context.Background(), policy.OperatorInfo{ID: "opr_admin", Roles: []string{"administrator"}, Enabled: true}, grants[0].ID, "incident")
	must(t, err)
	select {
	case err := <-done:
		var ee *ssh.ExitError
		if !errors.As(err, &ee) || ee.ExitStatus() == 0 {
			t.Fatalf("expected gateway termination exit, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("channel not terminated within 5s of revocation")
	}
	t.Logf("terminated %v after revoke", time.Since(t0))
}

// HP-OPS-002: shutdown drains and terminates remaining sessions.
func TestGatewayShutdownTerminates(t *testing.T) {
	g := startGateway(t)
	started := make(chan struct{})
	g.dest.Exec = func(_ string, stdin io.Reader, _, _ io.Writer) uint32 {
		close(started)
		_, _ = io.Copy(io.Discard, stdin)
		return 0
	}
	c, err := g.client(g.key)
	must(t, err)
	defer c.Close()
	s, err := c.NewSession()
	must(t, err)
	pr, pw := io.Pipe() // stdin that stays open
	defer pw.Close()
	s.Stdin = pr
	done := make(chan error, 1)
	go func() { done <- s.Run("exec web1 --role inspect -- sleep 1000") }()
	<-started
	g.stop()
	select {
	case err := <-done:
		t.Logf("session ended: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("session survived shutdown")
	}
	if _, err := net.DialTimeout("tcp", g.addr, time.Second); err == nil {
		t.Fatal("listener still accepting after shutdown")
	}
}

// HP-SRV-004, HP-SSH-015: a destination presenting an unenrolled host key is refused (exit 88) and nothing runs.
func TestGatewayHostKeyMismatch(t *testing.T) {
	g := startGateway(t)
	impostor := sshtest.Start(t)
	host, port := impostor.Addr()
	_, err := g.a.Inventory.UpdateServer(context.Background(), admin, g.srv.ID, inventory.ServerInput{Version: g.srv.Version, Address: ptr(host), Port: ptr(port)})
	must(t, err)
	ran := false
	impostor.Exec = func(string, io.Reader, io.Writer, io.Writer) uint32 { ran = true; return 0 }
	_, errOut, code := g.run("exec web1 --role inspect -- id")
	if code != 88 || ran || len(impostor.Logins()) != 0 {
		t.Fatalf("code %d ran=%v stderr %q", code, ran, errOut)
	}
	// The channel row says why, without the address.
	var detail string
	var gw int
	must(t, g.a.Store.ReadDB().QueryRowContext(context.Background(), `SELECT close_detail, gateway_exit_code FROM ssh_channels WHERE state = 'failed'`).Scan(&detail, &gw))
	if !strings.Contains(detail, "host key") || gw != 88 || strings.Contains(detail, host) {
		t.Fatalf("close_detail %q gateway_exit_code %d", detail, gw)
	}
}

// HP-SSH-022: when a reason is required and there is no PTY to prompt on, the gateway fails with exit 90.
func TestGatewayReasonRequiredWithoutPTY(t *testing.T) {
	g := startGateway(t)
	ctx := context.Background()
	rules, err := g.a.Policy.ListRules(ctx)
	must(t, err)
	r := rules[0]
	r.Level, r.AutoMaxDuration, r.RequireReason = policy.LevelRequestable, 0, true
	_, err = g.a.Policy.UpdateRule(ctx, admin, r.ID, r)
	must(t, err)
	_, errOut, code := g.run("exec web1 --role inspect -- id")
	if code != 90 || !strings.Contains(errOut, `"exit_code":90`) {
		t.Fatalf("code %d stderr %q", code, errOut)
	}
	// With a reason and --no-wait the request is created and left pending (exit 86 wait timeout is not reached).
	out, errOut, code := g.run("request web1 --role inspect --reason 'disk alert' --no-wait --json")
	if code != 0 || !strings.Contains(out, `"pending"`) {
		t.Fatalf("request: %d %q %q", code, out, errOut)
	}
}

// HP-SSH-006/008: an interactive PTY shell is proxied and recorded as a terminal session.
func TestGatewayPTYShell(t *testing.T) {
	g := startGateway(t)
	c, err := g.client(g.key)
	must(t, err)
	defer c.Close()
	s, err := c.NewSession()
	must(t, err)
	must(t, s.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{}))
	pr, pw := io.Pipe()
	var out bytes.Buffer
	var mu sync.Mutex
	s.Stdin = pr
	s.Stdout = writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return out.Write(p) })
	must(t, s.Start("connect web1 --role inspect"))
	_, _ = pw.Write([]byte("hello-pty\n"))
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		got := out.String()
		mu.Unlock()
		if strings.Contains(got, "hello-pty") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("echo not seen: %q", got)
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = pw.Close()
	if err := s.Wait(); err != nil {
		t.Fatalf("shell exit: %v", err)
	}
	if vr := g.recordingsFinalized(1); !vr.OK || len(vr.Segments) != 1 {
		t.Fatalf("%+v", vr)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// HP-SSH-017..021: informational commands and the request → wait → approve/deny/cancel lifecycle over SSH.
func TestGatewayRequestLifecycle(t *testing.T) {
	g := startGateway(t)
	ctx := context.Background()
	rules, err := g.a.Policy.ListRules(ctx)
	must(t, err)
	r := rules[0]
	r.Level, r.AutoMaxDuration = policy.LevelRequestable, 0
	_, err = g.a.Policy.UpdateRule(ctx, admin, r.ID, r)
	must(t, err)
	opID := "opr_01aaaaaaaaaaaaaaaaaaaaaaaa"
	// Decisions re-read the operator in the decision transaction (SR-23): the approver must be a real operator.
	must(t, g.a.Store.W().Exec(ctx, `INSERT INTO operators (id, email, display_name, enabled, provisioned_via, created_at, created_by, updated_at)
		VALUES (?, 'approver@example.com', 'Approver', 1, 'admin', 1, 'test', 1)`, opID))
	must(t, g.a.Store.W().Exec(ctx, `INSERT INTO operator_roles (operator_id, role, source) VALUES (?, 'approver', 'manual')`, opID))
	_, err = g.a.Policy.CreateApproverRule(ctx, admin, policy.ApproverRule{Name: "oncall", Enabled: true,
		Operators: policy.OperatorSelector{Operators: []string{opID}}, Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}})
	must(t, err)
	approver := policy.OperatorInfo{ID: opID, Roles: []string{"approver"}, Enabled: true}

	for _, cmd := range []string{"roles web1 --json", "roles web1", "list", "whoami --json", "whoami", "version --json", "version", "help", "help exec", "sessions", "sessions --all --json"} {
		if out, errOut, code := g.run(cmd); code != 0 || out == "" {
			t.Fatalf("%s: %d %q %q", cmd, code, out, errOut)
		}
	}
	if _, _, code := g.run("list --bogus"); code != 81 {
		t.Fatalf("unknown command exit %d", code)
	}

	reqID := func(out string) string {
		var doc struct {
			Request struct{ ID, State string }
		}
		must(t, json.Unmarshal([]byte(out), &doc))
		return doc.Request.ID
	}
	// Create, inspect and cancel.
	out, errOut, code := g.run("request web1 --role inspect --reason 'disk alert' --no-wait --json")
	if code != 0 {
		t.Fatalf("request: %d %q", code, errOut)
	}
	id := reqID(out)
	if out, _, code = g.run("status " + id + " --json"); code != 0 || !strings.Contains(out, `"pending"`) {
		t.Fatalf("status: %d %q", code, out)
	}
	if out, _, code = g.run("cancel " + id + " --json"); code != 0 || !strings.Contains(out, `"canceled"`) {
		t.Fatalf("cancel: %d %q", code, out)
	}

	// Waiting request approved by an operator while the agent waits.
	decide := func(approve bool) {
		go func() {
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				time.Sleep(100 * time.Millisecond)
				var pending string
				if err := g.a.Store.ReadDB().QueryRowContext(ctx, `SELECT id FROM access_requests WHERE state = 'pending'`).Scan(&pending); err != nil {
					continue
				}
				_, _ = g.a.Access.Decide(ctx, access.DecideInput{RequestID: pending, Approve: approve, Operator: approver, Channel: access.ChannelWeb})
				return
			}
		}()
	}
	decide(false)
	if _, _, code = g.run("request web1 --role inspect --reason 'disk alert' --wait --json"); code != 83 {
		t.Fatalf("denied request exit %d", code)
	}
	decide(true)
	if out, errOut, code = g.run("request web1 --role inspect --reason 'disk alert' --wait --json"); code != 0 || !strings.Contains(out, `"active"`) {
		t.Fatalf("approved request: %d %q %q", code, out, errOut)
	}
	if out, _, code = g.run("sessions --json"); code != 0 || !strings.Contains(out, "web1") {
		t.Fatalf("sessions: %d %q", code, out)
	}
	if _, _, code = g.run("exec web1 --role inspect -- id"); code != 0 {
		t.Fatalf("exec with approved grant: %d", code)
	}
}

// requestable switches the test rule to manual approval.
func (g *gw) requestable() {
	g.t.Helper()
	ctx := context.Background()
	rules, err := g.a.Policy.ListRules(ctx)
	must(g.t, err)
	r := rules[0]
	r.Level, r.AutoMaxDuration = policy.LevelRequestable, 0
	_, err = g.a.Policy.UpdateRule(ctx, admin, r.ID, r)
	must(g.t, err)
}

func (g *gw) pendingRequests() int {
	g.t.Helper()
	var n int
	must(g.t, g.a.Store.ReadDB().QueryRowContext(context.Background(), `SELECT count(*) FROM access_requests WHERE state = 'pending'`).Scan(&n))
	return n
}

// HP-SSH-008: only allowlisted environment variables reach the destination.
func TestGatewayEnvAllowlist(t *testing.T) {
	g := startGateway(t)
	c, err := g.client(g.key)
	must(t, err)
	defer c.Close()
	s, err := c.NewSession()
	must(t, err)
	_ = s.Setenv("LANG", "C.UTF-8")
	_ = s.Setenv("LC_ALL", "C")
	_ = s.Setenv("LD_PRELOAD", "/tmp/evil.so")
	_ = s.Setenv("AWS_SECRET_ACCESS_KEY", "x")
	must(t, s.Run("exec web1 -- env"))
	got := map[string]string{}
	for _, kv := range g.dest.Envs() {
		got[kv[0]] = kv[1]
	}
	if got["LANG"] != "C.UTF-8" || got["LC_ALL"] != "C" || got["LD_PRELOAD"] != "" || got["AWS_SECRET_ACCESS_KEY"] != "" {
		t.Fatalf("forwarded env %v", got)
	}
}

// HP-SSH-010: exit-signal is propagated as exit-signal.
func TestGatewayExitSignal(t *testing.T) {
	g := startGateway(t)
	g.dest.ExitSignal = func(string) string { return "KILL" }
	c, err := g.client(g.key)
	must(t, err)
	defer c.Close()
	s, err := c.NewSession()
	must(t, err)
	err = s.Run("exec web1 -- kill -9 $$")
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.Signal() != "KILL" {
		t.Fatalf("expected exit-signal KILL, got %v", err)
	}
}

// HP-SSH-022: the role is implicit only when exactly one is available; otherwise exit 81 lists the choices.
func TestGatewayImplicitRole(t *testing.T) {
	g := startGateway(t)
	if _, errOut, code := g.run("exec web1 -- id"); code != 0 {
		t.Fatalf("single role: %d %q", code, errOut)
	}
	_, err := g.a.Inventory.CreateRole(context.Background(), admin, g.srv.ID, inventory.RoleInput{Alias: ptr("deploy"), RemoteUser: ptr("deploy")})
	must(t, err)
	// inspect now has an active grant and deploy is requestable: two candidates, so the agent must choose.
	_, errOut, code := g.run("exec web1 -- id")
	if code != 81 || !strings.Contains(errOut, "inspect") || !strings.Contains(errOut, "deploy") {
		t.Fatalf("ambiguous role: %d %q", code, errOut)
	}
}

// HP-SSH-020/021: a wait that times out exits 86 and leaves the request pending; disconnecting mid-wait does too.
func TestGatewayWaitTimeoutAndDisconnect(t *testing.T) {
	g := startGateway(t)
	g.requestable()
	_, errOut, code := g.run("exec web1 --reason 'disk alert' --wait-timeout 1s -- id")
	if code != 86 || !strings.Contains(errOut, "req_") || g.pendingRequests() != 1 {
		t.Fatalf("wait timeout: %d %q pending=%d", code, errOut, g.pendingRequests())
	}
	c, err := g.client(g.key)
	must(t, err)
	s, err := c.NewSession()
	must(t, err)
	var stderr syncBuf
	s.Stderr = &stderr
	must(t, s.Start("exec web1 --role inspect --reason 'second' -- id"))
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(stderr.String(), "req_") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	_ = c.Close()
	time.Sleep(200 * time.Millisecond)
	if g.pendingRequests() != 1 { // deduplicated with the first request, still pending
		t.Fatalf("pending after disconnect: %d", g.pendingRequests())
	}
}

// HP-SSH-012: an idle session is terminated after the idle timeout.
func TestGatewayIdleTimeout(t *testing.T) {
	g := startGateway(t, func(c *config.Config) { c.SSH.IdleTimeout = config.Duration(400 * time.Millisecond) })
	g.dest.Exec = func(_ string, stdin io.Reader, _, _ io.Writer) uint32 {
		_, _ = io.Copy(io.Discard, stdin)
		return 0
	}
	c, err := g.client(g.key)
	must(t, err)
	defer c.Close()
	s, err := c.NewSession()
	must(t, err)
	pr, pw := io.Pipe()
	defer pw.Close()
	s.Stdin = pr
	start := time.Now()
	err = s.Run("exec web1 -- cat")
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 87 || time.Since(start) > 5*time.Second {
		t.Fatalf("idle: %v after %v", err, time.Since(start))
	}
}

// HP-SSH-013: unauthenticated connections are bounded per source IP.
func TestGatewayPreAuthLimit(t *testing.T) {
	g := startGateway(t, func(c *config.Config) { c.SSH.MaxUnauthenticatedPerIP = 1 })
	idle, err := net.Dial("tcp", g.addr)
	must(t, err)
	time.Sleep(100 * time.Millisecond)
	if c, err := g.client(g.key); err == nil {
		_ = c.Close()
		t.Fatal("second pre-auth connection accepted while the first is unauthenticated")
	}
	_ = idle.Close()
	time.Sleep(100 * time.Millisecond)
	c, err := g.client(g.key)
	must(t, err)
	_ = c.Close()
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// HP-SSH-015: sessions release their goroutines (and with them connections and pipes) when they end.
func TestGatewayNoGoroutineLeak(t *testing.T) {
	g := startGateway(t)
	g.run("exec web1 -- warmup")
	time.Sleep(200 * time.Millisecond)
	base := runtime.NumGoroutine()
	for range 30 {
		if _, _, code := g.run("exec web1 -- true"); code != 0 {
			t.Fatalf("exit %d", code)
		}
	}
	var n int
	for range 50 {
		time.Sleep(100 * time.Millisecond)
		if n = runtime.NumGoroutine(); n <= base+5 {
			return
		}
	}
	buf := make([]byte, 1<<20)
	t.Fatalf("goroutines %d → %d after 30 sessions\n%s", base, n, buf[:runtime.Stack(buf, true)])
}

// HP-SSH-001/004: only public-key auth with allowed signature algorithms; SHA-1 ssh-rsa and passwords are refused.
func TestGatewayAuthMethodsAndAlgorithms(t *testing.T) {
	g := startGateway(t)
	cfg := func(auth ssh.AuthMethod) *ssh.ClientConfig {
		return &ssh.ClientConfig{User: "agent", Auth: []ssh.AuthMethod{auth}, HostKeyCallback: ssh.FixedHostKey(g.hostPK), Timeout: 5 * time.Second}
	}
	if c, err := ssh.Dial("tcp", g.addr, cfg(ssh.Password("hunter2"))); err == nil {
		_ = c.Close()
		t.Fatal("password auth accepted")
	}
	rsa := sshkeys.RSA(t, 3072)
	ag, err := g.a.Agents.List(context.Background())
	must(t, err)
	_, err = g.a.Agents.AddKey(context.Background(), admin, ag[0].ID, rsa.AuthorizedLine(""))
	must(t, err)
	sha1, err := ssh.NewSignerWithAlgorithms(rsa.Signer.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSA})
	must(t, err)
	if c, err := ssh.Dial("tcp", g.addr, cfg(ssh.PublicKeys(sha1))); err == nil {
		_ = c.Close()
		t.Fatal("ssh-rsa (SHA-1) signature accepted")
	}
	sha512, err := ssh.NewSignerWithAlgorithms(rsa.Signer.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSASHA512})
	must(t, err)
	c, err := ssh.Dial("tcp", g.addr, cfg(ssh.PublicKeys(sha512)))
	must(t, err)
	_ = c.Close()
}

// HP-OPS-001, HP-OBS-004: health/readiness endpoints and Prometheus metrics fed by real SSH traffic.
func TestGatewayHealthAndMetrics(t *testing.T) {
	var httpLn net.Listener
	g := startGateway(t, func(c *config.Config) {
		c.Telemetry.Prometheus = true
		var err error
		httpLn, err = net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test listener
		must(t, err)
		c.PublicURL = "http://" + httpLn.Addr().String()
	})
	// Serve the infrastructure endpoints of the running gateway on the reserved listener.
	base := "http://" + httpLn.Addr().String()
	go func() { _ = http.Serve(httpLn, g.a.RootHandlerForTest()) }() //nolint:gosec // test server
	get := func(path string) (int, string) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, base+path, nil)
		res, err := http.DefaultClient.Do(req)
		must(t, err)
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	if code, _ := get("/healthz"); code != 200 {
		t.Fatalf("healthz %d", code)
	}
	var code int
	var body string
	for range 50 {
		if code, body = get("/readyz"); code == 200 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if code != 200 || !strings.Contains(body, `"status":"ready"`) {
		t.Fatalf("readyz %d %s", code, body)
	}
	if _, _, c := g.run("exec web1 -- true"); c != 0 {
		t.Fatalf("exec %d", c)
	}
	if _, err := g.client(sshkeys.Ed25519(t)); err == nil {
		t.Fatal("unknown key accepted")
	}
	_, metrics := get("/metrics")
	for _, want := range []string{"hallpass_ssh_connections_total", "hallpass_ssh_auth_failures_total", "hallpass_access_grants_active",
		"hallpass_recording_records_total", "hallpass_store_tx_duration_seconds", "hallpass_http_requests_total", "hallpass_readiness_state"} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metric %s missing", want)
		}
	}
	g.stop()
	if code, _ := get("/readyz"); code != 503 {
		t.Fatalf("readyz after shutdown %d", code)
	}
}

// HP-AGT-007: an agent restricted to source CIDRs cannot authenticate from elsewhere (uniform rejection).
func TestGatewaySourceCIDR(t *testing.T) {
	g := startGateway(t)
	ctx := context.Background()
	ags, err := g.a.Agents.List(ctx)
	must(t, err)
	_, err = g.a.Agents.Update(ctx, admin, ags[0].ID, agents.UpdateInput{Version: ags[0].Version, SourceCIDRs: ptr([]string{"10.0.0.0/8"})})
	must(t, err)
	if c, err := g.client(g.key); err == nil {
		_ = c.Close()
		t.Fatal("agent authenticated from outside its source CIDRs")
	}
	_, err = g.a.Agents.Update(ctx, admin, ags[0].ID, agents.UpdateInput{Version: ags[0].Version + 1, SourceCIDRs: ptr([]string{"127.0.0.0/8"})})
	must(t, err)
	c, err := g.client(g.key)
	must(t, err)
	_ = c.Close()
}

// HP-CRY-002: every registered sealed column exists and re-seals after rotation without breaking reads.
func TestResealRegistry(t *testing.T) {
	g := startGateway(t)
	ctx := context.Background()
	if _, err := g.a.Keyring.Rotate(ctx, g.a.Store, keyring.PurposeCredential); err != nil {
		t.Fatal(err)
	}
	n, err := g.a.Keyring.ResealColumns(ctx, g.a.Store, SealedColumns(), 1000)
	if err != nil || n == 0 { // the gateway host key and the role's login key are credential-sealed
		t.Fatalf("resealed %d: %v", n, err)
	}
	if _, _, c := g.run("exec web1 -- true"); c != 0 { // re-sealed login credential still works
		t.Fatalf("exec after reseal: %d", c)
	}
	if n, err := g.a.Keyring.ResealColumns(ctx, g.a.Store, SealedColumns(), 1000); err != nil || n != 0 {
		t.Fatalf("second pass %d %v", n, err)
	}
}

// HP-SSH-022: with a PTY and several candidate roles the gateway asks; an invalid answer fails like a non-PTY call.
func TestGatewayPTYRolePrompt(t *testing.T) {
	g := startGateway(t)
	_, err := g.a.Inventory.CreateRole(context.Background(), admin, g.srv.ID, inventory.RoleInput{Alias: ptr("deploy"), RemoteUser: ptr("deploy")})
	must(t, err)
	if _, _, code := g.run("exec web1 --role inspect -- true"); code != 0 { // inspect gets an active grant; deploy stays requestable
		t.Fatalf("baseline %d", code)
	}
	prompt := func(answer func(menu string) string) (string, error) {
		c, err := g.client(g.key)
		must(t, err)
		defer c.Close()
		s, err := c.NewSession()
		must(t, err)
		must(t, s.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{}))
		pr, pw := io.Pipe()
		var out bytes.Buffer
		var mu sync.Mutex
		w := writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return out.Write(p) })
		s.Stdin, s.Stdout, s.Stderr = pr, w, w
		must(t, s.Start("exec web1 -- echo chosen-ok"))
		deadline := time.Now().Add(5 * time.Second)
		for {
			mu.Lock()
			got := out.String()
			mu.Unlock()
			if strings.Contains(got, "role number:") {
				_, _ = pw.Write([]byte(answer(got) + "\r"))
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no role prompt: %q", got)
			}
			time.Sleep(20 * time.Millisecond)
		}
		err = s.Wait()
		_ = pw.Close()
		mu.Lock()
		defer mu.Unlock()
		return out.String(), err
	}
	out, err := prompt(func(menu string) string {
		for _, line := range strings.Split(menu, "\n") {
			if n, name, ok := strings.Cut(strings.TrimSpace(line), ") "); ok && strings.HasPrefix(name, "inspect") {
				return n
			}
		}
		t.Fatalf("inspect not offered: %q", menu)
		return ""
	})
	if err != nil || !strings.Contains(out, "deploy") || !strings.Contains(out, "chosen-ok") {
		t.Fatalf("chosen role: %v %q", err, out)
	}
	_, err = prompt(func(string) string { return "9" })
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 81 {
		t.Fatalf("invalid choice: %v", err)
	}
}

// HP-SSH-012: keepalives on the destination leg detect a hung destination and end the channel (exit 88).
func TestGatewayDestinationKeepalive(t *testing.T) {
	g := startGateway(t, func(c *config.Config) {
		c.SSH.KeepaliveInterval = config.Duration(100 * time.Millisecond)
		c.SSH.KeepaliveMaxMissed = 2
	})
	g.dest.Exec = func(_ string, stdin io.Reader, _, _ io.Writer) uint32 {
		_, _ = io.Copy(io.Discard, stdin)
		return 0
	}
	c, err := g.client(g.key)
	must(t, err)
	defer c.Close()
	s, err := c.NewSession()
	must(t, err)
	pr, pw := io.Pipe()
	defer pw.Close()
	s.Stdin = pr
	must(t, s.Start("exec web1 -- cat"))
	time.Sleep(500 * time.Millisecond) // a responsive destination survives several probes
	g.dest.Unresponsive.Store(true)
	start := time.Now()
	err = s.Wait()
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 88 || time.Since(start) > 3*time.Second {
		t.Fatalf("hung destination: %v after %v", err, time.Since(start))
	}
}

// HP-SSH-012: keepalives on the agent leg close connections whose client stopped answering.
func TestGatewayAgentKeepalive(t *testing.T) {
	g := startGateway(t, func(c *config.Config) {
		c.SSH.KeepaliveInterval = config.Duration(100 * time.Millisecond)
		c.SSH.KeepaliveMaxMissed = 2
	})
	raw, err := net.Dial("tcp", g.addr)
	must(t, err)
	defer raw.Close()
	conn, _, reqs, err := ssh.NewClientConn(raw, g.addr, &ssh.ClientConfig{User: "agent", Auth: []ssh.AuthMethod{ssh.PublicKeys(g.key.Signer)},
		HostKeyCallback: ssh.FixedHostKey(g.hostPK), Timeout: 5 * time.Second})
	must(t, err)
	defer conn.Close()
	go func() {
		for range reqs { // read keepalives but never answer: a hung agent
		}
	}()
	done := make(chan error, 1)
	go func() { done <- conn.Wait() }()
	select {
	case err := <-done:
		t.Logf("connection closed: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("silent agent connection not closed")
	}
}

// A shell without a PTY works (piped scripts) but tells the agent on stderr that it is non-interactive.
func TestGatewayShellWithoutPTYHint(t *testing.T) {
	g := startGateway(t)
	c, err := g.client(g.key)
	must(t, err)
	defer c.Close()
	s, err := c.NewSession()
	must(t, err)
	var out, errb syncBuf
	s.Stdin, s.Stdout, s.Stderr = strings.NewReader("echo piped\n"), &out, &errb
	must(t, s.Run("connect web1 --role inspect"))
	if !strings.Contains(out.String(), "echo piped") || !strings.Contains(errb.String(), "ssh -t") {
		t.Fatalf("stdout %q stderr %q", out.String(), errb.String())
	}
}

// HP-SSH-026: repeated failed authentication bans the source; banned sources are cut before the SSH banner; lifting
// the ban restores access, and valid agents from other sources are unaffected.
func TestGatewaySSHBan(t *testing.T) {
	g := startGateway(t, func(c *config.Config) {
		c.SSH.Ban = config.SSHBanConfig{Enabled: true, MaxFailures: 3, Window: config.Duration(time.Minute), Duration: config.Duration(time.Hour),
			MaxDuration: config.Duration(time.Hour)}
	})
	stranger := sshkeys.Ed25519(t)
	for i := range 3 {
		if _, err := g.client(stranger); err == nil {
			t.Fatalf("attempt %d: unknown key authenticated", i)
		}
	}
	// The server records the failure after the client gave up: wait for the ban to land.
	deadline := time.Now().Add(5 * time.Second)
	for !g.a.Bans.Banned(netip.MustParseAddr("127.0.0.1")) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	nc, err := net.Dial("tcp", g.addr)
	must(t, err)
	defer nc.Close()
	_ = nc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	if n, _ := nc.Read(buf); n != 0 {
		t.Fatalf("banned source got a banner: %q", buf[:n])
	}
	if _, err := g.client(g.key); err == nil {
		t.Fatal("banned source authenticated with a valid key")
	}
	bans, err := g.a.Bans.List(context.Background())
	if err != nil || len(bans) != 1 || bans[0].Address != "127.0.0.1" {
		t.Fatalf("bans %+v %v", bans, err)
	}
	must(t, g.a.Bans.Lift(context.Background(), admin, bans[0].ID))
	if _, _, code := g.run("list"); code != 0 {
		t.Fatalf("after lift: exit %d", code)
	}
}

type limitRecorder struct {
	code int
	h    http.Header
}

func (l *limitRecorder) Header() http.Header {
	if l.h == nil {
		l.h = http.Header{}
	}
	return l.h
}
func (l *limitRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (l *limitRecorder) WriteHeader(c int)           { l.code = c }

// SR-19 (HP-REC-012): a flood of random collector IDs does not push an active collector into a saturated overflow
// window; its batches still reach the handler.
func TestCollectorLimitIgnoresUnknownIDs(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })
	h := destauditLimit(time.Now, func(context.Context) ([]string, error) { return []string{"dac_real"}, nil }, next)
	post := func(id string) int {
		r, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "/hooks/destaudit/"+id, strings.NewReader("{}"))
		r.SetPathValue("collector_id", id)
		w := &limitRecorder{code: http.StatusOK}
		h.ServeHTTP(w, r)
		return w.code
	}
	for i := range 5000 {
		post("dac_bogus" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + string(rune('a'+i/676%26)))
	}
	if code := post("dac_real"); code != http.StatusAccepted {
		t.Fatalf("active collector refused after a random-ID flood: %d", code)
	}
}
