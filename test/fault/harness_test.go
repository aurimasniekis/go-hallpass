//go:build fault

// Package fault runs the fault-injection catalog (TEST_STRATEGY.md §4, HP-TST-005) against an in-process gateway, an
// in-process destination and, for crash scenarios, a gateway child process killed with SIGKILL. See README.md.
package fault

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/app"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/sshproxy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshkeys"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshtest"
)

var admin = audit.Actor{Type: audit.ActorOperator, ID: "opr_admin"}

var adminOp = policy.OperatorInfo{ID: "opr_admin", Roles: []string{"administrator"}, Enabled: true}

// Environment of a gateway child process (crash scenarios).
const (
	envChild = "HALLPASS_FAULT_CHILD"
	envDir   = "HALLPASS_FAULT_DIR"
	envAddr  = "HALLPASS_FAULT_ADDR_FILE"
	envHook  = "HALLPASS_FAULT_HOOK"
)

func TestMain(m *testing.M) {
	if os.Getenv(envChild) != "" {
		os.Exit(childMain())
	}
	os.Exit(m.Run())
}

func ptr[T any](v T) *T { return &v }

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func logger() *slog.Logger {
	if os.Getenv("HALLPASS_FAULT_LOG") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.DiscardHandler)
}

// baseConfig is the development-mode configuration shared by in-process gateways and child processes.
func baseConfig(dir string) *config.Config {
	cfg := config.Default()
	cfg.Mode = config.ModeDevelopment
	cfg.DataDir = dir
	cfg.KEK.File = ""
	cfg.Egress.AllowCIDRs = []string{"127.0.0.0/8"}
	cfg.Egress.AllowSpecialCIDRs = []string{"127.0.0.1/32"}
	cfg.Shutdown.DrainTimeout = config.Duration(500 * time.Millisecond)
	cfg.HTTP.Listen = ""
	cfg.Telemetry.Prometheus = false
	cfg.Access.RequestsPerAgentHour = 10000 // request storms are not rate-limit tests
	cfg.Access.MaxPendingPerAgent = 1000
	return cfg
}

// world is the provisioned state that survives gateway restarts: data directory, agent key, destination and IDs.
type world struct {
	dir      string
	agent    sshkeys.Key
	dest     *sshtest.Server
	destAddr string // address enrolled for the server (the destination or a proxy in front of it)
	hostPK   ssh.PublicKey
	agentID  string
	serverID string
	roleID   string
	roles    []string // extra role aliases (role0..roleN-1)
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{dir: filepath.Join(t.TempDir(), "data"), agent: sshkeys.Ed25519(t), dest: sshtest.Start(t)}
	h, p := w.dest.Addr()
	w.destAddr = net.JoinHostPort(h, fmt.Sprint(p))
	return w
}

// provision creates the agent (group sre), server web1 with the destination's host key, role inspect with an active
// generated credential, extra roles, and an auto-approve rule for the agent group.
func (w *world) provision(t testing.TB, a *app.App, extraRoles int) {
	t.Helper()
	ctx := context.Background()
	ag, err := a.Agents.Create(ctx, admin, agents.CreateInput{Name: "sre-bot", Groups: []string{"sre"}, PublicKeys: []string{w.agent.AuthorizedLine("")}})
	must(t, err)
	w.agentID = ag.ID
	host, port, err := net.SplitHostPort(w.destAddr)
	must(t, err)
	var portN int
	_, _ = fmt.Sscan(port, &portN)
	srv, err := a.Inventory.CreateServer(ctx, admin, inventory.ServerInput{Alias: ptr("web1"), Address: ptr(host), Port: ptr(portN)})
	must(t, err)
	w.serverID = srv.ID
	_, err = a.Inventory.AddHostIdentity(ctx, admin, srv.ID, w.dest.KnownHostsLine(0))
	must(t, err)
	mk := func(alias string) string {
		role, err := a.Inventory.CreateRole(ctx, admin, srv.ID, inventory.RoleInput{Alias: ptr(alias), RemoteUser: ptr("ro"),
			MaxConcurrent: ptr(1000), MaxConcurrentPerAgent: ptr(1000)})
		must(t, err)
		cred, err := a.Credentials.Generate(ctx, admin, role.ID)
		must(t, err)
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cred.PublicKey))
		must(t, err)
		w.dest.Authorize(pk)
		_, err = a.Credentials.Probe(ctx, admin, cred.ID)
		must(t, err)
		_, err = a.Credentials.Activate(ctx, admin, cred.ID, false)
		must(t, err)
		return role.ID
	}
	w.roleID = mk("inspect")
	for i := range extraRoles {
		name := fmt.Sprintf("role%d", i)
		mk(name)
		w.roles = append(w.roles, name)
	}
	_, err = a.Policy.CreateRule(ctx, admin, policy.Rule{Name: "sre", Effect: policy.EffectAllow, Level: policy.LevelAutoApprove, Enabled: true,
		AutoMaxDuration: time.Hour, Subjects: policy.SubjectSelector{AgentGroups: []string{"sre"}}, Targets: policy.TargetSelector{All: true},
		Roles: policy.RoleSelector{All: true}})
	must(t, err)
	keys, err := a.Credentials.GatewayHostKeys(ctx)
	must(t, err)
	w.hostPK, _, _, _, err = ssh.ParseAuthorizedKey([]byte(keys[0].PublicKey))
	must(t, err)
}

// setup provisions the world's data directory with a short-lived in-process app (no listener) and closes it, so a
// child process or a later gateway can own the directory.
func (w *world) setup(t *testing.T, extraRoles int, then ...func(*app.App)) {
	t.Helper()
	a, err := app.New(context.Background(), baseConfig(w.dir), logger())
	must(t, err)
	w.provision(t, a, extraRoles)
	for _, f := range then {
		f(a)
	}
	must(t, a.Close())
}

// requestable switches the auto-approve rule to manual approval.
func requestable(t testing.TB) func(*app.App) {
	return func(a *app.App) {
		ctx := context.Background()
		rules, err := a.Policy.ListRules(ctx)
		must(t, err)
		r := rules[0]
		r.Level, r.AutoMaxDuration = policy.LevelRequestable, 0
		_, err = a.Policy.UpdateRule(ctx, admin, r.ID, r)
		must(t, err)
	}
}

type gwOptions struct {
	tweaks     []func(*config.Config)
	appOpts    []app.Option
	wrap       func(sshproxy.RecorderFactory) sshproxy.RecorderFactory
	extraRoles int
}

type gwOption func(*gwOptions)

func withConfig(f func(*config.Config)) gwOption {
	return func(o *gwOptions) { o.tweaks = append(o.tweaks, f) }
}

func withApp(opts ...app.Option) gwOption {
	return func(o *gwOptions) { o.appOpts = append(o.appOpts, opts...) }
}

func withRecorders(f func(sshproxy.RecorderFactory) sshproxy.RecorderFactory) gwOption {
	return func(o *gwOptions) { o.wrap = f }
}

func withRoles(n int) gwOption { return func(o *gwOptions) { o.extraRoles = n } }

// gw is a running in-process gateway.
type gw struct {
	t      *testing.T
	w      *world
	a      *app.App
	addr   string
	cancel context.CancelFunc
	done   chan error
	once   sync.Once
}

// start runs an in-process gateway on the world's data directory, provisioning it on first use.
func (w *world) start(t *testing.T, opts ...gwOption) *gw {
	t.Helper()
	var o gwOptions
	for _, f := range opts {
		f(&o)
	}
	cfg := baseConfig(w.dir)
	for _, f := range o.tweaks {
		f(cfg)
	}
	ctx := context.Background()
	a, err := app.New(ctx, cfg, logger(), o.appOpts...)
	must(t, err)
	if w.agentID == "" {
		w.provision(t, a, o.extraRoles)
	}
	if o.wrap != nil {
		a.Recorders = o.wrap(a.Recorders)
	}
	ln, err := app.Listen(ctx, "127.0.0.1:0")
	must(t, err)
	sctx, cancel := context.WithCancel(ctx)
	g := &gw{t: t, w: w, a: a, addr: ln.Addr().String(), cancel: cancel, done: make(chan error, 1)}
	go func() { g.done <- a.Serve(sctx, ln) }()
	t.Cleanup(g.stop)
	return g
}

// stop shuts the gateway down and closes its storage (idempotent).
func (g *gw) stop() {
	g.once.Do(func() {
		g.cancel()
		select {
		case err := <-g.done:
			if err != nil {
				g.t.Logf("serve: %v", err)
			}
		case <-time.After(15 * time.Second):
			g.t.Error("gateway did not stop")
		}
		_ = g.a.Close()
	})
}

func dial(addr string, w *world, key sshkeys.Key) (*ssh.Client, error) {
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "agent", Auth: []ssh.AuthMethod{ssh.PublicKeys(key.Signer)},
		HostKeyCallback: ssh.FixedHostKey(w.hostPK), Timeout: 5 * time.Second})
}

func (g *gw) client() (*ssh.Client, error) { return dial(g.addr, g.w, g.w.agent) }

// exitCode maps a session error to the exit status (-1: no exit status).
func exitCode(err error) int {
	var ee *ssh.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee):
		return ee.ExitStatus()
	default:
		return -1
	}
}

// run executes one gateway command and returns stdout, stderr and the exit status.
func run(t testing.TB, addr string, w *world, cmd string) (string, string, int) {
	t.Helper()
	c, err := dial(addr, w, w.agent)
	must(t, err)
	defer c.Close()
	s, err := c.NewSession()
	must(t, err)
	defer s.Close()
	var out, errb bytes.Buffer
	s.Stdout, s.Stderr = &out, &errb
	err = s.Run(cmd)
	return out.String(), errb.String(), exitCode(err)
}

func (g *gw) run(cmd string) (string, string, int) { return run(g.t, g.addr, g.w, cmd) }

// longExec is an exec session whose agent stdin stays open until closed.
type longExec struct {
	c      *ssh.Client
	s      *ssh.Session
	stdin  *io.PipeWriter
	stdout *syncBuf
	stderr *syncBuf
	done   chan error
	ended  atomic.Int64 // unix nanos when Wait returned
}

func startExec(t testing.TB, addr string, w *world, cmd string) *longExec {
	t.Helper()
	c, err := dial(addr, w, w.agent)
	must(t, err)
	s, err := c.NewSession()
	must(t, err)
	pr, pw := io.Pipe()
	le := &longExec{c: c, s: s, stdin: pw, stdout: &syncBuf{}, stderr: &syncBuf{}, done: make(chan error, 1)}
	s.Stdin, s.Stdout, s.Stderr = pr, le.stdout, le.stderr
	must(t, s.Start(cmd))
	go func() {
		err := s.Wait()
		le.ended.Store(time.Now().UnixNano())
		le.done <- err
	}()
	t.Cleanup(func() {
		_ = pw.Close()
		_ = c.Close()
	})
	return le
}

// wait returns the session result, or fails after d.
func (le *longExec) wait(t testing.TB, d time.Duration) error {
	t.Helper()
	select {
	case err := <-le.done:
		return err
	case <-time.After(d):
		t.Fatalf("session still running after %s", d)
		return nil
	}
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

func (s *syncBuf) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Len()
}

// blockingExec makes the destination run every exec until its stdin closes, signalling each start.
func blockingExec(dest *sshtest.Server) <-chan string {
	started := make(chan string, 64)
	dest.Exec = func(cmd string, stdin io.Reader, _, _ io.Writer) uint32 {
		started <- cmd
		_, _ = io.Copy(io.Discard, stdin)
		return 0
	}
	return started
}

func waitStarted(t testing.TB, ch <-chan string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("destination exec never started")
	}
}

// eventually polls cond every 25 ms until it holds or d passes.
func eventually(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// queryInt runs a scalar integer query.
func queryInt(t testing.TB, d *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	must(t, d.QueryRowContext(context.Background(), q, args...).Scan(&n))
	return n
}

func queryStr(t testing.TB, d *sql.DB, q string, args ...any) string {
	t.Helper()
	var s sql.NullString
	must(t, d.QueryRowContext(context.Background(), q, args...).Scan(&s))
	return s.String
}

// openRO opens the data directory's database read-only (for inspection while another process owns it).
func openRO(t testing.TB, dir string) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", "file:"+filepath.Join(dir, store.DBFile)+"?mode=ro&_pragma=busy_timeout(5000)&_pragma=query_only(1)")
	must(t, err)
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// activeGrants returns the agent's active grants.
func (g *gw) activeGrants() []*access.Grant {
	g.t.Helper()
	gs, err := g.a.Access.ActiveGrantsForAgent(context.Background(), g.w.agentID, "")
	must(g.t, err)
	return gs
}

// ---- child process gateway (crash scenarios) ----

type child struct {
	cmd  *exec.Cmd
	addr string
	log  string
}

// spawn starts a gateway child process on the world's (already provisioned) data directory.
func (w *world) spawn(t *testing.T, hook string) *child {
	t.Helper()
	tmp := t.TempDir()
	addrFile := filepath.Join(tmp, "addr")
	logFile := filepath.Join(tmp, "child.log")
	lf, err := os.Create(logFile)
	must(t, err)
	cmd := exec.Command(os.Args[0], "-test.run=^$") //nolint:gosec // re-exec of the test binary
	cmd.Env = append(os.Environ(), envChild+"=1", envDir+"="+w.dir, envAddr+"="+addrFile, envHook+"="+hook)
	cmd.Stdout, cmd.Stderr = lf, lf
	must(t, cmd.Start())
	c := &child{cmd: cmd, log: logFile}
	t.Cleanup(func() {
		c.kill()
		_ = lf.Close()
	})
	if !eventually(30*time.Second, func() bool {
		b, err := os.ReadFile(addrFile)
		if err != nil || len(b) == 0 {
			return false
		}
		c.addr = string(b)
		return true
	}) {
		b, _ := os.ReadFile(logFile)
		t.Fatalf("child gateway did not start:\n%s", b)
	}
	return c
}

// kill sends SIGKILL (kill -9) and reaps the process.
func (c *child) kill() {
	if c.cmd.ProcessState != nil {
		return
	}
	_ = c.cmd.Process.Kill()
	_ = c.cmd.Wait()
}

// childMain runs a gateway until SIGTERM. Hooks inject faults inside the process:
//
//	block-open: recordings never open (the channel is registered, the segment is not created).
func childMain() int {
	dir, addrFile, hook := os.Getenv(envDir), os.Getenv(envAddr), os.Getenv(envHook)
	lf, err := os.OpenFile(filepath.Join(filepath.Dir(addrFile), "child-app.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 2
	}
	defer lf.Close()
	log := slog.New(slog.NewJSONHandler(lf, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	cfg := baseConfig(dir)
	if strings.Contains(hook, "strict") {
		cfg.Recording.Durability = "strict"
	}
	a, err := app.New(ctx, cfg, log)
	if err != nil {
		log.Error("start", "error", err.Error())
		return 3
	}
	defer a.Close()
	if strings.Contains(hook, "block-open") {
		a.Recorders = blockOpen{}
	}
	ln, err := app.Listen(ctx, "127.0.0.1:0")
	if err != nil {
		return 4
	}
	tmp := addrFile + ".tmp"
	if os.WriteFile(tmp, []byte(ln.Addr().String()), 0o600) != nil || os.Rename(tmp, addrFile) != nil {
		return 5
	}
	if err := a.Serve(ctx, ln); err != nil {
		log.Error("serve", "error", err.Error())
		return 6
	}
	return 0
}

// blockOpen never establishes a recording: the process is "between channel registration and segment creation".
type blockOpen struct{}

func (blockOpen) Open(ctx context.Context, _ *access.ChannelReg, _ string, _ bool) (sshproxy.Recorder, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// ---- recorder fault wrapper (failing/slow storage at the recorder boundary) ----

// faultFactory wraps the real recorder factory. Output fails with failErr once more than failAfter bytes were
// offered (failAfter > 0), and every Output call sleeps delay first (slow storage).
type faultFactory struct {
	inner     sshproxy.RecorderFactory
	failAfter int64
	failErr   error
	delay     time.Duration

	mu   sync.Mutex
	recs []*faultRecorder
}

func (f *faultFactory) Open(ctx context.Context, reg *access.ChannelReg, kind string, pty bool) (sshproxy.Recorder, error) {
	r, err := f.inner.Open(ctx, reg, kind, pty)
	if err != nil {
		return nil, err
	}
	fr := &faultRecorder{Recorder: r, f: f}
	f.mu.Lock()
	f.recs = append(f.recs, fr)
	f.mu.Unlock()
	return fr, nil
}

func (f *faultFactory) last() *faultRecorder {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.recs) == 0 {
		return nil
	}
	return f.recs[len(f.recs)-1]
}

type faultRecorder struct {
	sshproxy.Recorder
	f        *faultFactory
	offered  atomic.Int64 // output bytes handed to the recorder
	recorded atomic.Int64 // output bytes the recorder accepted
	failed   atomic.Bool
}

func (r *faultRecorder) Output(s sshproxy.Stream, data []byte) error {
	if r.f.delay > 0 {
		time.Sleep(r.f.delay)
	}
	n := r.offered.Add(int64(len(data)))
	if r.f.failAfter > 0 && n > r.f.failAfter {
		r.failed.Store(true)
		return r.f.failErr
	}
	if err := r.Recorder.Output(s, data); err != nil {
		return err
	}
	r.recorded.Add(int64(len(data)))
	return nil
}

// ---- TCP proxy in front of the destination (blackhole, target switch) ----

type tcpProxy struct {
	ln        net.Listener
	target    atomic.Value // string
	blackhole atomic.Bool
	stopped   atomic.Bool
	mu        sync.Mutex
	conns     []net.Conn
	accepted  atomic.Int64
}

func startProxy(t testing.TB, target string) *tcpProxy {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	must(t, err)
	p := &tcpProxy{ln: ln}
	p.target.Store(target)
	go p.serve()
	t.Cleanup(p.close)
	return p
}

func (p *tcpProxy) addr() string { return p.ln.Addr().String() }

func (p *tcpProxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.accepted.Add(1)
		up, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", p.target.Load().(string))
		if err != nil {
			_ = c.Close()
			continue
		}
		p.mu.Lock()
		p.conns = append(p.conns, c, up)
		p.mu.Unlock()
		go p.pump(c, up)
		go p.pump(up, c)
	}
}

// pump forwards bytes until the proxy is blackholed; then it holds everything (no delivery, no close), like a
// network path that silently drops packets.
func (p *tcpProxy) pump(dst, src net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		for p.blackhole.Load() {
			time.Sleep(50 * time.Millisecond)
			if p.stopped.Load() {
				return
			}
		}
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			_ = dst.Close()
			return
		}
	}
}

func (p *tcpProxy) close() {
	p.stopped.Store(true)
	_ = p.ln.Close()
	p.mu.Lock()
	for _, c := range p.conns {
		_ = c.Close()
	}
	p.conns = nil
	p.mu.Unlock()
}
