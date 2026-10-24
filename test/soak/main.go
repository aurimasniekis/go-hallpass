// Command soak drives an in-process HallPass gateway in front of an in-process destination with concurrent agents
// running exec and PTY sessions for a configurable duration, samples goroutines, open file descriptors, heap and RSS,
// measures session, echo and enforcement latency, and writes a JSON report (HP-TST-006, HP-TST-007; method in
// TEST_STRATEGY.md §5).
//
// Gateway, destination and agents share one process, so goroutine and FD counts include all three. Results from
// this harness on other hardware are not RH-1 numbers (TEST_STRATEGY.md §5.1).
//
//	go run ./test/soak -duration 30s -agents 20 -out soak.json        # smoke
//	go run ./test/soak -duration 24h -warmup 1h -agents 100 -out soak.json
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/app"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/buildinfo"
	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
)

var admin = audit.Actor{Type: audit.ActorOperator, ID: "opr_admin"}

type options struct {
	Duration      time.Duration `json:"duration"`
	Warmup        time.Duration `json:"warmup"`
	Agents        int           `json:"agents"`
	PTYShare      float64       `json:"pty_share"`
	ExecBytes     int           `json:"exec_bytes"`
	Keystrokes    float64       `json:"keystrokes_per_second"`
	Sample        time.Duration `json:"sample_interval"`
	ProbeInterval time.Duration `json:"enforcement_probe_interval"`
	Durability    string        `json:"recording_durability"`
	DataDir       string        `json:"-"`
}

func main() {
	var o options
	var out string
	flag.DurationVar(&o.Duration, "duration", 30*time.Second, "measured run time (after warmup)")
	flag.DurationVar(&o.Warmup, "warmup", 5*time.Second, "warmup before drift baselines are taken")
	flag.IntVar(&o.Agents, "agents", 20, "concurrent agents (one worker each)")
	flag.Float64Var(&o.PTYShare, "pty-share", 0.5, "share of agents running PTY echo sessions (the rest run exec)")
	flag.IntVar(&o.ExecBytes, "exec-bytes", 64<<10, "output bytes per exec session")
	flag.Float64Var(&o.Keystrokes, "keystrokes", 5, "PTY keystrokes per second per agent")
	flag.DurationVar(&o.Sample, "sample", time.Second, "resource sampling interval")
	flag.DurationVar(&o.ProbeInterval, "probe", 3*time.Second, "enforcement probe interval (revoke a live grant)")
	flag.StringVar(&o.Durability, "durability", "group", "recording durability: group or strict")
	flag.StringVar(&o.DataDir, "data", "", "data directory (default: a new temporary directory, removed afterwards)")
	flag.StringVar(&out, "out", "", "report path (default stdout)")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	rep, err := run(context.Background(), o, log)
	if err != nil {
		log.Error("soak failed", "error", err.Error())
		os.Exit(1)
	}
	w := io.Writer(os.Stdout)
	if out != "" {
		f, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // operator-chosen report path
		if err != nil {
			log.Error("report", "error", err.Error())
			os.Exit(1)
		}
		defer f.Close()
		w = f
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		log.Error("report", "error", err.Error())
		os.Exit(1)
	}
	if !rep.RecordingsVerified {
		os.Exit(2)
	}
}

// ---- report ----

type sample struct {
	At         float64 `json:"t_s"`
	Goroutines int     `json:"goroutines"`
	FDs        int     `json:"fds"`
	HeapBytes  uint64  `json:"heap_bytes"`
	SysBytes   uint64  `json:"sys_bytes"`
	RSSBytes   int64   `json:"rss_bytes,omitempty"` // Linux only (current RSS)
	MaxRSS     int64   `json:"max_rss_bytes"`
	Sessions   int64   `json:"sessions_completed"`
	Failures   int64   `json:"session_failures"`
}

type dist struct {
	N   int     `json:"n"`
	P50 float64 `json:"p50_ms"`
	P95 float64 `json:"p95_ms"`
	P99 float64 `json:"p99_ms"`
	Max float64 `json:"max_ms"`
}

type drift struct {
	Baseline float64 `json:"baseline"`
	Final    float64 `json:"final"`
	Percent  float64 `json:"percent"`
}

type report struct {
	Tool     string            `json:"tool"`
	Started  time.Time         `json:"started"`
	Options  options           `json:"options"`
	Host     map[string]string `json:"host"`
	Samples  []sample          `json:"samples"`
	Latency  map[string]dist   `json:"latency"`
	Counters map[string]int64  `json:"counters"`
	Drift    map[string]drift  `json:"drift_after_warmup"`
	// Quiesce compares goroutines/FDs before the workload with after it stopped (leak check).
	Quiesce            map[string]int `json:"quiesce"`
	RecordingsVerified bool           `json:"recordings_verified"`
	Segments           int            `json:"segments"`
	Errors             []string       `json:"errors,omitempty"`
}

type recorder struct {
	mu   sync.Mutex
	lat  map[string][]time.Duration
	errs map[string]int
}

func (r *recorder) add(name string, d time.Duration) {
	r.mu.Lock()
	r.lat[name] = append(r.lat[name], d)
	r.mu.Unlock()
}

func (r *recorder) fail(err error) {
	msg := err.Error()
	if len(msg) > 160 {
		msg = msg[:160]
	}
	r.mu.Lock()
	r.errs[msg]++
	r.mu.Unlock()
}

func summarize(ds []time.Duration) dist {
	if len(ds) == 0 {
		return dist{}
	}
	s := slices.Clone(ds)
	slices.Sort(s)
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	q := func(p float64) float64 { return ms(s[min(len(s)-1, int(p*float64(len(s))))]) }
	return dist{N: len(s), P50: q(0.50), P95: q(0.95), P99: q(0.99), Max: ms(s[len(s)-1])}
}

func pct(a, b float64) float64 {
	if a == 0 {
		return 0
	}
	return (b - a) / a * 100
}

// ---- resource sampling ----

func countFDs() int {
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		if es, err := os.ReadDir(dir); err == nil {
			return len(es) - 1 // the directory handle itself
		}
	}
	return -1
}

func rss() (cur, peak int64) {
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) == nil {
		peak = ru.Maxrss
		if runtime.GOOS == "linux" {
			peak *= 1024 // KiB on Linux, bytes on macOS
		}
	}
	if b, err := os.ReadFile("/proc/self/statm"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 1 {
			if pages, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				cur = pages * int64(os.Getpagesize())
			}
		}
	}
	return cur, peak
}

func takeSample(start time.Time, done, failed int64) sample {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	cur, peak := rss()
	return sample{At: time.Since(start).Seconds(), Goroutines: runtime.NumGoroutine(), FDs: countFDs(), HeapBytes: ms.HeapAlloc,
		SysBytes: ms.Sys, RSSBytes: cur, MaxRSS: peak, Sessions: done, Failures: failed}
}

// ---- destination ----

type destination struct {
	ln      net.Listener
	cfg     *ssh.ServerConfig
	hostKey ssh.PublicKey
	mu      sync.Mutex
	allowed map[string]bool
	wg      sync.WaitGroup
}

func startDestination(ctx context.Context) (*destination, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	d := &destination{hostKey: signer.PublicKey(), allowed: map[string]bool{}}
	d.cfg = &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.allowed[ssh.FingerprintSHA256(k)] {
			return &ssh.Permissions{}, nil
		}
		return nil, errors.New("unknown key")
	}}
	d.cfg.AddHostKey(signer)
	if d.ln, err = (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0"); err != nil {
		return nil, err
	}
	d.wg.Go(d.serve)
	return d, nil
}

func (d *destination) authorize(k ssh.PublicKey) {
	d.mu.Lock()
	d.allowed[ssh.FingerprintSHA256(k)] = true
	d.mu.Unlock()
}

func (d *destination) close() {
	_ = d.ln.Close()
	d.wg.Wait()
}

func (d *destination) serve() {
	for {
		c, err := d.ln.Accept()
		if err != nil {
			return
		}
		d.wg.Go(func() { d.handle(c) })
	}
}

func (d *destination) handle(c net.Conn) {
	defer c.Close()
	sc, chans, reqs, err := ssh.NewServerConn(c, d.cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "sessions only")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go session(ch, creqs)
	}
}

func exitStatus(code uint32) []byte { return ssh.Marshal(struct{ Status uint32 }{code}) }

// session implements the destination commands: "burst N" writes N bytes, "block" runs until stdin closes, a shell
// echoes its input; anything else prints "ok".
func session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		switch req.Type {
		case "pty-req", "env", "window-change":
			_ = req.Reply(true, nil)
		case "shell":
			_ = req.Reply(true, nil)
			_, _ = io.Copy(ch, ch)
			_, _ = ch.SendRequest("exit-status", false, exitStatus(0))
			return
		case "exec":
			var p struct{ Cmd string }
			if ssh.Unmarshal(req.Payload, &p) != nil {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)
			f := strings.Fields(p.Cmd)
			switch {
			case len(f) == 2 && f[0] == "burst":
				n, _ := strconv.Atoi(f[1])
				buf := make([]byte, 32<<10)
				for n > 0 {
					k, err := ch.Write(buf[:min(n, len(buf))])
					if err != nil {
						break
					}
					n -= k
				}
			case len(f) == 1 && f[0] == "block":
				_, _ = io.Copy(io.Discard, ch)
			default:
				_, _ = io.WriteString(ch, "ok\n")
			}
			_ = ch.CloseWrite()
			_, _ = ch.SendRequest("exit-status", false, exitStatus(0))
			return
		default:
			_ = req.Reply(false, nil)
		}
	}
}

// ---- gateway setup ----

type agentKey struct {
	id     string
	signer ssh.Signer
}

func newAgentKey() (ssh.Signer, string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, "", err
	}
	return s, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey()))), nil
}

func provision(ctx context.Context, a *app.App, d *destination, n int) ([]agentKey, agentKey, ssh.PublicKey, error) {
	var keys []agentKey
	var probe agentKey
	for i := range n + 1 {
		s, line, err := newAgentKey()
		if err != nil {
			return nil, probe, nil, err
		}
		name := fmt.Sprintf("soak-%04d", i)
		if i == n {
			name = "soak-probe"
		}
		ag, err := a.Agents.Create(ctx, admin, agents.CreateInput{Name: name, Groups: []string{"soak"}, PublicKeys: []string{line}})
		if err != nil {
			return nil, probe, nil, err
		}
		if i == n {
			probe = agentKey{id: ag.ID, signer: s}
		} else {
			keys = append(keys, agentKey{id: ag.ID, signer: s})
		}
	}
	host, port, _ := net.SplitHostPort(d.ln.Addr().String())
	portN, _ := strconv.Atoi(port)
	alias, user := "web1", "ro"
	srv, err := a.Inventory.CreateServer(ctx, admin, inventory.ServerInput{Alias: &alias, Address: &host, Port: &portN})
	if err != nil {
		return nil, probe, nil, err
	}
	if _, err := a.Inventory.AddHostIdentity(ctx, admin, srv.ID, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(d.hostKey)))); err != nil {
		return nil, probe, nil, err
	}
	roleAlias, limit := "inspect", 10000
	role, err := a.Inventory.CreateRole(ctx, admin, srv.ID, inventory.RoleInput{Alias: &roleAlias, RemoteUser: &user, MaxConcurrent: &limit,
		MaxConcurrentPerAgent: &limit})
	if err != nil {
		return nil, probe, nil, err
	}
	cred, err := a.Credentials.Generate(ctx, admin, role.ID)
	if err != nil {
		return nil, probe, nil, err
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cred.PublicKey))
	if err != nil {
		return nil, probe, nil, err
	}
	d.authorize(pk)
	if _, err := a.Credentials.Probe(ctx, admin, cred.ID); err != nil {
		return nil, probe, nil, err
	}
	if _, err := a.Credentials.Activate(ctx, admin, cred.ID, false); err != nil {
		return nil, probe, nil, err
	}
	if _, err := a.Policy.CreateRule(ctx, admin, policy.Rule{Name: "soak", Effect: policy.EffectAllow, Level: policy.LevelAutoApprove,
		Enabled: true, AutoMaxDuration: time.Hour, Subjects: policy.SubjectSelector{AgentGroups: []string{"soak"}},
		Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}}); err != nil {
		return nil, probe, nil, err
	}
	hk, err := a.Credentials.GatewayHostKeys(ctx)
	if err != nil || len(hk) == 0 {
		return nil, probe, nil, fmt.Errorf("gateway host key: %w", err)
	}
	gwKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hk[0].PublicKey))
	return keys, probe, gwKey, err
}

// ---- workload ----

type harness struct {
	addr     string
	gwKey    ssh.PublicKey
	rec      *recorder
	done     atomic.Int64
	failed   atomic.Int64
	bytesOut atomic.Int64
}

func (h *harness) dial(k agentKey) (*ssh.Client, error) {
	return ssh.Dial("tcp", h.addr, &ssh.ClientConfig{User: "agent", Auth: []ssh.AuthMethod{ssh.PublicKeys(k.signer)},
		HostKeyCallback: ssh.FixedHostKey(h.gwKey), Timeout: 10 * time.Second})
}

// execOnce opens a connection, runs one exec session and checks its output size (W3-like connection churn with a
// W2-like output burst).
func (h *harness) execOnce(k agentKey, n int) error {
	t0 := time.Now()
	c, err := h.dial(k)
	if err != nil {
		return err
	}
	defer c.Close()
	s, err := c.NewSession()
	if err != nil {
		return err
	}
	defer s.Close()
	out, err := s.StdoutPipe()
	if err != nil {
		return err
	}
	if err := s.Start(fmt.Sprintf("exec web1 -- burst %d", n)); err != nil {
		return err
	}
	got, _ := io.Copy(io.Discard, out)
	if err := s.Wait(); err != nil {
		return err
	}
	if got != int64(n) {
		return fmt.Errorf("exec output %d bytes, want %d", got, n)
	}
	h.bytesOut.Add(got)
	h.rec.add("exec_session", time.Since(t0))
	return nil
}

// ptySession runs an interactive PTY shell sending timestamped keystroke lines and measuring their echo (W1-like).
func (h *harness) ptySession(ctx context.Context, k agentKey, rate float64, length time.Duration) error {
	c, err := h.dial(k)
	if err != nil {
		return err
	}
	defer c.Close()
	s, err := c.NewSession()
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		return err
	}
	in, err := s.StdinPipe()
	if err != nil {
		return err
	}
	out, err := s.StdoutPipe()
	if err != nil {
		return err
	}
	if err := s.Start("connect web1"); err != nil {
		return err
	}
	var echoed atomic.Int64
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			line := sc.Text()
			if i := strings.Index(line, "k:"); i >= 0 {
				if ns, err := strconv.ParseInt(strings.TrimSpace(line[i+2:]), 10, 64); err == nil {
					h.rec.add("pty_echo", time.Since(time.Unix(0, ns)))
					echoed.Add(1)
				}
			}
		}
	}()
	tick := time.NewTicker(time.Duration(float64(time.Second) / rate))
	defer tick.Stop()
	end := time.After(length)
	sent := int64(0)
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-end:
			break loop
		case <-tick.C:
			if _, err := fmt.Fprintf(in, "k:%d\n", time.Now().UnixNano()); err != nil {
				return err
			}
			sent++
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for echoed.Load() < sent && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	_ = in.Close()
	err = s.Wait()
	<-readDone
	if lost := sent - echoed.Load(); lost > 0 {
		return fmt.Errorf("%d of %d keystrokes not echoed", lost, sent)
	}
	return err
}

// probe opens a blocking exec on the probe agent, revokes its grant and measures the time until the channel ends
// (enforcement latency, HP-GRT-008).
func (h *harness) probe(ctx context.Context, a *app.App, k agentKey) error {
	c, err := h.dial(k)
	if err != nil {
		return err
	}
	defer c.Close()
	s, err := c.NewSession()
	if err != nil {
		return err
	}
	in, err := s.StdinPipe()
	if err != nil {
		return err
	}
	defer in.Close()
	if err := s.Start("exec web1 -- block"); err != nil {
		return err
	}
	waited := make(chan error, 1)
	go func() { waited <- s.Wait() }()
	var grantID string
	for range 200 {
		gs, err := a.Access.ActiveGrantsForAgent(ctx, k.id)
		if err == nil && len(gs) > 0 {
			var live int
			if a.Store.ReadDB().QueryRowContext(ctx, `SELECT count(*) FROM ssh_channels WHERE grant_id = ? AND state = 'active'`,
				gs[0].ID).Scan(&live) == nil && live > 0 {
				grantID = gs[0].ID
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if grantID == "" {
		return errors.New("probe: channel never active")
	}
	t0 := time.Now()
	if _, err := a.Access.RevokeGrant(ctx, policy.OperatorInfo{ID: "opr_admin", Roles: []string{"administrator"}, Enabled: true}, grantID,
		"soak probe"); err != nil {
		return err
	}
	select {
	case err := <-waited:
		lat := time.Since(t0)
		var ee *ssh.ExitError
		if !errors.As(err, &ee) || ee.ExitStatus() != 87 {
			return fmt.Errorf("probe: channel ended with %w, want gateway exit 87 (access ended)", err)
		}
		h.rec.add("enforcement", lat)
		return nil
	case <-time.After(10 * time.Second):
		return errors.New("probe: channel survived revocation for 10 s")
	}
}

func run(ctx context.Context, o options, log *slog.Logger) (*report, error) {
	dir := o.DataDir
	if dir == "" {
		tmp, err := os.MkdirTemp("", "hallpass-soak-*")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmp)
		dir = filepath.Join(tmp, "data")
	}
	cfg := config.Default()
	cfg.Mode, cfg.DataDir, cfg.KEK.File, cfg.HTTP.Listen = config.ModeDevelopment, dir, "", ""
	cfg.Egress.AllowCIDRs, cfg.Egress.AllowSpecialCIDRs = []string{"127.0.0.0/8"}, []string{"127.0.0.1/32"}
	cfg.Access.RequestsPerAgentHour, cfg.Access.MaxPendingPerAgent = 1_000_000, 1000
	cfg.SSH.MaxUnauthenticated, cfg.SSH.MaxUnauthenticatedPerIP = 4096, 4096
	cfg.Recording.Durability = o.Durability
	cfg.Telemetry.Prometheus = false
	cfg.Shutdown.DrainTimeout = config.Duration(time.Second)

	dest, err := startDestination(ctx)
	if err != nil {
		return nil, err
	}
	defer dest.close()
	a, err := app.New(ctx, cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		return nil, err
	}
	defer a.Close()
	keys, probeKey, gwKey, err := provision(ctx, a, dest, o.Agents)
	if err != nil {
		return nil, fmt.Errorf("provision: %w", err)
	}
	ln, err := app.Listen(ctx, "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	sctx, stopServe := context.WithCancel(ctx)
	served := make(chan error, 1)
	go func() { served <- a.Serve(sctx, ln) }()

	h := &harness{addr: ln.Addr().String(), gwKey: gwKey, rec: &recorder{lat: map[string][]time.Duration{}, errs: map[string]int{}}}
	rep := &report{Tool: "hallpass test/soak", Started: time.Now().UTC(), Options: o, Latency: map[string]dist{}, Counters: map[string]int64{},
		Drift: map[string]drift{}, Quiesce: map[string]int{}, Host: map[string]string{
			"goos": runtime.GOOS, "goarch": runtime.GOARCH, "cpus": strconv.Itoa(runtime.NumCPU()), "gomaxprocs": strconv.Itoa(runtime.GOMAXPROCS(0)),
			"go": runtime.Version(), "hallpass": buildinfo.Get().Version, "note": "in-process gateway, destination and agents; not RH-1"}}
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	pre := takeSample(time.Now(), 0, 0)
	start := time.Now()
	wctx, stopWork := context.WithTimeout(ctx, o.Warmup+o.Duration)
	defer stopWork()

	var wg sync.WaitGroup
	nPTY := int(float64(len(keys)) * o.PTYShare)
	for i, k := range keys {
		pty := i < nPTY
		wg.Go(func() {
			for wctx.Err() == nil {
				var err error
				if pty {
					err = h.ptySession(wctx, k, o.Keystrokes, 10*time.Second)
				} else {
					err = h.execOnce(k, o.ExecBytes)
				}
				if err != nil && wctx.Err() == nil {
					h.failed.Add(1)
					h.rec.fail(err)
					time.Sleep(100 * time.Millisecond)
					continue
				}
				h.done.Add(1)
			}
		})
	}
	wg.Go(func() {
		t := time.NewTicker(o.ProbeInterval)
		defer t.Stop()
		for {
			select {
			case <-wctx.Done():
				return
			case <-t.C:
				if err := h.probe(wctx, a, probeKey); err != nil && wctx.Err() == nil {
					h.rec.fail(err)
					h.failed.Add(1)
				}
			}
		}
	})
	var baseline *sample
	tick := time.NewTicker(o.Sample)
sampling:
	for {
		select {
		case <-wctx.Done():
			break sampling
		case <-tick.C:
			s := takeSample(start, h.done.Load(), h.failed.Load())
			rep.Samples = append(rep.Samples, s)
			if baseline == nil && time.Since(start) >= o.Warmup {
				baseline = &s
				log.Info("warmup done", "goroutines", s.Goroutines, "fds", s.FDs, "heap_mib", s.HeapBytes>>20)
			}
		}
	}
	tick.Stop()
	wg.Wait()
	log.Info("workload stopped", "sessions", h.done.Load(), "failures", h.failed.Load())

	if baseline != nil && len(rep.Samples) > 0 {
		last := rep.Samples[len(rep.Samples)-1]
		rep.Drift["goroutines"] = drift{float64(baseline.Goroutines), float64(last.Goroutines), pct(float64(baseline.Goroutines), float64(last.Goroutines))}
		rep.Drift["fds"] = drift{float64(baseline.FDs), float64(last.FDs), pct(float64(baseline.FDs), float64(last.FDs))}
		rep.Drift["heap_bytes"] = drift{float64(baseline.HeapBytes), float64(last.HeapBytes), pct(float64(baseline.HeapBytes), float64(last.HeapBytes))}
		if baseline.RSSBytes > 0 {
			rep.Drift["rss_bytes"] = drift{float64(baseline.RSSBytes), float64(last.RSSBytes), pct(float64(baseline.RSSBytes), float64(last.RSSBytes))}
		}
	}
	// Leak check: after the workload, goroutines and FDs return to the pre-workload level.
	var post sample
	for range 50 {
		time.Sleep(100 * time.Millisecond)
		runtime.GC()
		if post = takeSample(start, 0, 0); post.Goroutines <= pre.Goroutines+5 && post.FDs <= pre.FDs+5 {
			break
		}
	}
	rep.Quiesce = map[string]int{"goroutines_before": pre.Goroutines, "goroutines_after": post.Goroutines, "fds_before": pre.FDs, "fds_after": post.FDs}

	h.rec.mu.Lock()
	for name, ds := range h.rec.lat {
		rep.Latency[name] = summarize(ds)
	}
	for msg, n := range h.rec.errs {
		rep.Errors = append(rep.Errors, fmt.Sprintf("%d× %s", n, msg))
	}
	h.rec.mu.Unlock()
	slices.Sort(rep.Errors)
	rep.Counters["sessions_completed"] = h.done.Load()
	rep.Counters["session_failures"] = h.failed.Load()
	rep.Counters["exec_output_bytes"] = h.bytesOut.Load()

	stopServe()
	if err := <-served; err != nil {
		rep.Errors = append(rep.Errors, "serve: "+err.Error())
	}
	vr, err := a.Recording.Verify(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("verify recordings: %w", err)
	}
	rep.RecordingsVerified, rep.Segments = vr.OK, len(vr.Segments)
	return rep, nil
}
