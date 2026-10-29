// Command hallpass-api runs one API tool (gh, wrangler, gcloud, curl, …) through a HallPass gateway's API proxy, so
// the tool reaches its API with the credential HallPass holds and never with the agent's own token (ADR-0060).
//
//	hallpass-api --gateway center --reason 'Answer the customer on #42' -- gh issue comment 42 --body 'Fixed in #43'
//
// It uses the system ssh (your ssh config, keys and pinned host key) to fetch the API CA bundle and open a tunnel to
// the proxy, and sets the proxy and CA variables for the child process only. It reports the command line and the
// reason in each CONNECT, so a call that needs approval is filed as a request that shows approvers the command.
// When the proxy filed requests, hallpass-api waits for the decisions and, once approved, runs the command again.
//
// See docs/agent/guide.md.
package main

import (
	"bufio"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apienv"
	"github.com/aurimasniekis/go-hallpass/internal/buildinfo"
)

// Exit codes of hallpass-api itself; the tool's own exit status passes through otherwise. 83-86 match the gateway's.
const (
	exitUsage    = 2
	exitSetup    = 80
	exitDenied   = 83
	exitExpired  = 84
	exitCanceled = 85
	exitPending  = 86
)

// maxWaitPerCall is the gateway's limit for one "status --wait".
const maxWaitPerCall = 15 * time.Minute

type options struct {
	gateway string
	role    string
	session string
	reason  string
	wait    time.Duration
	retries int
	ssh     string
	verbose bool
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hallpass-api", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	fs.StringVar(&o.gateway, "gateway", os.Getenv("HALLPASS_GATEWAY"), "SSH host of the HallPass gateway, as in your ssh config (env HALLPASS_GATEWAY)")
	fs.StringVar(&o.role, "role", os.Getenv("HALLPASS_ROLE"), "use only this access profile (env HALLPASS_ROLE); default: the proxy picks one")
	fs.StringVar(&o.session, "session", cmp.Or(os.Getenv("HALLPASS_SESSION"), os.Getenv("CLAUDE_CODE_SESSION_ID")),
		"agent session the access belongs to (env HALLPASS_SESSION, else Claude Code's CLAUDE_CODE_SESSION_ID)")
	fs.StringVar(&o.reason, "reason", os.Getenv("HALLPASS_REASON"), "why you need the access, shown to approvers with the command (env HALLPASS_REASON)")
	fs.DurationVar(&o.wait, "wait", 10*time.Minute, "how long to wait for approval of requests the proxy filed (0: do not wait)")
	fs.IntVar(&o.retries, "retries", 2, "how many times to run the command again after approvals")
	fs.StringVar(&o.ssh, "ssh", "ssh", "ssh client to use")
	fs.BoolVar(&o.verbose, "v", false, "print what hallpass-api does")
	version := fs.Bool("version", false, "print the version")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: hallpass-api --gateway <host> [--role <profile>] [--reason <why>] [--wait 10m] -- <command> [args…]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *version {
		fmt.Fprintln(stdout, "hallpass-api", buildinfo.Get().Version)
		return 0
	}
	argv := fs.Args()
	switch {
	case len(argv) == 0:
		fs.Usage()
		return exitUsage
	case o.gateway == "":
		fmt.Fprintln(stderr, "hallpass-api: --gateway (or HALLPASS_GATEWAY) is required")
		return exitUsage
	case o.role != "" && !roleRE.MatchString(o.role):
		fmt.Fprintf(stderr, "hallpass-api: invalid --role %q\n", o.role)
		return exitUsage
	case o.session != "" && !sessionRE.MatchString(o.session):
		fmt.Fprintf(stderr, "hallpass-api: invalid --session %q\n", o.session)
		return exitUsage
	case o.wait < 0 || o.retries < 0:
		fmt.Fprintln(stderr, "hallpass-api: --wait and --retries must not be negative")
		return exitUsage
	}
	s := &session{o: o, stdin: stdin, stdout: stdout, stderr: stderr}
	return s.run(ctx, argv)
}

type session struct {
	o              options
	stdin          io.Reader
	stdout, stderr io.Writer
	dir            string
	tunnelPort     int
}

func (s *session) logf(format string, a ...any) {
	if s.o.verbose {
		fmt.Fprintf(s.stderr, "hallpass-api: "+format+"\n", a...)
	}
}

func (s *session) fail(code int, format string, a ...any) int {
	fmt.Fprintf(s.stderr, "hallpass-api: "+format+"\n", a...)
	return code
}

func (s *session) run(ctx context.Context, argv []string) int {
	dir, err := os.MkdirTemp("", "hallpass-api-")
	if err != nil {
		return s.fail(exitSetup, "%v", err)
	}
	defer os.RemoveAll(dir)
	s.dir = dir

	bundle, err := s.gatewayOutput(ctx, "api", "ca")
	if err != nil {
		return s.fail(exitSetup, "cannot get the API CA bundle from %s: %v", s.o.gateway, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), bundle, 0o600); err != nil {
		return s.fail(exitSetup, "%v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte(apienv.Placeholder+"\n"), 0o600); err != nil {
		return s.fail(exitSetup, "%v", err)
	}
	stopTunnel, err := s.openTunnel(ctx)
	if err != nil {
		return s.fail(exitSetup, "cannot open the API proxy tunnel through %s: %v", s.o.gateway, err)
	}
	defer stopTunnel()

	command := displayCommand(argv)
	for attempt := 0; ; attempt++ {
		invocation := newInvocation()
		code, err := s.runOnce(ctx, argv, command, invocation)
		if err != nil {
			return s.fail(exitSetup, "%v", err)
		}
		filed, err := s.gatewayOutput(ctx, "api", "requests", invocation)
		if err != nil {
			s.logf("cannot list the requests the proxy filed: %v", err)
			return code
		}
		ids := strings.Fields(string(filed))
		if len(ids) == 0 {
			return code
		}
		if s.o.wait == 0 || attempt >= s.o.retries {
			return s.fail(code, "access is waiting for approval: %s (check with ssh %s status <id>)", strings.Join(ids, ", "), s.o.gateway)
		}
		fmt.Fprintf(s.stderr, "hallpass-api: %s needs approval (%s); waiting up to %s\n", command, strings.Join(ids, ", "), s.o.wait)
		if c := s.awaitApproval(ctx, ids); c != 0 {
			return c
		}
		fmt.Fprintln(s.stderr, "hallpass-api: approved; running the command again")
	}
}

// runOnce runs the tool once behind a fresh local proxy that tags its CONNECTs with this invocation.
func (s *session) runOnce(ctx context.Context, argv []string, command, invocation string) (int, error) {
	lp, err := startLocalProxy(ctx, s.tunnelPort, map[string]string{
		apienv.HeaderCommand: apienv.Encode(command), apienv.HeaderReason: apienv.Encode(s.o.reason), apienv.HeaderInvocation: invocation,
		apienv.HeaderRole: s.o.role, apienv.HeaderSession: s.o.session,
	})
	if err != nil {
		return 0, err
	}
	defer lp.Close()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // G204: running the user's command is the point
	cmd.Stdin, cmd.Stdout, cmd.Stderr = s.stdin, s.stdout, s.stderr
	// The role travels in the CONNECT header the local proxy adds, so the child's proxy URL carries none.
	cmd.Env = childEnv(os.Environ(), apienv.Vars(lp.Port(), "", "", filepath.Join(s.dir, "ca.pem"), filepath.Join(s.dir, "token")))
	s.logf("running %s", command)
	err = cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &ee):
		return ee.ExitCode(), nil
	}
	return 0, fmt.Errorf("cannot run %s: %w", argv[0], err)
}

// awaitApproval waits for every filed request; it returns 0 when all were approved, else the gateway exit code.
func (s *session) awaitApproval(ctx context.Context, ids []string) int {
	deadline := time.Now().Add(s.o.wait)
	for _, id := range ids {
		for {
			left := min(time.Until(deadline).Round(time.Second), maxWaitPerCall)
			if left < time.Second {
				return s.fail(exitPending, "still waiting for approval of %s; check later with ssh %s status %s", id, s.o.gateway, id)
			}
			out, _ := s.gatewayOutput(ctx, "status", id, "--wait", "--wait-timeout", left.String(), "--json")
			var doc struct {
				Request struct {
					State string `json:"state"`
				} `json:"request"`
			}
			_ = json.Unmarshal(out, &doc)
			switch doc.Request.State {
			case "approved":
			case "pending":
				if ctx.Err() != nil {
					return exitPending
				}
				continue
			case "denied":
				return s.fail(exitDenied, "request %s was denied", id)
			case "expired":
				return s.fail(exitExpired, "request %s expired before a decision", id)
			case "canceled":
				return s.fail(exitCanceled, "request %s was canceled", id)
			default:
				return s.fail(exitSetup, "cannot read the state of request %s", id)
			}
			break
		}
	}
	return 0
}

// gatewayOutput runs a gateway command over ssh and returns its standard output.
func (s *session) gatewayOutput(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, s.o.ssh, append([]string{"-o", "BatchMode=yes", "-T", s.o.gateway}, args...)...) //nolint:gosec // G204: the user's ssh and gateway
	var errb strings.Builder
	cmd.Stderr = &errb
	out, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(errb.String()); msg != "" {
			return out, fmt.Errorf("%w: %s", err, msg)
		}
	}
	return out, err
}

// openTunnel starts "ssh -N -L 127.0.0.1:<port>:hallpass:443 <gateway>" and waits until the port accepts.
// ClearAllForwardings=no overrides the "ClearAllForwardings yes" agent ssh configs carry, which would drop the -L too.
func (s *session) openTunnel(ctx context.Context) (func(), error) {
	port, err := freePort(ctx)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, s.o.ssh, "-N", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=no", "-o", "ExitOnForwardFailure=yes", //nolint:gosec // G204: the user's ssh and gateway
		"-L", fmt.Sprintf("127.0.0.1:%d:hallpass:443", port), s.o.gateway)
	var errb strings.Builder
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	exited := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); close(exited) }()
	stop := func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
		}
	}
	deadline := time.After(20 * time.Second)
	for {
		d := net.Dialer{Timeout: time.Second}
		if c, err := d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			_ = c.Close()
			s.tunnelPort = port
			s.logf("tunnel open on 127.0.0.1:%d", port)
			return stop, nil
		}
		select {
		case <-exited:
			return nil, fmt.Errorf("ssh exited (%w): %s", waitErr, strings.TrimSpace(errb.String()))
		case <-deadline:
			stop()
			return nil, errors.New("timed out waiting for the tunnel")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func freePort(ctx context.Context) (int, error) {
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func newInvocation() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "inv_" + base64.RawURLEncoding.EncodeToString(b)
}

// roleRE is the access profile alias rule; sessionRE the agent session rule.
var (
	roleRE    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	sessionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
)

// proxyVars are replaced in the child's environment, whatever case the parent used.
var proxyVars = regexp.MustCompile(`(?i)^(https?_proxy|all_proxy|no_proxy|ssl_cert_file|ssl_cert_dir|node_extra_ca_certs|requests_ca_bundle|curl_ca_bundle|cloudsdk_.*|gh_token|github_token|gh_enterprise_token|cloudflare_api_token|cloudflare_api_key|node_use_env_proxy)=`)

// noProxyVar matches NO_PROXY in any case; its entries are kept (see childEnv).
var noProxyVar = regexp.MustCompile(`(?i)^no_proxy=`)

// childEnv is the parent's environment without proxy, CA and token variables, plus the proxy settings. The parent's
// NO_PROXY entries are added to the proxy's own, so public hosts that are not API targets (and need no credentials)
// can still be reached directly; "*" is dropped because it would bypass the proxy for every host.
func childEnv(parent []string, vars [][2]string) []string {
	out := make([]string, 0, len(parent)+len(vars))
	var extra []string
	for _, kv := range parent {
		switch {
		case noProxyVar.MatchString(kv):
			_, v, _ := strings.Cut(kv, "=")
			for e := range strings.SplitSeq(v, ",") {
				if e = strings.TrimSpace(e); e != "" && e != "*" {
					extra = append(extra, e)
				}
			}
		case !proxyVars.MatchString(kv):
			out = append(out, kv)
		}
	}
	for _, kv := range vars {
		if strings.EqualFold(kv[0], "NO_PROXY") {
			kv[1] = mergeNoProxy(kv[1], extra)
		}
		out = append(out, kv[0]+"="+kv[1])
	}
	return out
}

// mergeNoProxy appends entries to a NO_PROXY list, without duplicates.
func mergeNoProxy(list string, entries []string) string {
	seen := map[string]bool{}
	var out []string
	for e := range strings.SplitSeq(list, ",") {
		if e != "" && !seen[strings.ToLower(e)] {
			seen[strings.ToLower(e)] = true
			out = append(out, e)
		}
	}
	for _, e := range entries {
		if !seen[strings.ToLower(e)] {
			seen[strings.ToLower(e)] = true
			out = append(out, e)
		}
	}
	return strings.Join(out, ",")
}

var secretArg = regexp.MustCompile(`(?i)(token|secret|password|passwd|api[-_]?key|credential)`)

// displayCommand renders argv for approvers: shell-quoted where needed, with values of secret-looking options
// replaced (--token x, --token=x).
func displayCommand(argv []string) string {
	parts := make([]string, len(argv))
	redactNext := false
	for i, a := range argv {
		switch {
		case redactNext:
			a, redactNext = "[redacted]", false
		case strings.HasPrefix(a, "-") && strings.Contains(a, "=") && secretArg.MatchString(a[:strings.Index(a, "=")]):
			a = a[:strings.Index(a, "=")+1] + "[redacted]"
		case strings.HasPrefix(a, "-") && secretArg.MatchString(a):
			redactNext = true
		}
		parts[i] = shellQuote(a)
	}
	return strings.Join(parts, " ")
}

func shellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		safe := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:=@,+%[]#", r)
		return !safe
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// localProxy accepts the tool's proxy connections, adds the hallpass-api headers to each CONNECT and passes the
// connection through the SSH tunnel to the gateway's proxy. It never sees inside TLS.
type localProxy struct {
	ctx     context.Context
	ln      net.Listener
	tunnel  int
	headers map[string]string
}

func startLocalProxy(ctx context.Context, tunnelPort int, headers map[string]string) (*localProxy, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &localProxy{ctx: ctx, ln: ln, tunnel: tunnelPort, headers: headers}
	go p.serve()
	return p, nil
}

func (p *localProxy) Port() int    { return p.ln.Addr().(*net.TCPAddr).Port }
func (p *localProxy) Close() error { return p.ln.Close() }

func (p *localProxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *localProxy) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	if req.Method != http.MethodConnect {
		msg := "hallpass-api: only HTTPS (CONNECT) goes through the API proxy\n"
		_, _ = fmt.Fprintf(c, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(msg), msg)
		return
	}
	var d net.Dialer
	up, err := d.DialContext(p.ctx, "tcp", "127.0.0.1:"+strconv.Itoa(p.tunnel))
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	defer up.Close()
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", req.Host, req.Host)
	for k, v := range p.headers {
		if v != "" {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(up, b.String()); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, br); closeWrite(up); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); closeWrite(c); done <- struct{}{} }()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}
