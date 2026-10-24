// Package sshproxy is the SSH data plane: it bridges an agent's session channel to a destination session opened with
// gateway-held credentials and strict host verification, records the activity, propagates EOF, signals, window
// changes and exit status, and terminates on enforcer command (PLAN §5.6, §7.8, HP-SSH-006..015).
package sshproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/credentials"
	"github.com/aurimasniekis/go-hallpass/internal/destssh"
	"github.com/aurimasniekis/go-hallpass/internal/egress"
	"github.com/aurimasniekis/go-hallpass/internal/gitproto"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/obs/tracing"
	"github.com/aurimasniekis/go-hallpass/internal/sftpaudit"
	"github.com/aurimasniekis/go-hallpass/internal/sshkeepalive"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// Gateway exit codes used by the data plane (PLAN §7.7).
const (
	CodeInternal               = 80
	CodeAccessEnded            = 87
	CodeDestinationUnavailable = 88
	CodeLimitExceeded          = 89
)

// Stream identifies a recorded byte stream.
type Stream byte

// Streams.
const (
	StreamPTY    Stream = 0
	StreamStdout Stream = 1
	StreamStderr Stream = 2
	StreamStdin  Stream = 3
)

// Recorder records one channel. Output blocks when the recorder's bounded queue is full (backpressure); any error
// means recording failed and, in mandatory mode, the channel is terminated (HP-REC-007, HP-REC-011).
type Recorder interface {
	SegmentID() string
	ExecRequested(cmd string) error
	PTY(p *PTYRequest) error
	Resize(cols, rows uint32) error
	Output(s Stream, data []byte) error
	Input(data []byte) error
	Signal(sig string) error
	EOF(s Stream) error
	Exit(status *int, signal string) error
	Notice(text string) error
	// Finalize completes the recording (final frame, rename, manifest).
	Finalize(reason string) error
	// Abort marks the recording failed.
	Abort(err error)
}

// RecorderFactory opens a recording for a registered channel; it must not return until the recording is established
// (header durable), because forwarding starts only afterwards in mandatory mode.
type RecorderFactory interface {
	Open(ctx context.Context, reg *access.ChannelReg, kind string, pty bool) (Recorder, error)
}

// Options configure the proxy.
type Options struct {
	Access      *access.Service
	Inventory   *inventory.Service
	Credentials *credentials.Service
	Guard       *egress.Guard
	Enforcer    *access.Enforcer
	Recorders   RecorderFactory
	Audit       *audit.Writer
	Store       *store.Store
	Logger      *slog.Logger
	DialTimeout time.Duration
	IdleTimeout time.Duration
	// KeepaliveInterval and KeepaliveMaxMissed probe the destination; an unresponsive destination ends the
	// channel (HP-SSH-012). A zero interval disables probing.
	KeepaliveInterval  time.Duration
	KeepaliveMaxMissed int
	EnvAllow           []string // global allowlist; roles may add more
	// Metrics records channel results, active channels, dial latency and rejected environment variables
	// (HP-OBS-004). Nil disables.
	Metrics *metrics.Metrics
}

// Proxy runs destination sessions.
type Proxy struct{ o Options }

// New returns a proxy.
func New(o Options) *Proxy {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	o.Logger = obs.Component(o.Logger, "sshproxy")
	if o.DialTimeout <= 0 {
		o.DialTimeout = 10 * time.Second
	}
	return &Proxy{o: o}
}

// Session is one agent session to proxy.
type Session struct {
	ConnectionID string
	AgentID      string
	KeyID        string
	SourceIP     string
	Grant        *access.Grant
	Kind         string // access.KindShell | access.KindExec
	Command      string // raw destination command for exec (HP-SSH-023)
	PTY          *PTYRequest
	Env          [][2]string
	Agent        ssh.Channel
	AgentReqs    <-chan *ssh.Request
	// Notify writes a gateway message to the agent (stderr for non-PTY, terminal for PTY).
	Notify func(msg string)
	// Git marks a git operation on a git remote (Kind is exec, there is no PTY).
	Git *GitOp
	// FileTransfer runs the destination's SFTP subsystem; every file operation is recorded (Kind is exec, no PTY).
	FileTransfer bool
}

// GitOp is a git operation on a git remote. The service runs on the upstream host with the forwarded path; only
// metadata is recorded (no pack data), and a push passes the ref policy before any of it reaches the host.
type GitOp struct {
	Service string
	Repo    string              // normalized repository, for the timeline and audit
	Forward string              // path sent to the upstream host
	Push    *gitproto.RefPolicy // receive-pack only
}

// CodeNotPermitted is the gateway exit code for a refused git push (the agent's ref updates are not allowed).
const CodeNotPermitted = 82

// Result reports how the session ended. GatewayCode is non-zero when the gateway (not the destination) ended it.
type Result struct {
	ExitStatus  *int
	ExitSignal  string
	GatewayCode int
	Reason      string
	// Detail is a classified, address-free description of why the channel failed or was ended (failureDetail).
	Detail string
	Err    error
	// Delivered is true when the proxy already sent the exit status to the agent and closed its channel.
	Delivered bool
}

// Run executes the full channel lifecycle: register → record → dial → enforce → activate → forward → close.
func (p *Proxy) Run(ctx context.Context, s *Session) Result {
	kind := metrics.ChannelKind(s.Kind)
	_, span := tracing.Start(ctx, tracing.SpanAuthorize, tracing.AgentID(s.AgentID), tracing.GrantID(s.Grant.ID),
		tracing.ConnectionID(s.ConnectionID))
	in := access.RegisterInput{ConnectionID: s.ConnectionID, AgentID: s.AgentID, KeyID: s.KeyID,
		GrantID: s.Grant.ID, Kind: s.Kind, PTY: s.PTY != nil}
	if s.Git != nil {
		in.GitService, in.GitRepo = s.Git.Service, s.Git.Repo
	}
	if s.FileTransfer {
		in.Subsystem = "sftp"
	}
	reg, err := p.o.Access.RegisterChannel(ctx, in)
	tracing.End(span, err)
	if err != nil {
		p.o.Metrics.SSHChannel(kind, registerResult(err))
		return registerFailure(err)
	}
	ctx = obs.WithIDs(ctx, obs.GrantID(reg.Grant.ID), obs.SessionID(reg.SessionID), obs.ChannelID(reg.ChannelID))
	res := p.run(ctx, s, reg)
	if res.Reason == "failed_before_start" {
		r := metrics.ChannelFailed
		if res.GatewayCode == CodeAccessEnded {
			r = metrics.ChannelDenied
		}
		p.o.Metrics.SSHChannel(kind, r)
	}
	ci := access.CloseInfo{Failed: res.Reason == "failed_before_start", Reason: res.Reason, Detail: res.Detail, GatewayCode: res.GatewayCode,
		ExitStatus: res.ExitStatus, ExitSignal: res.ExitSignal}
	if err := p.o.Access.CloseChannel(context.WithoutCancel(ctx), reg, ci); err != nil {
		p.o.Logger.Error("recording channel close failed", slog.String(obs.FieldChannelID, reg.ChannelID), obs.Err(err))
	}
	return res
}

// registerResult classifies a RegisterChannel refusal for metrics.
func registerResult(err error) metrics.ChannelResult {
	switch {
	case errors.Is(err, access.ErrConcurrencyLimit):
		return metrics.ChannelLimited
	case errors.Is(err, access.ErrLockdown):
		return metrics.ChannelLockdown
	case errors.Is(err, access.ErrStorageUnavailable):
		return metrics.ChannelNoStorage
	case errors.Is(err, access.ErrAccessEnded), errors.Is(err, access.ErrCapability), access.IsNotFoundOrForbidden(err):
		return metrics.ChannelDenied
	default:
		return metrics.ChannelFailed
	}
}

// dialResult classifies a destination dial outcome for metrics.
func dialResult(err error) metrics.DialResult {
	var ne net.Error
	switch {
	case err == nil:
		return metrics.DialOK
	case errors.Is(err, egress.ErrDenied):
		return metrics.DialEgressDenied
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return metrics.DialTimeout
	case strings.Contains(err.Error(), "unable to authenticate"):
		return metrics.DialAuthFailed
	default:
		if _, ok := destssh.IsHostKeyError(err); ok {
			return metrics.DialHostKey
		}
		return metrics.DialError
	}
}

func registerFailure(err error) Result {
	switch {
	case errors.Is(err, access.ErrConcurrencyLimit):
		return Result{GatewayCode: CodeLimitExceeded, Reason: "concurrency_limit", Err: err}
	case errors.Is(err, access.ErrAccessEnded), errors.Is(err, access.ErrLockdown), errors.Is(err, access.ErrCapability):
		return Result{GatewayCode: CodeAccessEnded, Reason: "access_ended", Err: err}
	case access.IsNotFoundOrForbidden(err):
		return Result{GatewayCode: 82, Reason: "not_found_or_forbidden", Err: err}
	default:
		return Result{GatewayCode: CodeInternal, Reason: "internal", Err: err}
	}
}

func (p *Proxy) run(ctx context.Context, s *Session, reg *access.ChannelReg) Result {
	fail := func(code int, stage string, err error) Result {
		return Result{GatewayCode: code, Reason: "failed_before_start", Detail: failureDetail(stage, err), Err: fmt.Errorf("%s: %w", stage, err)}
	}
	// 1. Recording must be established before anything is forwarded (mandatory mode). Git operations record
	// metadata only: the timeline events below, never the pack data.
	var rec Recorder
	if s.Git != nil || s.FileTransfer {
		rec = nopRecorder{}
	} else if p.o.Recorders != nil {
		r, err := p.o.Recorders.Open(ctx, reg, s.Kind, s.PTY != nil)
		if err != nil {
			if reg.Role.RecordingMode == "mandatory" {
				return fail(CodeInternal, "recording unavailable", err)
			}
			p.o.Logger.Warn("best-effort recording unavailable", slog.String(obs.FieldChannelID, reg.ChannelID), obs.Err(err))
		} else {
			rec = r
		}
	} else if reg.Role.RecordingMode == "mandatory" && s.Git == nil && !s.FileTransfer {
		return fail(CodeInternal, "recording unavailable", errors.New("no recorder configured"))
	}
	if rec == nil {
		rec = nopRecorder{}
	}
	var recFailed atomic.Bool // set once by the first recording failure; pumps run concurrently
	defer func() {
		if !recFailed.Load() {
			_ = rec.Finalize("closed")
		}
	}()

	// 2. Dial the destination with strict host verification and the role's credential.
	srv, err := p.o.Inventory.GetServer(ctx, reg.Grant.ServerID)
	if err != nil {
		return fail(CodeDestinationUnavailable, "server lookup", err)
	}
	ver, err := p.o.Inventory.NewVerifier(ctx, srv.ID)
	if err != nil {
		p.hostKeyAlert(ctx, s, srv.ID, err)
		return fail(CodeDestinationUnavailable, "host identity", err)
	}
	auth, err := p.o.Credentials.RoleAuth(ctx, reg.Role.ID, reg.Grant.ID, s.ConnectionID)
	if err != nil {
		return fail(CodeDestinationUnavailable, "login credential", err)
	}
	dctx, dspan := tracing.StartKind(ctx, tracing.SpanDial, trace.SpanKindClient, tracing.ServerID(srv.ID), tracing.RoleID(reg.Role.ID))
	dialStart := time.Now()
	client, err := destssh.Dial(dctx, p.o.Guard, destssh.Target{Host: srv.Address, Port: srv.Port, User: reg.Role.RemoteUser,
		Verifier: ver, Signers: auth.Signers}, p.o.DialTimeout)
	p.o.Metrics.Dial(dialResult(err), time.Since(dialStart))
	tracing.End(dspan, err)
	if err != nil {
		if _, ok := destssh.IsHostKeyError(err); ok {
			p.hostKeyAlert(ctx, s, srv.ID, err)
		}
		return fail(CodeDestinationUnavailable, "destination connection", err)
	}
	defer client.Close()
	// Keepalives start before the session is opened, so a destination that hangs during session setup is also
	// detected (HP-SSH-012): closing the client unblocks NewSession and the later pumps.
	var term atomic.Pointer[terminator]
	kctx, stopKeepalive := context.WithCancel(ctx)
	defer stopKeepalive()
	go func() {
		reason := sshkeepalive.Run(kctx, client, p.o.KeepaliveInterval, p.o.KeepaliveMaxMissed)
		if reason == "" {
			return
		}
		if t := term.Load(); t != nil {
			t.terminate("destination_" + reason)
			return
		}
		_ = client.Close()
	}()
	var sess remoteSession
	var sub *subsystemSession
	if s.FileTransfer {
		sub, err = newSubsystemSession(client)
		sess = sub
	} else {
		sess, err = client.NewSession()
	}
	if err != nil {
		return fail(CodeDestinationUnavailable, "destination session", err)
	}
	defer sess.Close()

	// 3. Register with the enforcer; access may have ended since RegisterChannel (race guard).
	t := &terminator{agent: s.Agent, sess: sess, client: client, notify: s.Notify}
	term.Store(t)
	live := &access.Live{ChannelID: reg.ChannelID, ConnectionID: s.ConnectionID, AgentID: s.AgentID, KeyID: s.KeyID, GrantID: reg.Grant.ID,
		CredentialRef: auth.CredentialRef, ExpiresAt: reg.Grant.ExpiresAt, Terminate: t.terminate}
	if p.o.Enforcer != nil {
		if err := p.o.Enforcer.Register(live); err != nil {
			return fail(CodeAccessEnded, "access ended", err)
		}
		defer p.o.Enforcer.Unregister(reg.ChannelID)
	}

	// 4. Prepare the destination session: PTY, environment allowlist, pipes.
	if s.PTY != nil {
		if err := sess.RequestPty(s.PTY.Term, int(s.PTY.Rows), int(s.PTY.Cols), s.PTY.Modes); err != nil {
			return fail(CodeDestinationUnavailable, "destination pty", err)
		}
		_ = rec.PTY(s.PTY)
	}
	env := FilterEnv(s.Env, p.o.EnvAllow, reg.Role.EnvAllow)
	if s.Git != nil {
		env = gitEnv(s.Env)
	}
	if s.FileTransfer {
		env = nil
	}
	p.o.Metrics.SSHEnvRejected(len(s.Env) - len(env)) // HP-SSH-008: names are never exported
	for _, kv := range env {
		_ = sess.Setenv(kv[0], kv[1]) // destination sshd AcceptEnv decides; failures are not fatal
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return fail(CodeInternal, "stdin", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return fail(CodeInternal, "stdout", err)
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return fail(CodeInternal, "stderr", err)
	}
	data := map[string]any{"kind": s.Kind, "pty": s.PTY != nil, "credential_kind": auth.Kind, "segment_id": rec.SegmentID()}
	if s.FileTransfer {
		data["subsystem"] = "sftp"
		err = sub.Start("sftp")
	} else if s.Git != nil {
		data["git_service"], data["repo"] = s.Git.Service, s.Git.Repo
		_ = p.o.Access.AppendSessionEvent(ctx, reg, access.EvGitRequested, "", map[string]any{"service": s.Git.Service, "repo": s.Git.Repo})
		err = sess.(*ssh.Session).Start(s.Git.Service + " " + gitproto.Quote(s.Git.Forward))
	} else if s.Kind == access.KindExec {
		if err := rec.ExecRequested(s.Command); err != nil {
			recFailed.Store(true)
			rec.Abort(err)
			return fail(CodeInternal, "recording exec", err)
		}
		_ = p.o.Access.AppendSessionEvent(ctx, reg, access.EvExecRequested, rec.SegmentID(), map[string]any{"has_command": s.Command != "", "bytes": len(s.Command)})
		err = sess.(*ssh.Session).Start(s.Command)
	} else {
		err = sess.(*ssh.Session).Shell()
	}
	if err != nil {
		return fail(CodeDestinationUnavailable, "start", err)
	}
	if err := p.o.Access.ActivateChannel(ctx, reg, auth.CredentialRef, data); err != nil {
		return fail(CodeAccessEnded, "activate", err)
	}
	kind := metrics.ChannelKind(s.Kind)
	p.o.Metrics.SSHChannel(kind, metrics.ChannelOpened)
	p.o.Metrics.SSHChannelOpened(kind)
	defer p.o.Metrics.SSHChannelClosed(kind)

	// 5. Forward until the destination exits or the channel is terminated.
	recordInput := reg.Role.RecordInput
	var activity atomic.Int64
	activity.Store(time.Now().UnixNano())
	touch := func() { activity.Store(time.Now().UnixNano()) }
	outStream, errStream := StreamStdout, StreamStderr
	if s.PTY != nil {
		outStream = StreamPTY
	}
	// recFail handles a recording failure and reports whether forwarding may continue. With mandatory recording the
	// channel is terminated before anything else, so no unrecorded byte is forwarded (G-8, HP-REC-007); aborting the
	// recorder and the timeline write may block on stalled storage, so they run in the background (HP-REC-011).
	recFail := func(err error) (forward bool) {
		mandatory := reg.Role.RecordingMode == "mandatory"
		if mandatory {
			t.terminate("recording_failed")
		}
		if recFailed.CompareAndSwap(false, true) {
			p.o.Logger.Error("recording write failed", slog.String(obs.FieldChannelID, reg.ChannelID), obs.Err(err))
			go func() {
				// Timeline first: once the segment shows "failed", its recording.failed event already exists.
				_ = p.o.Access.AppendSessionEvent(context.WithoutCancel(ctx), reg, access.EvRecordingFailed, rec.SegmentID(), map[string]any{"error": "recording write failed"})
				rec.Abort(err)
			}()
		}
		return !mandatory
	}
	var outputs sync.WaitGroup
	var bytesIn, bytesOut atomic.Int64
	agentOut := io.Writer(s.Agent)
	if s.Git != nil {
		agentOut = countingWriter{w: s.Agent, n: &bytesOut}
	}
	var files *sftpaudit.Tracker
	if s.FileTransfer {
		files = sftpaudit.NewTracker(func(e sftpaudit.Event) {
			_ = p.o.Access.AppendSessionEvent(context.WithoutCancel(ctx), reg, access.EvFileOperation, "", map[string]any{
				"op": e.Op, "path": e.Path, "target": e.Target, "bytes": e.Bytes, "sha256": e.SHA256, "ok": e.OK, "error": e.Error})
		})
		outputs.Go(func() {
			_ = sftpaudit.Pipe(stdout, s.Agent, func(pkt []byte) { touch(); files.Server(pkt) })
		})
	} else {
		outputs.Go(func() { pump(stdout, agentOut, outStream, rec, touch, recFail) })
	}
	outputs.Go(func() { pump(stderr, s.Agent.Stderr(), errStream, rec, touch, recFail) })
	go func() {
		if files != nil {
			if err := sftpaudit.Pipe(s.Agent, stdin, func(pkt []byte) { touch(); files.Client(pkt) }); err != nil {
				t.terminate("sftp_protocol_error")
			}
			_ = stdin.Close()
			return
		}
		var src io.Reader = s.Agent
		if s.Git != nil && s.Git.Service == gitproto.ReceivePack {
			r, ok := p.gitPushGate(ctx, s, reg, t, stdin, &bytesIn)
			if !ok {
				return
			}
			src = r
			touch()
		}
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				touch()
				if recordInput {
					if rerr := rec.Input(buf[:n]); rerr != nil && !recFail(rerr) {
						return
					}
				}
				bytesIn.Add(int64(n))
				if _, werr := stdin.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				_ = rec.EOF(StreamStdin)
				_ = stdin.Close() // propagate EOF / half-close (HP-SSH-006)
				return
			}
		}
	}()
	go func() {
		p.agentRequests(s, sess, rec, touch)
		// The agent's request stream ends when its channel or connection closes: release the destination even if it
		// ignores stdin EOF or is unreachable (HP-SSH-015). After a normal exit this is a no-op.
		t.terminate("agent_disconnected")
	}()
	stopIdle := make(chan struct{})
	if p.o.IdleTimeout > 0 {
		go idleWatch(p.o.IdleTimeout, &activity, stopIdle, t)
	}
	outputs.Wait()
	waitErr := sess.Wait()
	close(stopIdle)
	if files != nil {
		sum := files.Summary()
		_ = p.o.Access.AppendSessionEvent(context.WithoutCancel(ctx), reg, access.EvFileSummary, "", map[string]any{
			"files": sum.Files, "bytes_read": sum.BytesRead, "bytes_written": sum.BytesWritten, "suppressed_events": sum.Suppressed})
	}
	if s.Git != nil {
		_ = p.o.Access.AppendSessionEvent(context.WithoutCancel(ctx), reg, access.EvGitTransferred, "",
			map[string]any{"service": s.Git.Service, "repo": s.Git.Repo, "bytes_in": bytesIn.Load(), "bytes_out": bytesOut.Load()})
	}

	res := Result{Reason: "exit"}
	if reason := t.reason(); reason != "" {
		res = Result{GatewayCode: CodeAccessEnded, Reason: reason, Detail: terminationDetail(reason)}
		switch {
		case reason == "recording_failed":
			res.GatewayCode = CodeInternal
		case reason == "git_push_refused":
			res.GatewayCode = CodeNotPermitted
		case strings.HasPrefix(reason, "destination_keepalive"):
			res.GatewayCode = CodeDestinationUnavailable
		}
		code := res.GatewayCode
		_ = rec.Exit(&code, "")
		t.finish(code)
		res.Delivered = true
		return res
	}
	switch e := waitErr.(type) { //nolint:errorlint // ssh.Session.Wait returns these concrete types unwrapped
	case nil:
		zero := 0
		res.ExitStatus = &zero
	case *ssh.ExitError:
		if sig := e.Signal(); sig != "" {
			res.ExitSignal = sig
		} else {
			st := e.ExitStatus()
			res.ExitStatus = &st
		}
	case *remoteExit:
		if e.signal != "" {
			res.ExitSignal = e.signal
		} else {
			res.ExitStatus = &e.status
		}
	case *ssh.ExitMissingError:
		res.Reason = "destination_no_exit_status"
	default:
		res.Reason, res.Err, res.Detail = "destination_error", waitErr, "destination connection lost"
	}
	_ = rec.Exit(res.ExitStatus, res.ExitSignal)
	_ = s.Agent.CloseWrite()
	if res.ExitSignal != "" {
		_, _ = s.Agent.SendRequest("exit-signal", false, ExitSignalPayload(res.ExitSignal, false, ""))
	} else if res.ExitStatus != nil {
		_, _ = s.Agent.SendRequest("exit-status", false, ExitStatusPayload(uint32(*res.ExitStatus))) //nolint:gosec // exit codes are 0..255
	}
	_ = s.Agent.Close()
	res.Delivered = true
	return res
}

// pump copies destination output to the agent, recording it first. Writes to the agent block on its SSH window, which
// stops reading from the destination: bounded memory and end-to-end backpressure (HP-SSH-014).
func pump(src io.Reader, dst io.Writer, stream Stream, rec Recorder, touch func(), recFail func(error) bool) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			touch()
			if rerr := rec.Output(stream, buf[:n]); rerr != nil && !recFail(rerr) {
				return // the chunk was not recorded: it must not reach the agent
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			_ = rec.EOF(stream)
			return
		}
	}
}

// agentRequests forwards window changes and signals; everything else (including late exec/shell/subsystem) is refused.
func (p *Proxy) agentRequests(s *Session, sess remoteSession, rec Recorder, touch func()) {
	for r := range s.AgentReqs {
		ok := false
		switch r.Type {
		case "window-change":
			if wc, err := ParseWindowChange(r.Payload); err == nil && s.PTY != nil {
				ok = sess.WindowChange(int(wc.Rows), int(wc.Cols)) == nil
				_ = rec.Resize(wc.Cols, wc.Rows)
				touch()
			}
		case "signal":
			if sig, err := ParseSignal(r.Payload); err == nil {
				ok = sess.Signal(sig) == nil
				_ = rec.Signal(string(sig))
			}
		}
		if r.WantReply {
			_ = r.Reply(ok, nil)
		}
	}
}

func idleWatch(limit time.Duration, last *atomic.Int64, stop <-chan struct{}, t *terminator) {
	tick := time.NewTicker(min(limit/4, time.Minute))
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-tick.C:
			if now.Sub(time.Unix(0, last.Load())) > limit {
				t.terminate("idle_timeout")
				return
			}
		}
	}
}

// terminator ends a session on enforcer command: notify the agent, HUP and close the destination session.
type terminator struct {
	agent  ssh.Channel
	sess   remoteSession
	client *ssh.Client
	notify func(string)

	mu       sync.Mutex
	why      string
	done     bool
	notified chan struct{} // closed when the termination notice has been written
}

func (t *terminator) terminate(reason string) { t.end(reason, "access ended ("+reason+")") }

// refuse ends the session like terminate but without the "access ended" notice: the caller already told the agent why.
func (t *terminator) refuse(reason string) { t.end(reason, "") }

func (t *terminator) end(reason, notice string) {
	t.mu.Lock()
	if t.why != "" {
		t.mu.Unlock()
		return
	}
	t.why = reason
	t.notified = make(chan struct{})
	t.mu.Unlock()
	go func() {
		defer close(t.notified)
		if t.notify != nil && notice != "" {
			t.notify(notice)
		}
	}()
	_ = t.sess.Signal(ssh.SIGHUP)
	_ = t.sess.Close()
	_ = t.client.Close() // unblocks pumps and Wait
	// An output pump blocked on a full agent window (the agent stopped reading) would keep the channel open forever:
	// close the agent side if the normal finish has not happened shortly (HP-SSH-012, HP-SSH-015).
	time.AfterFunc(agentCloseGrace, func() {
		t.mu.Lock()
		done := t.done
		t.mu.Unlock()
		if !done {
			_ = t.agent.Close()
		}
	})
}

// agentCloseGrace bounds how long a terminated channel waits for its output pumps before the agent side is closed.
const agentCloseGrace = 2 * time.Second

func (t *terminator) reason() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.why
}

// finish sends the gateway exit code to the agent and closes its channel.
func (t *terminator) finish(code int) {
	t.mu.Lock()
	if t.done {
		t.mu.Unlock()
		return
	}
	t.done = true
	notified := t.notified
	t.mu.Unlock()
	// The notice is written to the agent channel from another goroutine; x/crypto channels do not allow a concurrent
	// write and CloseWrite, so wait for it (bounded: a stalled agent window must not hold the session open).
	if notified != nil {
		select {
		case <-notified:
		case <-time.After(2 * time.Second):
			_ = t.agent.Close()
			return
		}
	}
	_ = t.agent.CloseWrite()
	_, _ = t.agent.SendRequest("exit-status", false, ExitStatusPayload(uint32(code))) //nolint:gosec // small constant
	_ = t.agent.Close()
}

func (p *Proxy) hostKeyAlert(ctx context.Context, s *Session, serverID string, err error) {
	// The raw error embeds the destination host:port; the audit row carries the address-free classification and the
	// raw error stays in the gateway log (HP-SRV-010, SR-08).
	details := map[string]any{"server_id": serverID, "error": dialDetail(err)}
	if he, ok := destssh.IsHostKeyError(err); ok {
		details["presented_fingerprint"], details["algorithm"], details["reason"] = he.Presented, he.Algorithm, he.Reason
	}
	p.o.Logger.Error("destination host key not trusted", slog.String(obs.FieldServerID, serverID), obs.Err(err))
	_ = p.o.Store.W().TxNamed(context.WithoutCancel(ctx), "sshproxy.host_key_alert", func(tx *store.Tx) error {
		_, err := p.o.Audit.Append(ctx, tx, audit.Event{Actor: audit.System, Action: "server.host_key_mismatch", Outcome: audit.OutcomeFailure,
			Target: audit.Target{Type: "server", ID: serverID}, Details: details})
		return err
	})
}

// FilterEnv keeps variables matching the global or role allowlist (exact names or trailing-* prefixes, HP-SSH-008).
func FilterEnv(env [][2]string, global, role []string) [][2]string {
	allow := slices.Concat(global, role)
	var out [][2]string
	for _, kv := range env {
		if len(out) >= 64 || len(kv[0]) > 64 || len(kv[1]) > 4096 {
			continue
		}
		for _, a := range allow {
			if a == kv[0] || (strings.HasSuffix(a, "*") && strings.HasPrefix(kv[0], strings.TrimSuffix(a, "*"))) {
				out = append(out, kv)
				break
			}
		}
	}
	return out
}

type nopRecorder struct{}

func (nopRecorder) SegmentID() string           { return "" }
func (nopRecorder) ExecRequested(string) error  { return nil }
func (nopRecorder) PTY(*PTYRequest) error       { return nil }
func (nopRecorder) Resize(uint32, uint32) error { return nil }
func (nopRecorder) Output(Stream, []byte) error { return nil }
func (nopRecorder) Input([]byte) error          { return nil }
func (nopRecorder) Signal(string) error         { return nil }
func (nopRecorder) EOF(Stream) error            { return nil }
func (nopRecorder) Exit(*int, string) error     { return nil }
func (nopRecorder) Notice(string) error         { return nil }
func (nopRecorder) Finalize(string) error       { return nil }
func (nopRecorder) Abort(error)                 {}
