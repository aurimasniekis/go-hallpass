package sshfront

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/buildinfo"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/sshfront/grammar"
	"github.com/aurimasniekis/go-hallpass/internal/sshproxy"
)

// startTimeout bounds how long a session may take to send its shell/exec request.
const startTimeout = 30 * time.Second

// Handler implements the agent command interface (PLAN §7) on top of the access service and the data plane.
type Handler struct {
	Access      *access.Service
	Engine      *policy.Engine
	Proxy       *sshproxy.Proxy
	Bus         *eventbus.Bus
	Log         *slog.Logger
	WaitDefault time.Duration
	WaitMax     time.Duration
	// Deny is called for refused session requests (subsystems, forwarding) so they are audited.
	Deny func(ctx context.Context, c *Conn, action string, details map[string]any)
	// Metrics counts refused session requests (subsystem, x11, agent forwarding; HP-SSH-007). Nil disables.
	Metrics *metrics.Metrics
}

// session is the per-channel state.
type session struct {
	h     *Handler
	c     *Conn
	ch    ssh.Channel
	reqs  <-chan *ssh.Request
	pty   *sshproxy.PTYRequest
	env   [][2]string
	out   io.Writer // stdout (PTY: terminal)
	diag  io.Writer // gateway messages: stderr, or the terminal when a PTY is allocated
	snap  *policy.Snapshot
	jsonE bool // errors as JSON
}

// HandleSession implements SessionHandler.
func (h *Handler) HandleSession(ctx context.Context, c *Conn, ch ssh.Channel, reqs <-chan *ssh.Request) {
	s := &session{h: h, c: c, ch: ch, reqs: reqs, out: ch, diag: ch.Stderr()}
	command, ok := s.awaitStart(ctx)
	if !ok {
		return
	}
	if s.pty != nil {
		s.out = crlfWriter{ch}
		s.diag = s.out
	}
	code := s.run(ctx, command)
	if code >= 0 {
		s.exit(code)
	}
}

// awaitStart collects pty-req and env until shell or exec arrives; forwarding-related and subsystem requests are
// refused (HP-SSH-007).
func (s *session) awaitStart(ctx context.Context) (string, bool) {
	t := time.NewTimer(startTimeout)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", false
		case <-t.C:
			return "", false
		case r, ok := <-s.reqs:
			if !ok {
				return "", false
			}
			switch r.Type {
			case "pty-req":
				p, err := sshproxy.ParsePTYRequest(r.Payload)
				if err == nil {
					s.pty = p
				}
				reply(r, err == nil)
			case "env":
				name, val, err := sshproxy.ParseEnv(r.Payload)
				if err == nil && len(s.env) < 64 {
					s.env = append(s.env, [2]string{name, val})
				}
				reply(r, err == nil)
			case "window-change":
				if wc, err := sshproxy.ParseWindowChange(r.Payload); err == nil && s.pty != nil {
					s.pty.Cols, s.pty.Rows = wc.Cols, wc.Rows
				}
				reply(r, false)
			case "shell":
				reply(r, true)
				return "", true
			case "exec":
				var p struct{ Cmd string }
				if err := ssh.Unmarshal(r.Payload, &p); err != nil {
					reply(r, false)
					return "", false
				}
				reply(r, true)
				return p.Cmd, true
			default: // subsystem (sftp), x11-req, auth-agent-req@openssh.com, unknown
				reply(r, false)
				s.h.Metrics.SSHRefused(refusedType(r.Type))
				if s.h.Deny != nil {
					s.h.Deny(ctx, s.c, "ssh.session_request.denied", map[string]any{"request_type": truncate(r.Type, 64)})
				}
			}
		}
	}
}

func reply(r *ssh.Request, ok bool) {
	if r.WantReply {
		_ = r.Reply(ok, nil)
	}
}

func (s *session) exit(code int) {
	_ = s.ch.CloseWrite()
	_, _ = s.ch.SendRequest("exit-status", false, sshproxy.ExitStatusPayload(uint32(code))) //nolint:gosec // 0..255
	_ = s.ch.Close()
}

// fail writes a gateway error: one JSON line on stderr for JSON mode or non-PTY sessions, text otherwise.
func (s *session) fail(err error) int {
	if s.jsonE || s.pty == nil {
		_, _ = s.ch.Stderr().Write(grammar.ErrorJSON(err))
	} else {
		_, _ = io.WriteString(s.diag, grammar.ErrorText(err))
	}
	return int(grammar.ExitCodeOf(err))
}

func (s *session) notice(msg string) {
	_, _ = io.WriteString(s.diag, "hallpass: "+msg+"\n")
}

// mapErr converts service errors to gateway errors without leaking internals.
func mapErr(err error, requestID string) error {
	var ge *grammar.Error
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ge):
		return err
	case access.IsNotFoundOrForbidden(err), errors.Is(err, policy.ErrNotFoundOrForbidden):
		return grammar.NotFoundOrForbidden()
	case errors.Is(err, access.ErrReasonRequired):
		return grammar.ReasonRequired()
	case errors.Is(err, access.ErrLockdown), errors.Is(err, access.ErrAccessEnded), errors.Is(err, access.ErrCapability):
		return grammar.NewError(grammar.ExitAccessEnded, "access is not available: "+publicMessage(err)).WithRequestID(requestID)
	case errors.Is(err, apperr.ErrRateLimited):
		return grammar.NewError(grammar.ExitLimitExceeded, publicMessage(err)).WithRequestID(requestID)
	case errors.Is(err, apperr.ErrInvalid):
		return grammar.Usage(publicMessage(err))
	case errors.Is(err, access.ErrStorageUnavailable):
		return grammar.Internal()
	}
	return grammar.Internal()
}

func publicMessage(err error) string {
	var ae *apperr.Error
	if errors.As(err, &ae) {
		return ae.Message
	}
	return "unavailable"
}

func (s *session) run(ctx context.Context, command string) int {
	cmd, err := grammar.Parse(command)
	if err != nil {
		return s.fail(err)
	}
	s.jsonE = grammar.JSONOutput(cmd)
	if s.snap, err = s.h.Engine.Current(ctx); err != nil {
		s.h.Log.Error("policy snapshot unavailable", obs.Err(err))
		return s.fail(grammar.Internal())
	}
	switch c := cmd.(type) {
	case grammar.List:
		return s.list(ctx, c)
	case grammar.Roles:
		return s.roles(ctx, c)
	case grammar.Request:
		return s.request(ctx, c)
	case grammar.Status:
		return s.status(ctx, c)
	case grammar.Cancel:
		return s.cancel(ctx, c)
	case grammar.Sessions:
		return s.sessions(ctx, c)
	case grammar.WhoAmI:
		doc := grammar.NewWhoAmIDoc(s.c.AgentID, s.c.AgentName, s.c.KeyID, s.c.Fingerprint, s.c.SourceIP.String())
		return s.emit(c.JSON, doc, grammar.RenderWhoAmI(doc))
	case grammar.Version:
		bi := buildinfo.Get()
		doc := grammar.NewVersionDoc(bi.Version, bi.Commit)
		return s.emit(c.JSON, doc, grammar.RenderVersion(doc))
	case grammar.Help:
		text, err := grammar.HelpText(c.Topic)
		if err != nil {
			return s.fail(err)
		}
		_, _ = io.WriteString(s.out, text)
		return 0
	case grammar.Connect:
		return s.connect(ctx, c.Alias, c.Opts, c.EffectiveWait(), access.KindShell, "")
	case grammar.Exec:
		return s.connect(ctx, c.Alias, c.Opts, c.EffectiveWait(), access.KindExec, c.Remote)
	}
	return s.fail(grammar.Internal())
}

func (s *session) emit(asJSON bool, doc any, human string) int {
	if asJSON {
		b, err := grammar.Marshal(doc)
		if err != nil {
			return s.fail(grammar.Internal())
		}
		_, _ = s.out.Write(b)
		return 0
	}
	_, _ = io.WriteString(s.out, human)
	return 0
}

func level(l string) string {
	if l == policy.LevelAutoApprove {
		return grammar.LevelAuto
	}
	return l
}

func durs(ds []time.Duration) []grammar.Duration {
	out := make([]grammar.Duration, len(ds))
	for i, d := range ds {
		out[i] = grammar.Duration(d)
	}
	return out
}

// activeGrants maps roleID → the grant activity would use.
func (s *session) activeGrants(ctx context.Context) map[string]*access.Grant {
	out := map[string]*access.Grant{}
	gs, err := s.h.Access.ActiveGrantsForAgent(ctx, s.c.AgentID)
	if err != nil {
		return out
	}
	for _, g := range gs {
		if cur, ok := out[g.RoleID]; !ok || g.ExpiresAt.After(cur.ExpiresAt) {
			out[g.RoleID] = g
		}
	}
	return out
}

func activeOf(g *access.Grant) *grammar.ActiveGrant {
	if g == nil {
		return nil
	}
	return &grammar.ActiveGrant{GrantID: g.ID, ExpiresAt: grammar.Time(g.ExpiresAt)}
}

func (s *session) list(ctx context.Context, c grammar.List) int {
	now := s.h.Access.Clock().Now()
	active := s.activeGrants(ctx)
	var servers []grammar.ListServer
	for _, vs := range s.snap.Visible(s.c.AgentID) {
		if c.Server != "" && vs.Server.Alias != c.Server {
			continue
		}
		ls := grammar.ListServer{Alias: vs.Server.Alias, Description: vs.Server.Description}
		for _, r := range vs.Roles {
			ls.Roles = append(ls.Roles, grammar.ListRole{Alias: r.Role.Name, Description: r.Role.Description, Level: level(r.Decision.Level),
				ActiveGrant: activeOf(active[r.Role.ID])})
		}
		servers = append(servers, ls)
	}
	if c.Server != "" && len(servers) == 0 {
		return s.fail(grammar.NotFoundOrForbidden())
	}
	doc := grammar.NewListDoc(now, servers)
	return s.emit(c.JSON, doc, grammar.RenderList(doc))
}

func (s *session) roles(ctx context.Context, c grammar.Roles) int {
	vs, err := s.snap.ResolveServer(s.c.AgentID, c.Alias)
	if err != nil {
		return s.fail(mapErr(err, ""))
	}
	active := s.activeGrants(ctx)
	var roles []grammar.RoleDetail
	for _, r := range vs.Roles {
		roles = append(roles, grammar.RoleDetail{Alias: r.Role.Name, Description: r.Role.Description, Level: level(r.Decision.Level),
			Capabilities: r.Role.Capabilities, DefaultDuration: grammar.Duration(s.snap.DefaultDuration(r.Role.ID, r.Decision)),
			MaxDuration: grammar.Duration(r.Decision.MaxDuration), AllowedDurations: durs(r.Decision.AllowedDurations),
			ActiveGrant: activeOf(active[r.Role.ID])})
	}
	doc := grammar.NewRolesDoc(s.h.Access.Clock().Now(), grammar.ServerRef{Alias: vs.Server.Alias, Description: vs.Server.Description}, roles)
	return s.emit(c.JSON, doc, grammar.RenderRoles(doc))
}

// resolveRole picks the role: explicit --role, else the single role with an active grant, else the single
// requestable role; otherwise an interactive choice on a PTY or an ambiguity error (HP-SSH-022).
func (s *session) resolveRole(ctx context.Context, alias, roleAlias string) (policy.VisibleServer, policy.VisibleRole, error) {
	if roleAlias != "" {
		vs, vr, err := s.snap.ResolveRole(s.c.AgentID, alias, roleAlias)
		return vs, vr, mapErr(err, "")
	}
	vs, err := s.snap.ResolveServer(s.c.AgentID, alias)
	if err != nil {
		return vs, policy.VisibleRole{}, mapErr(err, "")
	}
	// HP-SSH-022: implicit only when exactly one role is requestable or has an active grant.
	active := s.activeGrants(ctx)
	var choices []policy.VisibleRole
	for _, r := range vs.Roles {
		if active[r.Role.ID] != nil || r.Decision.Requestable() {
			choices = append(choices, r)
		}
	}
	switch len(choices) {
	case 0:
		return vs, policy.VisibleRole{}, grammar.NotFoundOrForbidden()
	case 1:
		return vs, choices[0], nil
	}
	names := make([]string, len(choices))
	for i, r := range choices {
		names[i] = r.Role.Name
	}
	if s.pty == nil {
		return vs, policy.VisibleRole{}, grammar.AmbiguousRole(alias, names)
	}
	s.notice("choose a role on " + alias + ":")
	for i, r := range choices {
		_, _ = fmt.Fprintf(s.diag, "  %d) %s — %s\n", i+1, r.Role.Name, sanitize(r.Role.Description))
	}
	line, err := s.prompt(ctx, "role number: ", 8)
	if err != nil {
		return vs, policy.VisibleRole{}, err
	}
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(line), "%d", &n); err != nil || n < 1 || n > len(choices) {
		return vs, policy.VisibleRole{}, grammar.AmbiguousRole(alias, names)
	}
	return vs, choices[n-1], nil
}

func (s *session) request(ctx context.Context, c grammar.Request) int {
	vs, vr, err := s.resolveRole(ctx, c.Alias, c.Opts.Role)
	if err != nil {
		return s.fail(err)
	}
	res, code := s.createRequest(ctx, vs, vr, c.Opts)
	if res == nil {
		return code
	}
	if !c.EffectiveWait() || res.Grant != nil || res.Request.Terminal() {
		doc := grammar.NewRequestDoc(s.h.Access.Clock().Now(), s.requestInfo(res))
		return s.emit(c.Opts.JSON, doc, grammar.RenderRequest(doc))
	}
	req, g, err := s.wait(ctx, res.Request, c.Opts.EffectiveWaitTimeout())
	if err != nil {
		return s.fail(err)
	}
	doc := grammar.NewStatusDoc(s.h.Access.Clock().Now(), s.statusInfo(req, g))
	if code := s.emit(c.Opts.JSON, doc, grammar.RenderStatus(doc)); code != 0 {
		return code
	}
	return stateExit(req.State)
}

func stateExit(state string) int {
	switch state {
	case access.ReqDenied:
		return int(grammar.ExitDenied)
	case access.ReqExpired:
		return int(grammar.ExitExpired)
	case access.ReqCanceled:
		return int(grammar.ExitCanceled)
	}
	return 0
}

// createRequest collects the reason (prompting on a PTY when required) and creates or reuses the request.
func (s *session) createRequest(ctx context.Context, vs policy.VisibleServer, vr policy.VisibleRole, o grammar.Opts) (*access.CreateResult, int) {
	if !vr.Decision.Requestable() {
		return nil, s.fail(grammar.NotFoundOrForbidden())
	}
	reason := o.Reason
	if reason == "" && vr.Decision.RequireReason {
		if s.pty == nil {
			return nil, s.fail(grammar.ReasonRequired())
		}
		line, err := s.prompt(ctx, "reason for access to "+vs.Server.Alias+" as "+vr.Role.Name+": ", grammar.MaxReasonRunes)
		if err != nil {
			return nil, s.fail(err)
		}
		if reason = strings.TrimSpace(line); reason == "" {
			return nil, s.fail(grammar.ReasonRequired())
		}
	}
	res, err := s.h.Access.CreateRequest(ctx, access.CreateRequestInput{AgentID: s.c.AgentID, KeyID: s.c.KeyID, ServerID: vs.Server.ID,
		RoleID: vr.Role.ID, Reason: reason, Duration: o.Duration, IdempotencyKey: o.IdempotencyKey})
	if err != nil {
		return nil, s.fail(mapErr(err, ""))
	}
	return res, 0
}

func (s *session) requestInfo(res *access.CreateResult) grammar.RequestInfo {
	r := res.Request
	info := grammar.RequestInfo{ID: r.ID, Server: s.serverAlias(r.ServerID), Role: s.roleAlias(r.RoleID), State: r.State,
		Deduplicated: res.Deduplicated, CreatedAt: grammar.Time(r.CreatedAt), ExpiresAt: grammar.Time(r.ExpiresAt),
		RequestedDuration: grammar.Duration(r.RequestedDuration)}
	if res.Grant != nil {
		info.Grant = grantInfo(res.Grant)
	}
	return info
}

func grantInfo(g *access.Grant) *grammar.GrantInfo {
	return &grammar.GrantInfo{ID: g.ID, State: g.State, StartsAt: grammar.Time(g.StartsAt), ExpiresAt: grammar.Time(g.ExpiresAt)}
}

func (s *session) statusInfo(r *access.Request, g *access.Grant) grammar.StatusInfo {
	info := grammar.StatusInfo{ID: r.ID, Server: s.serverAlias(r.ServerID), Role: s.roleAlias(r.RoleID), State: r.State,
		StateReason: grammar.NullString(r.StateReason), CreatedAt: grammar.Time(r.CreatedAt), ExpiresAt: grammar.Time(r.ExpiresAt),
		RequestedDuration: grammar.Duration(r.RequestedDuration)}
	if r.DecidedAt != nil {
		info.DecidedAt = grammar.TimePtr(*r.DecidedAt)
	}
	if g != nil {
		info.Grant = grantInfo(g)
	}
	return info
}

func (s *session) serverAlias(id string) string {
	if srv := s.snap.Server(id); srv != nil {
		return srv.Alias
	}
	return ""
}

func (s *session) roleAlias(id string) string {
	if r := s.snap.Role(id); r != nil {
		return r.Name
	}
	return ""
}

// wait blocks until the request leaves pending or the timeout passes. It holds no transaction; it listens for
// request events and polls as a fallback. Disconnecting abandons the wait without touching the request (HP-SSH-021).
func (s *session) wait(ctx context.Context, r *access.Request, timeout time.Duration) (*access.Request, *access.Grant, error) {
	if timeout <= 0 {
		timeout = s.h.WaitDefault
	}
	timeout = min(timeout, s.h.WaitMax)
	if !r.Terminal() {
		s.notice(strings.TrimPrefix(strings.TrimSpace(grammar.PendingNotice(r.ID, r.ExpiresAt, timeout)), "hallpass: "))
	}
	var events <-chan eventbus.Event
	if s.h.Bus != nil {
		sub := s.h.Bus.Subscribe(16, eventbus.TopicRequestUpdated)
		defer sub.Close()
		events = sub.C
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	poll := time.NewTicker(2 * time.Second)
	defer poll.Stop()
	for {
		cur, g, err := s.h.Access.GetRequestForAgent(ctx, s.c.AgentID, r.ID)
		if err != nil {
			return nil, nil, mapErr(err, r.ID)
		}
		if cur.Terminal() {
			return cur, g, nil
		}
		select {
		case <-ctx.Done():
			return nil, nil, grammar.NewError(grammar.ExitWaitTimeout, "connection closed while waiting").WithRequestID(r.ID)
		case <-deadline.C:
			return nil, nil, grammar.WaitTimedOut(r.ID, timeout)
		case ev := <-events:
			_ = ev
		case <-poll.C:
		}
	}
}

func (s *session) status(ctx context.Context, c grammar.Status) int {
	r, g, err := s.h.Access.GetRequestForAgent(ctx, s.c.AgentID, c.RequestID)
	if err != nil {
		return s.fail(mapErr(err, ""))
	}
	if c.Wait && !r.Terminal() {
		if r, g, err = s.wait(ctx, r, c.EffectiveWaitTimeout()); err != nil {
			return s.fail(err)
		}
	}
	doc := grammar.NewStatusDoc(s.h.Access.Clock().Now(), s.statusInfo(r, g))
	return s.emit(c.JSON, doc, grammar.RenderStatus(doc))
}

func (s *session) cancel(ctx context.Context, c grammar.Cancel) int {
	r, err := s.h.Access.CancelByAgent(ctx, s.c.AgentID, c.RequestID)
	if err != nil {
		return s.fail(mapErr(err, ""))
	}
	_, g, _ := s.h.Access.GetRequestForAgent(ctx, s.c.AgentID, r.ID)
	doc := grammar.NewStatusDoc(s.h.Access.Clock().Now(), s.statusInfo(r, g))
	return s.emit(c.JSON, doc, grammar.RenderStatus(doc))
}

func (s *session) sessions(ctx context.Context, c grammar.Sessions) int {
	now := s.h.Access.Clock().Now()
	var grants []*access.Grant
	var err error
	if c.All {
		grants, err = s.h.Access.RecentGrantsForAgent(ctx, s.c.AgentID, now.Add(-7*24*time.Hour))
	} else {
		grants, err = s.h.Access.ActiveGrantsForAgent(ctx, s.c.AgentID)
	}
	if err != nil {
		return s.fail(grammar.Internal())
	}
	items := make([]grammar.SessionItem, 0, len(grants))
	for _, g := range grants {
		state := g.State
		if state == access.GrantActive && !g.ActiveAt(now) {
			state = access.GrantExpired
		}
		it := grammar.SessionItem{GrantID: g.ID, SessionID: grammar.NullString(g.SessionID), Server: s.serverAlias(g.ServerID),
			Role: s.roleAlias(g.RoleID), State: state, StartsAt: grammar.Time(g.StartsAt), ExpiresAt: grammar.Time(g.ExpiresAt),
			EndReason: grammar.NullString(g.EndReason)}
		if g.EndedAt != nil {
			it.EndedAt = grammar.TimePtr(*g.EndedAt)
		}
		if g.SessionID != "" {
			it.TotalConnections, it.ActiveConnections, _ = s.h.Access.SessionChannelCounts(ctx, g.SessionID)
		}
		items = append(items, it)
	}
	doc := grammar.NewSessionsDoc(now, items)
	return s.emit(c.JSON, doc, grammar.RenderSessions(doc))
}

// connect implements connect/exec/shorthand: reuse an active grant or request and wait, then proxy (PLAN §7.6).
func (s *session) connect(ctx context.Context, alias string, o grammar.Opts, wait bool, kind, remote string) int {
	vs, vr, err := s.resolveRole(ctx, alias, o.Role)
	if err != nil {
		return s.fail(err)
	}
	g, err := s.h.Access.FindActiveGrant(ctx, s.c.AgentID, vs.Server.ID, vr.Role.ID)
	if err != nil {
		return s.fail(grammar.Internal())
	}
	if g == nil {
		res, code := s.createRequest(ctx, vs, vr, o)
		if res == nil {
			return code
		}
		switch {
		case res.Grant != nil:
			g = res.Grant
		case res.Request.Terminal():
			return s.fail(grammar.NewError(grammar.ExitCode(stateExit(res.Request.State)), "request "+res.Request.State).WithRequestID(res.Request.ID))
		case !wait:
			return s.fail(grammar.NewError(grammar.ExitWaitTimeout, "request pending approval; connect again when approved").WithRequestID(res.Request.ID))
		default:
			req, rg, err := s.wait(ctx, res.Request, o.EffectiveWaitTimeout())
			if err != nil {
				return s.fail(err)
			}
			if req.State != access.ReqApproved || rg == nil {
				return s.fail(grammar.NewError(grammar.ExitCode(stateExit(req.State)), "request "+req.State).WithRequestID(req.ID))
			}
			g = rg
		}
	}
	if s.pty != nil {
		s.notice(fmt.Sprintf("connecting to %s as %s (access until %s)", vs.Server.Alias, vr.Role.Name, g.ExpiresAt.UTC().Format(time.RFC3339)))
	}
	res := s.h.Proxy.Run(ctx, &sshproxy.Session{
		ConnectionID: s.c.ID, AgentID: s.c.AgentID, KeyID: s.c.KeyID, SourceIP: s.c.SourceIP.String(), Grant: g, Kind: kind,
		Command: remote, PTY: s.pty, Env: s.env, Agent: s.ch, AgentReqs: s.reqs, Notify: s.notice,
	})
	if res.Delivered {
		return -1
	}
	if res.Err != nil {
		s.h.Log.Warn("session could not start", slog.String(obs.FieldAgentID, s.c.AgentID), slog.String("reason", res.Reason), obs.Err(res.Err))
	}
	switch res.GatewayCode {
	case int(grammar.ExitDestinationUnavailable):
		return s.fail(grammar.NewError(grammar.ExitDestinationUnavailable, "destination unavailable"))
	case int(grammar.ExitAccessEnded):
		return s.fail(grammar.NewError(grammar.ExitAccessEnded, "access is not available"))
	case int(grammar.ExitLimitExceeded):
		return s.fail(grammar.NewError(grammar.ExitLimitExceeded, "concurrency limit reached for this role"))
	case int(grammar.ExitNotFoundOrForbidden):
		return s.fail(grammar.NotFoundOrForbidden())
	}
	return s.fail(grammar.Internal())
}

// prompt reads one line from a PTY with local echo and basic editing; Ctrl-C/Ctrl-D abort.
func (s *session) prompt(ctx context.Context, label string, maxRunes int) (string, error) {
	_, _ = io.WriteString(s.diag, label)
	type res struct {
		line string
		err  error
	}
	done := make(chan res, 1)
	go func() {
		var buf []rune
		b := make([]byte, 1)
		for {
			if _, err := s.ch.Read(b); err != nil {
				done <- res{err: grammar.NewError(grammar.ExitInputRequired, "input ended")}
				return
			}
			switch c := b[0]; {
			case c == '\r' || c == '\n':
				_, _ = io.WriteString(s.ch, "\r\n")
				done <- res{line: string(buf)}
				return
			case c == 3 || c == 4:
				_, _ = io.WriteString(s.ch, "^C\r\n")
				done <- res{err: grammar.NewError(grammar.ExitInputRequired, "input aborted")}
				return
			case c == 0x7f || c == 0x08:
				if len(buf) > 0 {
					buf = buf[:len(buf)-1]
					_, _ = io.WriteString(s.ch, "\b \b")
				}
			case c >= 0x20 && c < 0x7f && len(buf) < maxRunes:
				buf = append(buf, rune(c))
				_, _ = s.ch.Write(b)
			}
		}
	}()
	select {
	case <-ctx.Done():
		return "", grammar.NewError(grammar.ExitInputRequired, "connection closed")
	case r := <-done:
		return r.line, r.err
	case <-time.After(5 * time.Minute):
		return "", grammar.NewError(grammar.ExitInputRequired, "no input received")
	}
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, s)
}

// crlfWriter converts LF to CRLF for gateway output on a raw terminal.
type crlfWriter struct{ w io.Writer }

func (c crlfWriter) Write(p []byte) (int, error) {
	if _, err := c.w.Write([]byte(strings.ReplaceAll(string(p), "\n", "\r\n"))); err != nil {
		return 0, err
	}
	return len(p), nil
}
