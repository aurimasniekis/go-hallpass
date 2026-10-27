package apiproxy

import (
	"bytes"
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/apirules"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
)

// tunnel is one CONNECT tunnel to one API host. Each grant it uses gets its own channel record, so a tunnel's
// requests appear in the timeline of the access session they were made under.
type tunnel struct {
	p        *Proxy
	cl       Client
	srv      *inventory.Server
	host     string
	ctx      context.Context
	cancel   func()
	closeRaw func()
	// command, reason and invocation are reported by hallpass-api in the CONNECT request ("" without it).
	command, reason, invocation string
	// role, when set, is the only access profile the tunnel may use (hallpass-api --role, or the proxy URL's user).
	role string

	mu        sync.Mutex
	chans     map[string]*tunnelChannel // grant ID → channel
	cands     []candidate
	candsAt   time.Time
	endReason string
	closed    bool
}

// tunnelChannel is the channel record of a grant used by the tunnel.
type tunnelChannel struct {
	reg                *access.ChannelReg
	requests, refused  int
	bytesIn, bytesOut  int64
	registeredWithLive bool
}

// candidate is an access profile the agent can use on the target.
type candidate struct {
	role     *inventory.Role
	rules    *apirules.Policy
	decision policy.Decision
	grant    *access.Grant
}

func (c candidate) rank() int {
	switch {
	case c.grant != nil:
		return 0
	case c.decision.Level == policy.LevelAutoApprove && !c.decision.RequireReason:
		return 1
	}
	return 2
}

// kill ends the tunnel because access ended (enforcer) — at most once.
func (t *tunnel) kill(reason string) {
	t.mu.Lock()
	if t.endReason == "" {
		t.endReason = reason
	}
	t.mu.Unlock()
	t.cancel()
	if t.closeRaw != nil {
		t.closeRaw()
	}
}

// close records the end of every channel the tunnel used.
func (t *tunnel) close(ctx context.Context) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	reason := cmp.Or(t.endReason, "client_closed")
	chans := t.chans
	t.mu.Unlock()
	t.cancel()
	if t.closeRaw != nil {
		t.closeRaw()
	}
	ctx = context.WithoutCancel(ctx)
	for _, ch := range chans {
		if ch.registeredWithLive {
			t.p.o.Enforcer.Unregister(ch.reg.ChannelID)
		}
		_ = t.p.o.Access.CloseChannel(ctx, ch.reg, access.CloseInfo{Reason: reason, Data: map[string]any{
			"api_host": t.host, "requests": ch.requests, "refused": ch.refused, "bytes_in": ch.bytesIn, "bytes_out": ch.bytesOut}})
	}
}

// candidates returns the agent's usable access profiles on the target, refreshed every candidateTTL.
func (t *tunnel) candidates(ctx context.Context, fresh bool) ([]candidate, error) {
	now := t.p.o.Clock.Now()
	t.mu.Lock()
	if !fresh && t.cands != nil && now.Sub(t.candsAt) < candidateTTL {
		defer t.mu.Unlock()
		return t.cands, nil
	}
	t.mu.Unlock()
	snap, err := t.p.o.Engine.Current(ctx)
	if err != nil {
		return nil, err
	}
	vs, err := snap.ResolveServer(t.cl.AgentID, t.srv.Alias)
	if err != nil || vs.Server.ID != t.srv.ID {
		return nil, policy.ErrNotFoundOrForbidden
	}
	grants, err := t.p.o.Access.ActiveGrantsForAgent(ctx, t.cl.AgentID)
	if err != nil {
		return nil, err
	}
	var out []candidate
	for _, vr := range vs.Roles {
		role, err := t.p.o.Inventory.GetRole(ctx, vr.Role.ID)
		if err != nil || role.API == nil || !role.Has(inventory.CapAPI) {
			continue
		}
		rules, err := role.API.Compile()
		if err != nil {
			continue
		}
		if t.role != "" && role.Alias != t.role {
			continue
		}
		c := candidate{role: role, rules: rules, decision: vr.Decision}
		for _, g := range grants {
			if g.RoleID == role.ID && g.ServerID == t.srv.ID && g.ActiveAt(now) && (c.grant == nil || g.ExpiresAt.After(c.grant.ExpiresAt)) {
				c.grant = g
			}
		}
		if c.grant == nil && !vr.Decision.Requestable() {
			continue
		}
		out = append(out, c)
	}
	slices.SortStableFunc(out, func(a, b candidate) int {
		return cmp.Or(cmp.Compare(a.rank(), b.rank()), cmp.Compare(a.role.Alias, b.role.Alias))
	})
	t.mu.Lock()
	t.cands, t.candsAt = out, now
	t.mu.Unlock()
	return out, nil
}

// hop-by-hop and proxy headers never forwarded in either direction.
var hopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Te",
	"Trailer", "Transfer-Encoding", "Upgrade"}

// headers the agent may not send: credentials (HallPass sets its own) and forwarding metadata.
var strippedRequestHeaders = []string{"Authorization", "Cookie", "Forwarded", "Via", "X-Forwarded-For", "X-Forwarded-Host",
	"X-Forwarded-Proto", "X-Real-Ip"}

func removeHop(h http.Header) {
	for _, f := range h.Values("Connection") {
		for _, name := range strings.Split(f, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopHeaders {
		h.Del(name)
	}
}

// ServeHTTP handles one request inside the tunnel.
func (t *tunnel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := t.p.o.Clock.Now()
	ev := map[string]any{"method": r.Method, "host": t.host}
	if t.command != "" {
		ev["command"] = t.command
	}
	if r.Method == http.MethodConnect || r.Header.Get("Upgrade") != "" {
		t.refuse(ctx, w, nil, ev, http.StatusNotImplemented, "upgrade", "protocol upgrades (WebSocket) and nested tunnels are not supported")
		return
	}
	if h, _, err := net.SplitHostPort(r.Host); (err == nil && !strings.EqualFold(h, t.host)) || (err != nil && !strings.EqualFold(r.Host, t.host)) {
		t.refuse(ctx, w, nil, ev, http.StatusMisdirectedRequest, "host_mismatch", "the Host header must name the CONNECT host "+t.host)
		return
	}
	rawPath, rawQuery := splitTarget(r.RequestURI)
	ev["path"], ev["query"] = truncate(rawPath, maxLoggedBytes), redactQuery(rawQuery)
	segs, err := apirules.SplitPath(rawPath)
	if err != nil {
		t.refuse(ctx, w, nil, ev, http.StatusBadRequest, "invalid_path", "the request path has dot segments or invalid escapes")
		return
	}
	cands, err := t.candidates(ctx, false)
	if errors.Is(err, policy.ErrNotFoundOrForbidden) {
		t.refuse(ctx, w, nil, ev, http.StatusForbidden, "not_permitted", t.srv.Alias+" is no longer available to you")
		return
	} else if err != nil {
		t.p.log.Error("access profiles unavailable", obs.Err(err))
		t.refuse(ctx, w, nil, ev, http.StatusServiceUnavailable, "unavailable", "HallPass cannot check access right now")
		return
	}

	rq := apirules.Request{Method: r.Method, Host: t.host, Segments: segs}
	if slices.ContainsFunc(cands, func(c candidate) bool { return c.rules.NeedsGraphQL(rq) }) {
		var body []byte
		if body, r.Body, err = peekBody(r.Body, MaxGraphQLBody); err != nil {
			t.refuse(ctx, w, nil, ev, http.StatusBadRequest, "body", "the request body could not be read")
			return
		}
		switch {
		case r.Method == http.MethodGet:
			rq.GraphQL = apirules.ClassifyDocument(queryParam(rawQuery, "query"))
		case len(body) > MaxGraphQLBody:
			rq.GraphQL = apirules.Unknown
		default:
			rq.GraphQL = apirules.ClassifyBody(body)
		}
		ev["graphql"] = rq.GraphQL.Names()
	}

	c, d, refusal := t.choose(ctx, cands, rq)
	if refusal != nil {
		if refusal.requestID != "" {
			ev["request_id"] = refusal.requestID
			w.Header().Set("X-Hallpass-Request", refusal.requestID)
		}
		t.refuse(ctx, w, refusal.via, ev, http.StatusForbidden, refusal.code, refusal.msg)
		return
	}
	ev["profile"], ev["rule"] = c.role.Alias, d.Rule+1
	cred, err := t.p.o.Service.credential(ctx, c.role.ID)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			t.p.log.Error("API credential unavailable", obs.Err(err))
		}
		t.refuse(ctx, w, c.grant, ev, http.StatusBadGateway, "no_credential", fmt.Sprintf("no credential is set for %s as %s; ask an operator", t.srv.Alias, c.role.Alias))
		return
	}
	ch, err := t.channel(ctx, c.grant, cred.Credential)
	if err != nil {
		t.refuse(ctx, w, nil, ev, http.StatusForbidden, "access_ended", "access to "+t.srv.Alias+" is not available: "+publicMessage(err))
		return
	}
	t.forward(w, r, rawPath, rawQuery, cred, ch, ev, start)
}

type refusal struct {
	code, msg string
	via       *access.Grant // the grant whose timeline records the refusal, if any
	requestID string        // the access request filed for it, if any
}

// choose picks the access profile for a request: the first (active grant, then auto-approved, then requestable)
// whose rules allow it. An auto-approved profile gets its grant now; a requestable one needs a request first.
func (t *tunnel) choose(ctx context.Context, cands []candidate, rq apirules.Request) (candidate, apirules.Decision, *refusal) {
	var anyGrant *access.Grant
	for _, c := range cands {
		if c.grant != nil && anyGrant == nil {
			anyGrant = c.grant
		}
		d := c.rules.Decide(rq)
		if !d.Allowed {
			continue
		}
		switch c.rank() {
		case 0:
			// Re-read the grant: the candidate list is cached, a revocation must apply to the next request.
			if g, err := t.p.o.Access.GetGrant(ctx, c.grant.ID); err == nil && g.ActiveAt(t.p.o.Clock.Now()) {
				c.grant = g
				return c, d, nil
			}
			_, _ = t.candidates(ctx, true)
		case 1:
			res, err := t.p.o.Access.CreateRequest(ctx, access.CreateRequestInput{AgentID: t.cl.AgentID, KeyID: t.cl.KeyID,
				ServerID: t.srv.ID, RoleID: c.role.ID})
			if err == nil && res.Grant != nil {
				c.grant = res.Grant
				_, _ = t.candidates(ctx, true)
				return c, d, nil
			}
			if err == nil {
				return c, d, &refusal{code: "approval_pending", via: anyGrant, msg: fmt.Sprintf(
					"access to %s as %s is waiting for approval (request %s); retry when it is approved", t.srv.Alias, c.role.Alias, res.Request.ID)}
			}
			return c, d, &refusal{code: "request_failed", via: anyGrant, msg: "access could not be requested: " + publicMessage(err)}
		default:
			if t.invocation != "" && (t.reason != "" || !c.decision.RequireReason) {
				return c, d, t.fileRequest(ctx, c, rq, anyGrant)
			}
			return c, d, &refusal{code: "approval_required", via: anyGrant, msg: fmt.Sprintf(
				"%s %s needs access to %s as %s: run ssh <gateway> request %s --role %s --reason '<why>' --wait, then retry",
				rq.Method, "/"+strings.Join(rq.Segments, "/"), t.srv.Alias, c.role.Alias, t.srv.Alias, c.role.Alias)}
		}
	}
	if t.role != "" {
		if len(cands) == 0 {
			return candidate{}, apirules.Decision{Rule: -1}, &refusal{code: "role", msg: fmt.Sprintf(
				"%s is not an access profile you can use on %s", t.role, t.srv.Alias)}
		}
		return candidate{}, apirules.Decision{Rule: -1}, &refusal{code: "rule", via: anyGrant, msg: fmt.Sprintf(
			"access profile %s on %s does not allow %s %s", t.role, t.srv.Alias, rq.Method, "/"+strings.Join(rq.Segments, "/"))}
	}
	return candidate{}, apirules.Decision{Rule: -1}, &refusal{code: "rule", via: anyGrant, msg: fmt.Sprintf(
		"no access profile you can use on %s allows %s %s", t.srv.Alias, rq.Method, "/"+strings.Join(rq.Segments, "/"))}
}

// fileRequest files (or reuses) the access request a hallpass-api call needs, with the agent's reason and the
// command it reported, so approvers see what the access is for. hallpass-api waits for it and runs the command again.
func (t *tunnel) fileRequest(ctx context.Context, c candidate, rq apirules.Request, via *access.Grant) *refusal {
	reason := t.reason
	if t.command != "" {
		reason = strings.TrimSpace(reason + " | Command (reported by the agent): " + t.command)
	}
	res, err := t.p.o.Access.CreateRequest(ctx, access.CreateRequestInput{AgentID: t.cl.AgentID, KeyID: t.cl.KeyID,
		ServerID: t.srv.ID, RoleID: c.role.ID, Reason: truncateRunes(reason, access.MaxReasonRunes)})
	if err != nil {
		return &refusal{code: "request_failed", via: via, msg: "access could not be requested: " + publicMessage(err)}
	}
	t.p.noteFiled(t.cl.AgentID, t.invocation, res.Request.ID)
	return &refusal{code: "approval_pending", via: via, requestID: res.Request.ID, msg: fmt.Sprintf(
		"%s %s needs approval of access to %s as %s: request %s is waiting for an approver",
		rq.Method, "/"+strings.Join(rq.Segments, "/"), t.srv.Alias, c.role.Alias, res.Request.ID)}
}

// channel returns the tunnel's channel record for a grant, registering it (and the enforcer hook) on first use.
func (t *tunnel) channel(ctx context.Context, g *access.Grant, cred *Credential) (*tunnelChannel, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, access.ErrAccessEnded
	}
	if ch := t.chans[g.ID]; ch != nil {
		return ch, nil
	}
	reg, err := t.p.o.Access.RegisterChannel(ctx, access.RegisterInput{ConnectionID: t.cl.ConnectionID, AgentID: t.cl.AgentID,
		KeyID: t.cl.KeyID, GrantID: g.ID, Kind: access.KindExec, APIHost: t.host})
	if err != nil {
		return nil, err
	}
	ch := &tunnelChannel{reg: reg}
	live := &access.Live{ChannelID: reg.ChannelID, ConnectionID: t.cl.ConnectionID, AgentID: t.cl.AgentID, KeyID: t.cl.KeyID,
		GrantID: g.ID, ExpiresAt: reg.Grant.ExpiresAt, Terminate: t.kill}
	if err := t.p.o.Enforcer.Register(live); err != nil {
		_ = t.p.o.Access.CloseChannel(context.WithoutCancel(ctx), reg, access.CloseInfo{Failed: true, Reason: "access_ended"})
		return nil, err
	}
	ch.registeredWithLive = true
	data := map[string]any{"api_host": t.host, "api_target": t.srv.Alias}
	if t.command != "" {
		data["command"] = t.command
	}
	if err := t.p.o.Access.ActivateChannel(ctx, reg, cred.Ref(), data); err != nil {
		t.p.o.Enforcer.Unregister(reg.ChannelID)
		_ = t.p.o.Access.CloseChannel(context.WithoutCancel(ctx), reg, access.CloseInfo{Failed: true, Reason: "access_ended"})
		return nil, err
	}
	t.chans[g.ID] = ch
	return ch, nil
}

// forward sends the request upstream with the profile's credential and streams the response back.
func (t *tunnel) forward(w http.ResponseWriter, r *http.Request, rawPath, rawQuery string, cred *secretCredential, ch *tunnelChannel,
	ev map[string]any, start time.Time) {
	ctx := r.Context()
	// The path goes upstream exactly as the agent escaped it, the form the rules were checked against.
	u := &url.URL{Scheme: "https", Host: t.host, RawPath: rawPath, RawQuery: rawQuery}
	u.Path, _ = url.PathUnescape(rawPath)
	body := io.Reader(r.Body)
	if r.ContentLength == 0 {
		body = http.NoBody
	}
	in := &countingReader{r: body}
	out, err := http.NewRequestWithContext(ctx, r.Method, u.String(), in)
	if err != nil {
		t.respondError(w, http.StatusBadRequest, "invalid_request", "the request could not be forwarded")
		return
	}
	if body == http.NoBody {
		out.Body = http.NoBody
	}
	out.ContentLength = r.ContentLength
	out.Host = t.host
	out.Header = r.Header.Clone()
	removeHop(out.Header)
	for _, h := range strippedRequestHeaders {
		out.Header.Del(h)
	}
	if cred.Type == CredHeader {
		out.Header.Del(cred.Header)
	}
	if err := t.p.authorize(ctx, out.Header, cred); err != nil {
		t.p.log.Warn("API credential could not be applied", obs.Err(err))
		t.record(ctx, ch, ev, start, in.n, 0, http.StatusBadGateway, "credential")
		t.respondError(w, http.StatusBadGateway, "credential", "the access profile's credential could not be used; ask an operator")
		return
	}
	resp, err := t.p.transport.RoundTrip(out)
	if err != nil {
		status, code, msg := http.StatusBadGateway, "upstream", t.host+" could not be reached"
		if errors.Is(err, context.Canceled) {
			status, code, msg = http.StatusServiceUnavailable, "access_ended", "the request was canceled"
		}
		t.record(ctx, ch, ev, start, in.n, 0, status, code)
		t.respondError(w, status, code, msg)
		return
	}
	defer resp.Body.Close()
	h := w.Header()
	for k, v := range resp.Header {
		h[k] = v
	}
	removeHop(h)
	h.Del("Alt-Svc") // keep clients on this tunnel
	w.WriteHeader(resp.StatusCode)
	n, _ := copyFlush(w, resp.Body)
	t.record(ctx, ch, ev, start, in.n, n, resp.StatusCode, "")
}

// record appends the request to the timeline of the grant's session and updates the channel counters.
func (t *tunnel) record(ctx context.Context, ch *tunnelChannel, ev map[string]any, start time.Time, in, out int64, status int, refused string) {
	t.mu.Lock()
	ch.requests++
	if refused != "" {
		ch.refused++
	}
	ch.bytesIn += in
	ch.bytesOut += out
	t.mu.Unlock()
	ev["status"], ev["bytes_in"], ev["bytes_out"] = status, in, out
	ev["duration_ms"] = t.p.o.Clock.Now().Sub(start).Milliseconds()
	if refused != "" {
		ev["refused"] = refused
	}
	_ = t.p.o.Access.AppendSessionEvent(context.WithoutCancel(ctx), ch.reg, access.EvAPIRequest, "", ev)
}

// refuse answers a request HallPass will not forward and records it: in the session of an active grant on the target
// when there is one, otherwise as a (rate-limited) audit event.
func (t *tunnel) refuse(ctx context.Context, w http.ResponseWriter, via *access.Grant, ev map[string]any, status int, code, msg string) {
	recorded := false
	if via != nil {
		if ch, err := t.channelFor(ctx, via); err == nil {
			t.record(ctx, ch, ev, t.p.o.Clock.Now(), 0, 0, status, code)
			recorded = true
		}
	}
	if !recorded {
		details := map[string]any{"api_target": t.srv.Alias, "refused": code}
		for k, v := range ev {
			details[k] = v
		}
		t.cl.deny("api.request.denied", details)
	}
	t.respondError(w, status, code, msg)
}

// channelFor returns an existing channel of the grant, or registers one so that refusals under an active grant are
// part of its session.
func (t *tunnel) channelFor(ctx context.Context, g *access.Grant) (*tunnelChannel, error) {
	t.mu.Lock()
	ch := t.chans[g.ID]
	t.mu.Unlock()
	if ch != nil {
		return ch, nil
	}
	cred := &Credential{RoleID: g.RoleID}
	if c, err := t.p.o.Service.GetCredential(ctx, g.RoleID); err == nil {
		cred = c
	}
	return t.channel(ctx, g, cred)
}

// respondError writes a refusal every common API client can show: GitHub reads "message", Cloudflare "errors" and
// Google "error.message".
func (t *tunnel) respondError(w http.ResponseWriter, status int, code, msg string) {
	msg = "hallpass: " + msg
	body, _ := json.Marshal(map[string]any{
		"message": msg,
		"success": false,
		"errors":  []map[string]any{{"code": status, "message": msg}},
		"error":   map[string]any{"code": status, "message": msg, "status": googleStatus(status)},
		"hallpass": map[string]any{
			"code":   code,
			"target": t.srv.Alias,
		},
	})
	h := w.Header()
	for k := range h {
		if k != "X-Hallpass-Request" {
			delete(h, k)
		}
	}
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Hallpass-Error", code)
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}

func googleStatus(status int) string {
	switch status {
	case http.StatusForbidden:
		return "PERMISSION_DENIED"
	case http.StatusBadRequest:
		return "INVALID_ARGUMENT"
	case http.StatusServiceUnavailable:
		return "UNAVAILABLE"
	}
	return "FAILED_PRECONDITION"
}

func publicMessage(err error) string {
	switch {
	case errors.Is(err, access.ErrLockdown):
		return "access is temporarily suspended (lockdown)"
	case errors.Is(err, access.ErrConcurrencyLimit):
		return "concurrency limit reached for this access profile"
	case errors.Is(err, access.ErrReasonRequired):
		return "a reason is required"
	case errors.Is(err, access.ErrRateLimited):
		return "too many requests"
	}
	return "access has ended"
}

// splitTarget splits an origin-form (or absolute-form) request target into its escaped path and raw query.
func splitTarget(requestURI string) (string, string) {
	if !strings.HasPrefix(requestURI, "/") {
		if u, err := url.Parse(requestURI); err == nil {
			return cmp.Or(u.EscapedPath(), "/"), u.RawQuery
		}
		return "", ""
	}
	path, query, _ := strings.Cut(requestURI, "?")
	return path, query
}

// sensitiveParams are query parameters whose values are never recorded.
var sensitiveParams = []string{"token", "key", "secret", "password", "passwd", "signature", "sig", "code", "auth", "credential", "session"}

// redactQuery keeps parameter names and replaces values that may be secrets.
func redactQuery(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "&")
	for i, p := range parts {
		name, _, hasValue := strings.Cut(p, "=")
		lname := strings.ToLower(name)
		if hasValue && slices.ContainsFunc(sensitiveParams, func(s string) bool { return strings.Contains(lname, s) }) {
			parts[i] = name + "=[redacted]"
		}
	}
	return truncate(strings.Join(parts, "&"), maxLoggedBytes)
}

func queryParam(raw, name string) string {
	v, _ := url.ParseQuery(raw)
	return v.Get(name)
}

// peekBody reads up to limit+1 bytes of a body and returns them with a reader that yields the whole body again.
func peekBody(body io.ReadCloser, limit int64) ([]byte, io.ReadCloser, error) {
	if body == nil || body == http.NoBody {
		return nil, http.NoBody, nil
	}
	b, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, nil, err
	}
	return b, readCloser{Reader: io.MultiReader(bytes.NewReader(b), body), Closer: body}, nil
}

type readCloser struct {
	io.Reader
	io.Closer
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// copyFlush streams a response body, flushing after every read so event streams and long polls work.
func copyFlush(w http.ResponseWriter, r io.Reader) (int64, error) {
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	var n int64
	for {
		k, err := r.Read(buf)
		if k > 0 {
			if _, werr := w.Write(buf[:k]); werr != nil {
				return n, werr
			}
			n += int64(k)
			_ = rc.Flush()
		}
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return n, err
		}
	}
}
