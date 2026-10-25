// Package httpapi serves the operator REST API (api/openapi.yaml), the OIDC browser endpoints and the SSE stream
// (PLAN §8, WP15). Routing, permissions and security flags come from the generated operation table; every
// operation passes through the same middleware: rate limits, session, CSRF/Origin, RBAC, recent authentication,
// idempotency and RFC 9457 errors.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/credentials"
	"github.com/aurimasniekis/go-hallpass/internal/destaudit"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/httpapi/gen"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/notify"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/oidc"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/rbac"
	"github.com/aurimasniekis/go-hallpass/internal/recording"
	"github.com/aurimasniekis/go-hallpass/internal/remotebackup"
	"github.com/aurimasniekis/go-hallpass/internal/sshban"
	"github.com/aurimasniekis/go-hallpass/internal/sshproxy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// Deps are the services behind the API.
type Deps struct {
	Store       *store.Store
	Audit       *audit.Writer
	Bus         *eventbus.Bus
	Agents      *agents.Service
	Inventory   *inventory.Service
	Credentials *credentials.Service
	Engine      *policy.Engine
	Policy      *policy.Service
	Access      *access.Service
	Enforcer    *access.Enforcer
	Recording   *recording.Service
	Auth        *opauth.Service
	OIDC        *oidc.Service
	Notify      *notify.Service
	Destaudit   *destaudit.Service
	Bans        *sshban.Service
	// Proxy runs web terminals through the SSH data plane (nil: web terminals unavailable).
	Proxy *sshproxy.Proxy
	// RemoteBackup manages backups to object storage.
	RemoteBackup *remotebackup.Service
	Matrix       *rbac.Matrix
	Metrics      *metrics.Metrics
	BootID       string
	Version      string
}

// Options configure the HTTP layer.
type Options struct {
	// PublicURL is the external origin; mutations must carry a matching Origin header.
	PublicURL string
	// Secure selects __Host- cookies with the Secure flag and HSTS (production / https).
	Secure bool
	// TrustedProxies are CIDRs whose X-Forwarded-For is honored for the client IP.
	TrustedProxies []netip.Prefix
	// UI serves the web application for non-API paths (nil: 404).
	UI     http.Handler
	Clock  clock.Clock
	Logger *slog.Logger
	// Rate limits per minute (0 = defaults: 600 per session, 300 per IP, 20 per IP on auth endpoints).
	SessionRate, IPRate, AuthRate int
}

// Server is the HTTP API.
type Server struct {
	d        Deps
	o        Options
	log      *slog.Logger
	origin   string
	handlers map[string]gen.Handler
	limits   *limiters
	hub      *Hub

	testMu      sync.Mutex
	testResults map[string]testEntry // operatorID|providerID → latest test-login preview
	terminals   terminalTickets      // web terminal tickets waiting for their WebSocket (ADR-0055)
}

type testEntry struct {
	res *oidc.TestResult
	at  time.Time
}

// Session cookie names (HP-AUTH-012). __Host- requires Secure, so plain-http development uses a prefix-free name.
const (
	sessionCookieSecure   = "__Host-hp_session"
	sessionCookieInsecure = "hp_session"
	oidcCookieSecure      = "__Host-hp_oidc"
	oidcCookieInsecure    = "hp_oidc"
)

// New builds the server.
func New(d Deps, o Options) *Server {
	if o.Clock == nil {
		o.Clock = clock.System{}
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.SessionRate <= 0 {
		o.SessionRate = 600
	}
	if o.IPRate <= 0 {
		o.IPRate = 300
	}
	if o.AuthRate <= 0 {
		o.AuthRate = 20
	}
	s := &Server{d: d, o: o, log: obs.Component(o.Logger, "httpapi"), origin: originOf(o.PublicURL), limits: newLimiters(o.Clock),
		testResults: map[string]testEntry{}}
	s.handlers = gen.Handlers(s)
	s.hub = NewHub(d, o.Clock, s.log)
	return s
}

// Hub returns the SSE hub (started by Run).
func (s *Server) Hub() *Hub { return s.hub }

// Run starts background work (SSE fan-out, limiter cleanup) until ctx ends.
func (s *Server) Run(ctx context.Context) {
	go s.limits.gc(ctx)
	s.hub.Run(ctx)
}

func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// Handler returns the root handler: API operations, OIDC browser endpoints and (optionally) the UI.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	for i := range gen.Operations {
		op := &gen.Operations[i]
		mux.Handle(op.Method+" "+op.Path, s.wrap(op, s.handlers[op.ID]))
	}
	mux.Handle("/api/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.problem(w, r, apperr.New(apperr.CodeNotFound, "no such API endpoint"))
	}))
	if s.o.UI != nil {
		mux.Handle("/", s.o.UI)
	}
	return s.securityHeaders(mux)
}

// securityHeaders sets HP-API-007 headers on every response; CORS is never enabled.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "+
			"font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		if s.o.Secure {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/auth/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) cookieName() string {
	if s.o.Secure {
		return sessionCookieSecure
	}
	return sessionCookieInsecure
}

func (s *Server) oidcCookieName() string {
	if s.o.Secure {
		return oidcCookieSecure
	}
	return oidcCookieInsecure
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	// Secure is off only for plain-http development (public_url http://); production requires https (HP-AUTH-012).
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: s.o.Secure, SameSite: http.SameSiteLaxMode, //nolint:gosec // G124: see above
		MaxAge: maxAge})
}

// clientIP returns the peer address, honoring X-Forwarded-For only from trusted proxies.
func (s *Server) clientIP(r *http.Request) string {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	ip := ap.Addr().Unmap()
	for _, p := range s.o.TrustedProxies {
		if p.Contains(ip) {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				parts := strings.Split(xff, ",")
				if a, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
					return a.Unmap().String()
				}
			}
		}
	}
	return ip.String()
}

func (s *Server) meta(r *http.Request) opauth.SessionMeta {
	return opauth.SessionMeta{IP: s.clientIP(r), UserAgent: r.UserAgent()}
}

// errTokenNotAllowed refuses an automation token on an operation that needs a person (decisions, recording content,
// operators, tokens, the caller's own account).
var errTokenNotAllowed = apperr.New(apperr.CodeForbidden, "API tokens cannot use this operation; sign in to the web console instead")

// ErrOrigin rejects cross-site mutations (HP-AUTH-013).
var ErrOrigin = apperr.New(apperr.CodeForbidden, "cross-site request refused")

// checkOrigin requires a same-origin Origin header (or Sec-Fetch-Site: same-origin) on state-changing requests.
func (s *Server) checkOrigin(r *http.Request) error {
	if o := r.Header.Get("Origin"); o != "" {
		if o == s.origin {
			return nil
		}
		return ErrOrigin
	}
	if r.Header.Get("Sec-Fetch-Site") == "same-origin" {
		return nil
	}
	return ErrOrigin
}

func mutating(m string) bool { return m != http.MethodGet && m != http.MethodHead }

// wrap applies the per-operation pipeline.
func (s *Server) wrap(op *gen.Operation, h gen.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := s.o.Clock.Now()
		src := sourceKey(s.clientIP(r))
		authOp := strings.HasPrefix(op.Path, "/api/v1/auth/") || strings.HasPrefix(op.Path, "/auth/")
		// Per-source flood guard for every request (operators behind one NAT share it, so it is generous);
		// unauthenticated requests get the stricter IPRate below, authenticated ones the per-session SessionRate
		// (HP-API-008). Sources are IPv4 addresses or IPv6 /64 prefixes (SR-30).
		if !s.limits.allow("ip:"+src, 4*s.o.IPRate) || (authOp && op.Method != http.MethodGet && !s.limits.allowKey("auth:"+src, s.o.AuthRate, true)) {
			w.Header().Set("Retry-After", "60")
			s.problem(w, r, apperr.New(apperr.CodeRateLimited, "too many requests; slow down"))
			return
		}
		// An automation token (Authorization: Bearer) replaces the session cookie entirely: it is never combined with
		// one, and a request that presents an invalid token fails instead of falling back to the cookie (ADR-0052).
		bearer, hasBearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if mutating(op.Method) && !op.Redirect && !hasBearer {
			if err := s.checkOrigin(r); err != nil {
				s.problem(w, r, err)
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		c := &gen.Call{W: w, R: r, Op: op}
		switch {
		case hasBearer:
			p, err := s.d.Auth.AuthenticateAPIToken(r.Context(), strings.TrimSpace(bearer), s.clientIP(r))
			if err != nil {
				if !s.limits.allowKey("anon:"+src, s.o.IPRate, true) {
					w.Header().Set("Retry-After", "60")
					s.problem(w, r, apperr.New(apperr.CodeRateLimited, "too many requests; slow down"))
					return
				}
				s.problem(w, r, opauth.ErrUnauthorized)
				return
			}
			if !op.Token {
				s.problem(w, r, errTokenNotAllowed)
				return
			}
			c.Principal = p
		default:
			if ck, err := r.Cookie(s.cookieName()); err == nil && ck.Value != "" {
				c.SessionToken = ck.Value
				if p, err := s.d.Auth.Authenticate(r.Context(), ck.Value); err == nil {
					c.Principal = p
				}
			}
		}
		if (c.Principal == nil && !s.limits.allowKey("anon:"+src, s.o.IPRate, true)) ||
			(c.Principal != nil && !s.limits.allow("ses:"+c.Principal.SessionID, s.o.SessionRate)) {
			w.Header().Set("Retry-After", "60")
			s.problem(w, r, apperr.New(apperr.CodeRateLimited, "too many requests; slow down"))
			return
		}
		if err := s.d.Matrix.Authorize(c.Principal, rbac.Permission(op.Permission)); err != nil {
			s.problem(w, r, err)
			return
		}
		if c.Principal != nil && c.Principal.TokenID == "" && op.Permission != string(rbac.Public) && mutating(op.Method) && !op.Redirect &&
			!c.Principal.VerifyCSRF(r.Header.Get("X-CSRF-Token")) {
			s.problem(w, r, apperr.New(apperr.CodeForbidden, "missing or invalid CSRF token"))
			return
		}
		// Tokens skip step-up: issuing one already required recent authentication and MFA (ADR-0052).
		if (op.Reauth || op.MFA) && (c.Principal == nil || c.Principal.TokenID == "") {
			if err := s.d.Auth.RequireRecentAuth(c.Principal, op.MFA); err != nil {
				s.problem(w, r, err)
				return
			}
		}
		if op.Idempotent && r.Header.Get("Idempotency-Key") != "" && c.Principal != nil {
			if s.replayIdempotent(c) { //nolint:contextcheck // uses the request context carried by c
				return
			}
		}
		res, err := h(c)
		if err != nil {
			s.problem(w, r, err)
			s.logOp(op, r, c, http.StatusBadRequest, start, err)
			return
		}
		status := s.writeResult(c, res) //nolint:contextcheck // uses the request context carried by c
		s.logOp(op, r, c, status, start, nil)
	})
}

func (s *Server) logOp(op *gen.Operation, r *http.Request, c *gen.Call, status int, start time.Time, err error) {
	attrs := []any{slog.String("operation", op.ID), slog.Int("status", status), slog.Duration("duration", s.o.Clock.Now().Sub(start))}
	if c.Principal != nil {
		attrs = append(attrs, slog.String("operator_id", c.Principal.Operator.ID))
	}
	if err != nil && apperr.CodeOf(err) == "" {
		s.log.Error("api operation failed", append(attrs, obs.Err(err))...)
		return
	}
	s.log.Debug("api operation", attrs...)
}

// writeResult encodes a handler result and stores idempotent responses.
func (s *Server) writeResult(c *gen.Call, res *gen.Result) int {
	if res == nil {
		return 0
	}
	w := c.W
	if res.ClearSession {
		s.setCookie(w, s.cookieName(), "", -1)
	}
	if res.SetSession != "" {
		s.setCookie(w, s.cookieName(), res.SetSession, 0)
	}
	if res.Location != "" {
		status := res.Status
		if status == 0 {
			status = http.StatusSeeOther
		}
		// The Location is set verbatim: http.Redirect would path-clean relative targets (fragment included) and turn
		// a sanitized "/#/../api/…" into "/api/…" (SR-24). Handlers only produce sanitized relative paths or the
		// identity provider's absolute authorization URL.
		w.Header().Set("Location", res.Location)
		w.WriteHeader(status)
		return status
	}
	status := res.Status
	if status == 0 {
		status = http.StatusOK
	}
	if status == http.StatusNoContent || res.Body == nil {
		w.WriteHeader(status)
		s.storeIdempotent(c, status, nil)
		return status
	}
	body, err := json.Marshal(res.Body)
	if err != nil {
		s.problem(w, c.R, err)
		return http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
	s.storeIdempotent(c, status, body)
	return status
}

// problemStatus maps stable error codes to HTTP statuses.
func problemStatus(code apperr.Code) int {
	switch code {
	case apperr.CodeInvalid:
		return http.StatusUnprocessableEntity
	case apperr.CodeNotFound:
		return http.StatusNotFound
	case apperr.CodeAlreadyExists, apperr.CodeConflict, apperr.CodePrecondition:
		return http.StatusConflict
	case apperr.CodeForbidden:
		return http.StatusForbidden
	case apperr.CodeUnauthorized, apperr.CodeReauth, apperr.CodeMFARequired:
		return http.StatusUnauthorized
	case apperr.CodeRateLimited:
		return http.StatusTooManyRequests
	case apperr.CodeUnavailable:
		return http.StatusServiceUnavailable
	case codePreconditionRequired:
		return http.StatusPreconditionRequired
	}
	return http.StatusInternalServerError
}

const codePreconditionRequired apperr.Code = "precondition_required"

// Problem is an RFC 9457 problem document (HP-API-003).
type Problem struct {
	Type     string         `json:"type"`
	Title    string         `json:"title"`
	Status   int            `json:"status"`
	Code     string         `json:"code"`
	Detail   string         `json:"detail,omitempty"`
	Instance string         `json:"instance,omitempty"`
	Errors   []ProblemField `json:"errors,omitempty"`
}

// ProblemField is one validation error.
type ProblemField struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// problem writes an error. Unknown errors become a generic 500 without internals (HP-API-003).
func (s *Server) problem(w http.ResponseWriter, r *http.Request, err error) {
	p := Problem{Type: "about:blank", Instance: r.URL.Path}
	var ae *apperr.Error
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe):
		p.Code, p.Status, p.Title = "payload_too_large", http.StatusRequestEntityTooLarge, "request body too large"
	case errors.As(err, &ae):
		p.Code = string(ae.Code)
		p.Status = problemStatus(ae.Code)
		p.Title = ae.Message
		for _, f := range ae.Fields {
			p.Errors = append(p.Errors, ProblemField{Field: f.Field, Message: f.Message})
		}
	default:
		p.Code, p.Status, p.Title = "internal", http.StatusInternalServerError, "internal error"
		s.log.Error("unhandled api error", slog.String("path", r.URL.Path), obs.Err(err))
	}
	p.Type = "https://hallpass.dev/problems/" + p.Code
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// decode reads a JSON body strictly (unknown fields rejected). An empty body decodes to the zero value when optional.
func decode(c *gen.Call, v any, optional bool) error {
	dec := json.NewDecoder(c.R.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return err
		}
		if optional && err.Error() == "EOF" {
			return nil
		}
		return apperr.New(apperr.CodeInvalid, "invalid JSON body: %s", sanitizeJSONError(err))
	}
	if dec.More() {
		return apperr.New(apperr.CodeInvalid, "invalid JSON body: trailing data")
	}
	return nil
}

func sanitizeJSONError(err error) string {
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

// ifMatch returns the version from If-Match ("<n>" or W/"<n>"), or fallback from the body; neither → 428.
func ifMatch(c *gen.Call, fallback int64) (int64, error) {
	h := strings.TrimSpace(c.R.Header.Get("If-Match"))
	if h == "" {
		if fallback > 0 {
			return fallback, nil
		}
		return 0, apperr.New(codePreconditionRequired, "If-Match header (resource version) is required")
	}
	h = strings.Trim(strings.TrimPrefix(h, "W/"), `"`)
	v, err := strconv.ParseInt(h, 10, 64)
	if err != nil || v <= 0 {
		return 0, apperr.New(apperr.CodeInvalid, "invalid If-Match header")
	}
	return v, nil
}

func ok(body any) (*gen.Result, error) { return &gen.Result{Body: body}, nil }
func created(body any) (*gen.Result, error) {
	return &gen.Result{Status: http.StatusCreated, Body: body}, nil
}
func noContent() (*gen.Result, error) { return &gen.Result{Status: http.StatusNoContent}, nil }

type items[T any] struct {
	Items []T `json:"items"`
}

func list[T any](v []T) items[T] {
	if v == nil {
		v = []T{}
	}
	return items[T]{Items: v}
}

func actor(c *gen.Call) audit.Actor {
	if c.Principal == nil {
		return audit.Actor{Type: audit.ActorSystem, ID: "api"}
	}
	if c.Principal.TokenID != "" {
		return audit.Actor{Type: audit.ActorOperator, ID: c.Principal.Operator.ID, Via: "api_token:" + c.Principal.TokenID}
	}
	return audit.Actor{Type: audit.ActorOperator, ID: c.Principal.Operator.ID}
}

// operatorInfo describes the principal for domain authorization (approver scope, self-approval).
func operatorInfo(c *gen.Call) policy.OperatorInfo {
	p := c.Principal
	return policy.OperatorInfo{ID: p.Operator.ID, Roles: p.Operator.Roles, Groups: p.Operator.Groups, Enabled: p.Operator.Enabled,
		MFAPassed: p.MFAAt != nil || p.Method == opauth.MethodOIDC}
}
