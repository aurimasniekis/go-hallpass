package httpapi_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/app"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/buildinfo"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/httpapi"
	"github.com/aurimasniekis/go-hallpass/internal/httpapi/gen"
	"github.com/aurimasniekis/go-hallpass/internal/oidc/oidctest"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
	"github.com/aurimasniekis/go-hallpass/internal/rbac"
	"github.com/aurimasniekis/go-hallpass/internal/sshproxy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshkeys"
)

var sysActor = audit.Actor{Type: audit.ActorSystem, ID: "test"}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

type harness struct {
	t      *testing.T
	ctx    context.Context
	clk    *clock.Fake
	a      *app.App
	api    *httpapi.Server
	srv    *httptest.Server
	base   string
	matrix *rbac.Matrix
	spec   *specIndex
	cancel context.CancelFunc
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test listener
	must(t, err)
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Mode = "development"
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.KEK.File = ""
	cfg.HTTP.Listen = ""
	cfg.Egress.AllowCIDRs = []string{"10.0.0.0/8"}
	cfg.PublicURL = "http://" + ln.Addr().String()
	clk := clock.NewFake(time.Now())
	ctx := context.Background()
	a, err := app.New(ctx, cfg, slog.New(slog.DiscardHandler), app.WithClock(clk))
	must(t, err)
	h := &harness{t: t, ctx: ctx, clk: clk, a: a, base: cfg.PublicURL, matrix: rbac.New(rbac.Options{}), spec: loadSpec(t)}
	h.api = httpapi.New(httpapi.Deps{Store: a.Store, Audit: a.Audit, Bus: a.Bus, Agents: a.Agents, Inventory: a.Inventory, Credentials: a.Credentials,
		Engine: a.Engine, Policy: a.Policy, Access: a.Access, Enforcer: a.Enforcer, Recording: a.Recording, Auth: a.Auth, OIDC: a.OIDC, Notify: a.Notify,
		Matrix: h.matrix, BootID: a.BootID, Version: buildinfo.Get().Version},
		httpapi.Options{PublicURL: cfg.PublicURL, Clock: clk, SessionRate: 100000, IPRate: 100000, AuthRate: 100000})
	rctx, cancel := context.WithCancel(ctx)
	h.cancel = cancel
	go h.api.Run(rctx)
	h.srv = httptest.NewUnstartedServer(h.api.Handler())
	h.srv.Listener = ln
	h.srv.Start()
	t.Cleanup(func() {
		h.srv.Close()
		cancel()
		_ = a.Close()
	})
	return h
}

// client is a browser-like API client (cookie jar, CSRF header, same-origin Origin).
type client struct {
	h    *harness
	hc   *http.Client
	csrf string
}

func (h *harness) client() *client {
	jar, _ := cookiejar.New(nil)
	return &client{h: h, hc: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

type resp struct {
	status int
	body   []byte
	header http.Header
}

func (r resp) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("decode %s: %v", r.body, err)
	}
}

func (r resp) problemCode() string {
	var p struct{ Code string }
	_ = json.Unmarshal(r.body, &p)
	return p.Code
}

func (c *client) do(method, path string, body any, hdr ...string) resp {
	c.h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		must(c.h.t, err)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(c.h.ctx, method, c.h.base+path, rd)
	must(c.h.t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", c.h.base)
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := c.hc.Do(req)
	must(c.h.t, err)
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{status: res.StatusCode, body: b, header: res.Header}
}

// ok asserts the status and validates the body against the operation's response schema in the spec.
func (c *client) ok(opID string, want int, method, path string, body any, hdr ...string) resp {
	c.h.t.Helper()
	r := c.do(method, path, body, hdr...)
	if r.status != want {
		c.h.t.Fatalf("%s %s: status %d, want %d: %s", method, path, r.status, want, r.body)
	}
	c.h.spec.validate(c.h.t, opID, r)
	return r
}

func totp(t *testing.T, secretB32 string, now time.Time) string {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	must(t, err)
	return opauth.TOTPCode(secret, opauth.TOTPStep(now))
}

// bootstrapAdmin runs the real first-admin flow: setup token → bootstrap → login → TOTP enrollment → MFA.
func (h *harness) bootstrapAdmin() *client {
	h.t.Helper()
	c := h.client()
	r := c.ok("getAuthConfig", 200, "GET", "/api/v1/auth/config", nil)
	var cfg struct {
		BootstrapRequired bool `json:"bootstrap_required"`
	}
	r.json(h.t, &cfg)
	if !cfg.BootstrapRequired {
		h.t.Fatal("bootstrap not required on a fresh store")
	}
	tok, _, err := h.a.Auth.IssueSetupToken(h.ctx)
	must(h.t, err)
	c.ok("bootstrap", 201, "POST", "/api/v1/auth/bootstrap", map[string]string{"token": tok, "email": "admin@example.com", "display_name": "Admin",
		"password": "correct horse battery staple"})
	r = c.ok("login", 200, "POST", "/api/v1/auth/login", map[string]string{"email": "admin@example.com", "password": "correct horse battery staple"})
	var lr struct {
		MustEnroll bool `json:"must_enroll"`
		Me         struct {
			CSRF string `json:"csrf_token"`
		} `json:"me"`
	}
	r.json(h.t, &lr)
	if !lr.MustEnroll {
		h.t.Fatalf("admin without MFA not forced to enroll: %s", r.body)
	}
	c.csrf = lr.Me.CSRF
	if r := c.do("GET", "/api/v1/agents", nil); r.status != 401 || r.problemCode() != "mfa_required" {
		h.t.Fatalf("limited session reached the API: %d %s", r.status, r.body)
	}
	r = c.ok("beginTOTP", 200, "POST", "/api/v1/me/mfa/totp", nil)
	var enr struct{ Secret string }
	r.json(h.t, &enr)
	c.ok("confirmTOTP", 200, "POST", "/api/v1/me/mfa/totp/confirm", map[string]string{"code": totp(h.t, enr.Secret, h.clk.Now())})
	h.clk.Advance(30 * time.Second)
	r = c.ok("verifyMFA", 200, "POST", "/api/v1/auth/mfa", map[string]string{"code": totp(h.t, enr.Secret, h.clk.Now())})
	var me struct {
		CSRF        string   `json:"csrf_token"`
		Permissions []string `json:"permissions"`
	}
	r.json(h.t, &me)
	c.csrf = me.CSRF
	if !slices.Contains(me.Permissions, "operators.manage") {
		h.t.Fatalf("admin permissions %v", me.Permissions)
	}
	return c
}

// principalClient creates an operator with roles and a session of the given method directly in the store.
func (h *harness) principalClient(roles []string, method string) *client {
	h.t.Helper()
	op, err := h.a.Auth.Create(h.ctx, sysActor, opauth.CreateInput{Email: fmt.Sprintf("%s-%s-%d@example.com", strings.Join(roles, "-"), method,
		time.Now().UnixNano()), DisplayName: "op", Roles: roles})
	must(h.t, err)
	var token string
	must(h.t, h.a.Store.W().Tx(h.ctx, func(tx *store.Tx) error {
		var err error
		token, err = h.a.Auth.CreateSessionTx(h.ctx, tx, op.ID, method, opauth.SessionMeta{IP: "127.0.0.1"})
		return err
	}))
	p, err := h.a.Auth.Authenticate(h.ctx, token)
	must(h.t, err)
	c := h.client()
	u, _ := http.NewRequest(http.MethodGet, h.base, nil) //nolint:noctx // cookie URL only
	c.hc.Jar.SetCookies(u.URL, []*http.Cookie{{Name: "hp_session", Value: token, Path: "/"}})
	c.csrf = p.CSRFToken
	return c
}

// ---- spec helpers

type specIndex struct {
	doc map[string]any
	c   *jsonschema.Compiler
	ops map[string]map[string]any // operationId → operation object
}

func loadSpec(t *testing.T) *specIndex {
	t.Helper()
	raw, err := os.ReadFile("../../api/openapi.yaml")
	must(t, err)
	var y any
	must(t, yaml.Unmarshal(raw, &y))
	b, err := json.Marshal(y)
	must(t, err)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	must(t, err)
	c := jsonschema.NewCompiler()
	must(t, c.AddResource("openapi.json", doc))
	var m map[string]any
	must(t, json.Unmarshal(b, &m))
	s := &specIndex{doc: m, c: c, ops: map[string]map[string]any{}}
	for _, item := range m["paths"].(map[string]any) {
		for _, op := range item.(map[string]any) {
			if o, isOp := op.(map[string]any); isOp {
				if id, has := o["operationId"].(string); has {
					s.ops[id] = o
				}
			}
		}
	}
	return s
}

func (s *specIndex) validate(t *testing.T, opID string, r resp) {
	t.Helper()
	if err := s.check(opID, r); err != nil {
		t.Fatal(err)
	}
}

func (s *specIndex) check(opID string, r resp) error {
	op := s.ops[opID]
	if op == nil {
		return fmt.Errorf("operation %s not in spec", opID)
	}
	responses := op["responses"].(map[string]any)
	rs, found := responses[fmt.Sprint(r.status)]
	if !found {
		return fmt.Errorf("%s: status %d not declared in the spec", opID, r.status)
	}
	content, _ := rs.(map[string]any)["content"].(map[string]any)
	if content == nil {
		if len(bytes.TrimSpace(r.body)) != 0 {
			return fmt.Errorf("%s: undeclared body %s", opID, r.body)
		}
		return nil
	}
	appJSON, _ := content["application/json"].(map[string]any)
	if appJSON == nil {
		return nil
	}
	sch, err := s.c.Compile(s.pointerTo(appJSON["schema"]))
	if err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(r.body))
	if err != nil {
		return err
	}
	if err := sch.Validate(inst); err != nil {
		return fmt.Errorf("%s: response does not match the spec: %w\n%s", opID, err, r.body)
	}
	return nil
}

// pointerTo finds the JSON pointer of a schema object inside the spec (by identity of its $ref, or by search).
func (s *specIndex) pointerTo(schema any) string {
	if m, isMap := schema.(map[string]any); isMap {
		if ref, has := m["$ref"].(string); has && len(m) == 1 {
			return "openapi.json" + ref
		}
	}
	var found string
	var walk func(v any, ptr string)
	walk = func(v any, ptr string) {
		if found != "" {
			return
		}
		switch x := v.(type) {
		case map[string]any:
			if fmt.Sprint(x) == fmt.Sprint(schema) && ptr != "" && strings.HasSuffix(ptr, "/schema") {
				found = ptr
				return
			}
			for k, c := range x {
				walk(c, ptr+"/"+strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1"))
			}
		case []any:
			for i, c := range x {
				walk(c, fmt.Sprintf("%s/%d", ptr, i))
			}
		}
	}
	walk(s.doc, "")
	return "openapi.json#" + found
}

// ---- tests

// HP-API-001: every spec operation is generated, routed and declares a known permission.
func TestSpecConformance(t *testing.T) {
	s := loadSpec(t)
	if len(gen.Operations) != len(s.ops) {
		t.Fatalf("generated %d operations, spec has %d (run make api)", len(gen.Operations), len(s.ops))
	}
	for _, op := range gen.Operations {
		if !rbac.Known(rbac.Permission(op.Permission)) {
			t.Errorf("%s: unknown x-permission %q", op.ID, op.Permission)
		}
		if op.Method != http.MethodGet && op.Permission == string(rbac.Public) && !strings.Contains(op.Path, "/auth/") {
			t.Errorf("%s: public mutation outside /auth", op.ID)
		}
	}
}

// The spec validator really rejects drift (guards against vacuous schema checks).
func TestSpecValidatorRejects(t *testing.T) {
	s := loadSpec(t)
	for _, tc := range []struct {
		op   string
		r    resp
		good bool
	}{
		{"getMe", resp{status: 200, body: []byte(`{}`)}, false},
		{"listAgents", resp{status: 200, body: []byte(`{"items":[{"id":1}]}`)}, false},
		{"listAgents", resp{status: 200, body: []byte(`{"items":[]}`)}, true},
		{"getPolicyVersion", resp{status: 200, body: []byte(`{"version":"x"}`)}, false},
		{"getAuthConfig", resp{status: 201, body: []byte(`{}`)}, false},
	} {
		if err := s.check(tc.op, tc.r); (err == nil) != tc.good {
			t.Errorf("%s %s: err=%v", tc.op, tc.r.body, err)
		}
	}
}

// HP-AUTH-001/012/013, HP-API-003/007: bootstrap flow, cookies, CSRF, Origin, problem details, security headers.
func TestAuthFlowAndProtections(t *testing.T) {
	h := newHarness(t)
	c := h.bootstrapAdmin()
	r := c.ok("getMe", 200, "GET", "/api/v1/me", nil)
	for k, want := range map[string]string{"X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin", "X-Frame-Options": "DENY"} {
		if r.header.Get(k) != want {
			t.Errorf("%s = %q", k, r.header.Get(k))
		}
	}
	if csp := r.header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("CSP %q", csp)
	}
	if r.header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS enabled")
	}
	body := map[string]any{"name": "bot-1"}
	saved := c.csrf
	c.csrf = ""
	if r := c.do("POST", "/api/v1/agents", body); r.status != 403 {
		t.Fatalf("mutation without CSRF: %d", r.status)
	}
	c.csrf = saved
	if r := c.do("POST", "/api/v1/agents", body, "Origin", "https://evil.example"); r.status != 403 {
		t.Fatalf("cross-origin mutation: %d", r.status)
	}
	r = c.do("POST", "/api/v1/agents", map[string]any{"name": "BAD NAME"})
	if r.status != 422 || r.header.Get("Content-Type") != "application/problem+json" || r.problemCode() != "validation_failed" {
		t.Fatalf("validation problem: %d %s", r.status, r.body)
	}
	if r := c.do("GET", "/api/v1/nope", nil); r.status != 404 || r.problemCode() != "not_found" {
		t.Fatalf("unknown endpoint: %d %s", r.status, r.body)
	}
	if r := c.do("POST", "/api/v1/agents", map[string]any{"name": "x", "unknown_field": 1}); r.status != 422 {
		t.Fatalf("unknown field accepted: %d", r.status)
	}
	big := strings.Repeat("a", 2<<20)
	if r := c.do("POST", "/api/v1/agents", map[string]any{"name": big}); r.status != 413 {
		t.Fatalf("oversized body: %d", r.status)
	}
	// Logout revokes the session; the cookie no longer works.
	c.ok("logout", 200, "POST", "/api/v1/auth/logout", nil)
	if r := c.do("GET", "/api/v1/me", nil); r.status != 401 {
		t.Fatalf("after logout: %d", r.status)
	}
	// Wrong password is a uniform 401.
	anon := h.client()
	if r := anon.do("POST", "/api/v1/auth/login", map[string]string{"email": "admin@example.com", "password": "wrong password here"}); r.status != 401 ||
		r.problemCode() != "unauthorized" {
		t.Fatalf("bad login: %d %s", r.status, r.body)
	}
	if r := anon.do("GET", "/api/v1/agents", nil); r.status != 401 {
		t.Fatalf("anonymous API access: %d", r.status)
	}
}

// HP-RBAC-001/006/007: the full matrix for every operation, for local and SSO principals with the same roles.
func TestRBACMatrix(t *testing.T) {
	h := newHarness(t)
	h.bootstrapAdmin()
	roleSets := [][]string{{opauth.RoleAdministrator}, {opauth.RoleApprover}, {opauth.RoleAuditor}, {opauth.RoleViewer}, {}}
	type outcome struct{ forbidden bool }
	results := map[string]map[string]outcome{} // op → principal label → outcome
	for _, roles := range roleSets {
		for _, method := range []string{opauth.MethodPassword, opauth.MethodOIDC} {
			c := h.principalClient(roles, method)
			label := strings.Join(roles, "+") + "/" + method
			for _, op := range gen.Operations {
				if op.Stream || op.Redirect || op.ID == "logout" || op.Permission == string(rbac.Public) {
					continue
				}
				path := strings.NewReplacer("{id}", "x", "{kid}", "x", "{mid}", "x", "{token}", "x").Replace(op.Path)
				var body any
				if op.Method != http.MethodGet && op.Method != http.MethodDelete {
					body = map[string]any{}
				}
				r := c.do(op.Method, path, body, "If-Match", `"1"`)
				forbidden := r.status == 403 && strings.Contains(string(r.body), "you do not have permission")
				want := op.Permission != string(rbac.Session) && op.Permission != string(rbac.Limited) &&
					!h.matrix.Has(roles, rbac.Permission(op.Permission))
				if forbidden != want {
					t.Errorf("%s as %s: rbac forbidden=%v want %v (%d %s)", op.ID, label, forbidden, want, r.status, r.body)
				}
				if r.status == 500 {
					t.Errorf("%s as %s: 500 %s", op.ID, label, r.body)
				}
				if results[op.ID] == nil {
					results[op.ID] = map[string]outcome{}
				}
				results[op.ID][label] = outcome{forbidden}
			}
		}
	}
	// HP-RBAC-006: identical decisions for local and SSO principals.
	for op, byLabel := range results {
		for label, o := range byLabel {
			if strings.HasSuffix(label, "/"+opauth.MethodPassword) {
				sso := strings.TrimSuffix(label, opauth.MethodPassword) + opauth.MethodOIDC
				if byLabel[sso] != o {
					t.Errorf("%s: %s and %s differ", op, label, sso)
				}
			}
		}
	}
}

// End-to-end administration flow through the API with response-schema validation, idempotency, pagination,
// address redaction and reason visibility.
func TestAdministrationFlow(t *testing.T) {
	h := newHarness(t)
	c := h.bootstrapAdmin()
	key := sshkeys.Ed25519(t)
	r := c.ok("createAgent", 201, "POST", "/api/v1/agents", map[string]any{"name": "sre-bot", "groups": []string{"sre"},
		"public_keys": []string{key.AuthorizedLine("")}})
	var agent struct {
		ID      string
		Version int64
	}
	r.json(t, &agent)
	c.ok("listAgents", 200, "GET", "/api/v1/agents", nil)
	c.ok("getAgent", 200, "GET", "/api/v1/agents/"+agent.ID, nil)
	c.ok("updateAgent", 200, "PATCH", "/api/v1/agents/"+agent.ID, map[string]any{"description": "bot"}, "If-Match", fmt.Sprintf(`"%d"`, agent.Version))
	if r := c.do("PATCH", "/api/v1/agents/"+agent.ID, map[string]any{"description": "x"}); r.status != 428 {
		t.Fatalf("PATCH without If-Match: %d %s", r.status, r.body)
	}
	r = c.ok("createServer", 201, "POST", "/api/v1/servers", map[string]any{"alias": "web1", "address": "10.1.2.3", "port": 22})
	var srv struct {
		ID, Address string
		Port        int
	}
	r.json(t, &srv)
	if srv.Address != "10.1.2.3" {
		t.Fatalf("admin cannot see address: %s", r.body)
	}
	viewer := h.principalClient([]string{opauth.RoleViewer}, opauth.MethodPassword)
	r = viewer.ok("getServer", 200, "GET", "/api/v1/servers/"+srv.ID, nil)
	if strings.Contains(string(r.body), "10.1.2.3") || !strings.Contains(string(r.body), `"address_redacted":true`) {
		t.Fatalf("viewer saw address: %s", r.body)
	}
	if r := viewer.do("GET", "/api/v1/servers/"+srv.ID+"/host-identities", nil); r.status != 403 {
		t.Fatalf("viewer saw host identities: %d", r.status)
	}
	r = c.ok("createRole", 201, "POST", "/api/v1/servers/"+srv.ID+"/roles", map[string]any{"alias": "inspect", "remote_user": "ro",
		"default_duration": 1800, "max_duration": 3600})
	var role struct {
		ID              string
		DefaultDuration int64 `json:"default_duration"`
	}
	r.json(t, &role)
	if role.DefaultDuration != 1800 {
		t.Fatalf("durations are not seconds: %s", r.body)
	}
	c.ok("listRoles", 200, "GET", "/api/v1/servers/"+srv.ID+"/roles", nil)
	c.ok("createPolicyRule", 201, "POST", "/api/v1/policy/rules", map[string]any{"name": "sre", "effect": "allow", "level": "requestable",
		"require_reason": true, "enabled": true, "subjects": map[string]any{"agent_groups": []string{"sre"}}, "targets": map[string]any{"all": true},
		"roles": map[string]any{"all": true}, "max_duration": 3600})
	c.ok("listPolicyRules", 200, "GET", "/api/v1/policy/rules", nil)
	r = c.ok("getMe", 200, "GET", "/api/v1/me", nil)
	var me struct {
		Operator struct{ ID string } `json:"operator"`
	}
	r.json(t, &me)
	c.ok("createApproverRule", 201, "POST", "/api/v1/policy/approver-rules", map[string]any{"name": "admins", "enabled": true,
		"operators": map[string]any{"operators": []string{me.Operator.ID}}, "targets": map[string]any{"all": true}, "roles": map[string]any{"all": true}})
	c.ok("getAgentEffectiveAccess", 200, "GET", "/api/v1/agents/"+agent.ID+"/effective-access", nil)
	c.ok("getServerEffectiveAccess", 200, "GET", "/api/v1/servers/"+srv.ID+"/effective-access", nil)
	c.ok("getPolicyVersion", 200, "GET", "/api/v1/policy/version", nil)

	// Requests arrive from agents; create three directly through the service.
	keys, _ := h.a.Agents.Keys(h.ctx, agent.ID)
	ids := []string{}
	for i := range 3 {
		res, err := h.a.Access.CreateRequest(h.ctx, accessReq(agent.ID, keys[0].ID, srv.ID, role.ID, fmt.Sprintf("investigate alert %d", i)))
		must(t, err)
		ids = append(ids, res.Request.ID)
		h.clk.Advance(time.Second)
		if i < 2 { // only one pending per agent/server/role: cancel the first two so new ones can be created
			_, err := h.a.Access.CancelByAgent(h.ctx, agent.ID, res.Request.ID)
			must(t, err)
		}
	}
	r = c.ok("listRequests", 200, "GET", "/api/v1/requests?limit=2", nil)
	var pg struct {
		Items []struct {
			ID     string
			Reason *string
		}
		NextCursor *string `json:"next_cursor"`
	}
	r.json(t, &pg)
	if len(pg.Items) != 2 || pg.NextCursor == nil || pg.Items[0].ID != ids[2] || pg.Items[0].Reason == nil {
		t.Fatalf("page 1: %s", r.body)
	}
	r = c.ok("listRequests", 200, "GET", "/api/v1/requests?limit=2&cursor="+*pg.NextCursor, nil)
	r.json(t, &pg)
	if len(pg.Items) != 1 || pg.NextCursor != nil || pg.Items[0].ID != ids[0] {
		t.Fatalf("page 2: %s", r.body)
	}
	if r := c.do("GET", "/api/v1/requests?cursor=!!", nil); r.status != 422 {
		t.Fatalf("bad cursor: %d", r.status)
	}
	r = viewer.ok("getRequest", 200, "GET", "/api/v1/requests/"+ids[2], nil)
	if strings.Contains(string(r.body), "investigate alert") {
		t.Fatalf("viewer saw the reason: %s", r.body)
	}
	// Approve with an idempotency key; a replay returns the same result, a different body conflicts.
	idem := "approve-key-0001"
	r = c.ok("approveRequest", 200, "POST", "/api/v1/requests/"+ids[2]+"/approve", map[string]any{"duration": 1800}, "Idempotency-Key", idem)
	var dec struct {
		Grant struct {
			ID        string `json:"id"`
			SessionID string `json:"session_id"`
		}
	}
	r.json(t, &dec)
	r2 := c.do("POST", "/api/v1/requests/"+ids[2]+"/approve", map[string]any{"duration": 1800}, "Idempotency-Key", idem)
	if r2.status != 200 || r2.header.Get("Idempotent-Replayed") != "true" || !bytes.Equal(r.body, r2.body) {
		t.Fatalf("replay: %d %s", r2.status, r2.body)
	}
	if r := c.do("POST", "/api/v1/requests/"+ids[2]+"/approve", map[string]any{"duration": 900}, "Idempotency-Key", idem); r.status != 409 {
		t.Fatalf("key reuse with different body: %d", r.status)
	}
	c.ok("listGrants", 200, "GET", "/api/v1/grants?state=active", nil)
	c.ok("getGrant", 200, "GET", "/api/v1/grants/"+dec.Grant.ID, nil)
	c.ok("listAccessSessions", 200, "GET", "/api/v1/access-sessions", nil)
	c.ok("getAccessSession", 200, "GET", "/api/v1/access-sessions/"+dec.Grant.SessionID, nil)
	c.ok("getSessionTimeline", 200, "GET", "/api/v1/access-sessions/"+dec.Grant.SessionID+"/timeline", nil)
	c.ok("listSessionChannels", 200, "GET", "/api/v1/access-sessions/"+dec.Grant.SessionID+"/channels", nil)
	c.ok("listSessionSegments", 200, "GET", "/api/v1/access-sessions/"+dec.Grant.SessionID+"/segments", nil)
	c.ok("listActivities", 200, "GET", "/api/v1/activities", nil)
	// Record a real channel so replay and export have data.
	connID, err := h.a.Access.OpenConnection(h.ctx, access.ConnectionInfo{AgentID: agent.ID, KeyID: keys[0].ID, ClientUser: "x", ClientVersion: "SSH-2.0-test",
		SourceIP: "10.9.9.9"})
	must(t, err)
	reg, err := h.a.Access.RegisterChannel(h.ctx, access.RegisterInput{ConnectionID: connID, AgentID: agent.ID, KeyID: keys[0].ID, GrantID: dec.Grant.ID,
		Kind: access.KindExec})
	must(t, err)
	rec, err := h.a.Recording.Open(h.ctx, reg, access.KindExec, false)
	must(t, err)
	must(t, rec.ExecRequested("uptime"))
	must(t, rec.Output(sshproxy.StreamStdout, []byte("up 3 days\n")))
	must(t, rec.Finalize("exit_status"))
	r = c.ok("listSessionSegments", 200, "GET", "/api/v1/access-sessions/"+dec.Grant.SessionID+"/segments", nil)
	var segs struct{ Items []struct{ ID string } }
	r.json(t, &segs)
	if len(segs.Items) != 1 {
		t.Fatalf("segments %s", r.body)
	}
	r = c.ok("getRecordingRecords", 200, "GET", "/api/v1/recordings/"+segs.Items[0].ID+"/records", nil)
	if !strings.Contains(string(r.body), base64.StdEncoding.EncodeToString([]byte("up 3 days\n"))) || !strings.Contains(string(r.body), "stdout@1") {
		t.Fatalf("records %s", r.body)
	}
	r = c.ok("exportSessionRecordings", 200, "GET", "/api/v1/access-sessions/"+dec.Grant.SessionID+"/export", nil)
	if !strings.Contains(string(r.body), `"complete":true`) {
		t.Fatalf("export %s", r.body)
	}
	c.ok("acknowledgeBreakGlass", 200, "POST", "/api/v1/system/breakglass-ack", nil)
	if r := viewer.do("GET", "/api/v1/access-sessions/"+dec.Grant.SessionID+"/export", nil); r.status != 403 {
		t.Fatalf("viewer exported recordings: %d", r.status)
	}
	c.ok("revokeGrant", 200, "POST", "/api/v1/grants/"+dec.Grant.ID+"/revoke", map[string]string{"reason": "done"})
	r = c.ok("listAuditEvents", 200, "GET", "/api/v1/audit-events?limit=5", nil)
	var ap struct {
		NextCursor *string `json:"next_cursor"`
	}
	r.json(t, &ap)
	c.ok("listAuditEvents", 200, "GET", "/api/v1/audit-events?limit=5&cursor="+*ap.NextCursor, nil)
	c.ok("verifyAuditChain", 200, "GET", "/api/v1/audit-events/verify", nil)
	c.ok("getSystemStatus", 200, "GET", "/api/v1/system/status", nil)
	c.ok("getStatsOverview", 200, "GET", "/api/v1/stats/overview?range=7d", nil)
	c.ok("listGatewayHostKeys", 200, "GET", "/api/v1/system/gateway-host-keys", nil)
	c.ok("listOperators", 200, "GET", "/api/v1/operators", nil)
	c.ok("listMySessions", 200, "GET", "/api/v1/me/sessions", nil)
	c.ok("listGroups", 200, "GET", "/api/v1/groups", nil)
	c.ok("createInvitation", 200, "POST", "/api/v1/invitations", map[string]any{"email": "new@example.com", "roles": []string{"viewer"}})
	c.ok("getAuthSettings", 200, "GET", "/api/v1/settings/auth", nil)
	c.ok("listOIDCProviders", 200, "GET", "/api/v1/oidc-providers", nil)
	c.ok("enableLockdown", 200, "POST", "/api/v1/system/lockdown", nil)
	c.ok("liftLockdown", 200, "DELETE", "/api/v1/system/lockdown", nil)

	// Recent authentication: after the window, sensitive operations need re-authentication.
	h.clk.Advance(10 * time.Minute)
	if r := c.do("POST", "/api/v1/operators", map[string]any{"email": "x@example.com", "display_name": "x"}); r.status != 401 ||
		r.problemCode() != "reauth_required" {
		t.Fatalf("stale session created an operator: %d %s", r.status, r.body)
	}
}

// HP-API-005: SSE delivery, permission filtering, Last-Event-ID resume, reset on unknown IDs and stream limits.
func TestSSE(t *testing.T) {
	h := newHarness(t)
	admin := h.principalClient([]string{opauth.RoleAdministrator}, opauth.MethodOIDC)
	viewer := h.principalClient([]string{opauth.RoleViewer}, opauth.MethodOIDC)
	type frame struct{ id, event, data string }
	open := func(c *client, lastID string) (<-chan frame, func()) {
		ctx, cancel := context.WithCancel(h.ctx)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.base+"/api/v1/events", nil)
		if lastID != "" {
			req.Header.Set("Last-Event-ID", lastID)
		}
		res, err := c.hc.Do(req)
		must(t, err)
		if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "text/event-stream" {
			t.Fatalf("stream: %d", res.StatusCode)
		}
		out := make(chan frame, 64)
		go func() {
			defer res.Body.Close()
			sc := bufio.NewScanner(res.Body)
			var f frame
			for sc.Scan() {
				line := sc.Text()
				switch {
				case strings.HasPrefix(line, "id: "):
					f.id = line[4:]
				case strings.HasPrefix(line, "event: "):
					f.event = line[7:]
				case strings.HasPrefix(line, "data: "):
					f.data = line[6:]
				case line == "" && f.event != "":
					out <- f
					f = frame{}
				}
			}
			close(out)
		}()
		return out, cancel
	}
	next := func(ch <-chan frame) frame {
		select {
		case f := <-ch:
			return f
		case <-time.After(5 * time.Second):
			t.Fatal("no event")
			return frame{}
		}
	}
	aCh, aStop := open(admin, "")
	vCh, vStop := open(viewer, "")
	waitClients := func(n int) {
		for range 100 {
			if h.api.Hub().Clients() == n {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("clients %d", h.api.Hub().Clients())
	}
	waitClients(2)
	h.a.Bus.Publish(eventbus.Event{Topic: eventbus.TopicAudit, Key: "aud_1"})
	h.a.Bus.Publish(eventbus.Event{Topic: eventbus.TopicRequestCreated, Key: "req_1", Payload: "pending"})
	f1 := next(aCh)
	f2 := next(aCh)
	if f1.event != "audit.appended" || f2.event != "request.created" || !strings.Contains(f2.data, `"resource_id":"req_1"`) {
		t.Fatalf("admin frames %+v %+v", f1, f2)
	}
	if f := next(vCh); f.event != "request.created" {
		t.Fatalf("viewer got %+v (audit must be filtered)", f)
	}
	aStop()
	vStop()
	waitClients(0)
	// Resume after f1 replays f2; an unknown ID yields reset.
	rCh, rStop := open(admin, f1.id)
	if f := next(rCh); f.id != f2.id {
		t.Fatalf("resume got %+v want %s", f, f2.id)
	}
	rStop()
	xCh, xStop := open(admin, "otherboot.5")
	if f := next(xCh); f.event != "reset" {
		t.Fatalf("unknown id: %+v", f)
	}
	xStop()
	waitClients(0)
	// At most 4 streams per session.
	var stops []func()
	for range 4 {
		_, stop := open(admin, "")
		stops = append(stops, stop)
	}
	waitClients(4)
	if r := admin.do("GET", "/api/v1/events", nil); r.status != 429 {
		t.Fatalf("fifth stream: %d", r.status)
	}
	for _, s := range stops {
		s()
	}
}

// HP-API-008: rate limits on auth endpoints.
func TestRateLimit(t *testing.T) {
	h := newHarness(t)
	h.api = httpapi.New(httpapi.Deps{Store: h.a.Store, Audit: h.a.Audit, Auth: h.a.Auth, OIDC: h.a.OIDC, Matrix: h.matrix, BootID: h.a.BootID},
		httpapi.Options{PublicURL: h.base, Clock: h.clk, AuthRate: 3})
	srv := httptest.NewServer(h.api.Handler())
	defer srv.Close()
	codes := []int{}
	for range 5 {
		req, _ := http.NewRequestWithContext(h.ctx, http.MethodPost, srv.URL+"/api/v1/auth/login", strings.NewReader(`{"email":"a@b.c","password":"x"}`))
		req.Header.Set("Origin", h.base)
		res, err := http.DefaultClient.Do(req)
		must(t, err)
		_ = res.Body.Close()
		codes = append(codes, res.StatusCode)
	}
	if codes[3] != 429 || codes[4] != 429 || res4(codes) {
		t.Fatalf("codes %v", codes)
	}
}

func res4(codes []int) bool { return codes[0] == 429 }

var _ = sync.Mutex{}

func accessReq(agentID, keyID, serverID, roleID, reason string) access.CreateRequestInput {
	return access.CreateRequestInput{AgentID: agentID, KeyID: keyID, ServerID: serverID, RoleID: roleID, Reason: reason, Duration: 30 * time.Minute}
}

// HP-OIDC-002/005 over HTTP: start sets the binding cookie and redirects; the callback sets the session cookie and
// redirects to the sanitized return path; a callback without the binding cookie fails back to /login.
func TestOIDCBrowserFlow(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrapAdmin()
	idp := oidctest.New(t)
	idp.RedirectURI = h.base + "/auth/oidc/callback"
	r := admin.ok("createOIDCProvider", 201, "POST", "/api/v1/oidc-providers", map[string]any{"slug": "corp", "display_name": "Corp",
		"issuer": idp.Issuer(), "client_id": idp.ClientID, "client_secret": idp.ClientSecret, "ca_bundle_pem": idp.CAPEM(),
		"allow_private_network": true, "enabled": true})
	var prov struct {
		ID          string
		RedirectURI string `json:"redirect_uri"`
	}
	r.json(t, &prov)
	if strings.Contains(string(r.body), idp.ClientSecret) || prov.RedirectURI != idp.RedirectURI {
		t.Fatalf("provider DTO: %s", r.body)
	}
	op, err := h.a.Auth.Create(h.ctx, sysActor, opauth.CreateInput{Email: "sso@example.com", DisplayName: "SSO", Roles: []string{"viewer"}})
	must(t, err)
	must(t, h.a.OIDC.LinkIdentity(h.ctx, sysActor, op.ID, prov.ID, "user-1"))

	browser := h.client()
	r = browser.do("GET", "/auth/oidc/corp/start?return_to=/requests", nil)
	if r.status != 302 || !strings.HasPrefix(r.header.Get("Location"), idp.Issuer()+"/authorize") {
		t.Fatalf("start: %d %v", r.status, r.header)
	}
	q, err := idp.Authorize(r.header.Get("Location"))
	must(t, err)
	r = browser.do("GET", "/auth/oidc/callback?state="+q.Get("state")+"&code="+q.Get("code"), nil)
	if r.status != 303 || r.header.Get("Location") != "/requests" {
		t.Fatalf("callback: %d %v %s", r.status, r.header, r.body)
	}
	r = browser.ok("getMe", 200, "GET", "/api/v1/me", nil)
	if !strings.Contains(string(r.body), `"method":"oidc"`) {
		t.Fatalf("me: %s", r.body)
	}
	// A callback in a browser without the binding cookie is refused.
	other := h.client()
	r = browser.do("GET", "/auth/oidc/corp/start", nil)
	q, err = idp.Authorize(r.header.Get("Location"))
	must(t, err)
	r = other.do("GET", "/auth/oidc/callback?state="+q.Get("state")+"&code="+q.Get("code"), nil)
	if r.status != 303 || !strings.HasPrefix(r.header.Get("Location"), "/login?sso_error=") {
		t.Fatalf("callback without binding: %d %v", r.status, r.header)
	}
	if r := other.do("GET", "/api/v1/me", nil); r.status != 401 {
		t.Fatal("session created without binding cookie")
	}
	// Test login preview via the API (HP-OIDC-014).
	r = admin.do("GET", "/auth/oidc/corp/start?purpose=test", nil)
	q, err = idp.Authorize(r.header.Get("Location"))
	must(t, err)
	r = admin.do("GET", "/auth/oidc/callback?state="+q.Get("state")+"&code="+q.Get("code"), nil)
	if r.status != 303 || !strings.Contains(r.header.Get("Location"), "test_login=") {
		t.Fatalf("test login: %d %v", r.status, r.header)
	}
	admin.ok("getOIDCTestLogin", 200, "GET", "/api/v1/oidc-providers/"+prov.ID+"/test-login", nil)
}
