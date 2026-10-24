package httpapi_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/httpapi/gen"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshkeys"
)

func strp[T any](v T) *T { return &v }

// sessionClients creates one operator with roles and n separate sessions of it.
func (h *harness) sessionClients(roles []string, n int) []*client {
	h.t.Helper()
	op, err := h.a.Auth.Create(h.ctx, sysActor, opauth.CreateInput{Email: fmt.Sprintf("multi-%d@example.com", time.Now().UnixNano()),
		DisplayName: "op", Roles: roles})
	must(h.t, err)
	out := make([]*client, n)
	for i := range n {
		var token string
		must(h.t, h.a.Store.W().Tx(h.ctx, func(tx *store.Tx) error {
			var err error
			token, err = h.a.Auth.CreateSessionTx(h.ctx, tx, op.ID, opauth.MethodOIDC, opauth.SessionMeta{IP: "127.0.0.1"})
			return err
		}))
		c := h.client()
		u, _ := http.NewRequest(http.MethodGet, h.base, nil) //nolint:noctx // cookie URL only
		c.hc.Jar.SetCookies(u.URL, []*http.Cookie{{Name: "hp_session", Value: token, Path: "/"}})
		out[i] = c
	}
	return out
}

// openStream opens GET /api/v1/events and returns a channel closed when the server ends the stream.
func openStream(t *testing.T, h *harness, c *client) (<-chan struct{}, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(h.ctx)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.base+"/api/v1/events", nil)
	res, err := c.hc.Do(req)
	must(t, err)
	if res.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("stream: %d", res.StatusCode)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer res.Body.Close()
		sc := bufio.NewScanner(res.Body)
		for sc.Scan() {
		}
	}()
	return done, cancel
}

// SR-09 (HP-AUTH-012): an open live-event stream does not keep an idle session alive, and it closes once the
// session is idle-expired.
func TestSSEDoesNotExtendIdleSession(t *testing.T) {
	h := newHarness(t)
	h.api.SetStreamRevalidate(20 * time.Millisecond)
	viewer := h.principalClient([]string{opauth.RoleViewer}, opauth.MethodOIDC)
	done, stop := openStream(t, h, viewer)
	defer stop()
	for range 20 { // 40 minutes without user requests, in steps longer than the one-minute touch threshold
		h.clk.Advance(2 * time.Minute)
		time.Sleep(60 * time.Millisecond) // several re-checks per step
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stream still open after the session's idle timeout")
	}
	if r := viewer.do("GET", "/api/v1/agents", nil); r.status != http.StatusUnauthorized {
		t.Fatalf("idle session still valid after 40 minutes with only a live-event stream: %d", r.status)
	}
}

// SR-31: one operator cannot hold more than 16 live-event streams, however many sessions it has.
func TestSSEPerOperatorCap(t *testing.T) {
	h := newHarness(t)
	clients := h.sessionClients([]string{opauth.RoleViewer}, 5)
	var stops []func()
	defer func() {
		for _, s := range stops {
			s()
		}
	}()
	for _, c := range clients[:4] {
		for range 4 {
			_, stop := openStream(t, h, c)
			stops = append(stops, stop)
		}
	}
	ctx, cancel := context.WithTimeout(h.ctx, 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.base+"/api/v1/events", nil)
	res, err := clients[4].hc.Do(req)
	must(t, err)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("17th stream of one operator: %d", res.StatusCode)
	}
}

// SR-08 (HP-RBAC-002, HP-SRV-010): audit details reveal destination addresses, ports, host-CA principals and raw
// dial errors only to callers holding inventory.address.read.
func TestAuditDetailsRedactedWithoutAddressRead(t *testing.T) {
	h := newHarness(t)
	srv, err := h.a.Inventory.CreateServer(h.ctx, sysActor, inventory.ServerInput{Alias: strp("db1"), Address: strp("10.1.2.3"), Port: strp(2202)})
	must(t, err)
	ca := sshkeys.Ed25519(t)
	hca, err := h.a.Inventory.CreateHostCA(h.ctx, sysActor, "corp", ca.AuthorizedLine(""), time.Hour)
	must(t, err)
	must(t, h.a.Inventory.BindHostCA(h.ctx, sysActor, srv.ID, hca.ID, []string{"db1.prod.internal.example.com"}))
	must(t, h.a.Store.W().Tx(h.ctx, func(tx *store.Tx) error { // a probe failure recorded before SR-08 (raw dial error)
		_, err := h.a.Audit.Append(h.ctx, tx, audit.Event{Actor: sysActor, Action: "credential.probed", Outcome: audit.OutcomeFailure,
			Target: audit.Target{Type: "role", ID: "rol_x"}, Details: map[string]any{"credential_id": "crd_x", "error": "dial tcp 10.255.254.253:2203: i/o timeout"}})
		return err
	}))
	secrets := []string{"10.1.2.3", "2202", "db1.prod.internal", "10.255.254.253"}
	auditor := h.principalClient([]string{opauth.RoleAuditor}, opauth.MethodOIDC)
	body := string(auditor.ok("listAuditEvents", 200, "GET", "/api/v1/audit-events", nil).body)
	for _, s := range secrets {
		if strings.Contains(body, s) {
			t.Errorf("auditor without inventory.address.read sees %q in audit details", s)
		}
	}
	if !strings.Contains(body, "server.created") || !strings.Contains(body, "redacted") {
		t.Fatalf("expected redacted events: %s", body)
	}
	admin := h.principalClient([]string{opauth.RoleAdministrator}, opauth.MethodOIDC)
	body = string(admin.ok("listAuditEvents", 200, "GET", "/api/v1/audit-events", nil).body)
	for _, s := range secrets {
		if !strings.Contains(body, s) {
			t.Errorf("administrator does not see %q", s)
		}
	}
}

// SR-28 (HP-SRV-010): host-CA principals (destination host names) are not returned without inventory.address.read.
func TestServerHostCAPrincipalsRedacted(t *testing.T) {
	h := newHarness(t)
	srv, err := h.a.Inventory.CreateServer(h.ctx, sysActor, inventory.ServerInput{Alias: strp("db1"), Address: strp("10.1.2.3")})
	must(t, err)
	ca := sshkeys.Ed25519(t)
	hca, err := h.a.Inventory.CreateHostCA(h.ctx, sysActor, "corp", ca.AuthorizedLine(""), time.Hour)
	must(t, err)
	must(t, h.a.Inventory.BindHostCA(h.ctx, sysActor, srv.ID, hca.ID, []string{"db1.prod.internal.example.com"}))
	viewer := h.principalClient([]string{opauth.RoleViewer}, opauth.MethodOIDC)
	body := string(viewer.ok("getServer", 200, "GET", "/api/v1/servers/"+srv.ID, nil).body)
	if strings.Contains(body, "db1.prod.internal") || strings.Contains(body, hca.ID) {
		t.Fatalf("viewer sees host-CA binding: %s", body)
	}
	admin := h.principalClient([]string{opauth.RoleAdministrator}, opauth.MethodOIDC)
	if body := string(admin.ok("getServer", 200, "GET", "/api/v1/servers/"+srv.ID, nil).body); !strings.Contains(body, "db1.prod.internal") {
		t.Fatalf("administrator does not see principals: %s", body)
	}
}

// SR-14 (HP-POL-012): the owner and self-approval handlers work end to end against the services; they become
// routable once the operations are declared in api/openapi.yaml.
func TestAgentOwnerHandlers(t *testing.T) {
	h := newHarness(t)
	op, err := h.a.Auth.Create(h.ctx, sysActor, opauth.CreateInput{Email: "owner@example.com", DisplayName: "owner", Roles: []string{opauth.RoleApprover}})
	must(t, err)
	ag, err := h.a.Agents.Create(h.ctx, sysActor, agents.CreateInput{Name: "bot"})
	must(t, err)
	var token string
	admin, err := h.a.Auth.Create(h.ctx, sysActor, opauth.CreateInput{Email: "adm@example.com", DisplayName: "adm", Roles: []string{opauth.RoleAdministrator}})
	must(t, err)
	must(t, h.a.Store.W().Tx(h.ctx, func(tx *store.Tx) error {
		var err error
		token, err = h.a.Auth.CreateSessionTx(h.ctx, tx, admin.ID, opauth.MethodOIDC, opauth.SessionMeta{IP: "127.0.0.1"})
		return err
	}))
	p, err := h.a.Auth.Authenticate(h.ctx, token)
	must(t, err)
	call := func(method, body string) *gen.Call {
		r := httptest.NewRequest(method, "/api/v1/agents/"+ag.ID+"/owners", strings.NewReader(body))
		r.SetPathValue("id", ag.ID)
		return &gen.Call{W: httptest.NewRecorder(), R: r, Principal: p}
	}
	res, err := h.api.SetAgentOwners(call(http.MethodPut, `{"owners":["`+op.ID+`"]}`))
	must(t, err)
	b, _ := json.Marshal(res.Body)
	if !strings.Contains(string(b), op.ID) {
		t.Fatalf("set owners: %s", b)
	}
	if _, err := h.api.SetAgentOwners(call(http.MethodPut, `{"owners":["opr_00000000000000000000000000"]}`)); err == nil {
		t.Fatal("unknown operator accepted")
	}
	res, err = h.api.GetAgentOwners(call(http.MethodGet, ""))
	must(t, err)
	if b, _ := json.Marshal(res.Body); string(b) != `{"agent_id":"`+ag.ID+`","owners":["`+op.ID+`"]}` {
		t.Fatalf("get owners: %s", b)
	}
	res, err = h.api.GetSelfApprovalSetting(call(http.MethodGet, ""))
	must(t, err)
	if b, _ := json.Marshal(res.Body); string(b) != `{"prohibit_self_approval":true}` {
		t.Fatalf("self-approval default: %s", b)
	}
	snap, err := h.a.Engine.Current(h.ctx)
	must(t, err)
	if snap.Agent(ag.ID) == nil || !slices.Contains(snap.Agent(ag.ID).Owners, op.ID) {
		t.Fatal("owner not visible to the policy engine")
	}
}

// SR-33 (HP-REQ-008): a policy rule created without require_reason requires a reason.
func TestRuleRequireReasonDefaultsTrue(t *testing.T) {
	h := newHarness(t)
	admin := h.principalClient([]string{opauth.RoleAdministrator}, opauth.MethodOIDC)
	r := admin.ok("createPolicyRule", 201, "POST", "/api/v1/policy/rules", map[string]any{"name": "r1", "effect": "allow", "level": "requestable",
		"enabled": true, "subjects": map[string]any{"all": true}, "targets": map[string]any{"all": true}, "roles": map[string]any{"all": true}})
	var out struct {
		RequireReason bool `json:"require_reason"`
	}
	r.json(t, &out)
	if !out.RequireReason {
		t.Fatal("rule created without require_reason does not require a reason")
	}
	r = admin.ok("createPolicyRule", 201, "POST", "/api/v1/policy/rules", map[string]any{"name": "r2", "effect": "allow", "level": "requestable",
		"enabled": true, "require_reason": false, "subjects": map[string]any{"all": true}, "targets": map[string]any{"all": true}, "roles": map[string]any{"all": true}})
	r.json(t, &out)
	if out.RequireReason {
		t.Fatal("explicit require_reason=false ignored")
	}
}

// SR-29 (HP-RBAC-001, PLAN §12.5): an approver reads request reasons only within its approver scope.
func TestApproverReasonReadScoped(t *testing.T) {
	h := newHarness(t)
	key := sshkeys.Ed25519(t)
	ag, err := h.a.Agents.Create(h.ctx, sysActor, agents.CreateInput{Name: "bot", Groups: []string{"sre"}, PublicKeys: []string{key.AuthorizedLine("")}})
	must(t, err)
	keys, _ := h.a.Agents.Keys(h.ctx, ag.ID)
	srv, err := h.a.Inventory.CreateServer(h.ctx, sysActor, inventory.ServerInput{Alias: strp("web1"), Address: strp("10.0.0.1")})
	must(t, err)
	role, err := h.a.Inventory.CreateRole(h.ctx, sysActor, srv.ID, inventory.RoleInput{Alias: strp("inspect"), RemoteUser: strp("ro")})
	must(t, err)
	_, err = h.a.Policy.CreateRule(h.ctx, sysActor, policy.Rule{Name: "sre", Effect: policy.EffectAllow, Level: policy.LevelRequestable, Enabled: true,
		Subjects: policy.SubjectSelector{AgentGroups: []string{"sre"}}, Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}})
	must(t, err)
	res, err := h.a.Access.CreateRequest(h.ctx, accessReq(ag.ID, keys[0].ID, srv.ID, role.ID, "SECRET-REASON-xyz"))
	must(t, err)
	path := "/api/v1/requests/" + res.Request.ID
	outOfScope := h.principalClient([]string{opauth.RoleApprover}, opauth.MethodOIDC)
	if body := string(outOfScope.ok("getRequest", 200, "GET", path, nil).body); strings.Contains(body, "SECRET-REASON") {
		t.Fatalf("approver without an approver rule read the reason: %s", body)
	}
	inScope := h.principalClient([]string{opauth.RoleApprover}, opauth.MethodOIDC)
	var me struct {
		Operator struct{ ID string } `json:"operator"`
	}
	inScope.ok("getMe", 200, "GET", "/api/v1/me", nil).json(t, &me)
	_, err = h.a.Policy.CreateApproverRule(h.ctx, sysActor, policy.ApproverRule{Name: "oncall", Enabled: true,
		Operators: policy.OperatorSelector{Operators: []string{me.Operator.ID}}, Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}})
	must(t, err)
	if body := string(inScope.ok("getRequest", 200, "GET", path, nil).body); !strings.Contains(body, "SECRET-REASON") {
		t.Fatalf("in-scope approver cannot read the reason: %s", body)
	}
	auditor := h.principalClient([]string{opauth.RoleAuditor}, opauth.MethodOIDC)
	if body := string(auditor.ok("getRequest", 200, "GET", path, nil).body); !strings.Contains(body, "SECRET-REASON") {
		t.Fatalf("auditor cannot read the reason: %s", body)
	}
}
