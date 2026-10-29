package apiproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/apienv"
	"github.com/aurimasniekis/go-hallpass/internal/apirules"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/egress"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/keyring/keyringtest"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshkeys"
)

const apiHost = "api.example.com"

var admin = audit.Actor{Type: audit.ActorOperator, ID: "opr_admin"}

func ptr[T any](v T) *T { return &v }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// seen is what the fake API received.
type seen struct {
	Method, Path, RawQuery, Authorization, APIKey, Cookie string
}

type fx struct {
	t        *testing.T
	ctx      context.Context
	s        *store.Store
	svc      *Service
	proxy    *Proxy
	acc      *access.Service
	enf      *access.Enforcer
	inv      *inventory.Service
	agentID  string
	keyID    string
	connID   string
	srv      *inventory.Server
	read     *inventory.Role
	write    *inventory.Role
	approver policy.OperatorInfo
	pol      *policy.Service
	denied   []map[string]any

	mu   sync.Mutex
	seen []seen
}

// upstreamTLS returns a server certificate for apiHost and a pool trusting it.
func upstreamTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: apiHost}, DNSNames: []string{apiHost},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(t, err)
	cert, err := x509.ParseCertificate(der)
	must(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, pool
}

type fakeResolver struct{}

func (fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if host == apiHost {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func newFx(t *testing.T) *fx {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f := &fx{t: t, ctx: ctx}
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.seen = append(f.seen, seen{Method: r.Method, Path: r.URL.EscapedPath(), RawQuery: r.URL.RawQuery,
			Authorization: r.Header.Get("Authorization"), APIKey: r.Header.Get("X-Api-Key"), Cookie: r.Header.Get("Cookie")})
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	upCfg, upPool := upstreamTLS(t)
	up.TLS = upCfg
	up.StartTLS()
	t.Cleanup(up.Close)
	port, _ := strconv.Atoi(up.URL[strings.LastIndex(up.URL, ":")+1:])

	f.s = storetest.Open(t)
	kr := keyringtest.Load(t, f.s)
	aw := audit.NewWriter(kr)
	bus := eventbus.New()
	g, _ := egress.New([]string{"10.0.0.0/8"}, nil, nil, time.Second)
	f.inv = inventory.New(f.s, aw, bus, inventory.Options{Guard: g, MaxGrantDuration: 24 * time.Hour})
	engine := policy.NewEngine(f.s, 24*time.Hour, []time.Duration{5 * time.Minute, 30 * time.Minute, time.Hour})
	pol := policy.NewService(f.s, aw, bus, engine)
	f.pol = pol
	f.acc = access.New(f.s, kr, aw, bus, engine, access.Options{PendingExpiry: 30 * time.Minute})
	f.enf = access.NewEnforcer(f.acc, bus, 50*time.Millisecond)
	go f.enf.Run(ctx)
	f.svc = NewService(f.s, kr, aw, bus, f.inv, nil)
	apiGuard, err := egress.NewPublic([]string{"0.0.0.0/0"}, []string{"127.0.0.0/8"}, fakeResolver{}, time.Second)
	must(t, err)
	f.proxy, err = New(Options{Service: f.svc, Access: f.acc, Enforcer: f.enf, Engine: engine, Inventory: f.inv, Guard: apiGuard,
		RootCAs: upPool, UpstreamPort: port, Clock: clock.System{}})
	must(t, err)
	t.Cleanup(f.proxy.Close)

	ag := agents.New(f.s, kr, aw, bus, clock.System{})
	agent, err := ag.Create(ctx, admin, agents.CreateInput{Name: "bot", Groups: []string{"bots"}, PublicKeys: []string{sshkeys.Ed25519(t).AuthorizedLine("")}})
	must(t, err)
	keys, _ := ag.Keys(ctx, agent.ID)
	f.agentID, f.keyID = agent.ID, keys[0].ID
	f.connID, err = f.acc.OpenConnection(ctx, access.ConnectionInfo{AgentID: f.agentID, KeyID: f.keyID, SourceIP: "10.9.9.9"})
	must(t, err)

	f.srv, err = f.inv.CreateServer(ctx, admin, inventory.ServerInput{Alias: ptr("gh"), Kind: ptr(inventory.KindAPI),
		API: &inventory.APITarget{Hosts: []string{apiHost}}})
	must(t, err)
	f.read, err = f.inv.CreateRole(ctx, admin, f.srv.ID, inventory.RoleInput{Alias: ptr("read"), API: &inventory.APIRules{Rules: []apirules.Rule{
		{Effect: apirules.Allow, Methods: []string{"GET", "HEAD"}},
		{Effect: apirules.Allow, Methods: []string{"POST"}, Paths: []string{"/graphql"}, GraphQL: []string{"query"}},
		{Effect: apirules.Deny, Paths: []string{"/user/keys"}},
	}}})
	must(t, err)
	f.write, err = f.inv.CreateRole(ctx, admin, f.srv.ID, inventory.RoleInput{Alias: ptr("write"), API: &inventory.APIRules{Rules: []apirules.Rule{
		{Effect: apirules.Allow, Methods: []string{"POST", "PATCH"}, Paths: []string{"/repos/acme/**"}},
	}}})
	must(t, err)
	_, err = f.svc.SetCredential(ctx, admin, f.read.ID, CredentialInput{Type: CredBearer, Secret: "read-secret-token-1234"})
	must(t, err)
	_, err = f.svc.SetCredential(ctx, admin, f.write.ID, CredentialInput{Type: CredHeader, Header: "x-api-key", Secret: "write-secret-key-5678"})
	must(t, err)

	_, err = pol.CreateRule(ctx, admin, policy.Rule{Name: "read", Effect: policy.EffectAllow, Level: policy.LevelAutoApprove,
		AutoMaxDuration: 30 * time.Minute, Enabled: true, Subjects: policy.SubjectSelector{AgentGroups: []string{"bots"}},
		Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{Names: []string{"read"}}})
	must(t, err)
	_, err = pol.CreateRule(ctx, admin, policy.Rule{Name: "write", Effect: policy.EffectAllow, Level: policy.LevelRequestable,
		RequireReason: true, Enabled: true, Subjects: policy.SubjectSelector{AgentGroups: []string{"bots"}},
		Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{Names: []string{"write"}}})
	must(t, err)
	opID := insertOperator(t, f.s, "approver")
	_, err = pol.CreateApproverRule(ctx, admin, policy.ApproverRule{Name: "oncall", Enabled: true,
		Operators: policy.OperatorSelector{Operators: []string{opID}}, Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}})
	must(t, err)
	f.approver = policy.OperatorInfo{ID: opID, Roles: []string{"approver"}, Enabled: true}
	return f
}

func insertOperator(t *testing.T, s *store.Store, roles ...string) string {
	t.Helper()
	id := ids.New(ids.Operator)
	must(t, s.W().Tx(context.Background(), func(tx *store.Tx) error {
		if _, err := tx.SQL.ExecContext(context.Background(), `INSERT INTO operators (id, email, display_name, enabled, provisioned_via,
			created_at, created_by, updated_at) VALUES (?, ?, 'op', 1, 'admin', ?, 'test', ?)`, id, id+"@example.com", tx.NowMicros(), tx.NowMicros()); err != nil {
			return err
		}
		for _, r := range roles {
			if _, err := tx.SQL.ExecContext(context.Background(), `INSERT INTO operator_roles (operator_id, role, source) VALUES (?, ?, 'manual')`, id, r); err != nil {
				return err
			}
		}
		return nil
	}))
	return id
}

// client returns an HTTP client whose every connection is a new tunnel served by the proxy, trusting the target CA.
func (f *fx) client() *http.Client { return f.clientWith(nil) }

// clientWith is client with extra CONNECT headers (what hallpass-api sends).
func (f *fx) clientWith(connectHeaders http.Header) *http.Client {
	return f.clientAs("", connectHeaders)
}

// clientAs is clientWith with a proxy URL user name (http://<user>@127.0.0.1:18080).
func (f *fx) clientAs(proxyUser string, connectHeaders http.Header) *http.Client {
	f.t.Helper()
	bundle, err := f.svc.CABundle(f.ctx, []string{f.srv.ID})
	must(f.t, err)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(bundle)) {
		f.t.Fatal("CA bundle has no certificates")
	}
	cl := Client{ConnectionID: f.connID, AgentID: f.agentID, KeyID: f.keyID, SourceIP: "10.9.9.9",
		Deny: func(action string, d map[string]any) {
			f.mu.Lock()
			f.denied = append(f.denied, d)
			f.mu.Unlock()
		}}
	tr := &http.Transport{
		Proxy: http.ProxyURL(proxyURL(proxyUser)),
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			a, b := net.Pipe()
			go f.proxy.Serve(f.ctx, cl, b)
			return a, nil
		},
		TLSClientConfig:    &tls.Config{RootCAs: pool},
		ProxyConnectHeader: connectHeaders,
	}
	f.t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

type apiErr struct {
	Message  string `json:"message"`
	HallPass struct {
		Code string `json:"code"`
	} `json:"hallpass"`
	Error struct {
		Status string `json:"status"`
	} `json:"error"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (f *fx) do(c *http.Client, method, path, body string, hdr ...string) (int, apiErr) {
	f.t.Helper()
	st, e, err := f.tryDo(c, method, path, body, hdr...)
	must(f.t, err)
	return st, e
}

// tryDo is do that returns transport errors (a tunnel the enforcer closes mid-request ends with EOF).
func (f *fx) tryDo(c *http.Client, method, path, body string, hdr ...string) (int, apiErr, error) {
	f.t.Helper()
	req, err := http.NewRequest(method, "https://"+apiHost+path, strings.NewReader(body))
	must(f.t, err)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, apiErr{}, err
	}
	defer resp.Body.Close()
	var e apiErr
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &e)
	return resp.StatusCode, e, nil
}

func (f *fx) last() seen {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.seen) == 0 {
		f.t.Fatal("upstream saw no request")
	}
	return f.seen[len(f.seen)-1]
}

func (f *fx) upstreamCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}

func TestProxyInjectsCredentialAndEnforcesRules(t *testing.T) {
	f := newFx(t)
	c := f.client()

	// Auto-approved read: the agent's own token and cookies are replaced by the profile's credential.
	st, _ := f.do(c, "GET", "/repos/acme/api?access_token=leak&page=2", "", "Authorization", "Bearer agent-token", "Cookie", "a=b")
	if st != 200 {
		t.Fatalf("GET status %d", st)
	}
	got := f.last()
	if got.Authorization != "Bearer read-secret-token-1234" || got.Cookie != "" || got.Path != "/repos/acme/api" || got.RawQuery != "access_token=leak&page=2" {
		t.Fatalf("upstream saw %+v", got)
	}
	grants, err := f.acc.ActiveGrantsForAgent(f.ctx, f.agentID, "")
	if err != nil || len(grants) != 1 || grants[0].RoleID != f.read.ID {
		t.Fatalf("auto-approved grant: %v %v", grants, err)
	}

	// A write needs the requestable profile: refused with what to request, and never sent upstream.
	n := f.upstreamCount()
	st, e := f.do(c, "POST", "/repos/acme/api/issues", `{}`)
	if st != 403 || e.HallPass.Code != "approval_required" || !strings.Contains(e.Message, "request gh --role write") ||
		e.Error.Status != "PERMISSION_DENIED" || len(e.Errors) != 1 {
		t.Fatalf("write before approval: %d %+v", st, e)
	}
	// Denied path, even for GET.
	if st, e = f.do(c, "GET", "/user/keys", ""); st != 403 || e.HallPass.Code != "rule" {
		t.Fatalf("denied path: %d %+v", st, e)
	}
	// GraphQL: queries pass the read profile, mutations do not.
	if st, _ = f.do(c, "POST", "/graphql", `{"query":"query { viewer { login } }"}`); st != 200 {
		t.Fatalf("graphql query: %d", st)
	}
	if f.upstreamCount() != n+1 {
		t.Fatalf("refused requests reached upstream: %d", f.upstreamCount()-n)
	}
	if st, e = f.do(c, "POST", "/graphql", `{"query":"mutation { addStar(input: {}) { clientMutationId } }"}`); st != 403 || e.HallPass.Code != "rule" {
		t.Fatalf("graphql mutation: %d %+v", st, e)
	}
	if st, e = f.do(c, "GET", "/a/%2e%2e/user/keys", ""); st != 400 || e.HallPass.Code != "invalid_path" {
		t.Fatalf("dot segments: %d %+v", st, e)
	}

	// Approve write: the next POST uses the write profile's header credential and no Authorization.
	res, err := f.acc.CreateRequest(f.ctx, access.CreateRequestInput{AgentID: f.agentID, KeyID: f.keyID, ServerID: f.srv.ID,
		RoleID: f.write.ID, Reason: "label issues"})
	must(t, err)
	dec, err := f.acc.Decide(f.ctx, access.DecideInput{RequestID: res.Request.ID, Approve: true, Operator: f.approver, Channel: access.ChannelWeb})
	must(t, err)
	time.Sleep(candidateTTL + 100*time.Millisecond) // let the tunnel's cached profile list expire
	if st, e = f.do(c, "POST", "/repos/acme/api/issues", `{"title":"x"}`, "Authorization", "Bearer agent-token"); st != 200 {
		t.Fatalf("write after approval: %d %+v", st, e)
	}
	if got = f.last(); got.APIKey != "write-secret-key-5678" || got.Authorization != "" || got.Method != http.MethodPost {
		t.Fatalf("write upstream saw %+v", got)
	}

	// Revoking the write grant ends its tunnels and refuses the next write.
	_, err = f.acc.RevokeGrant(f.ctx, f.approver, dec.Grant.ID, "done")
	must(t, err)
	deadline := time.Now().Add(access.EnforcementBound)
	for {
		var err error
		st, e, err = f.tryDo(c, "POST", "/repos/acme/api/issues", `{}`)
		if err == nil && st == 403 && e.HallPass.Code == "approval_required" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("write still allowed after revocation: %d %+v", st, e)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Every forwarded and refused request under a grant is in the session timeline; the query's secret is redacted.
	c.CloseIdleConnections()
	time.Sleep(200 * time.Millisecond)
	rows, err := f.s.ReadDB().QueryContext(f.ctx, `SELECT data_json FROM timeline_events WHERE type = 'api.request' ORDER BY access_session_id, seq`)
	must(t, err)
	defer rows.Close()
	var events []map[string]any
	for rows.Next() {
		var raw string
		must(t, rows.Scan(&raw))
		var m map[string]any
		must(t, json.Unmarshal([]byte(raw), &m))
		events = append(events, m)
	}
	must(t, rows.Err())
	if len(events) < 6 {
		t.Fatalf("api.request events: %d", len(events))
	}
	first := events[0]
	if first["query"] != "access_token=[redacted]&page=2" || first["profile"] != "read" || first["status"] != float64(200) || first["method"] != "GET" {
		t.Fatalf("first event %v", first)
	}
	var refused int
	for _, e := range events {
		if e["refused"] != nil {
			refused++
		}
		if raw, _ := json.Marshal(e); strings.Contains(string(raw), "secret") {
			t.Fatalf("event leaks a credential: %s", raw)
		}
	}
	if refused == 0 {
		t.Fatal("refusals were not recorded")
	}
}

func TestProxyRefusesUnknownHostsAndPlainHTTP(t *testing.T) {
	f := newFx(t)
	cl := Client{ConnectionID: f.connID, AgentID: f.agentID, KeyID: f.keyID, Deny: func(string, map[string]any) {}}
	for _, c := range []struct{ req, want string }{
		{"CONNECT evil.example.org:443 HTTP/1.1\r\nHost: evil.example.org:443\r\n\r\n", "403 Forbidden"},
		{"CONNECT " + apiHost + ":80 HTTP/1.1\r\nHost: " + apiHost + ":80\r\n\r\n", "400 Bad Request"},
		{"GET http://" + apiHost + "/ HTTP/1.1\r\nHost: " + apiHost + "\r\n\r\n", "405 Method Not Allowed"},
	} {
		a, b := net.Pipe()
		go f.proxy.Serve(f.ctx, cl, b)
		go func() { _, _ = io.WriteString(a, c.req) }()
		resp, err := io.ReadAll(a)
		must(t, err)
		if !strings.HasPrefix(string(resp), "HTTP/1.1 "+c.want) || !strings.Contains(string(resp), "hallpass:") {
			t.Fatalf("%q: %q", c.req, resp)
		}
	}
}

func TestCAIsNameConstrainedAndFollowsHosts(t *testing.T) {
	f := newFx(t)
	ca, err := f.svc.CA(f.ctx, f.srv.ID)
	must(t, err)
	if !ca.PermittedDNSDomainsCritical || len(ca.PermittedDNSDomains) != 1 || ca.PermittedDNSDomains[0] != apiHost ||
		!ca.IsCA || !ca.MaxPathLenZero || len(ca.ExcludedIPRanges) != 2 {
		t.Fatalf("CA constraints: %+v", ca.PermittedDNSDomains)
	}
	// A leaf for another name cannot verify against the CA.
	signer, err := f.svc.signer(f.ctx, f.srv.ID)
	must(t, err)
	lc, err := signer.leaf("www.google.com", f.proxy.leafKey, time.Now())
	must(t, err)
	leaf, err := x509.ParseCertificate(lc.chain[0])
	must(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "www.google.com"}); err == nil {
		t.Fatal("the target CA verified a certificate for a host outside its constraints")
	}
	// Changing the hosts issues a new CA.
	srv, err := f.inv.UpdateServer(f.ctx, admin, f.srv.ID, inventory.ServerInput{Version: f.srv.Version,
		API: &inventory.APITarget{Hosts: []string{apiHost, "*.uploads.example.com"}}})
	must(t, err)
	ca2, err := f.svc.CA(f.ctx, srv.ID)
	must(t, err)
	if ca2.Equal(ca) || len(ca2.PermittedDNSDomains) != 2 {
		t.Fatalf("CA not reissued: %v", ca2.PermittedDNSDomains)
	}
	if srv.Address != apiHost || srv.Port != 443 {
		t.Fatalf("address %s:%d", srv.Address, srv.Port)
	}
}

func TestCredentialValidation(t *testing.T) {
	f := newFx(t)
	for _, in := range []CredentialInput{
		{Type: "token", Secret: "x"},
		{Type: CredBearer, Secret: ""},
		{Type: CredBearer, Secret: "a\nb"},
		{Type: CredHeader, Header: "Host", Secret: "x"},
		{Type: CredHeader, Header: "Proxy-Foo", Secret: "x"},
		{Type: CredBasic, Secret: "x"},
		{Type: CredGoogle, Secret: `{"type":"service_account"}`},
		{Type: CredBearer, Secret: "x", Scopes: []string{"https://www.googleapis.com/auth/cloud-platform"}},
	} {
		if _, err := f.svc.SetCredential(f.ctx, admin, f.read.ID, in); err == nil {
			t.Errorf("%+v accepted", in)
		}
	}
	c, err := f.svc.GetCredential(f.ctx, f.read.ID)
	must(t, err)
	if c.Type != CredBearer || c.Hint != "…1234" || c.Version != 1 {
		t.Fatalf("credential %+v", c)
	}
	// SSH servers' roles cannot hold API credentials.
	web, err := f.inv.CreateServer(f.ctx, admin, inventory.ServerInput{Alias: ptr("web1"), Address: ptr("10.0.0.1")})
	must(t, err)
	r, err := f.inv.CreateRole(f.ctx, admin, web.ID, inventory.RoleInput{Alias: ptr("ops"), RemoteUser: ptr("ops")})
	must(t, err)
	if _, err := f.svc.SetCredential(f.ctx, admin, r.ID, CredentialInput{Type: CredBearer, Secret: "x"}); err == nil {
		t.Fatal("credential set on an SSH role")
	}
	must(t, f.svc.DeleteCredential(f.ctx, admin, f.read.ID))
	if _, err := f.svc.GetCredential(f.ctx, f.read.ID); err == nil {
		t.Fatal("credential still present")
	}
}

// hallpass-api reports the command and reason in the CONNECT: a call that needs a requestable profile files the
// request itself, with the command in the reason, and "api requests <invocation>" finds it.
func TestProxyFilesRequestsForReportedCommands(t *testing.T) {
	f := newFx(t)
	const inv = "inv-test-invocation-one"
	c := f.clientWith(http.Header{
		apienv.HeaderCommand:    {apienv.Encode("gh issue comment 42 --body 'Fixed in #43'")},
		apienv.HeaderReason:     {apienv.Encode("Answer the customer on #42")},
		apienv.HeaderInvocation: {inv},
	})
	req, err := http.NewRequest(http.MethodPost, "https://"+apiHost+"/repos/acme/api/issues/42/comments", strings.NewReader(`{}`))
	must(t, err)
	resp, err := c.Do(req)
	must(t, err)
	_ = resp.Body.Close()
	reqID := resp.Header.Get("X-Hallpass-Request")
	if resp.StatusCode != http.StatusForbidden || reqID == "" || resp.Header.Get("X-Hallpass-Error") != "approval_pending" {
		t.Fatalf("status %d, request %q, error %q", resp.StatusCode, reqID, resp.Header.Get("X-Hallpass-Error"))
	}
	if got := f.proxy.Filed(f.agentID, inv); len(got) != 1 || got[0] != reqID {
		t.Fatalf("filed %v, want %s", got, reqID)
	}
	if got := f.proxy.Filed("agt_other", inv); got != nil {
		t.Fatalf("another agent sees the invocation: %v", got)
	}
	reason, err := f.acc.Reason(f.ctx, reqID)
	must(t, err)
	if reason != "Answer the customer on #42 | Command (reported by the agent): gh issue comment 42 --body 'Fixed in #43'" {
		t.Fatalf("reason %q", reason)
	}
	// A second refused call in the same run reuses the pending request.
	resp, err = c.Do(req.Clone(f.ctx))
	must(t, err)
	_ = resp.Body.Close()
	if resp.Header.Get("X-Hallpass-Request") != reqID || len(f.proxy.Filed(f.agentID, inv)) != 1 {
		t.Fatalf("second call filed another request: %q", resp.Header.Get("X-Hallpass-Request"))
	}
	// Reads go through the auto-approved profile and carry the command in the timeline.
	st, _ := f.do(c, "GET", "/repos/acme/api", "")
	if st != 200 {
		t.Fatalf("GET %d", st)
	}
	// The event is written after the response reaches the client.
	var cmd string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && cmd == ""; time.Sleep(20 * time.Millisecond) {
		_ = f.s.ReadDB().QueryRowContext(f.ctx, `SELECT json_extract(data_json, '$.command') FROM timeline_events
			WHERE type = 'api.request' AND json_extract(data_json, '$.status') = 200`).Scan(&cmd)
	}
	if !strings.HasPrefix(cmd, "gh issue comment 42") {
		t.Fatalf("recorded command %q", cmd)
	}
}

// An auto-approved profile that requires a reason: a hallpass-api call that sends one gets the grant and goes through
// on the first try (no approval_pending, nothing filed to wait for, so the command is not run twice); without a reason
// it is still refused.
func TestProxyAutoApprovesProfilesThatRequireAReason(t *testing.T) {
	f := newFx(t)
	triage, err := f.inv.CreateRole(f.ctx, admin, f.srv.ID, inventory.RoleInput{Alias: ptr("triage"), API: &inventory.APIRules{
		Rules: []apirules.Rule{{Effect: apirules.Allow, Methods: []string{"POST"}, Paths: []string{"/repos/acme/*/issues/*/labels"}}}}})
	must(t, err)
	_, err = f.svc.SetCredential(f.ctx, admin, triage.ID, CredentialInput{Type: CredBearer, Secret: "triage-secret-token-9012"})
	must(t, err)
	_, err = f.pol.CreateRule(f.ctx, admin, policy.Rule{Name: "triage", Effect: policy.EffectAllow, Level: policy.LevelAutoApprove,
		RequireReason: true, AutoMaxDuration: 30 * time.Minute, Enabled: true, Subjects: policy.SubjectSelector{AgentGroups: []string{"bots"}},
		Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{Names: []string{"triage"}}})
	must(t, err)
	const path = "/repos/acme/api/issues/42/labels"
	grants := func() int {
		var n int
		must(t, f.s.ReadDB().QueryRowContext(f.ctx, `SELECT count(*) FROM grants WHERE role_id = ?`, triage.ID).Scan(&n))
		return n
	}

	// Without a reason the profile cannot be granted: refused, nothing forwarded, no grant.
	before := f.upstreamCount()
	noReason := f.clientWith(http.Header{apienv.HeaderCommand: {apienv.Encode("gh issue edit 42 --add-label bug")},
		apienv.HeaderInvocation: {"inv-test-no-reason"}})
	if st, e := f.do(noReason, "POST", path, `{}`); st != http.StatusForbidden || e.HallPass.Code != "approval_required" {
		t.Fatalf("without a reason: %d %q", st, e.HallPass.Code)
	}
	if f.upstreamCount() != before || grants() != 0 {
		t.Fatal("a call without a reason reached the API or got a grant")
	}

	const inv = "inv-test-auto-with-reason"
	c := f.clientWith(http.Header{
		apienv.HeaderCommand:    {apienv.Encode("gh issue edit 42 --add-label bug")},
		apienv.HeaderReason:     {apienv.Encode("Label the cart timeout report")},
		apienv.HeaderInvocation: {inv},
	})
	if st, e := f.do(c, "POST", path, `{}`); st != http.StatusOK {
		t.Fatalf("first call with a reason: %d %q %q", st, e.HallPass.Code, e.Message)
	}
	if got := f.last(); got.Method != http.MethodPost || got.Path != path || got.Authorization != "Bearer triage-secret-token-9012" {
		t.Fatalf("upstream saw %+v", got)
	}
	if got := f.proxy.Filed(f.agentID, inv); len(got) != 0 {
		t.Fatalf("an auto-approved request was reported as filed: %v", got)
	}
	var reqID, state string
	must(t, f.s.ReadDB().QueryRowContext(f.ctx, `SELECT id, state FROM access_requests WHERE role_id = ?`, triage.ID).Scan(&reqID, &state))
	reason, err := f.acc.Reason(f.ctx, reqID)
	must(t, err)
	if state != access.ReqApproved || reason != "Label the cart timeout report | Command (reported by the agent): gh issue edit 42 --add-label bug" {
		t.Fatalf("request %s %q", state, reason)
	}
	if grants() != 1 {
		t.Fatalf("grants = %d, want 1", grants())
	}
}

func proxyURL(user string) *url.URL {
	u := &url.URL{Scheme: "http", Host: "127.0.0.1:18080"}
	if name, pass, ok := strings.Cut(user, ":"); ok {
		u.User = url.UserPassword(name, pass)
	} else if user != "" {
		u.User = url.User(user)
	}
	return u
}

// A named access profile is the only one a tunnel uses: no fallback to another profile, and requests are filed for it.
func TestProxyNamedRole(t *testing.T) {
	f := newFx(t)
	write := f.clientWith(http.Header{
		apienv.HeaderRole:       {"write"},
		apienv.HeaderReason:     {apienv.Encode("Label the issue")},
		apienv.HeaderInvocation: {"inv-test-invocation-role"},
	})
	// The auto-approved read profile would allow a GET, but the tunnel may only use write.
	if st, e := f.do(write, "GET", "/repos/acme/api", ""); st != 403 || e.HallPass.Code != "rule" || !strings.Contains(e.Message, "access profile write on gh does not allow GET") {
		t.Fatalf("GET as write: %d %+v", st, e)
	}
	if grants, _ := f.acc.ActiveGrantsForAgent(f.ctx, f.agentID, ""); len(grants) != 0 {
		t.Fatalf("a grant was created for another profile: %+v", grants)
	}
	st, e := f.do(write, "POST", "/repos/acme/api/issues", `{}`)
	ids := f.proxy.Filed(f.agentID, "inv-test-invocation-role")
	if st != 403 || e.HallPass.Code != "approval_pending" || len(ids) != 1 {
		t.Fatalf("POST as write: %d %+v %v", st, e, ids)
	}
	r, err := f.acc.GetRequest(f.ctx, ids[0])
	must(t, err)
	if r.RoleID != f.write.ID {
		t.Fatalf("request filed for role %s, want write", r.RoleID)
	}

	// The proxy URL's user name works the same way (tools configured by "api env --role").
	read := f.clientAs("read", nil)
	if st, _ := f.do(read, "GET", "/repos/acme/api", ""); st != 200 {
		t.Fatalf("GET as read: %d", st)
	}
	if st, e := f.do(read, "POST", "/repos/acme/api/issues", `{}`); st != 403 || e.HallPass.Code != "rule" {
		t.Fatalf("POST as read: %d %+v", st, e)
	}
	if st, e := f.do(f.clientAs("nope", nil), "GET", "/repos/acme/api", ""); st != 403 || e.HallPass.Code != "role" {
		t.Fatalf("unknown role: %d %+v", st, e)
	}

	cl := Client{ConnectionID: f.connID, AgentID: f.agentID, KeyID: f.keyID}
	a, b := net.Pipe()
	go f.proxy.Serve(f.ctx, cl, b)
	go func() {
		_, _ = io.WriteString(a, "CONNECT "+apiHost+":443 HTTP/1.1\r\nHost: "+apiHost+":443\r\nHallpass-Role: Bad_Role\r\n\r\n")
	}()
	resp, err := io.ReadAll(a)
	must(t, err)
	if !strings.HasPrefix(string(resp), "HTTP/1.1 400") {
		t.Fatalf("invalid role: %q", resp)
	}
}

// Tunnels of different agent sessions get separate grants: the hallpass-api header or the proxy URL's password names
// the session.
func TestProxyAgentSessions(t *testing.T) {
	f := newFx(t)
	a := f.clientWith(http.Header{apienv.HeaderSession: {"conv-a"}})
	b := f.clientAs(apienv.NoRole+":conv-b", nil)
	if st, _ := f.do(a, "GET", "/repos/acme/api", ""); st != 200 {
		t.Fatalf("GET a: %d", st)
	}
	ga, _ := f.acc.ActiveGrantsForAgent(f.ctx, f.agentID, "conv-a")
	gb, _ := f.acc.ActiveGrantsForAgent(f.ctx, f.agentID, "conv-b")
	if len(ga) != 1 || len(gb) != 0 {
		t.Fatalf("after a: a=%d b=%d", len(ga), len(gb))
	}
	if st, _ := f.do(b, "GET", "/repos/acme/api", ""); st != 200 {
		t.Fatalf("GET b: %d", st)
	}
	gb, _ = f.acc.ActiveGrantsForAgent(f.ctx, f.agentID, "conv-b")
	if len(gb) != 1 || gb[0].ID == ga[0].ID {
		t.Fatalf("session b reused a's grant: %+v", gb)
	}
	// Approving write for session a does not let session b write.
	res, err := f.acc.CreateRequest(f.ctx, access.CreateRequestInput{AgentID: f.agentID, KeyID: f.keyID, ServerID: f.srv.ID,
		RoleID: f.write.ID, Reason: "label issues", AgentSession: "conv-a"})
	must(t, err)
	_, err = f.acc.Decide(f.ctx, access.DecideInput{RequestID: res.Request.ID, Approve: true, Operator: f.approver, Channel: access.ChannelWeb})
	must(t, err)
	time.Sleep(candidateTTL + 100*time.Millisecond)
	if st, e := f.do(b, "POST", "/repos/acme/api/issues", `{}`); st != 403 || e.HallPass.Code != "approval_required" {
		t.Fatalf("session b wrote with a's grant: %d %+v", st, e)
	}
	if st, _ := f.do(a, "POST", "/repos/acme/api/issues", `{}`); st != 200 {
		t.Fatalf("session a write: %d", st)
	}
}
