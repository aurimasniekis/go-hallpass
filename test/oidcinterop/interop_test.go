//go:build oidcinterop

package oidcinterop

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"text/template"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/aurimasniekis/go-hallpass/internal/opauth"
)

// idpUser is a test account at the IdP. Passwords are generated per run.
type idpUser struct {
	ID       string // IdP user ID (Keycloak user id, Dex static userID)
	Login    string // what is typed into the login form
	Password string
	Hash     string // bcrypt hash (Dex)
	Subject  string // expected ID token "sub"
}

// idp describes one provider under test.
type idp struct {
	Name          string
	Slug          string
	Issuer        string
	ClientID      string
	ClientSecret  string
	UsernameField string // login form field for the username
	Users         map[string]*idpUser
	// Scopes overrides the provider's default scopes (Dex sends the groups claim only for the "groups" scope).
	Scopes []string
	// LogoutStrict: RP-initiated logout without id_token_hint must redirect to post_logout_redirect_uri.
	LogoutStrict bool
}

type tmplData struct {
	*idp
	RedirectURI   string
	PostLogoutURI string
}

func render(t *testing.T, name string, data any) []byte {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("testdata", name))
	must(t, err)
	tm, err := template.New(name).Option("missingkey=error").Funcs(template.FuncMap{"json": func(v any) (string, error) {
		b, err := json.Marshal(v)
		return string(b), err
	}}).Parse(string(src))
	must(t, err)
	var buf bytes.Buffer
	must(t, tm.Execute(&buf, data))
	return buf.Bytes()
}

func newUsers(t *testing.T) map[string]*idpUser {
	t.Helper()
	users := map[string]*idpUser{}
	for _, name := range []string{"alice", "bob", "mallory"} {
		users[name] = &idpUser{ID: randomUUID(t), Login: name, Password: "Pw-" + randomHex(t, 12)}
	}
	return users
}

// TestKeycloak runs the interop scenario against Keycloak (start-dev, realm imported at startup).
func TestKeycloak(t *testing.T) {
	requireDocker(t)
	hp := startHallpass(t)
	runScenario(t, hp, startKeycloak(t, hp))
}

// TestDex runs the interop scenario against Dex with the static password connector and auth sessions enabled.
func TestDex(t *testing.T) {
	requireDocker(t)
	hp := startHallpass(t)
	runScenario(t, hp, startDex(t, hp))
}

// startKeycloak starts Keycloak with a realm whose client registers hp's exact redirect and post-logout URIs.
func startKeycloak(t *testing.T, hp *hallpass) *idp {
	t.Helper()
	p := &idp{Name: "keycloak", Slug: "keycloak", ClientID: "hallpass", ClientSecret: randomHex(t, 24), UsernameField: "username",
		Users: newUsers(t), LogoutStrict: true}
	for _, u := range p.Users {
		u.Subject = u.ID // Keycloak's sub is the user id
	}
	realm := render(t, "keycloak-realm.json.tmpl", tmplData{idp: p, RedirectURI: hp.RedirectURI(), PostLogoutURI: hp.PostLogoutURI()})
	c := startContainer(t, imageRef("HALLPASS_KEYCLOAK_IMAGE", keycloakImage), 8080, 0, nil,
		[]file{{Dir: "/opt/keycloak/data", Name: "import/hallpass-realm.json", Data: realm}}, "start-dev", "--import-realm")
	// start-dev derives the issuer from the request host, so it is the URL HallPass and the browser both use.
	p.Issuer = "http://localhost:" + strconv.Itoa(c.Port) + "/realms/hallpass"
	waitHTTP(t, p.Issuer+"/.well-known/openid-configuration", 4*time.Minute)
	return p
}

// startDex starts Dex (static clients and passwords, sessions enabled) on a port fixed in advance: the issuer in its
// configuration must equal the URL clients use.
func startDex(t *testing.T, hp *hallpass) *idp {
	t.Helper()
	port := freePort(t)
	p := &idp{Name: "dex", Slug: "dex", ClientID: "hallpass", ClientSecret: randomHex(t, 24), UsernameField: "login", Users: newUsers(t),
		Issuer: "http://localhost:" + strconv.Itoa(port) + "/dex", Scopes: []string{"openid", "profile", "email", "groups"}}
	for _, u := range p.Users {
		h, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
		must(t, err)
		u.Hash = string(h)
		u.Login = u.Login + "@interop.example" // the password DB logs in by email
		u.Subject = dexSubject(u.ID, "local")
	}
	cfg := render(t, "dex-config.yaml.tmpl", tmplData{idp: p, RedirectURI: hp.RedirectURI(), PostLogoutURI: hp.PostLogoutURI()})
	startContainer(t, imageRef("HALLPASS_DEX_IMAGE", dexImage), 5556, port, []string{"DEX_SESSIONS_ENABLED=true"},
		[]file{{Dir: "/etc/dex", Name: "hallpass.yaml", Data: cfg}}, "dex", "serve", "/etc/dex/hallpass.yaml")
	waitHTTP(t, p.Issuer+"/.well-known/openid-configuration", 2*time.Minute)
	return p
}

// dexSubject is Dex's "sub": base64url(protobuf IDTokenSubject{user_id=1, conn_id=2}).
func dexSubject(userID, connID string) string {
	var b []byte
	b = append(b, 0x0a, byte(len(userID)))
	b = append(b, userID...)
	b = append(b, 0x12, byte(len(connID)))
	b = append(b, connID...)
	return base64.RawURLEncoding.EncodeToString(b)
}

// discovery fetches the provider's discovery document as the test sees it.
func discovery(t *testing.T, issuer string) map[string]any {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	must(t, err)
	res, err := http.DefaultClient.Do(req)
	must(t, err)
	defer res.Body.Close()
	var doc map[string]any
	must(t, json.NewDecoder(res.Body).Decode(&doc))
	return doc
}

// login starts an SSO flow at HallPass, fills in the IdP's login form when it is shown and returns the landing page
// and whether the IdP asked for credentials.
func (p *idp) login(t *testing.T, b *browser, startPath string, u *idpUser) (landing string, prompted bool) {
	t.Helper()
	b.resetHops()
	pg := b.navigate(http.MethodGet, startPath, nil)
	if pg.Landing != "" {
		return pg.Landing, false
	}
	f, ok := pg.loginForm()
	if !ok {
		t.Fatalf("%s: expected the IdP login form at %s (status %d): %s", p.Name, pg.URL.Redacted(), pg.Status, snippet(pg.Body))
	}
	pg = b.submit(pg, f, map[string]string{p.UsernameField: u.Login, "password": u.Password})
	if pg.Landing == "" {
		t.Fatalf("%s: login did not return to HallPass; ended at %s (status %d): %s", p.Name, pg.URL.Redacted(), pg.Status, snippet(pg.Body))
	}
	return pg.Landing, true
}

func runScenario(t *testing.T, hp *hallpass, p *idp) {
	doc := discovery(t, p.Issuer)
	if doc["issuer"] != p.Issuer {
		t.Fatalf("discovery issuer %v, want %s", doc["issuer"], p.Issuer)
	}
	endSession, _ := doc["end_session_endpoint"].(string)
	t.Logf("%s issuer %s; end_session_endpoint %q; claims_supported %v", p.Name, p.Issuer, endSession, doc["claims_supported"])

	prov := hp.createProvider(p.Slug, p.Issuer, p.ClientID, p.ClientSecret, p.Scopes)
	_, err := hp.A.OIDC.AddMapping(hp.ctx, sysActor, prov.ID, "hallpass-approvers", opauth.RoleApprover, "")
	must(t, err)
	alice := hp.operator("alice@hallpass.example", opauth.RoleViewer)
	must(t, hp.A.OIDC.LinkIdentity(hp.ctx, sysActor, alice.ID, prov.ID, p.Users["alice"].Subject))
	bob := hp.operator("bob@hallpass.example")
	start := "/auth/oidc/" + p.Slug + "/start"

	// HP-OIDC-010: an unknown identity is refused in preprovisioned mode, even with a group that maps to a role.
	t.Run("unknown identity refused", func(t *testing.T) {
		b := newBrowser(t, hp.Base)
		before := hp.countAudit("operator.login.failed", "denied")
		landing, prompted := p.login(t, b, start, p.Users["mallory"])
		if !prompted || landing != "/login?sso_error=forbidden" {
			t.Fatalf("landing %q (prompted %v), want /login?sso_error=forbidden", landing, prompted)
		}
		if _, status := b.me(); status != 401 {
			t.Fatalf("unprovisioned identity got a session (me %d)", status)
		}
		if b.cookie("hp_session") != "" {
			t.Fatal("session cookie set for an unprovisioned identity")
		}
		if hp.countAudit("operator.login.failed", "denied") != before+1 {
			t.Fatal("denied SSO login not audited")
		}
		ops, err := hp.A.Auth.List(hp.ctx)
		must(t, err)
		for _, op := range ops {
			if strings.HasPrefix(op.Email, "mallory") {
				t.Fatal("preprovisioned mode created an operator")
			}
		}
	})

	aliceBrowser := newBrowser(t, hp.Base)
	var firstAuth time.Time

	// HP-OIDC-002/003/009/011: code flow + PKCE against the real IdP, identity by (iss, sub), groups claim → role.
	t.Run("linked identity login with group mapping", func(t *testing.T) {
		b := aliceBrowser
		landing, prompted := p.login(t, b, start+"?return_to=/requests", p.Users["alice"])
		if !prompted || landing != "/requests" {
			t.Fatalf("landing %q (prompted %v), want /requests", landing, prompted)
		}
		q := b.hop(endpoint(t, doc, "authorization_endpoint")).Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") == "" || q.Get("state") == "" ||
			q.Get("redirect_uri") != hp.RedirectURI() || q.Get("prompt") != "" || q.Get("response_type") != "code" {
			t.Fatalf("authorize parameters %v", q)
		}
		m, status := b.me()
		if status != 200 {
			t.Fatalf("me after login: %d", status)
		}
		if m.Operator.ID != alice.ID || m.Session.Method != opauth.MethodOIDC {
			t.Fatalf("session %+v", m)
		}
		if !slices.Contains(m.Operator.Roles, opauth.RoleApprover) || !slices.Contains(m.Operator.Roles, opauth.RoleViewer) {
			t.Fatalf("roles %v, want approver (group mapping) and viewer (manual)", m.Operator.Roles)
		}
		ssoApprover := slices.ContainsFunc(m.Operator.Assignments, func(a struct {
			Role   string `json:"role"`
			Source string `json:"source"`
		}) bool {
			return a.Role == opauth.RoleApprover && a.Source == "sso"
		})
		if !ssoApprover {
			t.Fatalf("approver not sourced from SSO: %+v", m.Operator.Assignments)
		}
		ids, err := hp.A.OIDC.Identities(hp.ctx, alice.ID)
		must(t, err)
		if len(ids) != 1 || ids[0].Issuer != p.Issuer || ids[0].Subject != p.Users["alice"].Subject || ids[0].LastLoginAt == nil {
			t.Fatalf("identity %+v", ids)
		}
		firstAuth = m.Session.AuthAt
	})

	// HP-OIDC-009: an admin link invitation links the identity at the IdP; a group without a mapping grants nothing.
	t.Run("link invitation then login", func(t *testing.T) {
		tok, _, err := hp.A.OIDC.IssueLinkInvite(hp.ctx, sysActor, bob.ID, prov.ID)
		must(t, err)
		b := newBrowser(t, hp.Base)
		landing, prompted := p.login(t, b, start+"?purpose=link&link_token="+url.QueryEscape(tok), p.Users["bob"])
		if !prompted || landing != "/" {
			t.Fatalf("link landing %q (prompted %v)", landing, prompted)
		}
		if q := b.hop(endpoint(t, doc, "authorization_endpoint")).Query(); q.Get("prompt") != "login" || q.Get("max_age") != "0" {
			t.Fatalf("link flow must force a fresh IdP login: %v", q)
		}
		ids, err := hp.A.OIDC.Identities(hp.ctx, bob.ID)
		must(t, err)
		if len(ids) != 1 || ids[0].Subject != p.Users["bob"].Subject || ids[0].LinkedVia != "admin" {
			t.Fatalf("bob identity %+v (expected sub %s)", ids, p.Users["bob"].Subject)
		}
		landing, _ = p.login(t, b, start, p.Users["bob"])
		if landing != "/" {
			t.Fatalf("bob login landing %q", landing)
		}
		m, status := b.me()
		if status != 200 || m.Operator.ID != bob.ID || len(m.Operator.Roles) != 0 {
			t.Fatalf("bob me %d %+v (an unmapped group must grant no role)", status, m)
		}
	})

	// IdP-side SSO: a second login in the same browser without prompt does not ask for credentials. This shows that
	// the re-prompt in the step-up below is caused by prompt=login&max_age=0, not by a missing IdP session.
	t.Run("idp session reused without prompt", func(t *testing.T) {
		landing, prompted := p.login(t, aliceBrowser, start+"?return_to=/again", p.Users["alice"])
		if landing != "/again" {
			t.Fatalf("landing %q", landing)
		}
		if prompted {
			t.Fatalf("%s asked for credentials again without prompt=login: no IdP SSO session, so the step-up re-prompt below would prove nothing", p.Name)
		}
	})

	// HP-OIDC-013: step-up sends prompt=login&max_age=0, the IdP re-authenticates, auth_time is fresh, the session's
	// recent-auth time moves forward.
	t.Run("step-up", func(t *testing.T) {
		b := aliceBrowser
		before, status := b.me()
		if status != 200 {
			t.Fatalf("me: %d", status)
		}
		time.Sleep(1100 * time.Millisecond) // auth_time has one-second resolution
		landing, prompted := p.login(t, b, start+"?purpose=stepup&return_to=/settings", p.Users["alice"])
		if landing != "/settings" {
			t.Fatalf("step-up landing %q", landing)
		}
		if !prompted {
			t.Fatal("the IdP did not ask for credentials on step-up (prompt=login&max_age=0 ignored)")
		}
		q := b.hop(endpoint(t, doc, "authorization_endpoint")).Query()
		if q.Get("prompt") != "login" || q.Get("max_age") != "0" {
			t.Fatalf("step-up authorize parameters %v", q)
		}
		after, status := b.me()
		if status != 200 || after.Operator.ID != alice.ID || after.Session.Method != opauth.MethodOIDC {
			t.Fatalf("after step-up: %d %+v", status, after)
		}
		if !after.Session.AuthAt.After(before.Session.AuthAt) || !after.Session.AuthAt.After(firstAuth) {
			t.Fatalf("auth_at not advanced: before %s after %s", before.Session.AuthAt, after.Session.AuthAt)
		}
		pr, err := hp.A.Auth.Authenticate(hp.ctx, b.cookie("hp_session"))
		must(t, err)
		must(t, hp.A.Auth.RequireRecentAuth(pr, false))
	})

	// HP-OIDC-013: HallPass compares the IdP's auth_time with the step-up start. Shifting HallPass's clock 2 minutes
	// ahead makes the IdP's honest, fresh auth_time older than start−60 s, which must be refused.
	t.Run("step-up with stale auth_time refused", func(t *testing.T) {
		b := aliceBrowser
		before, status := b.me()
		if status != 200 {
			t.Fatalf("me: %d", status)
		}
		hp.clk.Shift(2 * time.Minute)
		defer hp.clk.Shift(0)
		mark := hp.logs.Len()
		landing, _ := p.login(t, b, start+"?purpose=stepup&return_to=/settings", p.Users["alice"])
		if landing != "/login?sso_error=forbidden" {
			t.Fatalf("stale auth_time accepted: landing %q", landing)
		}
		// The refusal must come from the auth_time check, not from a rejected code exchange or ID token.
		for _, other := range []string{"code exchange rejected", "id token rejected", "identity provider returned an error", "token endpoint unavailable"} {
			if strings.Contains(hp.logs.Since(mark), other) {
				t.Fatalf("step-up failed for another reason (%s):\n%s", other, hp.logs.Since(mark))
			}
		}
		hp.clk.Shift(0)
		after, status := b.me()
		if status != 200 || after.Session.ID != before.Session.ID || !after.Session.AuthAt.Equal(before.Session.AuthAt) {
			t.Fatalf("refused step-up changed the session: %d %+v → %+v", status, before.Session, after.Session)
		}
	})

	// HP-OIDC-015: logout revokes the HallPass session and offers the provider's end_session_endpoint (no id_token_hint).
	t.Run("logout", func(t *testing.T) {
		b := aliceBrowser
		if _, status := b.me(); status != 200 {
			t.Fatalf("me: %d", status)
		}
		status, body := b.api("POST", "/api/v1/auth/logout")
		if status != 200 {
			t.Fatalf("logout: %d %s", status, body)
		}
		var out struct {
			URL *string `json:"provider_logout_url"`
		}
		must(t, json.Unmarshal(body, &out))
		if _, status := b.me(); status != 401 {
			t.Fatalf("session alive after logout (me %d)", status)
		}
		if endSession == "" {
			if out.URL != nil {
				t.Fatalf("logout URL %q without an advertised end_session_endpoint", *out.URL)
			}
			t.Logf("%s advertises no end_session_endpoint; no provider logout offered", p.Name)
			return
		}
		if out.URL == nil {
			t.Fatalf("no provider_logout_url although %s advertises %s", p.Name, endSession)
		}
		lu, err := url.Parse(*out.URL)
		must(t, err)
		q := lu.Query()
		if !strings.HasPrefix(*out.URL, endSession+"?") || q.Get("client_id") != p.ClientID || q.Get("post_logout_redirect_uri") != hp.PostLogoutURI() ||
			q.Has("id_token_hint") {
			t.Fatalf("provider logout URL %q", *out.URL)
		}
		pg := b.navigate(http.MethodGet, *out.URL, nil)
		if forms := parseForms(pg.Body); pg.Landing == "" && pg.Status == 200 && len(forms) > 0 {
			// Without id_token_hint the provider asks the user to confirm.
			pg = b.submit(pg, &forms[0], nil)
		}
		if pg.Landing != "/login" {
			msg := "got " + pg.URL.Redacted() + " status " + strconv.Itoa(pg.Status) + ": " + snippet(pg.Body)
			if p.LogoutStrict {
				t.Fatalf("%s RP-initiated logout did not redirect to post_logout_redirect_uri; %s", p.Name, msg)
			}
			t.Logf("%s RP-initiated logout did not redirect to post_logout_redirect_uri (known limitation without id_token_hint): %s", p.Name, msg)
		}
		// The IdP session is gone: the next login asks for credentials again.
		if _, prompted := p.login(t, b, start, p.Users["alice"]); !prompted {
			t.Fatalf("%s session survived RP-initiated logout", p.Name)
		}
	})
}

func endpoint(t *testing.T, doc map[string]any, name string) string {
	t.Helper()
	s, _ := doc[name].(string)
	if s == "" {
		t.Fatalf("discovery has no %s", name)
	}
	return s
}
