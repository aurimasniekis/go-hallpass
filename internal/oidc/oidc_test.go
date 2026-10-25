package oidc

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/keyring/keyringtest"
	"github.com/aurimasniekis/go-hallpass/internal/oidc/oidctest"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
)

var admin = audit.Actor{Type: audit.ActorOperator, ID: "opr_admin"}

func ptr[T any](v T) *T { return &v }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

type fx struct {
	t    *testing.T
	ctx  context.Context
	clk  *clock.Fake
	s    *store.Store
	auth *opauth.Service
	svc  *Service
	idp  *oidctest.IdP
	prov *Provider
	meta opauth.SessionMeta
}

func newFx(t *testing.T, mods ...func(*ProviderInput)) *fx {
	t.Helper()
	clk := clock.NewFake(time.Now())
	s := storetest.Open(t, storetest.WithClock(clk))
	kr := keyringtest.Load(t, s)
	aw := audit.NewWriter(kr)
	bus := eventbus.New()
	auth := opauth.New(s, kr, aw, bus, opauth.Options{Clock: clk, MFARequiredRoles: []string{}, HashConcurrency: 2})
	svc := New(s, kr, aw, bus, auth, Options{PublicURL: "https://hallpass.example", Clock: clk, JWKSMinRefetch: 10 * time.Second})
	idp := oidctest.New(t)
	idp.Now = clk.Now
	idp.RedirectURI = "https://hallpass.example/auth/oidc/callback"
	in := ProviderInput{Slug: ptr("corp"), DisplayName: ptr("Corp SSO"), Issuer: ptr(idp.Issuer()), ClientID: ptr(idp.ClientID),
		ClientSecret: ptr(idp.ClientSecret), CABundlePEM: ptr(idp.CAPEM()), AllowPrivateNetwork: ptr(true), Enabled: ptr(true), GroupsClaim: ptr("groups")}
	for _, m := range mods {
		m(&in)
	}
	p, err := svc.CreateProvider(context.Background(), admin, in)
	must(t, err)
	return &fx{t: t, ctx: context.Background(), clk: clk, s: s, auth: auth, svc: svc, idp: idp, prov: p, meta: opauth.SessionMeta{IP: "198.51.100.7"}}
}

// flow runs Start → IdP authorize → Callback.
func (f *fx) flow(purpose string, p *opauth.Principal) (*CallbackResult, error) {
	f.t.Helper()
	st, err := f.svc.Start(f.ctx, StartInput{Provider: f.prov.Slug, Purpose: purpose, ReturnTo: "/requests?x=1", Principal: p})
	if err != nil {
		return nil, err
	}
	q, err := f.idp.Authorize(st.RedirectURL)
	must(f.t, err)
	return f.svc.Callback(f.ctx, CallbackInput{State: q.Get("state"), Code: q.Get("code"), Error: q.Get("error"), Binding: st.Binding, Principal: p, Meta: f.meta})
}

func (f *fx) operator(email string, roles ...string) *opauth.Operator {
	f.t.Helper()
	op, err := f.auth.Create(f.ctx, admin, opauth.CreateInput{Email: email, DisplayName: email, Roles: roles, Password: "correct horse battery staple"})
	must(f.t, err)
	return op
}

func (f *fx) principal(token string) *opauth.Principal {
	f.t.Helper()
	p, err := f.auth.Authenticate(f.ctx, token)
	must(f.t, err)
	return p
}

func (f *fx) localSession(email string) *opauth.Principal {
	f.t.Helper()
	res, err := f.auth.Login(f.ctx, opauth.LoginInput{Email: email, Password: "correct horse battery staple", Meta: f.meta})
	must(f.t, err)
	return res.Principal
}

func isCode(err error, c apperr.Code) bool { return apperr.CodeOf(err) == c }

// HP-OIDC-002/003/009: code flow with PKCE, validated ID token, identity by (iss, sub), session created.
func TestLoginPreprovisioned(t *testing.T) {
	f := newFx(t)
	op := f.operator("alice@corp.example", opauth.RoleApprover)
	if _, err := f.flow(PurposeLogin, nil); !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("unlinked identity: %v", err)
	}
	must(t, f.svc.LinkIdentity(f.ctx, admin, op.ID, f.prov.ID, "user-1"))
	res, err := f.flow(PurposeLogin, nil)
	must(t, err)
	if res.ReturnTo != "/requests?x=1" || res.OperatorID != op.ID {
		t.Fatalf("%+v", res)
	}
	p := f.principal(res.SessionToken)
	if p.Method != opauth.MethodOIDC || p.Provider != "corp" || !p.HasRole(opauth.RoleApprover) || p.Limited {
		t.Fatalf("principal %+v", p)
	}
	q := f.idp.LastAuthorizeParams()
	if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("redirect_uri") != "https://hallpass.example/auth/oidc/callback" ||
		q.Get("prompt") != "" {
		t.Fatalf("authorize params %v", q)
	}
	ids, err := f.svc.Identities(f.ctx, op.ID)
	if err != nil || len(ids) != 1 || ids[0].LastLoginAt == nil {
		t.Fatalf("%+v %v", ids, err)
	}
}

// HP-OIDC-009: an email match never links or merges.
func TestNoEmailMerge(t *testing.T) {
	f := newFx(t, func(in *ProviderInput) {
		in.Provisioning = ptr(JIT)
		in.JIT = &JITRules{EmailDomains: []string{"example.com"}}
	})
	f.operator("alice@example.com", opauth.RoleAdministrator) // same email as the IdP user
	_, err := f.flow(PurposeLogin, nil)
	if !isCode(err, apperr.CodeConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	var n int
	must(t, f.s.ReadDB().QueryRowContext(f.ctx, `SELECT count(*) FROM operator_identities`).Scan(&n))
	if n != 0 {
		t.Fatal("identity linked by email")
	}
}

// HP-OIDC-010/011: JIT restrictions, no privileged role without a mapping, group sync on every login.
func TestJITAndGroupSync(t *testing.T) {
	f := newFx(t, func(in *ProviderInput) {
		in.Provisioning = ptr(JIT)
		in.JIT = &JITRules{EmailDomains: []string{"example.com"}, Groups: []string{"hallpass-users"}}
	})
	f.operator("root@corp.example", opauth.RoleAdministrator) // so role changes are not blocked by the last-admin guard
	f.idp.Set(func(i *oidctest.IdP) { i.User.Claims["groups"] = []string{"other"} })
	if _, err := f.flow(PurposeLogin, nil); !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("group restriction: %v", err)
	}
	f.idp.Set(func(i *oidctest.IdP) {
		i.User.Claims["groups"] = []string{"hallpass-users"}
		i.User.Claims["email_verified"] = false
	})
	if _, err := f.flow(PurposeLogin, nil); !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("unverified email: %v", err)
	}
	f.idp.Set(func(i *oidctest.IdP) { i.User.Claims["email_verified"] = true })
	res, err := f.flow(PurposeLogin, nil)
	must(t, err)
	p := f.principal(res.SessionToken)
	if len(p.Operator.Roles) != 0 || p.Operator.ProvisionedVia != "jit" {
		t.Fatalf("JIT user got roles %v via %s", p.Operator.Roles, p.Operator.ProvisionedVia)
	}
	_, err = f.svc.AddMapping(f.ctx, admin, f.prov.ID, "hallpass-approvers", opauth.RoleApprover, "")
	must(t, err)
	f.idp.Set(func(i *oidctest.IdP) { i.User.Claims["groups"] = []string{"hallpass-users", "hallpass-approvers"} })
	res, err = f.flow(PurposeLogin, nil)
	must(t, err)
	if p = f.principal(res.SessionToken); !p.HasRole(opauth.RoleApprover) {
		t.Fatalf("mapped role missing: %v", p.Operator.Roles)
	}
	_, err = f.auth.SetRoles(f.ctx, admin, p.Operator.ID, []string{opauth.RoleViewer})
	must(t, err)
	f.idp.Set(func(i *oidctest.IdP) { i.User.Claims["groups"] = []string{"hallpass-users"} })
	res, err = f.flow(PurposeLogin, nil)
	must(t, err)
	p = f.principal(res.SessionToken)
	if p.HasRole(opauth.RoleApprover) || !p.HasRole(opauth.RoleViewer) {
		t.Fatalf("after group removal: %v (manual viewer must stay)", p.Operator.Roles)
	}
}

// HP-OIDC-011: groups_claim reads a nested claim by dotted path (Porch sends porch.groups), while a top-level claim
// whose name contains dots still wins.
func TestGroupsClaimPath(t *testing.T) {
	f := newFx(t, func(in *ProviderInput) {
		in.GroupsClaim = ptr("porch.groups")
		in.Provisioning = ptr(JIT)
		in.JIT = &JITRules{Groups: []string{"hallpass-users"}}
	})
	f.operator("root@corp.example", opauth.RoleAdministrator)
	_, err := f.svc.AddMapping(f.ctx, admin, f.prov.ID, "hallpass-approvers", opauth.RoleApprover, "")
	must(t, err)
	f.idp.Set(func(i *oidctest.IdP) {
		i.User.Claims["porch"] = map[string]any{"v": 1, "groups": []string{"hallpass-users", "hallpass-approvers"}}
	})
	res, err := f.flow(PurposeLogin, nil)
	must(t, err)
	if p := f.principal(res.SessionToken); !p.HasRole(opauth.RoleApprover) {
		t.Fatalf("nested groups not mapped: %v", p.Operator.Roles)
	}
	f.idp.Set(func(i *oidctest.IdP) {
		i.User.Claims["porch"] = map[string]any{"v": 1, "groups": []string{"hallpass-users"}}
	})
	res, err = f.flow(PurposeLogin, nil)
	must(t, err)
	if p := f.principal(res.SessionToken); p.HasRole(opauth.RoleApprover) {
		t.Fatalf("role kept after the nested group was removed: %v", p.Operator.Roles)
	}
}

func TestClaimAt(t *testing.T) {
	all := map[string]json.RawMessage{
		"groups":                     json.RawMessage(`["top"]`),
		"https://example.com/groups": json.RawMessage(`["url"]`),
		"porch.groups":               json.RawMessage(`["dotted-name"]`),
		"porch":                      json.RawMessage(`{"groups":["nested"],"tenant":{"slug":"acme"}}`),
		"flat":                       json.RawMessage(`"x"`),
		"nul":                        json.RawMessage(`null`),
	}
	for path, want := range map[string]string{
		"groups":                     `["top"]`,
		"https://example.com/groups": `["url"]`,
		"porch.groups":               `["dotted-name"]`, // an exact top-level name wins over the path
		"porch.tenant.slug":          `"acme"`,
		"porch.missing":              ``,
		"flat.groups":                ``,
		"nul.groups":                 ``,
		"absent":                     ``,
		"":                           ``,
	} {
		if got := string(claimAt(all, path)); got != want {
			t.Errorf("claimAt(%q) = %q, want %q", path, got, want)
		}
	}
	delete(all, "porch.groups")
	if got := string(claimAt(all, "porch.groups")); got != `["nested"]` {
		t.Errorf("nested path = %q", got)
	}
}

// HP-AUTH-015: SSO sync never removes the last enabled administrator.
func TestSyncKeepsLastAdmin(t *testing.T) {
	f := newFx(t)
	op, err := f.auth.Create(f.ctx, admin, opauth.CreateInput{Email: "sso-admin@example.com", DisplayName: "SSO admin"})
	must(t, err)
	must(t, f.svc.LinkIdentity(f.ctx, admin, op.ID, f.prov.ID, "user-1"))
	_, err = f.svc.AddMapping(f.ctx, admin, f.prov.ID, "admins", opauth.RoleAdministrator, "")
	must(t, err)
	f.idp.Set(func(i *oidctest.IdP) { i.User.Claims["groups"] = []string{"admins"} })
	_, err = f.flow(PurposeLogin, nil)
	must(t, err)
	f.idp.Set(func(i *oidctest.IdP) { i.User.Claims["groups"] = []string{} })
	res, err := f.flow(PurposeLogin, nil)
	must(t, err)
	if p := f.principal(res.SessionToken); !p.HasRole(opauth.RoleAdministrator) {
		t.Fatal("last administrator demoted by SSO sync")
	}
}

// HP-OIDC-002: state is single-use, bound to the browser and expires after 10 minutes.
func TestStateSafety(t *testing.T) {
	f := newFx(t)
	op := f.operator("bob@example.com")
	must(t, f.svc.LinkIdentity(f.ctx, admin, op.ID, f.prov.ID, "user-1"))
	st, err := f.svc.Start(f.ctx, StartInput{Provider: "corp", Purpose: PurposeLogin})
	must(t, err)
	q, err := f.idp.Authorize(st.RedirectURL)
	must(t, err)
	if _, err := f.svc.Callback(f.ctx, CallbackInput{State: q.Get("state"), Code: q.Get("code"), Binding: "wrong"}); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("binding: %v", err)
	}
	if _, err := f.svc.Callback(f.ctx, CallbackInput{State: q.Get("state"), Code: q.Get("code"), Binding: st.Binding}); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("replayed state accepted: %v", err)
	}
	st, err = f.svc.Start(f.ctx, StartInput{Provider: "corp", Purpose: PurposeLogin})
	must(t, err)
	q, err = f.idp.Authorize(st.RedirectURL)
	must(t, err)
	f.clk.Advance(11 * time.Minute)
	if _, err := f.svc.Callback(f.ctx, CallbackInput{State: q.Get("state"), Code: q.Get("code"), Binding: st.Binding}); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expired state: %v", err)
	}
	if n, err := f.svc.PurgeStates(f.ctx); err != nil || n != 0 {
		t.Fatalf("purge %d %v", n, err)
	}
	if _, err := f.svc.Callback(f.ctx, CallbackInput{State: "", Code: "x"}); !errors.Is(err, ErrInvalidState) {
		t.Fatal("empty state")
	}
	// IdP error responses are rejected after consuming the state.
	st, err = f.svc.Start(f.ctx, StartInput{Provider: "corp", Purpose: PurposeLogin})
	must(t, err)
	q, err = f.idp.Authorize(st.RedirectURL)
	must(t, err)
	if _, err := f.svc.Callback(f.ctx, CallbackInput{State: q.Get("state"), Error: "access_denied", Binding: st.Binding}); !errors.Is(err, ErrLoginRejected) {
		t.Fatalf("idp error: %v", err)
	}
}

// HP-OIDC-003: signature algorithms, iss/aud/azp, time claims and nonce are enforced.
func TestIDTokenValidation(t *testing.T) {
	f := newFx(t)
	op := f.operator("carol@example.com")
	must(t, f.svc.LinkIdentity(f.ctx, admin, op.ID, f.prov.ID, "user-1"))
	for _, alg := range []string{"RS256", "ES256", "EdDSA"} {
		f.idp.Set(func(i *oidctest.IdP) { i.Alg = alg })
		if _, err := f.flow(PurposeLogin, nil); err != nil {
			t.Fatalf("%s rejected: %v", alg, err)
		}
	}
	cases := map[string]func(i *oidctest.IdP){
		"alg none":  func(i *oidctest.IdP) { i.Alg = "none" },
		"alg HS256": func(i *oidctest.IdP) { i.Alg = "HS256" },
		"wrong iss": func(i *oidctest.IdP) { i.Mutate = func(c map[string]any) { c["iss"] = "https://evil.example" } },
		"wrong aud": func(i *oidctest.IdP) { i.Mutate = func(c map[string]any) { c["aud"] = "other-client" } },
		"multi aud": func(i *oidctest.IdP) { i.Mutate = func(c map[string]any) { c["aud"] = []string{"hallpass", "other"} } },
		"azp mismatch": func(i *oidctest.IdP) {
			i.Mutate = func(c map[string]any) { c["aud"] = []string{"hallpass", "other"}; c["azp"] = "other" }
		},
		"expired": func(i *oidctest.IdP) {
			i.Mutate = func(c map[string]any) { c["exp"] = time.Now().Add(-2 * time.Minute).Unix() }
		},
		"iat in future": func(i *oidctest.IdP) {
			i.Mutate = func(c map[string]any) { c["iat"] = time.Now().Add(5 * time.Minute).Unix() }
		},
		"nbf in future": func(i *oidctest.IdP) {
			i.Mutate = func(c map[string]any) { c["nbf"] = time.Now().Add(3 * time.Minute).Unix() }
		},
		"wrong nonce":    func(i *oidctest.IdP) { i.Mutate = func(c map[string]any) { c["nonce"] = "attacker" } },
		"missing nonce":  func(i *oidctest.IdP) { i.Mutate = func(c map[string]any) { delete(c, "nonce") } },
		"missing sub":    func(i *oidctest.IdP) { i.Mutate = func(c map[string]any) { c["sub"] = "" } },
		"missing iat":    func(i *oidctest.IdP) { i.Mutate = func(c map[string]any) { delete(c, "iat") } },
		"foreign signer": func(i *oidctest.IdP) { i.Alg = "RS256" },
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			f.idp.Set(func(i *oidctest.IdP) { i.Alg, i.Mutate = "RS256", nil })
			if name == "foreign signer" {
				// Tokens signed by keys the JWKS no longer has: rotate after discovery but deny refetch.
				f.idp.Set(func(i *oidctest.IdP) { i.FailJWKS = true })
				f.idp.RotateKeys()
				f.clk.Advance(time.Minute)
				defer f.idp.Set(func(i *oidctest.IdP) { i.FailJWKS = false })
			}
			f.idp.Set(set)
			if _, err := f.flow(PurposeLogin, nil); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	f.idp.Set(func(i *oidctest.IdP) {
		i.Alg, i.Mutate = "RS256", func(c map[string]any) { c["aud"] = []string{"hallpass", "other"}; c["azp"] = "hallpass" }
	})
	f.clk.Advance(time.Minute)
	if _, err := f.flow(PurposeLogin, nil); err != nil {
		t.Fatalf("multi-aud with matching azp: %v", err)
	}
	// Expired within the 60 s skew is still accepted.
	f.idp.Set(func(i *oidctest.IdP) {
		i.Mutate = func(c map[string]any) { c["exp"] = f.clk.Now().Add(-30 * time.Second).Unix() }
	})
	if _, err := f.flow(PurposeLogin, nil); err != nil {
		t.Fatalf("within skew: %v", err)
	}
}

// HP-OIDC-004: JWKS is cached, refetched on an unknown kid (key rotation) and refetches are rate-limited.
func TestJWKSRotation(t *testing.T) {
	f := newFx(t)
	op := f.operator("dave@example.com")
	must(t, f.svc.LinkIdentity(f.ctx, admin, op.ID, f.prov.ID, "user-1"))
	_, err := f.flow(PurposeLogin, nil)
	must(t, err)
	_, err = f.flow(PurposeLogin, nil)
	must(t, err)
	if h := f.idp.JWKSHits(); h != 1 {
		t.Fatalf("JWKS not cached: %d fetches", h)
	}
	f.idp.RotateKeys()
	if _, err := f.flow(PurposeLogin, nil); err == nil {
		t.Fatal("refetch should be rate-limited within the minimum interval")
	}
	f.clk.Advance(11 * time.Second)
	if _, err := f.flow(PurposeLogin, nil); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if h := f.idp.JWKSHits(); h != 2 {
		t.Fatalf("fetches %d", h)
	}
}

// HP-OIDC-001/005/006: issuer match, https, endpoint origin, private networks, TLS verification.
func TestProviderValidation(t *testing.T) {
	f := newFx(t)
	bad := []ProviderInput{
		{Slug: ptr("x1"), DisplayName: ptr("x"), Issuer: ptr("http://idp.example"), ClientID: ptr("c")},
		{Slug: ptr("x2"), DisplayName: ptr("x"), Issuer: ptr("https://idp.example?x=1"), ClientID: ptr("c")},
		{Slug: ptr("X bad"), DisplayName: ptr("x"), Issuer: ptr("https://idp.example"), ClientID: ptr("c")},
		{Slug: ptr("x3"), DisplayName: ptr("x"), Issuer: ptr("https://idp.example"), ClientID: ptr("c"), Scopes: ptr([]string{"profile"})},
		{Slug: ptr("x4"), DisplayName: ptr("x"), Issuer: ptr("https://idp.example"), ClientID: ptr("c"), Provisioning: ptr(JIT)},
		{Slug: ptr("x5"), DisplayName: ptr("x"), Issuer: ptr("https://idp.example"), ClientID: ptr("c"), CABundlePEM: ptr("not pem")},
		{Slug: ptr("x6"), DisplayName: ptr("x"), Issuer: ptr("https://idp.example"), ClientID: ptr("c"), StepUpFallback: ptr("sms")},
	}
	for i, in := range bad {
		if _, err := f.svc.CreateProvider(f.ctx, admin, in); !isCode(err, apperr.CodeInvalid) {
			t.Errorf("case %d accepted: %v", i, err)
		}
	}
	start := func(mod func(*ProviderInput)) error {
		in := ProviderInput{Version: f.prov.Version, AllowPrivateNetwork: ptr(true), Issuer: ptr(f.idp.Issuer()), CABundlePEM: ptr(f.idp.CAPEM())}
		mod(&in)
		p, err := f.svc.UpdateProvider(f.ctx, admin, f.prov.ID, in)
		must(t, err)
		f.prov = p
		_, err = f.svc.Start(f.ctx, StartInput{Provider: "corp", Purpose: PurposeLogin})
		return err
	}
	if err := start(func(in *ProviderInput) { in.AllowPrivateNetwork = ptr(false) }); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("private network IdP allowed: %v", err)
	}
	if err := start(func(in *ProviderInput) { in.CABundlePEM = ptr("") }); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("untrusted TLS accepted: %v", err)
	}
	f.idp.Set(func(i *oidctest.IdP) { i.IssuerOverride = "https://other.example" })
	if err := start(func(*ProviderInput) {}); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("issuer mismatch accepted: %v", err)
	}
	f.idp.Set(func(i *oidctest.IdP) { i.IssuerOverride, i.EndpointBase = "", "https://login.other-site.example" })
	if err := start(func(*ProviderInput) {}); !isCode(err, apperr.CodeUnavailable) {
		t.Fatalf("cross-origin endpoint accepted: %v", err)
	}
	if err := start(func(in *ProviderInput) { in.AllowCrossOriginEndpoints = ptr(true) }); err != nil {
		t.Fatalf("explicitly allowed cross-origin endpoint: %v", err)
	}
	f.idp.Set(func(i *oidctest.IdP) { i.EndpointBase = "" })
	if err := start(func(in *ProviderInput) { in.AllowCrossOriginEndpoints = ptr(false) }); err != nil {
		t.Fatal(err)
	}
	// Dev mode allows http on localhost only.
	plain := httptest.NewServer(http.NotFoundHandler())
	defer plain.Close()
	dev := New(f.s, nil, nil, nil, nil, Options{DevMode: true})
	if err := dev.validate(&Provider{Slug: "d", DisplayName: "d", Issuer: plain.URL, ClientID: "c", Scopes: []string{"openid"}, Provisioning: Preprovisioned,
		StepUpFallback: StepUpNone}); err != nil {
		t.Fatalf("dev localhost http: %v", err)
	}
	if err := dev.validate(&Provider{Slug: "d", DisplayName: "d", Issuer: "http://idp.example", ClientID: "c", Scopes: []string{"openid"},
		Provisioning: Preprovisioned, StepUpFallback: StepUpNone}); err == nil {
		t.Fatal("dev non-localhost http allowed")
	}
}

// HP-OIDC-007: the client secret is encrypted at rest and never returned.
func TestClientSecretWriteOnly(t *testing.T) {
	f := newFx(t)
	b, _ := json.Marshal(f.prov)
	if strings.Contains(string(b), f.idp.ClientSecret) || !f.prov.HasClientSecret {
		t.Fatalf("secret exposed or missing: %s", b)
	}
	var raw []byte
	must(t, f.s.ReadDB().QueryRowContext(f.ctx, `SELECT client_secret_enc FROM oidc_providers WHERE id = ?`, f.prov.ID).Scan(&raw))
	if bytes.Contains(raw, []byte(f.idp.ClientSecret)) {
		t.Fatal("client secret stored in plaintext")
	}
	// Updating without a secret keeps it; "" removes it.
	p, err := f.svc.UpdateProvider(f.ctx, admin, f.prov.ID, ProviderInput{Version: f.prov.Version, DisplayName: ptr("Corp")})
	must(t, err)
	if !p.HasClientSecret {
		t.Fatal("secret dropped by unrelated update")
	}
	p, err = f.svc.UpdateProvider(f.ctx, admin, f.prov.ID, ProviderInput{Version: p.Version, ClientSecret: ptr("")})
	must(t, err)
	if p.HasClientSecret {
		t.Fatal("secret not removed")
	}
	if _, err := f.svc.UpdateProvider(f.ctx, admin, f.prov.ID, ProviderInput{Version: 1}); !isCode(err, apperr.CodeConflict) {
		t.Fatalf("stale version accepted: %v", err)
	}
}

// HP-OIDC-012: outages fail closed; existing sessions continue.
func TestOutage(t *testing.T) {
	f := newFx(t)
	op := f.operator("erin@example.com")
	must(t, f.svc.LinkIdentity(f.ctx, admin, op.ID, f.prov.ID, "user-1"))
	res, err := f.flow(PurposeLogin, nil)
	must(t, err)
	f.idp.Set(func(i *oidctest.IdP) { i.FailToken = true })
	if _, err := f.flow(PurposeLogin, nil); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("token outage: %v", err)
	}
	f.idp.Close()
	f.svc.forget(f.prov.ID)
	if _, err := f.svc.Start(f.ctx, StartInput{Provider: "corp", Purpose: PurposeLogin}); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("discovery outage: %v", err)
	}
	if _, err := f.auth.Authenticate(f.ctx, res.SessionToken); err != nil {
		t.Fatalf("existing session broken by outage: %v", err)
	}
	if _, err := f.auth.Login(f.ctx, opauth.LoginInput{Email: "erin@example.com", Password: "correct horse battery staple", Meta: f.meta}); err != nil {
		t.Fatalf("local login unavailable during outage: %v", err)
	}
}

// HP-OIDC-013: step-up requires a fresh auth_time (and acr when configured); TOTP fallback when unsupported.
func TestStepUp(t *testing.T) {
	f := newFx(t)
	op := f.operator("frank@example.com")
	must(t, f.svc.LinkIdentity(f.ctx, admin, op.ID, f.prov.ID, "user-1"))
	res, err := f.flow(PurposeLogin, nil)
	must(t, err)
	p := f.principal(res.SessionToken)
	if _, err := f.svc.Start(f.ctx, StartInput{Provider: "corp", Purpose: PurposeStepUp}); err == nil {
		t.Fatal("step-up without a session")
	}
	f.clk.Advance(10 * time.Minute)
	if err := f.auth.RequireRecentAuth(p, false); err == nil {
		t.Fatal("stale auth accepted")
	}
	res, err = f.flow(PurposeStepUp, p)
	must(t, err)
	if q := f.idp.LastAuthorizeParams(); q.Get("prompt") != "login" || q.Get("max_age") != "0" {
		t.Fatalf("step-up params %v", q)
	}
	p2 := f.principal(res.SessionToken)
	if p2.Provider != "corp" {
		t.Fatal("provider lost on step-up rotation")
	}
	if err := f.auth.RequireRecentAuth(p2, false); err != nil {
		t.Fatalf("after step-up: %v", err)
	}
	if _, err := f.auth.Authenticate(f.ctx, mustToken(t, res)); err != nil {
		t.Fatal(err)
	}
	// An old auth_time (no fresh login at the IdP) fails.
	f.idp.Set(func(i *oidctest.IdP) {
		i.Mutate = func(c map[string]any) { c["auth_time"] = f.clk.Now().Add(-time.Hour).Unix() }
	})
	if _, err := f.flow(PurposeStepUp, p2); !errors.Is(err, ErrStepUpFailed) {
		t.Fatalf("stale auth_time: %v", err)
	}
	f.idp.Set(func(i *oidctest.IdP) { i.Mutate, i.OmitAuthTime = nil, true })
	p3 := f.principal(mustToken(t, mustFlow(t, f, PurposeLogin, nil)))
	if _, err := f.flow(PurposeStepUp, p3); !errors.Is(err, ErrStepUpFailed) {
		t.Fatalf("missing auth_time: %v", err)
	}
	pr, err := f.svc.UpdateProvider(f.ctx, admin, f.prov.ID, ProviderInput{Version: f.prov.Version, StepUpFallback: ptr(StepUpLocalTOTP),
		ACRValues: ptr([]string{"urn:mfa"})})
	must(t, err)
	f.prov = pr
	if _, err := f.flow(PurposeStepUp, p3); !isCode(err, apperr.CodeMFARequired) {
		t.Fatalf("totp fallback: %v", err)
	}
	f.idp.Set(func(i *oidctest.IdP) {
		i.OmitAuthTime = false
		i.Mutate = func(c map[string]any) { c["acr"] = "urn:password" }
	})
	if _, err := f.flow(PurposeStepUp, p3); !errors.Is(err, ErrStepUpFailed) {
		t.Fatalf("acr mismatch: %v", err)
	}
	if q := f.idp.LastAuthorizeParams(); q.Get("acr_values") != "urn:mfa" {
		t.Fatalf("acr_values not sent: %v", q)
	}
	f.idp.Set(func(i *oidctest.IdP) { i.Mutate = func(c map[string]any) { c["acr"] = "urn:mfa" } })
	if _, err := f.flow(PurposeStepUp, p3); err != nil {
		t.Fatalf("matching acr: %v", err)
	}
}

func mustFlow(t *testing.T, f *fx, purpose string, p *opauth.Principal) *CallbackResult {
	t.Helper()
	r, err := f.flow(purpose, p)
	must(t, err)
	return r
}

func mustToken(t *testing.T, r *CallbackResult) string {
	t.Helper()
	if r.SessionToken == "" {
		t.Fatal("no session token")
	}
	return r.SessionToken
}

// HP-OIDC-014, HP-AUTH-015: SSO-only enforcement needs a completed test login and an SSO-capable administrator.
func TestTestLoginAndSSOOnly(t *testing.T) {
	f := newFx(t)
	f.operator("root@example.com", opauth.RoleAdministrator)
	adminP := f.localSession("root@example.com")
	if err := f.svc.SetLocalLoginDisabled(f.ctx, admin, true); !errors.Is(err, ErrSSOOnlyPrecondition) {
		t.Fatalf("SSO-only without test login: %v", err)
	}
	if _, err := f.svc.Start(f.ctx, StartInput{Provider: "corp", Purpose: PurposeTest}); err == nil {
		t.Fatal("test login without admin session")
	}
	_, err := f.svc.AddMapping(f.ctx, admin, f.prov.ID, "admins", opauth.RoleAdministrator, "")
	must(t, err)
	f.idp.Set(func(i *oidctest.IdP) { i.User.Claims["groups"] = []string{"admins"} })
	res, err := f.flow(PurposeTest, adminP)
	must(t, err)
	if res.SessionToken != "" || res.Test == nil || res.Test.Claims.Subject != "user-1" || len(res.Test.MappedRoles) != 1 || res.Test.LinkedOperatorID != "" {
		t.Fatalf("test result %+v", res.Test)
	}
	if p, _ := f.svc.GetProvider(f.ctx, f.prov.ID); p.TestLoginOKAt == nil {
		t.Fatal("test login not recorded")
	}
	if err := f.svc.SetLocalLoginDisabled(f.ctx, admin, true); !errors.Is(err, ErrSSOOnlyPrecondition) {
		t.Fatalf("SSO-only without an SSO admin: %v", err)
	}
	// Self-link the administrator's identity (signed in locally + at the IdP).
	res, err = f.flow(PurposeLink, adminP)
	must(t, err)
	if res.OperatorID != adminP.Operator.ID {
		t.Fatalf("%+v", res)
	}
	must(t, f.svc.SetLocalLoginDisabled(f.ctx, admin, true))
	if _, err := f.auth.Login(f.ctx, opauth.LoginInput{Email: "root@example.com", Password: "correct horse battery staple"}); !errors.Is(err, opauth.ErrLocalLoginDisabled) {
		t.Fatalf("password login while SSO-only: %v", err)
	}
	if _, err := f.svc.UpdateProvider(f.ctx, admin, f.prov.ID, ProviderInput{Version: f.prov.Version, Enabled: ptr(false)}); !isCode(err, apperr.CodePrecondition) {
		t.Fatalf("disabling the only SSO provider while SSO-only: %v", err)
	}
	if err := f.svc.DeleteProvider(f.ctx, admin, f.prov.ID); !isCode(err, apperr.CodePrecondition) {
		t.Fatalf("deleting the only SSO provider while SSO-only: %v", err)
	}
	if res, err := f.flow(PurposeLogin, nil); err != nil || res.OperatorID != adminP.Operator.ID {
		t.Fatalf("SSO admin login: %v", err)
	}
	must(t, f.svc.SetLocalLoginDisabled(f.ctx, admin, false))
}

// HP-OIDC-009: linking requires a session or an admin invitation; identities are never moved.
func TestLinking(t *testing.T) {
	f := newFx(t)
	a := f.operator("a@example.com")
	b := f.operator("b@example.com")
	if _, err := f.svc.Start(f.ctx, StartInput{Provider: "corp", Purpose: PurposeLink}); err == nil {
		t.Fatal("anonymous link")
	}
	tok, _, err := f.svc.IssueLinkInvite(f.ctx, admin, a.ID, f.prov.ID)
	must(t, err)
	st, err := f.svc.Start(f.ctx, StartInput{Provider: "corp", Purpose: PurposeLink, LinkToken: tok})
	must(t, err)
	q, err := f.idp.Authorize(st.RedirectURL)
	must(t, err)
	res, err := f.svc.Callback(f.ctx, CallbackInput{State: q.Get("state"), Code: q.Get("code"), Binding: st.Binding})
	must(t, err)
	if res.OperatorID != a.ID {
		t.Fatalf("%+v", res)
	}
	if _, err := f.svc.Start(f.ctx, StartInput{Provider: "corp", Purpose: PurposeLink, LinkToken: tok}); err == nil {
		t.Fatal("link invitation reused")
	}
	pb := f.localSession("b@example.com")
	if _, err := f.flow(PurposeLink, pb); !isCode(err, apperr.CodeConflict) {
		t.Fatalf("identity moved to another operator: %v", err)
	}
	if err := f.svc.LinkIdentity(f.ctx, admin, b.ID, f.prov.ID, "user-1"); !isCode(err, apperr.CodeConflict) {
		t.Fatalf("admin link moved identity: %v", err)
	}
	must(t, f.svc.UnlinkIdentity(f.ctx, admin, a.ID, f.prov.Issuer, "user-1"))
	if _, err := f.flow(PurposeLogin, nil); !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("unlinked identity still logs in: %v", err)
	}
}

// HP-OIDC-005: post-login return paths are relative and allowlisted.
func TestSanitizeReturnTo(t *testing.T) {
	for in, want := range map[string]string{
		"/requests?x=1": "/requests?x=1", "": "/", "https://evil.example/": "/", "//evil.example": "/", "/\\evil": "/", "/api/v1/x": "/",
		"/auth/oidc/callback": "/", "javascript:alert(1)": "/", "/ok\r\nSet-Cookie: x": "/", "/sessions/ses_1#t=3": "/sessions/ses_1#t=3",
	} {
		if got := SanitizeReturnTo(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

// HP-OIDC-015: RP-initiated logout is optional and carries no id_token_hint.
func TestLogoutURL(t *testing.T) {
	f := newFx(t)
	if u, err := f.svc.LogoutURL(f.ctx, "corp", "/"); err != nil || u != "" {
		t.Fatalf("disabled: %q %v", u, err)
	}
	p, err := f.svc.UpdateProvider(f.ctx, admin, f.prov.ID, ProviderInput{Version: f.prov.Version, EndSessionEnabled: ptr(true)})
	must(t, err)
	f.prov = p
	u, err := f.svc.LogoutURL(f.ctx, "corp", "/login")
	must(t, err)
	if !strings.HasPrefix(u, f.idp.Issuer()+"/logout?") || strings.Contains(u, "id_token_hint") || !strings.Contains(u, "client_id=hallpass") {
		t.Fatalf("logout url %q", u)
	}
	pp, err := f.svc.EnabledProviders(f.ctx)
	if err != nil || len(pp) != 1 || pp[0].Slug != "corp" {
		t.Fatalf("%+v %v", pp, err)
	}
}

// Disabled operators and disabled providers cannot sign in.
func TestDisabled(t *testing.T) {
	f := newFx(t)
	f.operator("root@corp.example", opauth.RoleAdministrator)
	op := f.operator("gail@example.com")
	must(t, f.svc.LinkIdentity(f.ctx, admin, op.ID, f.prov.ID, "user-1"))
	_, err := f.auth.SetEnabled(f.ctx, admin, op.ID, false)
	must(t, err)
	if _, err := f.flow(PurposeLogin, nil); !errors.Is(err, ErrLoginRejected) {
		t.Fatalf("disabled operator: %v", err)
	}
	p, err := f.svc.UpdateProvider(f.ctx, admin, f.prov.ID, ProviderInput{Version: f.prov.Version, Enabled: ptr(false)})
	must(t, err)
	f.prov = p
	if _, err := f.svc.Start(f.ctx, StartInput{Provider: "corp", Purpose: PurposeLogin}); !isCode(err, apperr.CodeNotFound) {
		t.Fatalf("disabled provider: %v", err)
	}
	var n int
	must(t, f.s.ReadDB().QueryRowContext(f.ctx, `SELECT count(*) FROM audit_events WHERE action = 'operator.login.failed'`).Scan(&n))
	if n == 0 {
		t.Fatal("denied SSO login not audited")
	}
}

// HP-OIDC-008: after an SSO login no access, refresh or ID token is stored anywhere: not in any table and not in the
// database or WAL files on disk.
func TestTokensNotPersisted(t *testing.T) {
	f := newFx(t)
	op := f.operator("alice@corp.example", opauth.RoleApprover)
	must(t, f.svc.LinkIdentity(f.ctx, admin, op.ID, f.prov.ID, "user-1"))
	if _, err := f.flow(PurposeLogin, nil); err != nil {
		t.Fatal(err)
	}
	access, refresh, id := f.idp.LastTokens()
	if access == "" || refresh == "" || id == "" {
		t.Fatal("mock IdP issued no tokens")
	}
	// The ID token's signature part is unique to this token; its claims segment could legitimately overlap stored
	// claims (subject, issuer), so search for the whole token and the signature.
	sig := id[strings.LastIndex(id, ".")+1:]
	needles := map[string]string{"access token": access, "refresh token": refresh, "id token": id, "id token signature": sig}
	names, err := queryStrings(f.ctx, f.s.ReadDB(), `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	must(t, err)
	var found []string
	for _, table := range names {
		hits, err := tableContains(f.ctx, f.s.ReadDB(), table, needles)
		must(t, err)
		found = append(found, hits...)
	}
	if len(found) > 0 {
		t.Fatalf("tokens stored: %v", found)
	}
	for _, name := range []string{store.DBFile, store.DBFile + "-wal"} {
		raw, err := os.ReadFile(f.s.Path(name))
		if err != nil {
			continue
		}
		for what, needle := range needles {
			if bytes.Contains(raw, []byte(needle)) {
				t.Fatalf("%s found in %s on disk", what, name)
			}
		}
	}
}

func queryStrings(ctx context.Context, d *sql.DB, q string) ([]string, error) {
	rows, err := d.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// tableContains reports "<what> in <table>.<column>" for every text or blob cell that contains one of the needles.
func tableContains(ctx context.Context, d *sql.DB, table string, needles map[string]string) ([]string, error) {
	rows, err := d.QueryContext(ctx, `SELECT * FROM "`+table+`"`) //nolint:gosec // table names come from sqlite_master
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var found []string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		for i, v := range vals {
			var s string
			switch x := v.(type) {
			case string:
				s = x
			case []byte:
				s = string(x)
			}
			for what, needle := range needles {
				if s != "" && strings.Contains(s, needle) {
					found = append(found, what+" in "+table+"."+cols[i])
				}
			}
		}
	}
	return found, rows.Err()
}

// The sign-in page can go straight to one enabled provider; a disabled, renamed or deleted provider is handled.
func TestDirectProvider(t *testing.T) {
	f := newFx(t)
	direct := func() string {
		t.Helper()
		slug, err := f.svc.DirectProvider(f.ctx)
		must(t, err)
		return slug
	}
	if got := direct(); got != "" {
		t.Fatalf("direct provider before any setting: %q", got)
	}
	if err := f.svc.SetDirectProvider(f.ctx, admin, "nope"); !isCode(err, apperr.CodeInvalid) {
		t.Fatalf("unknown provider: %v", err)
	}
	must(t, f.svc.SetDirectProvider(f.ctx, admin, "corp"))
	if got := direct(); got != "corp" {
		t.Fatalf("direct provider = %q, want corp", got)
	}
	// Stored by ID: a renamed provider stays the direct one.
	p, err := f.svc.UpdateProvider(f.ctx, admin, f.prov.ID, ProviderInput{Version: f.prov.Version, Slug: ptr("corp2")})
	must(t, err)
	if got := direct(); got != "corp2" {
		t.Fatalf("after rename: %q, want corp2", got)
	}
	// A disabled provider is not used, and cannot be chosen.
	p, err = f.svc.UpdateProvider(f.ctx, admin, p.ID, ProviderInput{Version: p.Version, Enabled: ptr(false)})
	must(t, err)
	if got := direct(); got != "" {
		t.Fatalf("disabled provider still direct: %q", got)
	}
	if err := f.svc.SetDirectProvider(f.ctx, admin, "corp2"); !isCode(err, apperr.CodeInvalid) {
		t.Fatalf("choosing a disabled provider: %v", err)
	}
	must(t, f.svc.DeleteProvider(f.ctx, admin, p.ID))
	if got := direct(); got != "" {
		t.Fatalf("deleted provider still direct: %q", got)
	}
	must(t, f.svc.SetDirectProvider(f.ctx, admin, ""))
}
