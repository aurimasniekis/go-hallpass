package oidc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/url"
	gopath "path"
	"slices"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
)

// HP-TST-002, HP-OIDC-005: a sanitized return_to never leaves the Hallpass origin and is idempotent.
func FuzzSanitizeReturnTo(f *testing.F) {
	for _, s := range []string{"/", "/requests?id=1#x", "//evil.example", "/\\evil.example", "https://evil.example/", "/api/v1/me",
		"/auth/logout", "/api", "/%2e/x", "/./x", "/a/../b", "/\t/evil.example", "/x\r\nSet-Cookie: a", "/%0d%0a", "javascript:alert(1)",
		"/@evil.example", "/x?next=//evil.example", "/./api/v1/me", "/%2e/auth/logout", "/x/../api/v1/me", "/x/%2e%2e/api", "/" + strings.Repeat("a", 600), "/ ", "/\x7f"} {
		f.Add(s)
	}
	// Fragment tricks that path cleaning by redirect writers would turn into /api or /auth (SR-24).
	for _, s := range []string{"/#/../api/v1/me", "/x#/../../auth/oidc/corp/start?purpose=link", "/#/..", "/a//b", "/x#y/../../api"} {
		f.Add(s)
	}
	base, _ := url.Parse("https://hallpass.example/")
	f.Fuzz(func(t *testing.T, p string) {
		got := SanitizeReturnTo(p)
		if got != "/" && got != p {
			t.Fatalf("sanitizer rewrote %q to %q (must return the input or /)", p, got)
		}
		if again := SanitizeReturnTo(got); again != got {
			t.Fatalf("not idempotent: %q -> %q -> %q", p, got, again)
		}
		if !strings.HasPrefix(got, "/") || len(got) > 512 {
			t.Fatalf("not a bounded absolute path: %q", got)
		}
		for _, c := range got {
			if c < 0x20 || c == 0x7f {
				t.Fatalf("control character survived: %q", got)
			}
		}
		// Browsers treat backslash as a slash and drop tabs/newlines; neither may produce a scheme-relative URL.
		browser := strings.NewReplacer("\\", "/", "\t", "", "\n", "", "\r", "").Replace(got)
		if strings.HasPrefix(browser, "//") {
			t.Fatalf("scheme-relative after browser normalization: %q", got)
		}
		u, err := url.Parse(got)
		if err != nil {
			t.Fatalf("accepted unparsable %q: %v", got, err)
		}
		r := base.ResolveReference(u)
		if r.Scheme != base.Scheme || r.Host != base.Host || r.User != nil {
			t.Fatalf("%q resolves off-origin to %s", got, r)
		}
		// Redirect writers (net/http's Redirect) path-clean everything before "?", fragment included (SR-24).
		pre, _, _ := strings.Cut(got, "?")
		cleaned := gopath.Clean(pre)
		// Check the browser-resolved path too: dot segments ("/./api", "/%2e/auth", "/x/../api") must not reach the deny list.
		for _, path := range []string{u.Path, r.Path, cleaned} {
			if got != "/" && (path == "/api" || path == "/auth" || strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/auth/")) {
				t.Fatalf("API/auth path allowed: %q (resolves to %q)", got, r.Path)
			}
		}
	})
}

// HP-TST-002, HP-OIDC-011: the groups claim parser accepts only a string or a string array and bounds the result.
func FuzzParseGroups(f *testing.F) {
	for _, s := range []string{`["a","b"]`, `"admins"`, `""`, `null`, `[1,2]`, `{"a":1}`, `["x",null]`, `[` + strings.Repeat(`"g",`, 1200) + `"g"]`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		got := parseGroups(raw)
		if len(got) > 1000 {
			t.Fatalf("unbounded groups: %d", len(got))
		}
		var arr []string
		var one string
		switch {
		case json.Unmarshal(raw, &arr) == nil:
		case json.Unmarshal(raw, &one) == nil:
			if one == "" && got != nil {
				t.Fatalf("empty string produced groups %q", got)
			}
		default:
			if got != nil {
				t.Fatalf("non-string claim %q produced groups %q", raw, got)
			}
		}
	})
}

// HP-TST-002, HP-OIDC-005: an accepted issuer is https (or http on localhost in dev mode) without credentials, query or
// fragment.
func FuzzValidateIssuerURL(f *testing.F) {
	for _, s := range []string{"https://idp.example", "https://idp.example/realms/x", "http://localhost:8080", "http://idp.example",
		"https://user:pw@idp.example", "https://idp.example?x=1", "https://idp.example#f", "ftp://idp.example", "https://", "//idp.example"} {
		f.Add(s, false)
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, raw string, dev bool) {
		if validateIssuerURL(raw, dev) != nil {
			return
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			t.Fatalf("accepted malformed issuer %q", raw)
		}
		if u.Scheme != "https" && (!dev || u.Scheme != "http" || !isLocalhost(u.Hostname())) {
			t.Fatalf("accepted insecure issuer %q (dev=%v)", raw, dev)
		}
	})
}

// fuzzIdP is a fixed Ed25519 signing key and a JWKS key set that never refetches (no network in fuzzing).
type fuzzIdP struct {
	now    time.Time
	signer jose.Signer
	keys   *keySet
}

func newFuzzIdP(f *testing.F) *fuzzIdP {
	f.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: priv, KeyID: "k1"}}, nil)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	ks := &keySet{now: func() time.Time { return now }, minRefetch: time.Hour, fetchedAt: now,
		keys: []jose.JSONWebKey{{Key: pub, KeyID: "k1", Algorithm: string(jose.EdDSA), Use: "sig"}}}
	return &fuzzIdP{now: now, signer: signer, keys: ks}
}

func (i *fuzzIdP) sign(t testing.TB, payload []byte) string {
	t.Helper()
	jws, err := i.signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// HP-TST-002, HP-OIDC-003: whatever claims an IdP key signs, an accepted ID token satisfies every claim check
// (iss, aud, azp, exp, iat, nbf, nonce, sub), and a token whose payload was swapped after signing is rejected.
func FuzzVerifyIDTokenClaims(f *testing.F) {
	idp := newFuzzIdP(f)
	const issuer, client, nonce = "https://idp.example", "hallpass-client", "nonce-1"
	n := idp.now.Unix()
	claims := func(m map[string]any) []byte {
		base := map[string]any{"iss": issuer, "aud": client, "sub": "user-1", "exp": n + 300, "iat": n - 10, "nonce": nonce,
			"email": "A@Example.com", "groups": []string{"sre"}}
		for k, v := range m {
			if v == nil {
				delete(base, k)
			} else {
				base[k] = v
			}
		}
		b, _ := json.Marshal(base)
		return b
	}
	f.Add(claims(nil), false)
	f.Add(claims(map[string]any{"aud": []string{client, "other"}, "azp": client}), false)
	f.Add(claims(map[string]any{"aud": []string{client, "other"}}), false)
	f.Add(claims(map[string]any{"iss": "https://evil.example"}), false)
	f.Add(claims(map[string]any{"exp": n - 3600}), false)
	f.Add(claims(map[string]any{"iat": n + 3600}), false)
	f.Add(claims(map[string]any{"nbf": n + 3600}), false)
	f.Add(claims(map[string]any{"nonce": "other"}), false)
	f.Add(claims(map[string]any{"sub": ""}), false)
	f.Add(claims(map[string]any{"iat": nil}), false)
	f.Add(claims(map[string]any{"groups": "single"}), true)
	svc := &Service{opts: Options{Clock: clock.NewFake(idp.now), Skew: time.Minute}}
	p := &Provider{Issuer: issuer, ClientID: client, GroupsClaim: "groups"}
	r := &remote{keys: idp.keys}
	want := hashOf("nonce", nonce)
	f.Fuzz(func(t *testing.T, payload []byte, swap bool) {
		raw := idp.sign(t, payload)
		if swap {
			parts := strings.Split(raw, ".")
			parts[1] = base64.RawURLEncoding.EncodeToString(append(slices.Clone(payload), ' '))
			raw = strings.Join(parts, ".")
		}
		c, err := svc.verifyIDToken(context.Background(), p, r, raw, want)
		if err != nil {
			return
		}
		if swap {
			t.Fatal("token with a swapped payload verified")
		}
		var m struct {
			Iss   string          `json:"iss"`
			Aud   json.RawMessage `json:"aud"`
			AZP   string          `json:"azp"`
			Exp   json.Number     `json:"exp"`
			IAT   json.Number     `json:"iat"`
			NBF   *json.Number    `json:"nbf"`
			Nonce string          `json:"nonce"`
			Sub   string          `json:"sub"`
		}
		if err := json.Unmarshal(payload, &m); err != nil {
			t.Fatalf("accepted payload that is not a JSON object: %v", err)
		}
		var auds []string
		var one string
		if json.Unmarshal(m.Aud, &one) == nil {
			auds = []string{one}
		} else if json.Unmarshal(m.Aud, &auds) != nil {
			t.Fatalf("accepted unparsable aud %s", m.Aud)
		}
		num := func(n json.Number) float64 { v, _ := n.Float64(); return v }
		now := float64(n)
		switch {
		case m.Iss != issuer:
			t.Fatalf("wrong issuer accepted: %q", m.Iss)
		case !slices.Contains(auds, client):
			t.Fatalf("audience without the client accepted: %q", auds)
		case (len(auds) > 1 || m.AZP != "") && m.AZP != client:
			t.Fatalf("azp %q accepted for audiences %q", m.AZP, auds)
		case num(m.Exp) < now-60:
			t.Fatalf("expired token accepted: exp %s", m.Exp)
		case m.IAT == "" || num(m.IAT) == 0 || num(m.IAT) > now+60:
			t.Fatalf("missing/future iat accepted: %q", m.IAT)
		case m.NBF != nil && num(*m.NBF) > now+60:
			t.Fatalf("not-yet-valid token accepted: nbf %s", *m.NBF)
		case m.Nonce != nonce:
			t.Fatalf("nonce %q accepted", m.Nonce)
		case c.Subject == "" || len(c.Subject) > 255 || c.Subject != m.Sub:
			t.Fatalf("bad subject %q", c.Subject)
		case c.Email != strings.ToLower(strings.TrimSpace(c.Email)):
			t.Fatalf("email not normalized: %q", c.Email)
		case len(c.Groups) > 1000:
			t.Fatalf("unbounded groups %d", len(c.Groups))
		}
	})
}

// HP-TST-002, HP-OIDC-003/004: the JWKS key set verifies only payloads the IdP key actually signed, whatever the
// serialization (compact or JSON), headers or algorithm claims of the input.
func FuzzKeySetVerifySignature(f *testing.F) {
	idp := newFuzzIdP(f)
	signed := map[string]bool{}
	for _, p := range []string{`{"sub":"a"}`, `{}`, `x`} {
		signed[p] = true
		f.Add(idp.sign(f, []byte(p)))
		jws, err := idp.signer.Sign([]byte(p))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(jws.FullSerialize())
	}
	f.Add(`eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.`)
	f.Add(`eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln`)
	f.Fuzz(func(t *testing.T, raw string) {
		payload, err := idp.keys.VerifySignature(context.Background(), raw)
		if err != nil {
			return
		}
		if !signed[string(payload)] {
			t.Fatalf("forged payload verified: %q from %q", payload, raw)
		}
	})
}
