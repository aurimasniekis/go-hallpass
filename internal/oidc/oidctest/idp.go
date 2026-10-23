// Package oidctest is an in-process OpenID Connect provider for tests: discovery, JWKS with key rotation,
// authorization with PKCE, a token endpoint, and knobs for malformed or malicious tokens.
package oidctest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// User is who logs in at the IdP.
type User struct {
	Subject string
	Claims  map[string]any // extra claims (email, email_verified, groups, name, auth_time, acr, …)
}

// IdP is a test OpenID provider.
type IdP struct {
	t   testing.TB
	srv *httptest.Server

	ClientID     string
	ClientSecret string
	// RedirectURI, when set, is the only accepted redirect_uri (exact match, as a real IdP's client registration).
	RedirectURI string

	mu sync.Mutex
	// User is the user the authorize endpoint logs in.
	User User
	// Alg selects the signing algorithm: RS256 (default), ES256, EdDSA, HS256 (signed with the client secret: an
	// alg-confusion attack) or none.
	Alg string
	// Mutate edits the ID token claims before signing (wrong iss/aud/nonce, expired, …).
	Mutate func(claims map[string]any)
	// IssuerOverride makes discovery advertise a different issuer.
	IssuerOverride string
	// EndpointBase overrides the advertised endpoint base URL (cross-origin endpoint tests).
	EndpointBase string
	// FailDiscovery, FailJWKS and FailToken simulate an outage (HTTP 503).
	FailDiscovery, FailJWKS, FailToken bool
	// OmitAuthTime drops auth_time from tokens.
	OmitAuthTime bool
	// Now is the IdP clock.
	Now func() time.Time

	keys       []signingKey
	codes      map[string]codeGrant
	jwksHits   int
	tokenHits  int
	lastParams url.Values
}

type signingKey struct {
	kid  string
	alg  jose.SignatureAlgorithm
	priv any
}

type codeGrant struct {
	challenge, nonce, redirect string
	user                       User
	authTime                   time.Time
}

// New starts a TLS IdP on 127.0.0.1 with one RSA, one ECDSA and one Ed25519 key.
func New(t testing.TB) *IdP {
	t.Helper()
	idp := &IdP{t: t, ClientID: "hallpass", ClientSecret: "test-client-secret", Alg: "RS256", codes: map[string]codeGrant{}, Now: time.Now,
		User: User{Subject: "user-1", Claims: map[string]any{"email": "alice@example.com", "email_verified": true, "name": "Alice"}}}
	idp.RotateKeys()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", idp.discovery)
	mux.HandleFunc("/jwks", idp.jwks)
	mux.HandleFunc("/authorize", idp.authorize)
	mux.HandleFunc("/token", idp.token)
	mux.HandleFunc("/logout", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	idp.srv = httptest.NewTLSServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

// Issuer is the IdP's issuer URL.
func (i *IdP) Issuer() string { return i.srv.URL }

// CAPEM returns the IdP's TLS certificate as PEM (for the provider's ca_bundle_pem).
func (i *IdP) CAPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.srv.Certificate().Raw}))
}

// Close stops the IdP (outage).
func (i *IdP) Close() { i.srv.Close() }

// Set runs fn with the IdP locked (to change knobs safely).
func (i *IdP) Set(fn func(*IdP)) {
	i.mu.Lock()
	defer i.mu.Unlock()
	fn(i)
}

// JWKSHits returns how often the JWKS endpoint was fetched.
func (i *IdP) JWKSHits() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.jwksHits
}

// LastAuthorizeParams returns the query of the last authorization request.
func (i *IdP) LastAuthorizeParams() url.Values {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.lastParams
}

// RotateKeys replaces every signing key with fresh ones (new key IDs).
func (i *IdP) RotateKeys() {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		i.t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		i.t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		i.t.Fatal(err)
	}
	suffix := fmt.Sprint(time.Now().UnixNano())
	i.mu.Lock()
	i.keys = []signingKey{{"rsa-" + suffix, jose.RS256, rsaKey}, {"ec-" + suffix, jose.ES256, ecKey}, {"ed-" + suffix, jose.EdDSA, edKey}}
	i.mu.Unlock()
}

func (i *IdP) base() string {
	if i.EndpointBase != "" {
		return i.EndpointBase
	}
	return i.srv.URL
}

func (i *IdP) discovery(w http.ResponseWriter, _ *http.Request) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.FailDiscovery {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	iss := i.srv.URL
	if i.IssuerOverride != "" {
		iss = i.IssuerOverride
	}
	b := i.base()
	writeJSON(w, map[string]any{"issuer": iss, "authorization_endpoint": b + "/authorize", "token_endpoint": b + "/token", "jwks_uri": b + "/jwks",
		"end_session_endpoint": b + "/logout", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256", "ES256", "EdDSA"}, "code_challenge_methods_supported": []string{"S256"}})
}

func (i *IdP) jwks(w http.ResponseWriter, _ *http.Request) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.jwksHits++
	if i.FailJWKS {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	var set jose.JSONWebKeySet
	for _, k := range i.keys {
		var pub any
		switch p := k.priv.(type) {
		case *rsa.PrivateKey:
			pub = &p.PublicKey
		case *ecdsa.PrivateKey:
			pub = &p.PublicKey
		case ed25519.PrivateKey:
			pub = p.Public()
		}
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: pub, KeyID: k.kid, Algorithm: string(k.alg), Use: "sig"})
	}
	writeJSON(w, set)
}

// authorize logs User in immediately and redirects with a code (the test reads Location).
func (i *IdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	i.mu.Lock()
	defer i.mu.Unlock()
	i.lastParams = q
	if (i.RedirectURI != "" && q.Get("redirect_uri") != i.RedirectURI) || q.Get("client_id") != i.ClientID || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	code := randomString()
	i.codes[code] = codeGrant{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), redirect: q.Get("redirect_uri"), user: i.User, authTime: i.Now()}
	u, _ := url.Parse(q.Get("redirect_uri"))
	rq := u.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound) //nolint:gosec // G710: test IdP redirects to the client's registered redirect_uri by design
}

func (i *IdP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.tokenHits++
	if i.FailToken {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != i.ClientID || secret != i.ClientSecret {
		tokenError(w, "invalid_client")
		return
	}
	g, found := i.codes[r.PostForm.Get("code")]
	delete(i.codes, r.PostForm.Get("code"))
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !found || r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("redirect_uri") != g.redirect ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		tokenError(w, "invalid_grant")
		return
	}
	now := i.Now()
	claims := map[string]any{"iss": i.srv.URL, "sub": g.user.Subject, "aud": i.ClientID, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"nonce": g.nonce, "auth_time": g.authTime.Unix()}
	if i.OmitAuthTime {
		delete(claims, "auth_time")
	}
	maps.Copy(claims, g.user.Claims)
	if i.Mutate != nil {
		i.Mutate(claims)
	}
	idToken, err := i.sign(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"access_token": "at-" + randomString(), "refresh_token": "rt-" + randomString(), "token_type": "Bearer",
		"expires_in": 300, "id_token": idToken})
}

func (i *IdP) sign(claims map[string]any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	switch i.Alg {
	case "none":
		h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		return h + "." + base64.RawURLEncoding.EncodeToString(payload) + ".", nil
	case "HS256":
		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(i.ClientSecret)}, (&jose.SignerOptions{}).WithType("JWT"))
		if err != nil {
			return "", err
		}
		return signCompact(s, payload)
	}
	for _, k := range i.keys {
		if string(k.alg) == i.Alg {
			s, err := jose.NewSigner(jose.SigningKey{Algorithm: k.alg, Key: jose.JSONWebKey{Key: k.priv, KeyID: k.kid}},
				(&jose.SignerOptions{}).WithType("JWT"))
			if err != nil {
				return "", err
			}
			return signCompact(s, payload)
		}
	}
	return "", fmt.Errorf("no key for %s", i.Alg)
}

func signCompact(s jose.Signer, payload []byte) (string, error) {
	obj, err := s.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

func tokenError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = fmt.Fprintf(w, `{"error":%q}`, code)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func randomString() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Authorize follows the authorization URL like a browser and returns the callback query (state, code or error).
func (i *IdP) Authorize(authURL string) (url.Values, error) {
	client := i.srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Get(authURL) //nolint:noctx // test helper
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		return nil, fmt.Errorf("authorize: status %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return nil, err
	}
	return loc.Query(), nil
}
