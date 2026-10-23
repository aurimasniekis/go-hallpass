package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"syscall"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/net/publicsuffix"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
)

// ErrProviderUnavailable is returned when discovery, JWKS or the token endpoint cannot be used: SSO login fails
// closed with a clear message, existing sessions are unaffected (HP-OIDC-012).
var ErrProviderUnavailable = apperr.New(apperr.CodeUnavailable, "identity provider unavailable; try again later or use another sign-in method")

// signingAlgs are the accepted ID token algorithms: never "none" or HMAC (HP-OIDC-003).
var signingAlgs = []string{gooidc.RS256, gooidc.ES256, gooidc.EdDSA}

var joseAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.EdDSA}

// remote is the discovered state of one provider version.
type remote struct {
	version    int64
	client     *http.Client
	provider   *gooidc.Provider
	endSession string
	keys       *keySet
}

// denyPrivate reports whether an IP is loopback, private, link-local, CGNAT, unspecified or multicast.
func denyPrivate(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() ||
		ip.IsMulticast() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip) || netip.MustParsePrefix("169.254.0.0/16").Contains(ip)
}

// httpClient builds the client for one provider: TLS verification always on (custom roots only add trust), no proxy,
// no redirects, private networks refused at connect time unless explicitly allowed (HP-OIDC-005/006).
func (svc *Service) httpClient(p *Provider) (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if p.CABundlePEM != "" {
		certs, err := parseCABundle(p.CABundlePEM)
		if err != nil {
			return nil, err
		}
		for _, c := range certs {
			roots.AddCert(c)
		}
	}
	allowPrivate := p.AllowPrivateNetwork
	dialer := &net.Dialer{Timeout: svc.opts.HTTPTimeout, Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		if !allowPrivate && denyPrivate(ap.Addr()) {
			return fmt.Errorf("identity provider address %s is in a private or special-purpose range (allow_private_network is off)", ap.Addr())
		}
		return nil
	}}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:   svc.opts.HTTPTimeout,
		ResponseHeaderTimeout: svc.opts.HTTPTimeout,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{Transport: tr, Timeout: svc.opts.HTTPTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func (svc *Service) forget(id string) {
	svc.mu.Lock()
	delete(svc.remote, id)
	svc.mu.Unlock()
}

// discover returns the cached discovery for this provider version, or performs discovery and endpoint validation.
func (svc *Service) discover(ctx context.Context, p *Provider) (*remote, error) {
	svc.mu.Lock()
	r := svc.remote[p.ID]
	svc.mu.Unlock()
	if r != nil && r.version == p.Version {
		return r, nil
	}
	client, err := svc.httpClient(p)
	if err != nil {
		return nil, err
	}
	cctx := gooidc.ClientContext(ctx, client)
	// go-oidc requires the discovery document's issuer to equal the configured issuer exactly (HP-OIDC-001).
	prov, err := gooidc.NewProvider(cctx, p.Issuer)
	if err != nil {
		svc.log.Warn("oidc discovery failed", "provider", p.Slug, "error", err.Error())
		return nil, ErrProviderUnavailable
	}
	var doc struct {
		JWKSURI    string   `json:"jwks_uri"`
		EndSession string   `json:"end_session_endpoint"`
		CodeMethod []string `json:"code_challenge_methods_supported"`
	}
	if err := prov.Claims(&doc); err != nil {
		return nil, ErrProviderUnavailable
	}
	ep := prov.Endpoint()
	for name, u := range map[string]string{"authorization_endpoint": ep.AuthURL, "token_endpoint": ep.TokenURL, "jwks_uri": doc.JWKSURI,
		"end_session_endpoint": doc.EndSession} {
		if u == "" && name == "end_session_endpoint" {
			continue
		}
		if err := svc.checkEndpoint(p, u); err != nil {
			svc.log.Warn("oidc endpoint rejected", "provider", p.Slug, "endpoint", name, "error", err.Error())
			return nil, apperr.New(apperr.CodeUnavailable, "identity provider %s is not acceptable: %v", name, err)
		}
	}
	r = &remote{version: p.Version, client: client, provider: prov, endSession: doc.EndSession,
		keys: &keySet{url: doc.JWKSURI, client: client, minRefetch: svc.opts.JWKSMinRefetch, now: svc.opts.Clock.Now}}
	svc.mu.Lock()
	svc.remote[p.ID] = r
	svc.mu.Unlock()
	return r, nil
}

// checkEndpoint requires https (http only for localhost in dev mode) and, unless cross-origin endpoints are allowed,
// the same registrable domain as the issuer (HP-OIDC-006).
func (svc *Service) checkEndpoint(p *Provider, raw string) error {
	eu, err := url.Parse(raw)
	if err != nil || eu.Host == "" || eu.User != nil || eu.Fragment != "" {
		return errors.New("endpoint must be an absolute https URL")
	}
	devHTTP := eu.Scheme == "http" && svc.opts.DevMode && isLocalhost(eu.Hostname())
	if eu.Scheme != "https" && !devHTTP {
		return errors.New("endpoint must be an absolute https URL")
	}
	if p.AllowCrossOriginEndpoints {
		return nil
	}
	iu, _ := url.Parse(p.Issuer)
	if site(iu.Hostname()) != site(eu.Hostname()) {
		return fmt.Errorf("endpoint host %s does not belong to the issuer's site %s", eu.Hostname(), iu.Hostname())
	}
	return nil
}

// site is the registrable domain of a host (eTLD+1), or the host itself for IPs and single-label names.
func site(host string) string {
	if _, err := netip.ParseAddr(host); err == nil {
		return host
	}
	if s, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return s
	}
	return host
}

// keySet verifies JWS signatures with a cached JWKS. An unknown key ID triggers a refetch at most once per
// minRefetch; the cached keys keep working while the JWKS endpoint is down (HP-OIDC-004/012).
type keySet struct {
	url        string
	client     *http.Client
	minRefetch time.Duration
	now        func() time.Time

	mu        sync.Mutex
	keys      []jose.JSONWebKey
	fetchedAt time.Time
	fetches   int
}

// VerifySignature implements gooidc.KeySet.
func (k *keySet) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	jws, err := jose.ParseSigned(raw, joseAlgs)
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("oidc: expected exactly one signature")
	}
	kid := jws.Signatures[0].Header.KeyID
	if payload, ok := k.verifyCached(jws, kid); ok {
		return payload, nil
	}
	if err := k.refresh(ctx); err != nil {
		return nil, err
	}
	if payload, ok := k.verifyCached(jws, kid); ok {
		return payload, nil
	}
	return nil, errors.New("oidc: no matching key verified the signature")
}

func (k *keySet) verifyCached(jws *jose.JSONWebSignature, kid string) ([]byte, bool) {
	k.mu.Lock()
	keys := k.keys
	k.mu.Unlock()
	for _, key := range keys {
		if kid != "" && key.KeyID != kid {
			continue
		}
		if payload, err := jws.Verify(key); err == nil {
			return payload, true
		}
	}
	return nil, false
}

func (k *keySet) refresh(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.fetchedAt.IsZero() && k.now().Sub(k.fetchedAt) < k.minRefetch {
		return errors.New("oidc: unknown signing key (JWKS refetch rate-limited)")
	}
	k.fetchedAt = k.now()
	k.fetches++
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return err
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: jwks: %w", ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: jwks status %d", ErrProviderUnavailable, resp.StatusCode)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return fmt.Errorf("oidc: jwks: %w", err)
	}
	var keys []jose.JSONWebKey
	for _, key := range set.Keys {
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if acceptableKey(key.Key) {
			keys = append(keys, key)
		}
	}
	k.keys = keys
	return nil
}

// acceptableKey admits RSA ≥ 2048 bits, ECDSA P-256 and Ed25519 public keys; symmetric keys are never used, which
// blocks HMAC algorithm confusion.
func acceptableKey(key any) bool {
	switch pk := key.(type) {
	case *rsa.PublicKey:
		return pk.N.BitLen() >= 2048
	case *ecdsa.PublicKey:
		return pk.Curve == elliptic.P256()
	case ed25519.PublicKey:
		return true
	}
	return false
}

// Fetches returns how many JWKS fetches happened (tests).
func (k *keySet) Fetches() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.fetches
}
