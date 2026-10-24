// Package oidc implements generic OpenID Connect SSO for operators: provider configuration, Authorization Code
// flow with PKCE, ID-token validation, identity linking, provisioning and group→role mapping (PLAN §12.4, HP-OIDC-*).
package oidc

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Provisioning modes (HP-OIDC-010).
const (
	Preprovisioned = "preprovisioned"
	JIT            = "jit"
)

// Step-up fallbacks (HP-OIDC-013).
const (
	StepUpNone      = "none"
	StepUpLocalTOTP = "local_totp"
)

// Provider is an OIDC provider configuration. The client secret is write-only (HP-OIDC-007).
type Provider struct {
	ID                        string     `json:"id"`
	Slug                      string     `json:"slug"`
	DisplayName               string     `json:"display_name"`
	Issuer                    string     `json:"issuer"`
	ClientID                  string     `json:"client_id"`
	HasClientSecret           bool       `json:"has_client_secret"`
	Scopes                    []string   `json:"scopes"`
	GroupsClaim               string     `json:"groups_claim"`
	Provisioning              string     `json:"provisioning"`
	JIT                       JITRules   `json:"jit"`
	AllowPrivateNetwork       bool       `json:"allow_private_network"`
	AllowCrossOriginEndpoints bool       `json:"allow_cross_origin_endpoints"`
	CABundlePEM               string     `json:"ca_bundle_pem"`
	StepUpFallback            string     `json:"stepup_fallback"`
	ACRValues                 []string   `json:"acr_values"`
	EndSessionEnabled         bool       `json:"end_session_enabled"`
	Enabled                   bool       `json:"enabled"`
	TestLoginOKAt             *time.Time `json:"test_login_ok_at"`
	TestLoginBy               string     `json:"test_login_by,omitempty"`
	Version                   int64      `json:"version"`
	CreatedAt                 time.Time  `json:"created_at"`
	UpdatedAt                 time.Time  `json:"updated_at"`

	secretEnc []byte
}

// JITRules restrict just-in-time provisioning; at least one rule is required in JIT mode and every configured rule
// must match (HP-OIDC-010).
type JITRules struct {
	// EmailDomains require email_verified=true and an email in one of these domains.
	EmailDomains []string `json:"email_domains"`
	// Tenants match the "tid" claim (Microsoft Entra ID).
	Tenants []string `json:"tenants"`
	// HostedDomains match the "hd" claim (Google Workspace).
	HostedDomains []string `json:"hosted_domains"`
	// Groups require at least one of these values in the groups claim.
	Groups []string `json:"groups"`
}

func (j JITRules) empty() bool {
	return len(j.EmailDomains) == 0 && len(j.Tenants) == 0 && len(j.HostedDomains) == 0 && len(j.Groups) == 0
}

// ProviderInput creates or updates a provider. Nil fields are left unchanged on update. ClientSecret: nil keeps the
// stored secret, "" removes it.
type ProviderInput struct {
	Version                   int64     `json:"version"`
	Slug                      *string   `json:"slug"`
	DisplayName               *string   `json:"display_name"`
	Issuer                    *string   `json:"issuer"`
	ClientID                  *string   `json:"client_id"`
	ClientSecret              *string   `json:"client_secret"`
	Scopes                    *[]string `json:"scopes"`
	GroupsClaim               *string   `json:"groups_claim"`
	Provisioning              *string   `json:"provisioning"`
	JIT                       *JITRules `json:"jit"`
	AllowPrivateNetwork       *bool     `json:"allow_private_network"`
	AllowCrossOriginEndpoints *bool     `json:"allow_cross_origin_endpoints"`
	CABundlePEM               *string   `json:"ca_bundle_pem"`
	StepUpFallback            *string   `json:"stepup_fallback"`
	ACRValues                 *[]string `json:"acr_values"`
	EndSessionEnabled         *bool     `json:"end_session_enabled"`
	Enabled                   *bool     `json:"enabled"`
}

// Mapping maps one groups-claim value to an internal role or an operator group (HP-OIDC-011).
type Mapping struct {
	ID         string    `json:"id"`
	ProviderID string    `json:"provider_id"`
	GroupValue string    `json:"group_value"`
	Role       string    `json:"role,omitempty"`
	GroupID    string    `json:"group_id,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// Identity is an external identity linked to an operator (HP-OIDC-009).
type Identity struct {
	Issuer      string     `json:"issuer"`
	Subject     string     `json:"subject"`
	ProviderID  string     `json:"provider_id"`
	OperatorID  string     `json:"operator_id"`
	LinkedVia   string     `json:"linked_via"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

// Options configure the service.
type Options struct {
	// PublicURL is HallPass's external base URL; the redirect URI is PublicURL + CallbackPath.
	PublicURL string
	// DevMode allows http:// issuers on localhost (HP-OIDC-005).
	DevMode bool
	// StateTTL bounds pending authorizations (default and maximum 10 minutes, HP-OIDC-002).
	StateTTL time.Duration
	// HTTPTimeout bounds each request to the provider.
	HTTPTimeout time.Duration
	// JWKSMinRefetch rate-limits JWKS refetches on unknown key IDs (HP-OIDC-004).
	JWKSMinRefetch time.Duration
	// Skew is the accepted clock skew for exp/iat/nbf/auth_time (≤ 60 s, HP-OIDC-003).
	Skew   time.Duration
	Clock  clock.Clock
	Logger *slog.Logger
	// Metrics counts SSO login completions by provider slug and outcome (HP-OBS-004). Nil disables.
	Metrics *metrics.Metrics
}

// CallbackPath is the single redirect URI path for all providers (the state identifies the provider).
const CallbackPath = "/auth/oidc/callback"

// Service manages providers and runs SSO flows.
type Service struct {
	s     *store.Store
	kr    *keyring.Keyring
	audit *audit.Writer
	bus   *eventbus.Bus
	auth  *opauth.Service
	opts  Options
	log   *slog.Logger

	mu     sync.Mutex
	remote map[string]*remote // provider ID → discovered endpoints, HTTP client and key set (per version)
}

// New returns the OIDC service.
func New(s *store.Store, kr *keyring.Keyring, aw *audit.Writer, bus *eventbus.Bus, auth *opauth.Service, o Options) *Service {
	if o.StateTTL <= 0 || o.StateTTL > 10*time.Minute {
		o.StateTTL = 10 * time.Minute
	}
	if o.HTTPTimeout <= 0 {
		o.HTTPTimeout = 10 * time.Second
	}
	if o.JWKSMinRefetch <= 0 {
		o.JWKSMinRefetch = 10 * time.Second
	}
	if o.Skew <= 0 || o.Skew > time.Minute {
		o.Skew = time.Minute
	}
	if o.Clock == nil {
		o.Clock = clock.System{}
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	o.PublicURL = strings.TrimRight(o.PublicURL, "/")
	return &Service{s: s, kr: kr, audit: aw, bus: bus, auth: auth, opts: o, log: obs.Component(o.Logger, "oidc"), remote: map[string]*remote{}}
}

// RedirectURI is the exact redirect URI registered with every provider (HP-OIDC-005).
func (svc *Service) RedirectURI() string { return svc.opts.PublicURL + CallbackPath }

var slugRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func secretAAD(id string) []byte { return []byte("hallpass/oidc-client-secret/v1|" + id) }

func providerFromRow(r db.OidcProvider) (*Provider, error) {
	p := &Provider{ID: r.ID, Slug: r.Slug, DisplayName: r.DisplayName, Issuer: r.Issuer, ClientID: r.ClientID, HasClientSecret: len(r.ClientSecretEnc) > 0,
		GroupsClaim: r.GroupsClaim, Provisioning: r.Provisioning, AllowPrivateNetwork: r.AllowPrivateNetwork == 1,
		AllowCrossOriginEndpoints: r.AllowCrossOriginEndpoints == 1, CABundlePEM: r.CaBundlePem, StepUpFallback: r.StepupFallback,
		EndSessionEnabled: r.EndSessionEnabled == 1, Enabled: r.Enabled == 1, TestLoginBy: r.TestLoginBy.String, Version: r.Version,
		CreatedAt: time.UnixMicro(r.CreatedAt).UTC(), UpdatedAt: time.UnixMicro(r.UpdatedAt).UTC(), secretEnc: r.ClientSecretEnc}
	if err := json.Unmarshal([]byte(r.ScopesJson), &p.Scopes); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(r.JitJson), &p.JIT); err != nil {
		return nil, err
	}
	if r.AcrValues != "" {
		p.ACRValues = strings.Fields(r.AcrValues)
	}
	if r.TestLoginOkAt.Valid {
		t := time.UnixMicro(r.TestLoginOkAt.Int64).UTC()
		p.TestLoginOKAt = &t
	}
	return p, nil
}

// GetProvider returns a provider by ID.
func (svc *Service) GetProvider(ctx context.Context, id string) (*Provider, error) {
	r, err := svc.s.R().GetOIDCProvider(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeNotFound, "provider not found")
	}
	if err != nil {
		return nil, err
	}
	return providerFromRow(r)
}

func (svc *Service) providerBySlug(ctx context.Context, slug string) (*Provider, error) {
	r, err := svc.s.R().GetOIDCProviderBySlug(ctx, slug)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeNotFound, "provider not found")
	}
	if err != nil {
		return nil, err
	}
	return providerFromRow(r)
}

// ListProviders returns all providers.
func (svc *Service) ListProviders(ctx context.Context) ([]*Provider, error) {
	rows, err := svc.s.R().ListOIDCProviders(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*Provider, 0, len(rows))
	for _, r := range rows {
		p, err := providerFromRow(r)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// PublicProvider is what the login page may show (no configuration details).
type PublicProvider struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
}

// EnabledProviders lists enabled providers for the login page.
func (svc *Service) EnabledProviders(ctx context.Context) ([]PublicProvider, error) {
	ps, err := svc.ListProviders(ctx)
	if err != nil {
		return nil, err
	}
	var out []PublicProvider
	for _, p := range ps {
		if p.Enabled {
			out = append(out, PublicProvider{Slug: p.Slug, DisplayName: p.DisplayName})
		}
	}
	return out, nil
}

func invalid(format string, a ...any) error { return apperr.New(apperr.CodeInvalid, format, a...) }

// validateIssuerURL enforces https (or http on localhost in dev mode) and no query/fragment/userinfo (HP-OIDC-005).
func validateIssuerURL(raw string, dev bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return invalid("issuer must be an absolute URL without credentials, query or fragment")
	}
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && dev && isLocalhost(u.Hostname()):
		return nil
	}
	return invalid("issuer must use https (http is allowed only for localhost in development mode)")
}

func isLocalhost(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

func (svc *Service) validate(p *Provider) error {
	if !slugRE.MatchString(p.Slug) {
		return invalid("slug must match %s", slugRE)
	}
	if n := strings.TrimSpace(p.DisplayName); n == "" || len(n) > 64 {
		return invalid("display name is required (at most 64 bytes)")
	}
	if err := validateIssuerURL(p.Issuer, svc.opts.DevMode); err != nil {
		return err
	}
	if p.ClientID == "" || len(p.ClientID) > 256 {
		return invalid("client ID is required (at most 256 bytes)")
	}
	if !slices.Contains(p.Scopes, "openid") {
		return invalid("scopes must include openid")
	}
	for _, s := range p.Scopes {
		if s == "" || strings.ContainsAny(s, " \t\r\n\"") || len(s) > 64 {
			return invalid("invalid scope %q", s)
		}
	}
	if len(p.GroupsClaim) > 64 {
		return invalid("groups claim name is too long")
	}
	switch p.Provisioning {
	case Preprovisioned:
	case JIT:
		if p.JIT.empty() {
			return invalid("JIT provisioning needs at least one restriction (email domains, tenants, hosted domains or groups)")
		}
		if len(p.JIT.Groups) > 0 && p.GroupsClaim == "" {
			return invalid("JIT group restrictions need a groups claim")
		}
	default:
		return invalid("provisioning must be preprovisioned or jit")
	}
	if p.StepUpFallback != StepUpNone && p.StepUpFallback != StepUpLocalTOTP {
		return invalid("stepup_fallback must be none or local_totp")
	}
	for _, a := range p.ACRValues {
		if strings.ContainsAny(a, " \t\r\n") || len(a) > 128 {
			return invalid("invalid acr value")
		}
	}
	if p.CABundlePEM != "" {
		if _, err := parseCABundle(p.CABundlePEM); err != nil {
			return err
		}
	}
	return nil
}

func parseCABundle(pemData string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(pemData)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil, invalid("CA bundle may contain only CERTIFICATE blocks")
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, invalid("CA bundle: %v", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 || strings.TrimSpace(string(rest)) != "" {
		return nil, invalid("CA bundle must be PEM certificates")
	}
	return certs, nil
}

func apply(p *Provider, in ProviderInput) {
	set := func(dst *string, v *string) {
		if v != nil {
			*dst = strings.TrimSpace(*v)
		}
	}
	set(&p.Slug, in.Slug)
	set(&p.DisplayName, in.DisplayName)
	set(&p.Issuer, in.Issuer)
	set(&p.ClientID, in.ClientID)
	set(&p.GroupsClaim, in.GroupsClaim)
	set(&p.Provisioning, in.Provisioning)
	set(&p.StepUpFallback, in.StepUpFallback)
	if in.CABundlePEM != nil {
		p.CABundlePEM = *in.CABundlePEM
	}
	if in.Scopes != nil {
		p.Scopes = slices.Clone(*in.Scopes)
	}
	if in.ACRValues != nil {
		p.ACRValues = slices.Clone(*in.ACRValues)
	}
	if in.JIT != nil {
		p.JIT = *in.JIT
		for i, d := range p.JIT.EmailDomains {
			p.JIT.EmailDomains[i] = strings.ToLower(strings.TrimSpace(d))
		}
	}
	for dst, v := range map[*bool]*bool{&p.AllowPrivateNetwork: in.AllowPrivateNetwork, &p.AllowCrossOriginEndpoints: in.AllowCrossOriginEndpoints,
		&p.EndSessionEnabled: in.EndSessionEnabled, &p.Enabled: in.Enabled} {
		if v != nil {
			*dst = *v
		}
	}
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// CreateProvider adds a provider. Callers must require recent authentication (HP-AUTH-014).
func (svc *Service) CreateProvider(ctx context.Context, actor audit.Actor, in ProviderInput) (*Provider, error) {
	p := &Provider{ID: ids.New(ids.OIDCProvider), Scopes: []string{"openid", "profile", "email"}, Provisioning: Preprovisioned,
		StepUpFallback: StepUpNone}
	apply(p, in)
	if err := svc.validate(p); err != nil {
		return nil, err
	}
	enc, err := svc.sealSecret(p.ID, in.ClientSecret)
	if err != nil {
		return nil, err
	}
	scopes, _ := json.Marshal(p.Scopes)
	jit, _ := json.Marshal(p.JIT)
	err = svc.s.W().TxNamed(ctx, "oidc.create_provider", func(tx *store.Tx) error {
		if _, err := tx.Q.GetOIDCProviderBySlug(ctx, p.Slug); err == nil {
			return apperr.New(apperr.CodeAlreadyExists, "a provider with this slug exists")
		}
		if err := tx.Q.InsertOIDCProvider(ctx, db.InsertOIDCProviderParams{ID: p.ID, Slug: p.Slug, DisplayName: p.DisplayName, Issuer: p.Issuer,
			ClientID: p.ClientID, ClientSecretEnc: enc, ScopesJson: string(scopes), GroupsClaim: p.GroupsClaim, Provisioning: p.Provisioning,
			JitJson: string(jit), AllowPrivateNetwork: b2i(p.AllowPrivateNetwork), AllowCrossOriginEndpoints: b2i(p.AllowCrossOriginEndpoints),
			CaBundlePem: p.CABundlePEM, StepupFallback: p.StepUpFallback, AcrValues: strings.Join(p.ACRValues, " "),
			EndSessionEnabled: b2i(p.EndSessionEnabled), Enabled: b2i(p.Enabled), CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros()}); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "oidc.provider.created", Target: audit.Target{Type: "oidc_provider", ID: p.ID},
			Details: providerAudit(p, in.ClientSecret != nil && *in.ClientSecret != "")})
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.GetProvider(ctx, p.ID)
}

func providerAudit(p *Provider, secretSet bool) map[string]any {
	return map[string]any{"slug": p.Slug, "issuer": p.Issuer, "client_id": p.ClientID, "provisioning": p.Provisioning, "enabled": p.Enabled,
		"allow_private_network": p.AllowPrivateNetwork, "allow_cross_origin_endpoints": p.AllowCrossOriginEndpoints, "client_secret_changed": secretSet}
}

func (svc *Service) sealSecret(id string, secret *string) ([]byte, error) {
	if secret == nil || *secret == "" {
		return nil, nil
	}
	if len(*secret) > 1024 {
		return nil, invalid("client secret is too long")
	}
	return svc.kr.Seal(keyring.PurposeField, secretAAD(id), []byte(*secret))
}

func (svc *Service) clientSecret(p *Provider) (string, error) {
	if len(p.secretEnc) == 0 {
		return "", nil
	}
	b, err := svc.kr.Open(keyring.PurposeField, secretAAD(p.ID), p.secretEnc)
	return string(b), err
}

// UpdateProvider changes a provider (optimistic concurrency by Version). Changing the issuer or client resets the
// test-login evidence. Callers must require recent authentication (HP-AUTH-014).
func (svc *Service) UpdateProvider(ctx context.Context, actor audit.Actor, id string, in ProviderInput) (*Provider, error) {
	p, err := svc.GetProvider(ctx, id)
	if err != nil {
		return nil, err
	}
	prevIssuer, prevClient := p.Issuer, p.ClientID
	apply(p, in)
	if err := svc.validate(p); err != nil {
		return nil, err
	}
	enc := p.secretEnc
	if in.ClientSecret != nil {
		if enc, err = svc.sealSecret(p.ID, in.ClientSecret); err != nil {
			return nil, err
		}
	}
	testAt, testBy := sql.NullInt64{}, sql.NullString{}
	if p.TestLoginOKAt != nil && p.Issuer == prevIssuer && p.ClientID == prevClient {
		testAt = sql.NullInt64{Int64: p.TestLoginOKAt.UnixMicro(), Valid: true}
		testBy = sql.NullString{String: p.TestLoginBy, Valid: p.TestLoginBy != ""}
	}
	scopes, _ := json.Marshal(p.Scopes)
	jit, _ := json.Marshal(p.JIT)
	err = svc.s.W().TxNamed(ctx, "oidc.update_provider", func(tx *store.Tx) error {
		if other, err := tx.Q.GetOIDCProviderBySlug(ctx, p.Slug); err == nil && other.ID != p.ID {
			return apperr.New(apperr.CodeAlreadyExists, "a provider with this slug exists")
		}
		n, err := tx.Q.UpdateOIDCProvider(ctx, db.UpdateOIDCProviderParams{Slug: p.Slug, DisplayName: p.DisplayName, Issuer: p.Issuer, ClientID: p.ClientID,
			ClientSecretEnc: enc, ScopesJson: string(scopes), GroupsClaim: p.GroupsClaim, Provisioning: p.Provisioning, JitJson: string(jit),
			AllowPrivateNetwork: b2i(p.AllowPrivateNetwork), AllowCrossOriginEndpoints: b2i(p.AllowCrossOriginEndpoints), CaBundlePem: p.CABundlePEM,
			StepupFallback: p.StepUpFallback, AcrValues: strings.Join(p.ACRValues, " "), EndSessionEnabled: b2i(p.EndSessionEnabled),
			Enabled: b2i(p.Enabled), TestLoginOkAt: testAt, TestLoginBy: testBy, UpdatedAt: tx.NowMicros(), ID: p.ID, Version: in.Version})
		if err != nil {
			return err
		}
		if n == 0 {
			return apperr.New(apperr.CodeConflict, "provider was modified concurrently; reload and retry")
		}
		if !p.Enabled {
			if err := svc.checkSSOOnlyStillSafe(ctx, tx); err != nil {
				return err
			}
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "oidc.provider.updated", Target: audit.Target{Type: "oidc_provider", ID: p.ID},
			Details: providerAudit(p, in.ClientSecret != nil)})
		return err
	})
	if err != nil {
		return nil, err
	}
	svc.forget(p.ID)
	return svc.GetProvider(ctx, p.ID)
}

// DeleteProvider removes a provider with its mappings and linked identities. Operators who were linked to it lose
// their SSO-sourced roles and groups, which only SSO logins maintain (HP-OIDC-011, SR-26); they are restored from
// the mappings at the next SSO login through another provider. Leaving no enabled administrator is refused.
func (svc *Service) DeleteProvider(ctx context.Context, actor audit.Actor, id string) error {
	var affected []string
	err := svc.s.W().TxNamed(ctx, "oidc.delete_provider", func(tx *store.Tx) error {
		var err error
		if affected, err = tx.Q.ListOperatorIDsForProvider(ctx, id); err != nil {
			return err
		}
		n, err := tx.Q.DeleteOIDCProvider(ctx, id)
		if err != nil {
			return err
		}
		if n == 0 {
			return apperr.New(apperr.CodeNotFound, "provider not found")
		}
		for _, opID := range affected {
			if err := tx.Q.DeleteSSORoles(ctx, opID); err != nil {
				return err
			}
			if err := tx.Q.DeleteSSOGroups(ctx, opID); err != nil {
				return err
			}
		}
		if len(affected) > 0 {
			admins, err := tx.Q.CountEnabledAdmins(ctx)
			if err != nil {
				return err
			}
			if admins == 0 {
				return opauth.ErrLastAdmin
			}
			// Operator-group membership feeds approver rules.
			if _, err := tx.Q.BumpPolicyVersion(ctx, tx.NowMicros()); err != nil {
				return err
			}
		}
		if err := svc.checkSSOOnlyStillSafe(ctx, tx); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "oidc.provider.deleted", Target: audit.Target{Type: "oidc_provider", ID: id},
			Details: map[string]any{"unlinked_operators": len(affected)}})
		return err
	})
	if err == nil {
		svc.forget(id)
		if svc.bus != nil {
			for _, opID := range affected {
				svc.bus.Publish(eventbus.Event{Topic: eventbus.TopicOperatorChanged, Key: opID})
			}
		}
	}
	return err
}

// AddMapping adds a group→role or group→operator-group mapping (HP-OIDC-011).
func (svc *Service) AddMapping(ctx context.Context, actor audit.Actor, providerID, groupValue, role, groupID string) (*Mapping, error) {
	groupValue = strings.TrimSpace(groupValue)
	if groupValue == "" || len(groupValue) > 256 {
		return nil, invalid("group value is required (at most 256 bytes)")
	}
	if (role == "") == (groupID == "") {
		return nil, invalid("a mapping targets exactly one of role or group")
	}
	if role != "" && !slices.Contains(opauth.AllRoles, role) {
		return nil, invalid("unknown role %q", role)
	}
	m := &Mapping{ID: ids.New(ids.OIDCMapping), ProviderID: providerID, GroupValue: groupValue, Role: role, GroupID: groupID}
	err := svc.s.W().TxNamed(ctx, "oidc.add_mapping", func(tx *store.Tx) error {
		if _, err := tx.Q.GetOIDCProvider(ctx, providerID); err != nil {
			return apperr.New(apperr.CodeNotFound, "provider not found")
		}
		if err := tx.Q.InsertOIDCMapping(ctx, db.InsertOIDCMappingParams{ID: m.ID, ProviderID: providerID, GroupValue: groupValue,
			Role: sql.NullString{String: role, Valid: role != ""}, GroupID: sql.NullString{String: groupID, Valid: groupID != ""}, CreatedAt: tx.NowMicros()}); err != nil {
			return apperr.Wrap(apperr.CodeInvalid, err, "mapping could not be added (duplicate or unknown group)")
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "oidc.mapping.added", Target: audit.Target{Type: "oidc_provider", ID: providerID},
			Details: map[string]any{"group_value": groupValue, "role": role, "group_id": groupID}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

// DeleteMapping removes a mapping; affected operators lose the role at their next login (HP-OIDC-011).
func (svc *Service) DeleteMapping(ctx context.Context, actor audit.Actor, providerID, id string) error {
	return svc.s.W().TxNamed(ctx, "oidc.delete_mapping", func(tx *store.Tx) error {
		n, err := tx.Q.DeleteOIDCMapping(ctx, db.DeleteOIDCMappingParams{ID: id, ProviderID: providerID})
		if err != nil {
			return err
		}
		if n == 0 {
			return apperr.New(apperr.CodeNotFound, "mapping not found")
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "oidc.mapping.deleted", Target: audit.Target{Type: "oidc_provider", ID: providerID},
			Details: map[string]any{"mapping_id": id}})
		return err
	})
}

// ListMappings returns a provider's mappings.
func (svc *Service) ListMappings(ctx context.Context, providerID string) ([]Mapping, error) {
	rows, err := svc.s.R().ListOIDCMappings(ctx, providerID)
	if err != nil {
		return nil, err
	}
	out := make([]Mapping, len(rows))
	for i, r := range rows {
		out[i] = Mapping{ID: r.ID, ProviderID: r.ProviderID, GroupValue: r.GroupValue, Role: r.Role.String, GroupID: r.GroupID.String,
			CreatedAt: time.UnixMicro(r.CreatedAt).UTC()}
	}
	return out, nil
}
