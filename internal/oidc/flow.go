package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/obs/tracing"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Flow purposes.
const (
	PurposeLogin  = "login"
	PurposeStepUp = "stepup"
	PurposeTest   = "test"
	PurposeLink   = "link"
)

// Errors returned by the flow. Messages are safe to show; they never reveal whether an account exists beyond
// "not provisioned" (PLAN §12.4).
var (
	ErrInvalidState    = apperr.New(apperr.CodeInvalid, "sign-in session expired or invalid; start again")
	ErrNotProvisioned  = apperr.New(apperr.CodeForbidden, "this identity is not provisioned in Hallpass; ask an administrator")
	ErrLoginRejected   = apperr.New(apperr.CodeForbidden, "sign-in was rejected")
	ErrStepUpFailed    = apperr.New(apperr.CodeForbidden, "the identity provider did not confirm a fresh login")
	ErrTokenValidation = apperr.New(apperr.CodeUnauthorized, "the identity provider's response could not be validated")
)

// StartInput begins an authorization.
type StartInput struct {
	Provider string // slug
	Purpose  string
	ReturnTo string
	// Principal is the current session: required for stepup, test (administrators) and self-linking.
	Principal *opauth.Principal
	// LinkToken is an admin-issued link invitation (purpose link without a session).
	LinkToken string
}

// StartResult tells the HTTP layer where to redirect and which binding cookie to set (`__Host-hp_oidc`).
type StartResult struct {
	RedirectURL string
	Binding     string
	ExpiresAt   time.Time
}

func random32() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashOf(domain, v string) []byte {
	h := sha256.Sum256([]byte("hallpass/oidc/" + domain + "/v1|" + v))
	return h[:]
}

// SanitizeReturnTo accepts only same-origin relative paths outside /api and /auth (HP-OIDC-005).
func SanitizeReturnTo(p string) string {
	if p == "" || len(p) > 512 || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n\t") {
		return "/"
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	for _, c := range p {
		if c < 0x20 || c == 0x7f {
			return "/"
		}
	}
	// Dot segments (also percent-encoded: u.Path is decoded) would let the browser resolve "/./api/…" or
	// "/x/../auth/…" past the deny list below; no UI route needs them.
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return "/"
		}
	}
	if strings.HasPrefix(u.Path, "/api/") || strings.HasPrefix(u.Path, "/auth/") || u.Path == "/api" || u.Path == "/auth" {
		return "/"
	}
	// Redirect writers (net/http's Redirect among them) clean everything before "?" as a path, fragment included:
	// "/#/../api/…" would become "/api/…" (SR-24). Accept only input that such cleaning leaves unchanged.
	pre, _, _ := strings.Cut(p, "?")
	if cleaned := path.Clean(pre); cleaned != pre && cleaned+"/" != pre {
		return "/"
	}
	return p
}

func verifierAAD(stateHash []byte) []byte {
	return append([]byte("hallpass/oidc-pkce/v1|"), stateHash...)
}

// Start creates a single-use server-side state (state, nonce, PKCE verifier; 10 minutes) and returns the provider's
// authorization URL (HP-OIDC-002).
func (svc *Service) Start(ctx context.Context, in StartInput) (*StartResult, error) {
	p, err := svc.providerBySlug(ctx, in.Provider)
	if err != nil {
		return nil, err
	}
	if !p.Enabled && in.Purpose != PurposeTest {
		return nil, apperr.New(apperr.CodeNotFound, "provider not found")
	}
	var operatorID, sessionDisplay string
	switch in.Purpose {
	case PurposeLogin:
	case PurposeStepUp:
		if in.Principal == nil || in.Principal.Method != opauth.MethodOIDC {
			return nil, apperr.New(apperr.CodePrecondition, "step-up through SSO needs an SSO session")
		}
		operatorID, sessionDisplay = in.Principal.Operator.ID, in.Principal.SessionID
	case PurposeTest:
		// Callers also authorize auth.settings through the RBAC matrix (SR-48).
		if !canTest(in.Principal) {
			return nil, apperr.New(apperr.CodeForbidden, "only administrators can run an SSO test login")
		}
		operatorID, sessionDisplay = in.Principal.Operator.ID, in.Principal.SessionID
	case PurposeLink:
		switch {
		case in.LinkToken != "":
			if operatorID, err = svc.checkLinkToken(ctx, in.LinkToken, p.ID); err != nil {
				return nil, err
			}
		case in.Principal != nil && in.Principal.MFASatisfied():
			// Account linking needs recent authentication, with MFA where policy requires it or a factor is enrolled
			// (HP-AUTH-014, SR-10).
			if err := svc.auth.RequireRecentAuth(in.Principal, in.Principal.Operator.MFARequired); err != nil {
				return nil, err
			}
			operatorID, sessionDisplay = in.Principal.Operator.ID, in.Principal.SessionID
		default:
			return nil, apperr.New(apperr.CodeUnauthorized, "linking needs a signed-in session or a link invitation")
		}
	default:
		return nil, invalid("unknown purpose")
	}
	r, err := svc.discover(ctx, p)
	if err != nil {
		return nil, err
	}
	state, err := random32()
	if err != nil {
		return nil, err
	}
	nonce, err := random32()
	if err != nil {
		return nil, err
	}
	binding, err := random32()
	if err != nil {
		return nil, err
	}
	verifier := oauth2.GenerateVerifier()
	sh := hashOf("state", state)
	venc, err := svc.kr.Seal(keyring.PurposeToken, verifierAAD(sh), []byte(verifier))
	if err != nil {
		return nil, err
	}
	now := svc.opts.Clock.Now()
	exp := now.Add(svc.opts.StateTTL)
	returnTo := SanitizeReturnTo(in.ReturnTo)
	err = svc.s.W().TxNamed(ctx, "oidc.start", func(tx *store.Tx) error {
		return tx.Q.InsertAuthState(ctx, db.InsertAuthStateParams{StateHash: sh, ProviderID: p.ID, Purpose: in.Purpose, NonceHash: hashOf("nonce", nonce),
			VerifierEnc: venc, BindingHash: hashOf("binding", binding), ReturnTo: returnTo,
			OperatorID: sql.NullString{String: operatorID, Valid: operatorID != ""}, SessionDisplay: sql.NullString{String: sessionDisplay, Valid: sessionDisplay != ""},
			CreatedAt: tx.NowMicros(), ExpiresAt: exp.UnixMicro()})
	})
	if err != nil {
		return nil, err
	}
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), gooidc.Nonce(nonce)}
	if in.Purpose == PurposeStepUp || in.Purpose == PurposeTest || in.Purpose == PurposeLink {
		// Upstream step-up (HP-OIDC-013); test and link also require a fresh login at the IdP.
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
	}
	if len(p.ACRValues) > 0 {
		opts = append(opts, oauth2.SetAuthURLParam("acr_values", strings.Join(p.ACRValues, " ")))
	}
	conf := svc.oauthConfig(p, r, "")
	return &StartResult{RedirectURL: conf.AuthCodeURL(state, opts...), Binding: binding, ExpiresAt: exp}, nil
}

// canTest reports whether a session may run (and complete) an SSO test login: a full, MFA-complete administrator
// session, never a Limited one (SR-48).
func canTest(p *opauth.Principal) bool {
	return p != nil && !p.Limited && p.HasRole(opauth.RoleAdministrator)
}

func (svc *Service) oauthConfig(p *Provider, r *remote, secret string) *oauth2.Config {
	return &oauth2.Config{ClientID: p.ClientID, ClientSecret: secret, Endpoint: r.provider.Endpoint(), RedirectURL: svc.RedirectURI(), Scopes: p.Scopes}
}

// CallbackInput is the provider's redirect back to Hallpass.
type CallbackInput struct {
	State, Code         string
	Error, ErrorDetails string
	Binding             string // value of the __Host-hp_oidc cookie
	Principal           *opauth.Principal
	Meta                opauth.SessionMeta
}

// CallbackResult is the outcome per purpose.
type CallbackResult struct {
	Purpose    string
	ProviderID string
	ReturnTo   string
	// SessionToken is set for login and stepup (the rotated session).
	SessionToken string
	OperatorID   string
	Test         *TestResult
}

// Claims are the ID-token claims Hallpass uses (everything else is ignored).
type Claims struct {
	Issuer        string   `json:"iss"`
	Subject       string   `json:"sub"`
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified"`
	Name          string   `json:"name,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	Tenant        string   `json:"tid,omitempty"`
	HostedDomain  string   `json:"hd,omitempty"`
	AuthTime      *int64   `json:"auth_time,omitempty"`
	ACR           string   `json:"acr,omitempty"`
	AMR           []string `json:"amr,omitempty"`
}

// TestResult is the claim-mapping preview of a test login (HP-OIDC-014). No session is created.
type TestResult struct {
	Claims           Claims   `json:"claims"`
	LinkedOperatorID string   `json:"linked_operator_id,omitempty"`
	WouldProvision   bool     `json:"would_provision"`
	ProvisionReason  string   `json:"provision_reason,omitempty"`
	MappedRoles      []string `json:"mapped_roles"`
	MappedGroups     []string `json:"mapped_groups"`
	EffectiveRoles   []string `json:"effective_roles"`
}

// Callback validates the response and completes the purpose. The state is consumed first (single use) whatever
// happens next.
func (svc *Service) Callback(ctx context.Context, in CallbackInput) (_ *CallbackResult, cbErr error) {
	ctx, span := tracing.StartKind(ctx, tracing.SpanOIDCCallback, trace.SpanKindServer)
	defer func() { tracing.End(span, cbErr) }()
	if in.State == "" || len(in.State) > 128 {
		return nil, ErrInvalidState
	}
	var st db.OidcAuthState
	err := svc.s.W().TxNamed(ctx, "oidc.take_state", func(tx *store.Tx) error {
		var err error
		st, err = tx.Q.TakeAuthState(ctx, hashOf("state", in.State))
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidState
	}
	if err != nil {
		return nil, err
	}
	now := svc.opts.Clock.Now()
	if now.After(time.UnixMicro(st.ExpiresAt)) || subtle.ConstantTimeCompare(st.BindingHash, hashOf("binding", in.Binding)) != 1 {
		return nil, ErrInvalidState
	}
	if in.Error != "" {
		svc.log.Info("identity provider returned an error", "error", truncate(in.Error, 64))
		return nil, ErrLoginRejected
	}
	p, err := svc.GetProvider(ctx, st.ProviderID)
	if err != nil {
		return nil, ErrInvalidState
	}
	if st.Purpose == PurposeLogin {
		defer func() { svc.observeLogin(p.Slug, cbErr) }()
	}
	if !p.Enabled && st.Purpose != PurposeTest {
		return nil, ErrLoginRejected
	}
	r, err := svc.discover(ctx, p)
	if err != nil {
		return nil, err
	}
	verifier, err := svc.kr.Open(keyring.PurposeToken, verifierAAD(st.StateHash), st.VerifierEnc)
	if err != nil {
		return nil, ErrInvalidState
	}
	secret, err := svc.clientSecret(p)
	if err != nil {
		return nil, err
	}
	tok, err := svc.oauthConfig(p, r, secret).Exchange(gooidc.ClientContext(ctx, r.client), in.Code, oauth2.VerifierOption(string(verifier)))
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && re.Response != nil && re.Response.StatusCode < 500 {
			svc.log.Warn("oidc code exchange rejected", "provider", p.Slug, "status", re.Response.StatusCode)
			return nil, ErrLoginRejected
		}
		svc.log.Warn("oidc token endpoint unavailable", "provider", p.Slug, "error", err.Error())
		return nil, ErrProviderUnavailable
	}
	raw, _ := tok.Extra("id_token").(string)
	// Access and refresh tokens are dropped here: Hallpass has no use for them (HP-OIDC-008).
	tok = nil
	claims, err := svc.verifyIDToken(ctx, p, r, raw, st.NonceHash)
	if err != nil {
		svc.log.Warn("id token rejected", "provider", p.Slug, "error", err.Error())
		return nil, ErrTokenValidation
	}
	res := &CallbackResult{Purpose: st.Purpose, ReturnTo: st.ReturnTo, ProviderID: p.ID}
	switch st.Purpose {
	case PurposeLogin:
		res.SessionToken, res.OperatorID, err = svc.login(ctx, p, claims, in.Meta)
	case PurposeStepUp:
		res.SessionToken, err = svc.stepUp(ctx, p, st, claims, in)
		res.OperatorID = st.OperatorID.String
	case PurposeTest:
		res.Test, err = svc.testLogin(ctx, p, st, claims, in.Principal)
	case PurposeLink:
		res.OperatorID, err = svc.link(ctx, p, st, claims, in)
	default:
		err = ErrInvalidState
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

// observeLogin counts an SSO login completion for a known provider.
func (svc *Service) observeLogin(slug string, err error) {
	var o metrics.LoginOutcome
	switch {
	case err == nil:
		o = metrics.LoginSuccess
	case errors.Is(err, ErrLoginRejected), errors.Is(err, ErrNotProvisioned):
		o = metrics.LoginDenied
	case errors.Is(err, ErrTokenValidation), errors.Is(err, ErrInvalidState):
		o = metrics.LoginFailure
	default:
		o = metrics.LoginError
	}
	svc.opts.Metrics.OIDCLogin(slug, o)
	svc.opts.Metrics.OperatorLogin(metrics.LoginOIDC, o)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// verifyIDToken checks signature (RS256/ES256/EdDSA via JWKS), iss, aud, azp, exp/iat/nbf with ≤ 60 s skew and the
// nonce (HP-OIDC-003).
func (svc *Service) verifyIDToken(ctx context.Context, p *Provider, r *remote, raw string, nonceHash []byte) (*Claims, error) {
	if raw == "" {
		return nil, errors.New("token response has no id_token")
	}
	now := svc.opts.Clock.Now()
	v := gooidc.NewVerifier(p.Issuer, r.keys, &gooidc.Config{ClientID: p.ClientID, SupportedSigningAlgs: signingAlgs,
		Now: func() time.Time { return now.Add(-svc.opts.Skew) }})
	t, err := v.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	var extra struct {
		AZP string          `json:"azp"`
		IAT int64           `json:"iat"`
		NBF *int64          `json:"nbf"`
		Raw json.RawMessage `json:"-"`
	}
	if err := t.Claims(&extra); err != nil {
		return nil, err
	}
	if (len(t.Audience) > 1 || extra.AZP != "") && extra.AZP != p.ClientID {
		return nil, errors.New("azp does not match the client ID")
	}
	if extra.IAT == 0 || time.Unix(extra.IAT, 0).After(now.Add(svc.opts.Skew)) {
		return nil, errors.New("iat missing or in the future")
	}
	if extra.NBF != nil && time.Unix(*extra.NBF, 0).After(now.Add(svc.opts.Skew)) {
		return nil, errors.New("token not yet valid")
	}
	if subtle.ConstantTimeCompare(hashOf("nonce", t.Nonce), nonceHash) != 1 {
		return nil, errors.New("nonce mismatch")
	}
	var c Claims
	if err := t.Claims(&c); err != nil {
		return nil, err
	}
	if p.GroupsClaim != "" {
		c.Groups = nil
		var all map[string]json.RawMessage
		if err := t.Claims(&all); err == nil {
			c.Groups = parseGroups(all[p.GroupsClaim])
		}
	}
	if c.Subject == "" || len(c.Subject) > 255 {
		return nil, errors.New("sub missing or too long")
	}
	c.Email = strings.ToLower(strings.TrimSpace(c.Email))
	return &c, nil
}

// parseGroups accepts a string array or a single string; anything else yields no groups.
func parseGroups(raw json.RawMessage) []string {
	var arr []string
	if json.Unmarshal(raw, &arr) == nil {
		if len(arr) > 1000 {
			arr = arr[:1000]
		}
		return arr
	}
	var one string
	if json.Unmarshal(raw, &one) == nil && one != "" {
		return []string{one}
	}
	return nil
}

// mapped evaluates the allowlisted mappings for the claims' groups (HP-OIDC-011).
func (svc *Service) mapped(ctx context.Context, p *Provider, groups []string) (roles []string, groupIDs []string, refs map[string]string, err error) {
	ms, err := svc.ListMappings(ctx, p.ID)
	if err != nil {
		return nil, nil, nil, err
	}
	refs = map[string]string{}
	for _, m := range ms {
		if !slices.Contains(groups, m.GroupValue) {
			continue
		}
		if m.Role != "" && !slices.Contains(roles, m.Role) {
			roles = append(roles, m.Role)
			refs[m.Role] = m.GroupValue
		}
		if m.GroupID != "" && !slices.Contains(groupIDs, m.GroupID) {
			groupIDs = append(groupIDs, m.GroupID)
		}
	}
	slices.Sort(roles)
	slices.Sort(groupIDs)
	return roles, groupIDs, refs, nil
}

// jitAllowed checks every configured JIT restriction (HP-OIDC-010).
func jitAllowed(rules JITRules, c *Claims) (bool, string) {
	if rules.empty() {
		return false, "no JIT restrictions configured"
	}
	if len(rules.EmailDomains) > 0 {
		at := strings.LastIndexByte(c.Email, '@')
		if !c.EmailVerified || at < 0 || !slices.Contains(rules.EmailDomains, c.Email[at+1:]) {
			return false, "verified email domain not allowed"
		}
	}
	if len(rules.Tenants) > 0 && !slices.Contains(rules.Tenants, c.Tenant) {
		return false, "tenant not allowed"
	}
	if len(rules.HostedDomains) > 0 && !slices.Contains(rules.HostedDomains, c.HostedDomain) {
		return false, "hosted domain not allowed"
	}
	if len(rules.Groups) > 0 && !slices.ContainsFunc(c.Groups, func(g string) bool { return slices.Contains(rules.Groups, g) }) {
		return false, "no allowed group"
	}
	return true, ""
}

// login resolves (iss, sub) to an operator — never by email (HP-OIDC-009) — provisions JIT users, syncs SSO roles
// and groups and creates the session, all in one transaction.
func (svc *Service) login(ctx context.Context, p *Provider, c *Claims, meta opauth.SessionMeta) (string, string, error) {
	roles, groupIDs, refs, err := svc.mapped(ctx, p, c.Groups)
	if err != nil {
		return "", "", err
	}
	var token, operatorID string
	err = svc.s.W().TxNamed(ctx, "oidc.login", func(tx *store.Tx) error {
		ident, err := tx.Q.GetIdentity(ctx, db.GetIdentityParams{Issuer: c.Issuer, Subject: c.Subject})
		switch {
		case err == nil:
			operatorID = ident.OperatorID
		case errors.Is(err, sql.ErrNoRows):
			if p.Provisioning != JIT {
				return svc.auditDenied(ctx, tx, p, c, meta, "not_provisioned", ErrNotProvisioned)
			}
			if ok, why := jitAllowed(p.JIT, c); !ok {
				return svc.auditDenied(ctx, tx, p, c, meta, "jit_restricted: "+why, ErrNotProvisioned)
			}
			if operatorID, err = svc.provisionTx(ctx, tx, p, c); err != nil {
				return err
			}
		default:
			return err
		}
		op, err := tx.Q.GetOperator(ctx, operatorID)
		if err != nil || op.Enabled != 1 {
			return svc.auditDenied(ctx, tx, p, c, meta, "operator_disabled", ErrLoginRejected)
		}
		if err := svc.syncTx(ctx, tx, operatorID, roles, groupIDs, refs); err != nil {
			return err
		}
		if err := tx.Q.TouchIdentity(ctx, db.TouchIdentityParams{LastLoginAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, Issuer: c.Issuer, Subject: c.Subject}); err != nil {
			return err
		}
		meta.Provider = p.Slug
		if token, err = svc.auth.CreateSessionTx(ctx, tx, operatorID, opauth.MethodOIDC, meta); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorOperator, ID: operatorID}, Action: "operator.login",
			SourceIP: meta.IP, Details: map[string]any{"method": opauth.MethodOIDC, "provider": p.Slug, "sso_roles": roles}})
		return err
	})
	var de *deniedError
	if errors.As(err, &de) {
		svc.recordDenied(ctx, p, c, meta, de.reason)
		return "", "", de.pub
	}
	if err != nil {
		return "", "", err
	}
	return token, operatorID, nil
}

// auditDenied aborts the login transaction with a deniedError; login() records the audit row in its own
// transaction afterwards so the record survives the rollback.
func (svc *Service) auditDenied(_ context.Context, _ *store.Tx, _ *Provider, _ *Claims, _ opauth.SessionMeta, reason string, pub error) error {
	return &deniedError{reason: reason, pub: pub}
}

type deniedError struct {
	reason string
	pub    error
}

func (e *deniedError) Error() string { return e.reason }

func (svc *Service) recordDenied(ctx context.Context, p *Provider, c *Claims, meta opauth.SessionMeta, reason string) {
	err := svc.s.W().TxNamed(ctx, "oidc.login_denied", func(tx *store.Tx) error {
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorProvider, ID: "oidc:" + p.Slug}, Action: "operator.login.failed",
			Outcome: audit.OutcomeDenied, SourceIP: meta.IP, Details: map[string]any{"method": opauth.MethodOIDC, "provider": p.Slug, "reason": reason,
				"subject_hash": base64.RawURLEncoding.EncodeToString(hashOf("subject", c.Issuer+"|"+c.Subject)[:12])}})
		return err
	})
	if err != nil {
		svc.log.Error("audit of denied sso login failed", "error", err.Error())
	}
}

// provisionTx creates a JIT operator with no manual roles (HP-OIDC-010). An email already used by another operator is
// not merged and not reused (HP-OIDC-009).
func (svc *Service) provisionTx(ctx context.Context, tx *store.Tx, p *Provider, c *Claims) (string, error) {
	id := ids.New(ids.Operator)
	var email sql.NullString
	if c.EmailVerified && c.Email != "" {
		if _, err := tx.Q.GetOperatorByEmail(ctx, sql.NullString{String: c.Email, Valid: true}); err == nil {
			return "", &deniedError{reason: "jit_email_conflict", pub: apperr.New(apperr.CodeConflict,
				"an operator with this email already exists; ask an administrator to link your SSO identity")}
		}
		email = sql.NullString{String: c.Email, Valid: true}
	}
	name := strings.TrimSpace(c.Name)
	if name == "" {
		name = c.Email
	}
	if name == "" {
		name = "SSO user"
	}
	if len(name) > 128 {
		name = name[:128]
	}
	if err := tx.Q.InsertOperator(ctx, db.InsertOperatorParams{ID: id, Email: email, DisplayName: name, Enabled: 1, ProvisionedVia: "jit",
		CreatedAt: tx.NowMicros(), CreatedBy: "oidc:" + p.Slug, UpdatedAt: tx.NowMicros()}); err != nil {
		return "", err
	}
	if err := tx.Q.InsertIdentity(ctx, db.InsertIdentityParams{Issuer: c.Issuer, Subject: c.Subject, ProviderID: p.ID, OperatorID: id, LinkedVia: "jit",
		CreatedAt: tx.NowMicros()}); err != nil {
		return "", err
	}
	_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorSystem, ID: "oidc:" + p.Slug}, Action: "operator.created",
		Target: audit.Target{Type: "operator", ID: id}, Details: map[string]any{"via": "jit", "provider": p.Slug, "email": email.String}})
	return id, err
}

// syncTx replaces the operator's SSO-sourced roles and groups with the mapped set; manual assignments are untouched
// (HP-OIDC-011). Removing the last enabled administrator, or under SSO-only enforcement the last SSO-capable one, is
// refused (HP-AUTH-015): the SSO administrator role is kept and the conflict audited.
func (svc *Service) syncTx(ctx context.Context, tx *store.Tx, operatorID string, roles, groupIDs []string, refs map[string]string) error {
	before, err := tx.Q.ListOperatorRoles(ctx, operatorID)
	if err != nil {
		return err
	}
	hadSSOAdmin := slices.ContainsFunc(before, func(r db.ListOperatorRolesRow) bool { return r.Source == "sso" && r.Role == opauth.RoleAdministrator })
	if err := tx.Q.DeleteSSORoles(ctx, operatorID); err != nil {
		return err
	}
	for _, r := range roles {
		if err := tx.Q.InsertSSORole(ctx, db.InsertSSORoleParams{OperatorID: operatorID, Role: r, SourceRef: refs[r]}); err != nil {
			return err
		}
	}
	if hadSSOAdmin && !slices.Contains(roles, opauth.RoleAdministrator) {
		n, err := tx.Q.CountEnabledAdmins(ctx)
		if err != nil {
			return err
		}
		// Under SSO-only enforcement local administrators cannot sign in, so the last SSO-capable administrator is
		// kept as well (HP-AUTH-015, SR-06).
		ssoLockout, err := opauth.SSOAdminsAtRisk(ctx, tx.Q)
		if err != nil {
			return err
		}
		if n == 0 || ssoLockout {
			if err := tx.Q.InsertSSORole(ctx, db.InsertSSORoleParams{OperatorID: operatorID, Role: opauth.RoleAdministrator, SourceRef: "last-admin-guard"}); err != nil {
				return err
			}
			if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorSystem, ID: "oidc"}, Action: "operator.role_sync.blocked",
				Outcome: audit.OutcomeDenied, Target: audit.Target{Type: "operator", ID: operatorID},
				Details: map[string]any{"reason": lastAdminReason(n == 0)}}); err != nil {
				return err
			}
		}
	}
	if err := tx.Q.DeleteSSOGroups(ctx, operatorID); err != nil {
		return err
	}
	for _, g := range groupIDs {
		if err := tx.Q.InsertSSOGroup(ctx, db.InsertSSOGroupParams{GroupID: g, OperatorID: operatorID}); err != nil {
			return err
		}
	}
	after, err := tx.Q.ListOperatorRoles(ctx, operatorID)
	if err != nil {
		return err
	}
	if !sameRoles(before, after) {
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorSystem, ID: "oidc"}, Action: "operator.roles.synced",
			Target: audit.Target{Type: "operator", ID: operatorID}, Details: map[string]any{"sso_roles": roles, "sso_groups": groupIDs}})
	}
	return err
}

func lastAdminReason(noAdmin bool) string {
	if noAdmin {
		return "would remove the last enabled administrator"
	}
	return "would remove the last administrator who can sign in with SSO while password login is disabled"
}

func sameRoles(a, b []db.ListOperatorRolesRow) bool {
	key := func(rs []db.ListOperatorRolesRow) []string {
		out := make([]string, len(rs))
		for i, r := range rs {
			out[i] = r.Role + "|" + r.Source + "|" + r.SourceRef
		}
		slices.Sort(out)
		return out
	}
	return slices.Equal(key(a), key(b))
}

// stepUp verifies a fresh upstream login: auth_time must be at or after the step-up start (minus skew), and acr must
// match when configured (HP-OIDC-013).
func (svc *Service) stepUp(ctx context.Context, p *Provider, st db.OidcAuthState, c *Claims, in CallbackInput) (string, error) {
	pr := in.Principal
	if pr == nil || pr.Operator.ID != st.OperatorID.String || pr.SessionID != st.SessionDisplay.String {
		return "", ErrInvalidState
	}
	ident, err := svc.s.R().GetIdentity(ctx, db.GetIdentityParams{Issuer: c.Issuer, Subject: c.Subject})
	if err != nil || ident.OperatorID != pr.Operator.ID {
		return "", ErrStepUpFailed
	}
	if c.AuthTime == nil {
		if p.StepUpFallback == StepUpLocalTOTP {
			return "", apperr.New(apperr.CodeMFARequired, "this identity provider cannot prove a fresh login; confirm with your Hallpass TOTP code")
		}
		return "", ErrStepUpFailed
	}
	started := time.UnixMicro(st.CreatedAt)
	if time.Unix(*c.AuthTime, 0).Before(started.Add(-svc.opts.Skew)) {
		return "", ErrStepUpFailed
	}
	if len(p.ACRValues) > 0 && !slices.Contains(p.ACRValues, c.ACR) {
		return "", ErrStepUpFailed
	}
	return svc.auth.ReauthExternal(ctx, pr, p.Slug, in.Meta)
}

// testLogin records a successful end-to-end test login and returns the mapping preview without creating a session
// (HP-OIDC-014).
func (svc *Service) testLogin(ctx context.Context, p *Provider, st db.OidcAuthState, c *Claims, pr *opauth.Principal) (*TestResult, error) {
	if !canTest(pr) || pr.Operator.ID != st.OperatorID.String {
		return nil, ErrInvalidState
	}
	roles, groupIDs, _, err := svc.mapped(ctx, p, c.Groups)
	if err != nil {
		return nil, err
	}
	res := &TestResult{Claims: *c, MappedRoles: nonNil(roles), MappedGroups: nonNil(groupIDs)}
	effective := slices.Clone(roles)
	if ident, err := svc.s.R().GetIdentity(ctx, db.GetIdentityParams{Issuer: c.Issuer, Subject: c.Subject}); err == nil {
		res.LinkedOperatorID = ident.OperatorID
		if rs, err := svc.s.R().ListOperatorRoles(ctx, ident.OperatorID); err == nil {
			for _, r := range rs {
				if r.Source == "manual" && !slices.Contains(effective, r.Role) {
					effective = append(effective, r.Role)
				}
			}
		}
	} else if p.Provisioning == JIT {
		res.WouldProvision, res.ProvisionReason = jitAllowed(p.JIT, c)
	} else {
		res.ProvisionReason = "not provisioned (preprovisioned mode)"
	}
	slices.Sort(effective)
	res.EffectiveRoles = nonNil(effective)
	err = svc.s.W().TxNamed(ctx, "oidc.test_login", func(tx *store.Tx) error {
		if err := tx.Q.SetOIDCTestLogin(ctx, db.SetOIDCTestLoginParams{TestLoginOkAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
			TestLoginBy: sql.NullString{String: pr.Operator.ID, Valid: true}, ID: p.ID}); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorOperator, ID: pr.Operator.ID}, Action: "oidc.provider.test_login",
			Target: audit.Target{Type: "oidc_provider", ID: p.ID}, Details: map[string]any{"mapped_roles": roles, "linked": res.LinkedOperatorID != ""}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// link binds (iss, sub) to the operator who started the flow: a signed-in session on both sides, or an admin-issued
// link invitation (HP-OIDC-009). An identity linked to someone else is never moved.
func (svc *Service) link(ctx context.Context, p *Provider, st db.OidcAuthState, c *Claims, in CallbackInput) (string, error) {
	opID := st.OperatorID.String
	if st.SessionDisplay.Valid && (in.Principal == nil || in.Principal.SessionID != st.SessionDisplay.String || in.Principal.Operator.ID != opID) {
		return "", ErrInvalidState
	}
	via := "self_link"
	if !st.SessionDisplay.Valid {
		via = "admin"
	}
	err := svc.s.W().TxNamed(ctx, "oidc.link", func(tx *store.Tx) error {
		if ident, err := tx.Q.GetIdentity(ctx, db.GetIdentityParams{Issuer: c.Issuer, Subject: c.Subject}); err == nil {
			if ident.OperatorID == opID {
				return nil
			}
			return apperr.New(apperr.CodeConflict, "this SSO identity is already linked to another operator")
		}
		if err := tx.Q.InsertIdentity(ctx, db.InsertIdentityParams{Issuer: c.Issuer, Subject: c.Subject, ProviderID: p.ID, OperatorID: opID, LinkedVia: via,
			CreatedAt: tx.NowMicros()}); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorOperator, ID: opID}, Action: "operator.identity.linked",
			Target: audit.Target{Type: "operator", ID: opID}, SourceIP: in.Meta.IP, Details: map[string]any{"provider": p.Slug, "via": via}})
		return err
	})
	return opID, err
}

// ReauthTOTP is the local-TOTP step-up fallback (HP-OIDC-013): only for SSO sessions whose provider is enabled and
// configured with stepup_fallback = local_totp (SR-03). Other sessions re-authenticate upstream or with a password.
func (svc *Service) ReauthTOTP(ctx context.Context, pr *opauth.Principal, code string, meta opauth.SessionMeta) (string, error) {
	if pr == nil || pr.Method != opauth.MethodOIDC || pr.Provider == "" {
		return "", opauth.ErrTOTPStepUpNotAllowed
	}
	p, err := svc.providerBySlug(ctx, pr.Provider)
	if err != nil && !errors.Is(err, apperr.ErrNotFound) {
		return "", err
	}
	if err != nil || !p.Enabled || p.StepUpFallback != StepUpLocalTOTP {
		return "", opauth.ErrTOTPStepUpNotAllowed
	}
	return svc.auth.ReauthTOTP(ctx, pr, code, meta)
}
