package httpapi

import (
	"net/http"
	"net/url"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/httpapi/gen"
	"github.com/aurimasniekis/go-hallpass/internal/oidc"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
	"github.com/aurimasniekis/go-hallpass/internal/rbac"
)

func (s *Server) GetAuthConfig(c *gen.Call) (*gen.Result, error) {
	ctx := c.R.Context()
	off, err := s.d.Auth.LocalLoginDisabled(ctx)
	if err != nil {
		return nil, err
	}
	providers, err := s.d.OIDC.EnabledProviders(ctx)
	if err != nil {
		return nil, err
	}
	if providers == nil {
		providers = []oidc.PublicProvider{}
	}
	n, err := s.d.Store.R().CountOperators(ctx)
	if err != nil {
		return nil, err
	}
	direct, err := s.d.OIDC.DirectProvider(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"local_login": !off, "providers": providers, "bootstrap_required": n == 0}
	if direct != "" {
		out["direct_provider"] = direct
	}
	return ok(out)
}

func (s *Server) Login(c *gen.Call) (*gen.Result, error) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	res, err := s.d.Auth.Login(c.R.Context(), opauth.LoginInput{Email: in.Email, Password: in.Password, Meta: s.meta(c.R)})
	if err != nil {
		return nil, err
	}
	return &gen.Result{SetSession: res.Token, Body: map[string]any{"mfa_pending": res.MFAPending, "must_enroll": res.MustEnroll, "me": s.me(res.Principal)}}, nil
}

// withSession authenticates a freshly issued token and returns it with /me.
func (s *Server) withSession(c *gen.Call, token string) (*gen.Result, error) {
	p, err := s.d.Auth.Authenticate(c.R.Context(), token)
	if err != nil {
		return nil, err
	}
	return &gen.Result{SetSession: token, Body: s.me(p)}, nil
}

func (s *Server) VerifyMFA(c *gen.Call) (*gen.Result, error) {
	var in struct {
		Code string `json:"code"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	token, err := s.d.Auth.VerifyMFA(c.R.Context(), c.Principal, in.Code, s.meta(c.R))
	if err != nil {
		return nil, err
	}
	return s.withSession(c, token)
}

func (s *Server) Logout(c *gen.Call) (*gen.Result, error) {
	if err := s.d.Auth.Logout(c.R.Context(), c.SessionToken); err != nil {
		return nil, err
	}
	// RP-initiated logout at the provider that created this session is optional and not a global logout
	// (HP-OIDC-015).
	var logoutURL *string
	if c.Principal.Method == opauth.MethodOIDC && c.Principal.Provider != "" {
		if u, err := s.d.OIDC.LogoutURL(c.R.Context(), c.Principal.Provider, "/login"); err == nil && u != "" {
			logoutURL = &u
		}
	}
	return &gen.Result{ClearSession: true, Body: map[string]any{"provider_logout_url": logoutURL}}, nil
}

func (s *Server) Reauth(c *gen.Call) (*gen.Result, error) {
	var in struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	token, err := s.d.Auth.Reauth(c.R.Context(), c.Principal, in.Password, in.Code, s.meta(c.R))
	if err != nil {
		return nil, err
	}
	return s.withSession(c, token)
}

func (s *Server) ReauthTOTP(c *gen.Call) (*gen.Result, error) {
	var in struct {
		Code string `json:"code"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	token, err := s.d.OIDC.ReauthTOTP(c.R.Context(), c.Principal, in.Code, s.meta(c.R))
	if err != nil {
		return nil, err
	}
	return s.withSession(c, token)
}

// RecoverLogin redeems a break-glass recovery token (HP-AUTH-016). The route is public (the token is the
// credential), Origin-checked and under the strict per-IP auth rate limit like every /api/v1/auth mutation; opauth
// adds a per-source failure throttle, single use, expiry and audit.
func (s *Server) RecoverLogin(c *gen.Call) (*gen.Result, error) {
	var in struct {
		Token string `json:"token"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	res, err := s.d.Auth.RecoveryLogin(c.R.Context(), in.Token, s.meta(c.R))
	if err != nil {
		return nil, err
	}
	var reset any
	if res.ResetToken != "" {
		reset = map[string]any{"token": res.ResetToken, "expires_at": res.ResetExpiresAt.UTC(), "url": "/reset/" + res.ResetToken}
	}
	return &gen.Result{SetSession: res.Token, Body: map[string]any{"must_enroll": res.Principal.NeedsEnroll, "password_reset": reset,
		"me": s.me(res.Principal)}}, nil
}

func (s *Server) Bootstrap(c *gen.Call) (*gen.Result, error) {
	var in opauth.BootstrapInput
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	op, err := s.d.Auth.Bootstrap(c.R.Context(), in)
	if err != nil {
		return nil, err
	}
	return created(op)
}

func (s *Server) AcceptInvitation(c *gen.Call) (*gen.Result, error) {
	var in struct {
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	op, err := s.d.Auth.AcceptInvitation(c.R.Context(), c.R.PathValue("token"), in.DisplayName, in.Password)
	if err != nil {
		return nil, err
	}
	return created(op)
}

func (s *Server) ResetPassword(c *gen.Call) (*gen.Result, error) {
	var in struct {
		Password string `json:"password"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	if err := s.d.Auth.ResetPassword(c.R.Context(), c.R.PathValue("token"), in.Password); err != nil {
		return nil, err
	}
	return noContent()
}

// OidcStart redirects the browser to the provider and sets the binding cookie (HP-OIDC-002).
func (s *Server) OidcStart(c *gen.Call) (*gen.Result, error) {
	q := c.R.URL.Query()
	purpose := q.Get("purpose")
	if purpose == "" {
		purpose = oidc.PurposeLogin
	}
	if purpose == oidc.PurposeTest {
		// The test login sets the SSO-only precondition: same permission as the auth settings it unlocks (SR-48).
		if err := s.d.Matrix.Authorize(c.Principal, rbac.AuthSettings); err != nil {
			return s.loginErrorRedirect(err)
		}
	}
	res, err := s.d.OIDC.Start(c.R.Context(), oidc.StartInput{Provider: c.R.PathValue("provider"), Purpose: purpose, ReturnTo: q.Get("return_to"),
		Principal: c.Principal, LinkToken: q.Get("link_token")})
	if err != nil {
		return s.loginErrorRedirect(err)
	}
	s.setCookie(c.W, s.oidcCookieName(), res.Binding, int(time.Until(res.ExpiresAt).Seconds()))
	return &gen.Result{Status: http.StatusFound, Location: res.RedirectURL}, nil
}

// loginErrorRedirect sends the browser back to the login page with a stable error code (never internals).
func (s *Server) loginErrorRedirect(err error) (*gen.Result, error) {
	code := string(apperr.CodeOf(err))
	if code == "" {
		code = "internal"
	}
	return &gen.Result{Status: http.StatusSeeOther, Location: "/login?sso_error=" + url.QueryEscape(code)}, nil
}

// OidcCallback completes the flow and redirects into the UI.
func (s *Server) OidcCallback(c *gen.Call) (*gen.Result, error) {
	q := c.R.URL.Query()
	binding := ""
	if ck, err := c.R.Cookie(s.oidcCookieName()); err == nil {
		binding = ck.Value
	}
	s.setCookie(c.W, s.oidcCookieName(), "", -1)
	res, err := s.d.OIDC.Callback(c.R.Context(), oidc.CallbackInput{State: q.Get("state"), Code: q.Get("code"), Error: q.Get("error"),
		ErrorDetails: q.Get("error_description"), Binding: binding, Principal: c.Principal, Meta: s.meta(c.R)})
	if err != nil {
		return s.loginErrorRedirect(err)
	}
	switch res.Purpose {
	case oidc.PurposeLogin, oidc.PurposeStepUp:
		return &gen.Result{Status: http.StatusSeeOther, Location: res.ReturnTo, SetSession: res.SessionToken}, nil
	case oidc.PurposeTest:
		// The preview is fetched by the settings page (getOIDCTestLogin); nothing sensitive goes into the URL.
		s.testMu.Lock()
		s.testResults[c.Principal.Operator.ID+"|"+res.ProviderID] = testEntry{res: res.Test, at: s.o.Clock.Now()}
		s.testMu.Unlock()
		return &gen.Result{Status: http.StatusSeeOther, Location: "/settings/auth?test_login=" + url.QueryEscape(res.ProviderID)}, nil
	}
	return &gen.Result{Status: http.StatusSeeOther, Location: oidc.SanitizeReturnTo(res.ReturnTo)}, nil
}

// ---- me

func (s *Server) GetMe(c *gen.Call) (*gen.Result, error) { return ok(s.me(c.Principal)) }

func (s *Server) ListMySessions(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Auth.ListSessions(c.R.Context(), c.Principal.Operator.ID, c.Principal.SessionID)
	if err != nil {
		return nil, err
	}
	return ok(list(v))
}

func (s *Server) RevokeMySession(c *gen.Call) (*gen.Result, error) {
	if err := s.d.Auth.RevokeSession(c.R.Context(), c.Principal.Operator.ID, c.R.PathValue("id"), "revoked_by_owner"); err != nil {
		return nil, err
	}
	return noContent()
}

func (s *Server) ChangeMyPassword(c *gen.Call) (*gen.Result, error) {
	var in struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	if err := s.d.Auth.ChangePassword(c.R.Context(), c.Principal, in.Current, in.New); err != nil {
		return nil, err
	}
	return noContent()
}

func (s *Server) BeginTOTP(c *gen.Call) (*gen.Result, error) {
	e, err := s.d.Auth.BeginTOTP(c.R.Context(), c.Principal)
	if err != nil {
		return nil, err
	}
	return ok(map[string]string{"secret": e.Secret, "uri": e.URI})
}

func (s *Server) ConfirmTOTP(c *gen.Call) (*gen.Result, error) {
	var in struct {
		Code string `json:"code"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	codes, token, err := s.d.Auth.ConfirmTOTP(c.R.Context(), c.Principal, in.Code, s.meta(c.R))
	if err != nil {
		return nil, err
	}
	// A full session is rotated on enrollment (SR-27); a limited one is unchanged and finishes with verifyMFA.
	return &gen.Result{SetSession: token, Body: map[string]any{"codes": codes}}, nil
}

func (s *Server) DisableTOTP(c *gen.Call) (*gen.Result, error) {
	if err := s.d.Auth.DisableTOTP(c.R.Context(), c.Principal); err != nil {
		return nil, err
	}
	return noContent()
}

func (s *Server) RegenerateRecoveryCodes(c *gen.Call) (*gen.Result, error) {
	codes, err := s.d.Auth.RegenerateRecoveryCodes(c.R.Context(), c.Principal)
	if err != nil {
		return nil, err
	}
	return ok(map[string]any{"codes": codes})
}

func (s *Server) ListMyIdentities(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.OIDC.Identities(c.R.Context(), c.Principal.Operator.ID)
	if err != nil {
		return nil, err
	}
	return ok(list(v))
}

// ---- operators

func (s *Server) ListOperators(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Auth.List(c.R.Context())
	if err != nil {
		return nil, err
	}
	return ok(list(v))
}

func (s *Server) CreateOperator(c *gen.Call) (*gen.Result, error) {
	var in opauth.CreateInput
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	in.Password = "" // passwords are set by the operator through an invitation or reset token
	op, err := s.d.Auth.Create(c.R.Context(), actor(c), in)
	if err != nil {
		return nil, err
	}
	return created(op)
}

func (s *Server) GetOperator(c *gen.Call) (*gen.Result, error) {
	op, err := s.d.Auth.Get(c.R.Context(), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return ok(op)
}

func (s *Server) UpdateOperator(c *gen.Call) (*gen.Result, error) {
	var in struct {
		Roles   *[]string `json:"roles"`
		Enabled *bool     `json:"enabled"`
		Groups  *[]string `json:"groups"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	ctx, id := c.R.Context(), c.R.PathValue("id")
	if err := notTokenOwner(c, id); err != nil {
		return nil, err
	}
	if in.Enabled != nil && !*in.Enabled && id == c.Principal.Operator.ID {
		return nil, apperr.New(apperr.CodePrecondition, "you cannot disable your own account")
	}
	var op *opauth.Operator
	var err error
	if in.Roles != nil {
		if op, err = s.d.Auth.SetRoles(ctx, actor(c), id, *in.Roles); err != nil {
			return nil, err
		}
	}
	if in.Groups != nil {
		if op, err = s.d.Auth.SetGroups(ctx, actor(c), id, *in.Groups); err != nil {
			return nil, err
		}
	}
	if in.Enabled != nil {
		if op, err = s.d.Auth.SetEnabled(ctx, actor(c), id, *in.Enabled); err != nil {
			return nil, err
		}
	}
	if op == nil {
		if op, err = s.d.Auth.Get(ctx, id); err != nil {
			return nil, err
		}
	}
	return ok(op)
}

func (s *Server) IssueResetToken(c *gen.Call) (*gen.Result, error) {
	tok, exp, err := s.d.Auth.IssueResetToken(c.R.Context(), actor(c), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return ok(map[string]any{"token": tok, "expires_at": exp.UTC(), "url": "/reset/" + tok})
}

func (s *Server) ListOperatorSessions(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Auth.ListSessions(c.R.Context(), c.R.PathValue("id"), c.Principal.SessionID)
	if err != nil {
		return nil, err
	}
	return ok(list(v))
}

func (s *Server) RevokeOperatorSessions(c *gen.Call) (*gen.Result, error) {
	if err := s.d.Auth.RevokeAllSessions(c.R.Context(), c.R.PathValue("id"), "revoked_by_admin"); err != nil {
		return nil, err
	}
	return noContent()
}

// notTokenOwner refuses an API token's change to the roles, groups or enabled state of the operator it acts for
// (ADR-0059): Terraform must not lock out or re-shape the account its own token depends on.
func notTokenOwner(c *gen.Call, operatorID string) error {
	if c.Principal.TokenID != "" && operatorID == c.Principal.Operator.ID {
		return apperr.New(apperr.CodePrecondition, "an API token cannot change the operator it acts for")
	}
	return nil
}

func (s *Server) ListOperatorIdentities(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.OIDC.Identities(c.R.Context(), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return ok(list(v))
}

func (s *Server) LinkOperatorIdentity(c *gen.Call) (*gen.Result, error) {
	var in struct {
		ProviderID string `json:"provider_id"`
		Subject    string `json:"subject"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	if err := s.d.OIDC.LinkIdentity(c.R.Context(), actor(c), c.R.PathValue("id"), in.ProviderID, in.Subject); err != nil {
		return nil, err
	}
	return noContent()
}

func (s *Server) UnlinkOperatorIdentity(c *gen.Call) (*gen.Result, error) {
	q := c.R.URL.Query()
	if err := s.d.OIDC.UnlinkIdentity(c.R.Context(), actor(c), c.R.PathValue("id"), q.Get("issuer"), q.Get("subject")); err != nil {
		return nil, err
	}
	return noContent()
}

func (s *Server) IssueLinkInvite(c *gen.Call) (*gen.Result, error) {
	var in struct {
		ProviderID string `json:"provider_id"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	p, err := s.d.OIDC.GetProvider(c.R.Context(), in.ProviderID)
	if err != nil {
		return nil, err
	}
	tok, exp, err := s.d.OIDC.IssueLinkInvite(c.R.Context(), actor(c), c.R.PathValue("id"), in.ProviderID)
	if err != nil {
		return nil, err
	}
	return ok(map[string]any{"token": tok, "expires_at": exp.UTC(),
		"url": "/auth/oidc/" + url.PathEscape(p.Slug) + "/start?purpose=link&link_token=" + url.QueryEscape(tok)})
}

// ListInvitations returns pending invitations without their tokens (HP-AUTH-011).
func (s *Server) ListInvitations(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Auth.ListInvitations(c.R.Context())
	if err != nil {
		return nil, err
	}
	return ok(list(v))
}

// RevokeInvitation invalidates a pending invitation (audited, recent authentication).
func (s *Server) RevokeInvitation(c *gen.Call) (*gen.Result, error) {
	if err := s.d.Auth.RevokeInvitation(c.R.Context(), actor(c), c.R.PathValue("id")); err != nil {
		return nil, err
	}
	return noContent()
}

func (s *Server) CreateInvitation(c *gen.Call) (*gen.Result, error) {
	var in struct {
		Email string   `json:"email"`
		Roles []string `json:"roles"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	tok, exp, err := s.d.Auth.Invite(c.R.Context(), actor(c), in.Email, in.Roles)
	if err != nil {
		return nil, err
	}
	return ok(map[string]any{"token": tok, "expires_at": exp.UTC(), "url": "/invite/" + tok})
}
