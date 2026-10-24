package oidc

import (
	"encoding/base32"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/oidc/oidctest"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
)

// Regression tests for the 2026-10-24 internal security review (docs/security/review-2026-10-24.md).

func totpNow(t *testing.T, secretB32 string, now time.Time) string {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	must(t, err)
	return opauth.TOTPCode(secret, opauth.TOTPStep(now))
}

func (f *fx) roles(opID string) []string {
	f.t.Helper()
	rs, err := f.s.R().ListOperatorRoles(f.ctx, opID)
	must(f.t, err)
	out := []string{}
	for _, r := range rs {
		out = append(out, r.Role+"/"+r.Source)
	}
	return out
}

// ssoOnlySetup: a local administrator, an operator who is administrator only through the IdP "admins" group, a
// completed test login and SSO-only enforcement on.
func (f *fx) ssoOnlySetup() (local, sso *opauth.Operator) {
	f.t.Helper()
	local = f.operator("local@example.com", opauth.RoleAdministrator)
	sso = f.operator("sso@example.com")
	must(f.t, f.svc.LinkIdentity(f.ctx, admin, sso.ID, f.prov.ID, "user-1"))
	_, err := f.svc.AddMapping(f.ctx, admin, f.prov.ID, "admins", opauth.RoleAdministrator, "")
	must(f.t, err)
	f.idp.Set(func(i *oidctest.IdP) { i.User.Claims["groups"] = []string{"admins"} })
	if res, err := f.flow(PurposeLogin, nil); err != nil || res.OperatorID != sso.ID {
		f.t.Fatalf("sso login: %v", err)
	}
	_, err = f.flow(PurposeTest, f.localSession(local.Email))
	must(f.t, err)
	must(f.t, f.svc.SetLocalLoginDisabled(f.ctx, admin, true))
	return local, sso
}

// SR-06: under SSO-only enforcement the last SSO-capable administrator survives disable, role edits and IdP sync,
// although a local administrator (who cannot sign in) still exists.
func TestReviewSR06SSOOnlyAdminInvariant(t *testing.T) {
	f := newFx(t)
	_, sso := f.ssoOnlySetup()
	if _, err := f.auth.SetEnabled(f.ctx, admin, sso.ID, false); !errors.Is(err, opauth.ErrLastSSOAdmin) {
		t.Fatalf("disabled the only SSO administrator: %v", err)
	}
	// The IdP drops the admin group: the SSO administrator role is kept and the conflict audited.
	f.idp.Set(func(i *oidctest.IdP) { i.User.Claims["groups"] = []string{} })
	_, err := f.flow(PurposeLogin, nil)
	must(t, err)
	if n, err := f.s.R().CountSSOAdmins(f.ctx); err != nil || n != 1 || !slices.Contains(f.roles(sso.ID), "administrator/sso") {
		t.Fatalf("group sync removed the last SSO administrator: n=%d roles=%v err=%v", n, f.roles(sso.ID), err)
	}
	// With a manual administrator role the SSO one can go; removing the manual role is then refused.
	_, err = f.auth.SetRoles(f.ctx, admin, sso.ID, []string{opauth.RoleAdministrator})
	must(t, err)
	_, err = f.flow(PurposeLogin, nil)
	must(t, err)
	if slices.Contains(f.roles(sso.ID), "administrator/sso") {
		t.Fatalf("stale SSO role kept: %v", f.roles(sso.ID))
	}
	if _, err := f.auth.SetRoles(f.ctx, admin, sso.ID, []string{}); !errors.Is(err, opauth.ErrLastSSOAdmin) {
		t.Fatalf("demoted the only SSO administrator: %v", err)
	}
	// Turning SSO-only off lifts the SSO-specific guard.
	must(t, f.svc.SetLocalLoginDisabled(f.ctx, admin, false))
	_, err = f.auth.SetRoles(f.ctx, admin, sso.ID, []string{})
	must(t, err)
}

// SR-10: self-service account linking needs recent authentication.
func TestReviewSR10SelfLinkNeedsRecentAuth(t *testing.T) {
	f := newFx(t)
	op := f.operator("a@example.com")
	p := f.localSession(op.Email)
	f.clk.Advance(10 * time.Minute)
	if _, err := f.svc.Start(f.ctx, StartInput{Provider: "corp", Purpose: PurposeLink, Principal: p}); !errors.Is(err, opauth.ErrReauthRequired) {
		t.Fatalf("stale session started self-link: %v", err)
	}
	p = f.localSession(op.Email)
	if _, err := f.flow(PurposeLink, p); err != nil {
		t.Fatalf("fresh self-link: %v", err)
	}
}

// SR-48: an MFA-pending (Limited) administrator session cannot run the SSO test login.
func TestReviewSR48TestLoginNeedsFullSession(t *testing.T) {
	f := newFx(t)
	op := f.operator("root@example.com", opauth.RoleAdministrator)
	limited := &opauth.Principal{Operator: op, SessionID: "wss_x", Method: opauth.MethodPassword, Limited: true}
	if _, err := f.svc.Start(f.ctx, StartInput{Provider: "corp", Purpose: PurposeTest, Principal: limited}); !isCode(err, apperr.CodeForbidden) {
		t.Fatalf("limited session started a test login: %v", err)
	}
	if _, err := f.flow(PurposeTest, f.localSession(op.Email)); err != nil {
		t.Fatalf("full admin session: %v", err)
	}
}

// SR-03 (b): the TOTP step-up fallback needs an SSO session whose provider allows it.
func TestReviewSR03TOTPFallbackNeedsProviderOptIn(t *testing.T) {
	f := newFx(t)
	op := f.operator("alice@example.com", opauth.RoleApprover)
	must(t, f.svc.LinkIdentity(f.ctx, admin, op.ID, f.prov.ID, "user-1"))
	p := f.principal(mustToken(t, mustFlow(t, f, PurposeLogin, nil)))
	enr, err := f.auth.BeginTOTP(f.ctx, p)
	must(t, err)
	_, tok, err := f.auth.ConfirmTOTP(f.ctx, p, totpNow(t, enr.Secret, f.clk.Now()), f.meta)
	must(t, err)
	p = f.principal(tok)
	f.clk.Advance(30 * time.Second)
	if _, err := f.svc.ReauthTOTP(f.ctx, p, totpNow(t, enr.Secret, f.clk.Now()), f.meta); !errors.Is(err, opauth.ErrTOTPStepUpNotAllowed) {
		t.Fatalf("TOTP step-up with stepup_fallback=none: %v", err)
	}
	pw := f.localSession(op.Email)
	if _, err := f.svc.ReauthTOTP(f.ctx, pw, totpNow(t, enr.Secret, f.clk.Now()), f.meta); !errors.Is(err, opauth.ErrTOTPStepUpNotAllowed) {
		t.Fatalf("TOTP step-up on a password session: %v", err)
	}
	pr, err := f.svc.UpdateProvider(f.ctx, admin, f.prov.ID, ProviderInput{Version: f.prov.Version, StepUpFallback: ptr(StepUpLocalTOTP)})
	must(t, err)
	f.prov = pr
	if _, err := f.svc.ReauthTOTP(f.ctx, p, totpNow(t, enr.Secret, f.clk.Now()), f.meta); err != nil {
		t.Fatalf("TOTP step-up with local_totp: %v", err)
	}
}

// SR-26: deleting a provider removes the SSO-sourced roles and groups of the operators linked to it.
func TestReviewSR26DeleteProviderDropsSSORoles(t *testing.T) {
	f := newFx(t)
	f.operator("root@example.com", opauth.RoleAdministrator)
	op := f.operator("alice@example.com", opauth.RoleViewer)
	must(t, f.svc.LinkIdentity(f.ctx, admin, op.ID, f.prov.ID, "user-1"))
	_, err := f.svc.AddMapping(f.ctx, admin, f.prov.ID, "approvers", opauth.RoleApprover, "")
	must(t, err)
	f.idp.Set(func(i *oidctest.IdP) { i.User.Claims["groups"] = []string{"approvers"} })
	mustFlow(t, f, PurposeLogin, nil)
	if !slices.Contains(f.roles(op.ID), "approver/sso") {
		t.Fatalf("mapping not applied: %v", f.roles(op.ID))
	}
	must(t, f.svc.DeleteProvider(f.ctx, admin, f.prov.ID))
	if got := f.roles(op.ID); !slices.Equal(got, []string{"viewer/manual"}) {
		t.Fatalf("SSO roles survived provider deletion: %v", got)
	}
}

// SR-26: a provider whose deletion would strip the last administrator role is kept.
func TestReviewSR26DeleteProviderKeepsLastAdmin(t *testing.T) {
	f := newFx(t)
	op := f.operator("alice@example.com")
	must(t, f.svc.LinkIdentity(f.ctx, admin, op.ID, f.prov.ID, "user-1"))
	_, err := f.svc.AddMapping(f.ctx, admin, f.prov.ID, "admins", opauth.RoleAdministrator, "")
	must(t, err)
	f.idp.Set(func(i *oidctest.IdP) { i.User.Claims["groups"] = []string{"admins"} })
	mustFlow(t, f, PurposeLogin, nil)
	if err := f.svc.DeleteProvider(f.ctx, admin, f.prov.ID); !errors.Is(err, opauth.ErrLastAdmin) {
		t.Fatalf("deleted the provider of the only administrator: %v", err)
	}
	if _, err := f.svc.GetProvider(f.ctx, f.prov.ID); err != nil {
		t.Fatal(err)
	}
}

// SR-24: fragments that redirect path-cleaning would turn into /api or /auth are refused.
func TestReviewSR24ReturnToFragment(t *testing.T) {
	for _, in := range []string{"/#/../api/v1/me", "/x#/../../auth/oidc/corp/start?purpose=link", "/x#y/../../api", "/a//b"} {
		if got := SanitizeReturnTo(in); got != "/" {
			t.Errorf("%q accepted", in)
		}
	}
	for _, in := range []string{"/sessions/ses_1#t=3", "/requests/", "/x?y=/../api"} {
		if got := SanitizeReturnTo(in); got != in {
			t.Errorf("%q rewritten to %q", in, got)
		}
	}
}
