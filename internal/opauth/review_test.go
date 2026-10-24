package opauth

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Regression tests for the 2026-10-24 internal security review (docs/security/review-2026-10-24.md).

func (f *fx) auditCount(action string) int {
	f.t.Helper()
	rows, err := f.s.R().AuditEventsFrom(f.ctx, db.AuditEventsFromParams{Seq: 0, Limit: 10000})
	must(f.t, err)
	n := 0
	for _, r := range rows {
		if r.Action == action {
			n++
		}
	}
	return n
}

func (f *fx) session(opID, method string, meta SessionMeta) (string, *Principal) {
	f.t.Helper()
	var token string
	must(f.t, f.s.W().Tx(f.ctx, func(tx *store.Tx) error {
		var err error
		token, err = f.svc.CreateSessionTx(f.ctx, tx, opID, method, meta)
		return err
	}))
	p, err := f.svc.Authenticate(f.ctx, token)
	must(f.t, err)
	return token, p
}

// SR-01: a password alone (an MFA-pending session) can neither confirm nor restart enrollment over a confirmed
// factor, not even with a replayed valid code, and enrollment failures are throttled.
func TestReviewSR01ConfirmNeedsVerifiedFactor(t *testing.T) {
	f := newFx(t)
	op := f.bootstrap()
	f.loginEnrolled(op.Email)
	res, err := f.svc.Login(f.ctx, LoginInput{Email: op.Email, Password: strongPW})
	must(t, err)
	if !res.MFAPending {
		t.Fatal("second login not MFA-pending")
	}
	replayed := f.totpCode(op.ID) // the code the victim just used
	if _, _, err := f.svc.ConfirmTOTP(f.ctx, res.Principal, replayed, SessionMeta{}); !errors.Is(err, ErrCompleteMFAFirst) {
		t.Fatalf("confirm on an MFA-pending session: %v", err)
	}
	if _, err := f.svc.BeginTOTP(f.ctx, res.Principal); !errors.Is(err, ErrCompleteMFAFirst) {
		t.Fatalf("begin on an MFA-pending session: %v", err)
	}
	p, err := f.svc.Authenticate(f.ctx, res.Token)
	must(t, err)
	if !p.Limited || p.MFAAt != nil || f.svc.RequireRecentAuth(p, true) == nil {
		t.Fatalf("MFA-pending session upgraded: %+v", p)
	}
	if n, _ := f.s.R().CountUnusedRecoveryCodes(f.ctx, op.ID); n != RecoveryCodeCount {
		t.Fatalf("recovery codes replaced: %d", n)
	}

	// Enrollment codes share the MFA throttle (a NeedsEnroll session).
	other, err := f.svc.Create(f.ctx, audit.Actor{Type: audit.ActorOperator, ID: op.ID}, CreateInput{Email: "appr@example.com", DisplayName: "A",
		Roles: []string{RoleApprover}, Password: strongPW})
	must(t, err)
	res, err = f.svc.Login(f.ctx, LoginInput{Email: other.Email, Password: strongPW})
	must(t, err)
	if !res.MustEnroll {
		t.Fatal("approver not forced to enroll")
	}
	_, err = f.svc.BeginTOTP(f.ctx, res.Principal)
	must(t, err)
	for range 4 {
		_, _, _ = f.svc.ConfirmTOTP(f.ctx, res.Principal, "000000", SessionMeta{IP: "203.0.113.9"})
	}
	if _, _, err := f.svc.ConfirmTOTP(f.ctx, res.Principal, f.pendingCode(other.ID), SessionMeta{}); !errors.Is(err, ErrThrottled) {
		t.Fatalf("enrollment guessing not throttled: %v", err)
	}
	if f.auditCount("operator.mfa.failed") < 4 {
		t.Fatal("enrollment failures not audited")
	}
	// After the throttle a valid confirmation works once; the pending secret is single use.
	f.clk.Advance(20 * time.Minute)
	_, err = f.svc.BeginTOTP(f.ctx, res.Principal)
	must(t, err)
	code := f.pendingCode(other.ID)
	_, _, err = f.svc.ConfirmTOTP(f.ctx, res.Principal, code, SessionMeta{})
	must(t, err)
	p, err = f.svc.Authenticate(f.ctx, res.Token)
	must(t, err)
	if _, _, err := f.svc.ConfirmTOTP(f.ctx, p, code, SessionMeta{}); err == nil {
		t.Fatal("confirmation replayed")
	}
}

// SR-03: enrollment, ReauthTOTP and VerifyMFA never refresh a stale session's authentication.
func TestReviewSR03NoRecentAuthBypass(t *testing.T) {
	f := newFx(t)
	op := f.bootstrap()
	// (a) a stale SSO session cannot enroll its own factor to pass reauth gates.
	_, sso := f.session(op.ID, MethodOIDC, SessionMeta{Provider: "corp"})
	f.clk.Advance(10 * time.Minute)
	sso.AuthAt = f.clk.Now().Add(-10 * time.Minute)
	if _, err := f.svc.BeginTOTP(f.ctx, sso); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("stale SSO session started enrollment: %v", err)
	}
	// (c) VerifyMFA refuses full sessions (it used to refresh auth_at and turn them into password sessions).
	if _, err := f.svc.VerifyMFA(f.ctx, sso, "000000", SessionMeta{}); !errors.Is(err, ErrNoMFAPending) {
		t.Fatalf("VerifyMFA on a full SSO session: %v", err)
	}
	// (b) ReauthTOTP is for SSO sessions only.
	tok, _ := f.loginEnrolled(op.Email)
	f.clk.Advance(10 * time.Minute)
	p, err := f.svc.Authenticate(f.ctx, tok)
	must(t, err)
	f.clk.Advance(30 * time.Second)
	if _, err := f.svc.ReauthTOTP(f.ctx, p, f.totpCode(op.ID), SessionMeta{}); !errors.Is(err, ErrTOTPStepUpNotAllowed) {
		t.Fatalf("ReauthTOTP on a password session: %v", err)
	}
	if _, err := f.svc.VerifyMFA(f.ctx, p, f.totpCode(op.ID), SessionMeta{}); !errors.Is(err, ErrNoMFAPending) {
		t.Fatalf("VerifyMFA on a full password session: %v", err)
	}
	if err := f.svc.RequireRecentAuth(p, true); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("stale session became recent: %v", err)
	}

	// Enrollment on a full session keeps the original authentication time and rotates the session.
	aud, err := f.svc.Create(f.ctx, audit.Actor{Type: audit.ActorOperator, ID: op.ID}, CreateInput{Email: "aud@example.com", DisplayName: "Aud",
		Roles: []string{RoleAuditor}, Password: strongPW})
	must(t, err)
	res, err := f.svc.Login(f.ctx, LoginInput{Email: aud.Email, Password: strongPW})
	must(t, err)
	authAt := res.Principal.AuthAt
	f.clk.Advance(2 * time.Minute)
	_, err = f.svc.BeginTOTP(f.ctx, res.Principal)
	must(t, err)
	_, rotated, err := f.svc.ConfirmTOTP(f.ctx, res.Principal, f.pendingCode(aud.ID), SessionMeta{})
	must(t, err)
	p2, err := f.svc.Authenticate(f.ctx, rotated)
	must(t, err)
	if !p2.AuthAt.Equal(authAt) || p2.MFAAt == nil || p2.Limited {
		t.Fatalf("enrollment refreshed auth_at: before %s after %s (%+v)", authAt, p2.AuthAt, p2)
	}
}

// SR-04: starting and abandoning a re-enrollment keeps the confirmed factor working.
func TestReviewSR04AbandonedReenrollment(t *testing.T) {
	f := newFx(t)
	op := f.bootstrap()
	_, p := f.loginEnrolled(op.Email)
	_, err := f.svc.BeginTOTP(f.ctx, p)
	must(t, err)
	got, err := f.svc.Get(f.ctx, op.ID)
	must(t, err)
	if !got.MFAEnrolled {
		t.Fatal("abandoned re-enrollment removed the confirmed factor")
	}
	// An attacker with the password is not offered enrollment; the old factor still completes login.
	res, err := f.svc.Login(f.ctx, LoginInput{Email: op.Email, Password: strongPW})
	must(t, err)
	if res.MustEnroll || !res.MFAPending {
		t.Fatalf("login after abandoned re-enrollment: %+v", res)
	}
	f.clk.Advance(30 * time.Second)
	old := f.totpCode(op.ID)
	tok, err := f.svc.VerifyMFA(f.ctx, res.Principal, old, SessionMeta{})
	must(t, err)
	// Confirming the new secret replaces the factor.
	p, err = f.svc.Authenticate(f.ctx, tok)
	must(t, err)
	_, err = f.svc.BeginTOTP(f.ctx, p)
	must(t, err)
	newCode := f.pendingCode(op.ID)
	if newCode == old {
		t.Skip("old and new secret collide on this step")
	}
	_, _, err = f.svc.ConfirmTOTP(f.ctx, p, newCode, SessionMeta{})
	must(t, err)
	if f.totpCode(op.ID) != newCode {
		t.Fatal("confirmed secret not stored")
	}
}

// SR-05: wrong passwords and codes on reauthentication and password change are throttled and audited.
func TestReviewSR05ReauthThrottle(t *testing.T) {
	f := newFx(t)
	op := f.bootstrap()
	_, p := f.loginEnrolled(op.Email)
	for range 4 {
		_, _ = f.svc.Reauth(f.ctx, p, "wrong password!!", "", SessionMeta{})
	}
	if _, err := f.svc.Reauth(f.ctx, p, strongPW, f.totpCode(op.ID), SessionMeta{}); !errors.Is(err, ErrThrottled) {
		t.Fatalf("reauth password guessing not throttled: %v", err)
	}
	if err := f.svc.ChangePassword(f.ctx, p, strongPW, "another long password"); !errors.Is(err, ErrThrottled) {
		t.Fatalf("password change not throttled with the account: %v", err)
	}
	if f.auditCount("operator.password.failed") != 4 {
		t.Fatalf("password failures audited: %d", f.auditCount("operator.password.failed"))
	}
	f.clk.Advance(20 * time.Minute)
	_, p = f.loginEnrolled(op.Email)
	for range 4 {
		_, _ = f.svc.Reauth(f.ctx, p, strongPW, "000000", SessionMeta{})
	}
	if _, err := f.svc.Reauth(f.ctx, p, strongPW, "000001", SessionMeta{}); !errors.Is(err, ErrThrottled) {
		t.Fatalf("reauth code guessing not throttled: %v", err)
	}
	// The MFA key is shared: the login second factor is throttled too.
	res, err := f.svc.Login(f.ctx, LoginInput{Email: op.Email, Password: strongPW})
	must(t, err)
	if _, err := f.svc.VerifyMFA(f.ctx, res.Principal, f.totpCode(op.ID), SessionMeta{}); !errors.Is(err, ErrThrottled) {
		t.Fatalf("MFA throttle not shared: %v", err)
	}
	// SSO step-up fallback codes count against the same key.
	f.clk.Advance(20 * time.Minute)
	_, sso := f.session(op.ID, MethodOIDC, SessionMeta{Provider: "corp"})
	for range 4 {
		_, _ = f.svc.ReauthTOTP(f.ctx, sso, "000000", SessionMeta{})
	}
	if _, err := f.svc.ReauthTOTP(f.ctx, sso, f.totpCode(op.ID), SessionMeta{}); !errors.Is(err, ErrThrottled) {
		t.Fatalf("TOTP step-up guessing not throttled: %v", err)
	}
}

// SR-07: redeeming break-glass revokes other sessions, removes the lost factor, forces re-enrollment, issues a
// reset token, and failed redemptions are throttled and audited.
func TestReviewSR07RecoveryRedeem(t *testing.T) {
	f := newFx(t)
	op := f.bootstrap()
	oldTok, _ := f.loginEnrolled(op.Email)
	tok, _, err := f.svc.IssueRecoveryLogin(f.ctx, op.ID, "")
	must(t, err)
	f.clk.Advance(time.Minute)
	rec, err := f.svc.RecoveryLogin(f.ctx, tok, SessionMeta{IP: "192.0.2.10"})
	must(t, err)
	if _, err := f.svc.Authenticate(f.ctx, oldTok); err == nil {
		t.Fatal("pre-recovery session survived")
	}
	if !rec.MFAReset || rec.ResetToken == "" || !rec.Principal.Limited || !rec.Principal.NeedsEnroll || rec.Principal.Method != MethodBreakGlass {
		t.Fatalf("recovery result %+v principal %+v", rec, rec.Principal)
	}
	if n, _ := f.s.R().CountUnusedRecoveryCodes(f.ctx, op.ID); n != 0 {
		t.Fatalf("recovery codes kept: %d", n)
	}
	if _, err := f.svc.RecoveryLogin(f.ctx, tok, SessionMeta{IP: "192.0.2.10"}); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("recovery token reused: %v", err)
	}
	// The reset token sets a password the administrator knows (and ends the recovery session).
	must(t, f.svc.ResetPassword(f.ctx, rec.ResetToken, "a brand new long password"))
	if _, err := f.svc.Authenticate(f.ctx, rec.Token); err == nil {
		t.Fatal("reset left the recovery session alive")
	}
	if _, err := f.svc.Login(f.ctx, LoginInput{Email: op.Email, Password: "a brand new long password"}); err != nil {
		t.Fatalf("login with the reset password: %v", err)
	}
	// Expired tokens and guesses are refused, audited and throttled per source.
	tok2, _, err := f.svc.IssueRecoveryLogin(f.ctx, op.ID, "")
	must(t, err)
	f.clk.Advance(RecoveryLoginTTL + time.Second)
	if _, err := f.svc.RecoveryLogin(f.ctx, tok2, SessionMeta{IP: "198.51.100.20"}); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expired recovery token: %v", err)
	}
	for range 3 {
		_, _ = f.svc.RecoveryLogin(f.ctx, "guess", SessionMeta{IP: "198.51.100.20"})
	}
	if _, err := f.svc.RecoveryLogin(f.ctx, "guess", SessionMeta{IP: "198.51.100.20"}); !errors.Is(err, ErrThrottled) {
		t.Fatalf("recovery guessing not throttled: %v", err)
	}
	if n := f.auditCount("breakglass.login.failed"); n != 5 {
		t.Fatalf("failed redemptions audited: %d", n)
	}
}

// SR-26: SSO-sourced roles do not apply to password sessions.
func TestReviewSR26SSORolesOnlyForSSOSessions(t *testing.T) {
	f := newFx(t)
	admin := f.bootstrap()
	op, err := f.svc.Create(f.ctx, audit.Actor{Type: audit.ActorOperator, ID: admin.ID}, CreateInput{Email: "v@example.com", DisplayName: "V",
		Roles: []string{RoleViewer}, Password: strongPW})
	must(t, err)
	must(t, f.s.W().Tx(f.ctx, func(tx *store.Tx) error {
		return tx.Q.InsertSSORole(f.ctx, db.InsertSSORoleParams{OperatorID: op.ID, Role: RoleApprover, SourceRef: "approvers"})
	}))
	_, pw := f.session(op.ID, MethodPassword, SessionMeta{})
	if pw.HasRole(RoleApprover) || !pw.HasRole(RoleViewer) {
		t.Fatalf("password session roles %v", pw.Operator.Roles)
	}
	_, sso := f.session(op.ID, MethodOIDC, SessionMeta{Provider: "corp"})
	if !sso.HasRole(RoleApprover) || !sso.HasRole(RoleViewer) {
		t.Fatalf("SSO session roles %v", sso.Operator.Roles)
	}
}

// SR-27: a privilege elevation is granted only to new sessions.
func TestReviewSR27ElevationRevokesSessions(t *testing.T) {
	f := newFx(t)
	admin := f.bootstrap()
	actor := audit.Actor{Type: audit.ActorOperator, ID: admin.ID}
	op, err := f.svc.Create(f.ctx, actor, CreateInput{Email: "v@example.com", DisplayName: "V", Roles: []string{RoleViewer}})
	must(t, err)
	tok, _ := f.session(op.ID, MethodOIDC, SessionMeta{})
	_, err = f.svc.SetRoles(f.ctx, actor, op.ID, []string{RoleViewer, RoleApprover})
	must(t, err)
	if _, err := f.svc.Authenticate(f.ctx, tok); err == nil {
		t.Fatal("session survived privilege elevation")
	}
	tok, _ = f.session(op.ID, MethodOIDC, SessionMeta{})
	_, err = f.svc.SetRoles(f.ctx, actor, op.ID, []string{RoleApprover, RoleViewer}) // unchanged
	must(t, err)
	if _, err := f.svc.Authenticate(f.ctx, tok); err != nil {
		t.Fatal("unchanged roles revoked sessions")
	}
}

// SR-09 support: Validate checks a session without extending its idle timer.
func TestReviewValidateDoesNotTouch(t *testing.T) {
	f := newFx(t)
	op := f.bootstrap()
	tok, _ := f.session(op.ID, MethodOIDC, SessionMeta{})
	for range 2 {
		f.clk.Advance(10 * time.Minute)
		if _, err := f.svc.Validate(f.ctx, tok); err != nil {
			t.Fatalf("validate: %v", err)
		}
	}
	f.clk.Advance(11 * time.Minute)
	if _, err := f.svc.Authenticate(f.ctx, tok); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Validate kept the session alive past the idle timeout: %v", err)
	}
}

func TestReviewRolesWithoutSource(t *testing.T) {
	got := rolesWithoutSource([]RoleAssignment{{Role: "b", Source: "manual"}, {Role: "a", Source: "sso"}, {Role: "b", Source: "sso"}, {Role: "c"}}, "sso")
	if !slices.Equal(got, []string{"b", "c"}) {
		t.Fatal(got)
	}
}

// SR-07: a break-glass session re-authenticates with the account's password and new factor once its 5-minute window
// has passed; it stays a break-glass session.
func TestReviewSR07BreakGlassReauth(t *testing.T) {
	f := newFx(t)
	op := f.bootstrap()
	tok, _, err := f.svc.IssueRecoveryLogin(f.ctx, op.ID, "")
	must(t, err)
	rec, err := f.svc.RecoveryLogin(f.ctx, tok, SessionMeta{})
	must(t, err)
	_, err = f.svc.BeginTOTP(f.ctx, rec.Principal)
	must(t, err)
	_, _, err = f.svc.ConfirmTOTP(f.ctx, rec.Principal, f.pendingCode(op.ID), SessionMeta{})
	must(t, err)
	f.clk.Advance(6 * time.Minute)
	p, err := f.svc.Authenticate(f.ctx, rec.Token)
	must(t, err)
	if err := f.svc.RequireRecentAuth(p, true); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("stale break-glass session: %v", err)
	}
	tok2, err := f.svc.Reauth(f.ctx, p, strongPW, f.totpCode(op.ID), SessionMeta{})
	must(t, err)
	p2, err := f.svc.Authenticate(f.ctx, tok2)
	must(t, err)
	if p2.Method != MethodBreakGlass || f.svc.RequireRecentAuth(p2, true) != nil {
		t.Fatalf("after reauth: %+v", p2)
	}
}
