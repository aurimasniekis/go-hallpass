package opauth

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/keyring/keyringtest"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
)

func TestMain(m *testing.M) {
	// Light parameters keep race-enabled tests fast; production parameters are exercised by TestArgon2Production.
	ParamSets[2] = Params{Version: 2, Memory: 8 * 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}
	CurrentParams = ParamSets[2]
	os.Exit(m.Run())
}

const strongPW = "correct horse battery staple"

type fx struct {
	t   *testing.T
	ctx context.Context
	clk *clock.Fake
	s   *store.Store
	svc *Service
	kr  *keyring.Keyring
}

func newFx(t *testing.T) *fx {
	t.Helper()
	clk := clock.NewFake(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
	s := storetest.Open(t, storetest.WithClock(clk))
	kr := keyringtest.Load(t, s)
	return &fx{t: t, ctx: context.Background(), clk: clk, s: s, kr: kr,
		svc: New(s, kr, audit.NewWriter(kr), eventbus.New(), Options{Clock: clk})}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fx) bootstrap() *Operator {
	f.t.Helper()
	tok, _, err := f.svc.IssueSetupToken(f.ctx)
	must(f.t, err)
	op, err := f.svc.Bootstrap(f.ctx, BootstrapInput{Token: tok, Email: "Admin@Example.com", DisplayName: "Admin", Password: strongPW})
	must(f.t, err)
	return op
}

func (f *fx) totpCode(opID string) string {
	t, err := f.s.R().GetTOTP(f.ctx, opID)
	must(f.t, err)
	secret, err := f.kr.Open(keyring.PurposeField, totpAAD(opID), t.SecretEnc)
	must(f.t, err)
	return TOTPCode(secret, TOTPStep(f.clk.Now()))
}

// pendingCode is the current code of the operator's pending (unconfirmed) enrollment.
func (f *fx) pendingCode(opID string) string {
	t, err := f.s.R().GetTOTPPending(f.ctx, opID)
	must(f.t, err)
	secret, err := f.kr.Open(keyring.PurposeField, totpAAD(opID), t.SecretEnc)
	must(f.t, err)
	return TOTPCode(secret, TOTPStep(f.clk.Now()))
}

// login + enroll TOTP; returns a full (non-limited) session token.
func (f *fx) loginEnrolled(email string) (string, *Principal) {
	f.t.Helper()
	res, err := f.svc.Login(f.ctx, LoginInput{Email: email, Password: strongPW, Meta: SessionMeta{IP: "198.51.100.7"}})
	must(f.t, err)
	if res.MustEnroll {
		_, err := f.svc.BeginTOTP(f.ctx, res.Principal)
		must(f.t, err)
		codes, rotated, err := f.svc.ConfirmTOTP(f.ctx, res.Principal, f.pendingCode(res.Principal.Operator.ID), SessionMeta{})
		must(f.t, err)
		if len(codes) != RecoveryCodeCount || rotated != "" {
			f.t.Fatalf("recovery codes not issued or limited session rotated: %d %q", len(codes), rotated)
		}
		// Enrollment does not complete sign-in: the still-limited session verifies a later code.
		p, err := f.svc.Authenticate(f.ctx, res.Token)
		must(f.t, err)
		if !p.Limited || p.NeedsEnroll {
			f.t.Fatalf("after enrollment: limited=%v needsEnroll=%v", p.Limited, p.NeedsEnroll)
		}
		f.clk.Advance(30 * time.Second)
		tok, err := f.svc.VerifyMFA(f.ctx, p, f.totpCode(res.Principal.Operator.ID), SessionMeta{})
		must(f.t, err)
		p, err = f.svc.Authenticate(f.ctx, tok)
		must(f.t, err)
		return tok, p
	}
	if res.MFAPending {
		f.clk.Advance(30 * time.Second)
		tok, err := f.svc.VerifyMFA(f.ctx, res.Principal, f.totpCode(res.Principal.Operator.ID), SessionMeta{})
		must(f.t, err)
		p, err := f.svc.Authenticate(f.ctx, tok)
		must(f.t, err)
		return tok, p
	}
	return res.Token, res.Principal
}

// HP-AUTH-002/003
func TestPasswordHashing(t *testing.T) {
	pw, err := NormalizePassword(strongPW, 12)
	must(t, err)
	h, err := HashPassword(pw, CurrentParams)
	must(t, err)
	if !strings.HasPrefix(h, "$argon2id$v=19$m=8192,t=1,p=1$") {
		t.Fatal(h)
	}
	if ok, _ := VerifyPassword(pw, h); !ok {
		t.Fatal("verify failed")
	}
	if ok, _ := VerifyPassword([]byte(strongPW+"x"), h); ok {
		t.Fatal("wrong password verified")
	}
	// NFKC: compatibility forms normalize to the same password.
	a, _ := NormalizePassword("ﬁnest passphrase", 1)
	b, _ := NormalizePassword("finest passphrase", 1)
	if string(a) != string(b) {
		t.Fatal("NFKC normalization missing")
	}
	// No truncation: passwords differing only after byte 72 (the bcrypt limit) must differ.
	long := strings.Repeat("a", 100)
	ph, _ := HashPassword([]byte(long), CurrentParams)
	if ok, _ := VerifyPassword([]byte(long[:72]+strings.Repeat("b", 28)), ph); ok {
		t.Fatal("password truncated")
	}
	if _, err := NormalizePassword(strings.Repeat("x", 1024), 12); err != nil {
		t.Fatal("1024 bytes must be accepted")
	}
	for _, bad := range []string{"short", strings.Repeat("x", 1025), "has\x00nul-password"} {
		if _, err := NormalizePassword(bad, 12); err == nil {
			t.Errorf("accepted %q", bad[:min(len(bad), 10)])
		}
	}
	for _, mal := range []string{"", "$argon2i$v=19$m=1,t=1,p=1$AAAA$AAAA", "$argon2id$v=19$m=x$a$b", "$argon2id$v=19$m=65536,t=3,p=2$!!$!!"} {
		if _, err := VerifyPassword(pw, mal); err == nil {
			t.Errorf("malformed hash accepted: %q", mal)
		}
	}
}

func TestArgon2Production(t *testing.T) {
	p := ParamSets[1]
	if p.Memory < 64*1024 || p.Time < 3 {
		t.Fatalf("production parameters weakened: %+v", p)
	}
	if testing.Short() {
		t.Skip("short")
	}
	h, err := HashPassword([]byte(strongPW), p)
	must(t, err)
	if ok, _ := VerifyPassword([]byte(strongPW), h); !ok {
		t.Fatal("production params round trip failed")
	}
	if c := Calibrate(time.Millisecond); c.Time < 1 {
		t.Fatal("calibration")
	}
}

// RFC 6238 Appendix B vectors (SHA-1), truncated to 6 digits.
func TestTOTPVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for ts, want := range map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037", 20000000000: "353130"} {
		if got := TOTPCode(secret, ts/30); got != want {
			t.Errorf("t=%d: %s want %s", ts, got, want)
		}
	}
	now := time.Unix(1234567890, 0)
	if step, ok := VerifyTOTP(secret, "005924", now, 0); !ok || step != 1234567890/30 {
		t.Fatal("valid code rejected")
	}
	if _, ok := VerifyTOTP(secret, "005924", now, 1234567890/30); ok {
		t.Fatal("step reuse accepted (HP-AUTH-006)")
	}
	if _, ok := VerifyTOTP(secret, TOTPCode(secret, 1234567890/30-1), now, 0); !ok {
		t.Fatal("±1 step skew not accepted")
	}
	if _, ok := VerifyTOTP(secret, TOTPCode(secret, 1234567890/30-2), now, 0); ok {
		t.Fatal("2-step-old code accepted")
	}
	if !strings.HasPrefix(TOTPURI(secret, "HallPass", "a@b.c"), "otpauth://totp/HallPass:a@b.c?") {
		t.Fatal("uri")
	}
}

// HP-AUTH-001/008: bootstrap once; first admin must enroll MFA before using the console.
func TestBootstrapAndForcedEnrollment(t *testing.T) {
	f := newFx(t)
	op := f.bootstrap()
	if !slices.Equal(op.Roles, []string{RoleAdministrator}) || op.Email != "admin@example.com" || !op.MFARequired {
		t.Fatalf("%+v", op)
	}
	if _, _, err := f.svc.IssueSetupToken(f.ctx); !errors.Is(err, apperr.ErrPrecondition) {
		t.Fatal("second setup token issued after an admin exists")
	}
	res, err := f.svc.Login(f.ctx, LoginInput{Email: "admin@example.com", Password: strongPW})
	must(t, err)
	if !res.MustEnroll || !res.Principal.Limited {
		t.Fatalf("first login must force enrollment: %+v", res)
	}
	_, p := f.loginEnrolled("admin@example.com")
	if p.Limited || !p.Operator.MFAEnrolled {
		t.Fatalf("%+v", p)
	}
	// Next login requires the second factor.
	res2, err := f.svc.Login(f.ctx, LoginInput{Email: "admin@example.com", Password: strongPW})
	must(t, err)
	if !res2.MFAPending {
		t.Fatal("MFA not required on login")
	}
	if _, err := f.svc.VerifyMFA(f.ctx, res2.Principal, "000000", SessionMeta{}); err == nil {
		t.Fatal("wrong code accepted")
	}
}

func TestSetupTokenSingleUse(t *testing.T) {
	f := newFx(t)
	tok, _, err := f.svc.IssueSetupToken(f.ctx)
	must(t, err)
	_, err = f.svc.Bootstrap(f.ctx, BootstrapInput{Token: tok, Email: "a@example.com", Password: strongPW})
	must(t, err)
	if _, err := f.svc.Bootstrap(f.ctx, BootstrapInput{Token: tok, Email: "b@example.com", Password: strongPW}); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("setup token reused: %v", err)
	}
	f.clk.Advance(time.Hour)
	if _, err := f.svc.Bootstrap(f.ctx, BootstrapInput{Token: "made-up", Email: "c@example.com", Password: strongPW}); !errors.Is(err, ErrTokenInvalid) {
		t.Fatal(err)
	}
}

// HP-AUTH-004/005: throttling and enumeration resistance.
func TestLoginThrottlingAndEnumeration(t *testing.T) {
	f := newFx(t)
	f.bootstrap()
	n := 0
	bad := func(email string) error {
		n++ // a fresh source IP per attempt isolates the per-account throttle from the per-IP one
		_, err := f.svc.Login(f.ctx, LoginInput{Email: email, Password: "wrong password!!", Meta: SessionMeta{IP: "203.0.113." + itoa(n)}})
		return err
	}
	if err1, err2 := bad("admin@example.com"), bad("nobody@example.com"); err1.Error() != err2.Error() {
		t.Fatalf("responses differ: %v vs %v", err1, err2)
	}
	for range 3 {
		_ = bad("admin@example.com")
	}
	if err := bad("admin@example.com"); !errors.Is(err, ErrThrottled) {
		t.Fatalf("not throttled: %v", err)
	}
	if _, err := f.svc.Login(f.ctx, LoginInput{Email: "admin@example.com", Password: strongPW, Meta: SessionMeta{IP: "192.0.2.1"}}); !errors.Is(err, ErrThrottled) {
		t.Fatalf("account throttle must apply from any IP: %v", err)
	}
	f.clk.Advance(16 * time.Minute)
	if _, err := f.svc.Login(f.ctx, LoginInput{Email: "admin@example.com", Password: strongPW, Meta: SessionMeta{IP: "192.0.2.1"}}); err != nil {
		t.Fatalf("throttle must expire (no permanent lockout): %v", err)
	}
	op, _ := f.s.R().GetOperatorByEmail(f.ctx, nullStr("admin@example.com"))
	must(t, f.svc.ClearThrottle(f.ctx, audit.System, op.ID))
	// Timing: unknown accounts do comparable work (dummy hash). Medians must be within 25% (HP-AUTH-005).
	if testing.Short() {
		return
	}
	// Interleave the two kinds of attempts so load drift on the machine (CI runners) affects both alike.
	var kd, ud []time.Duration
	for i := range 21 {
		for _, email := range []string{"admin@example.com", "nobody@example.com"} {
			f.clk.Advance(time.Hour)
			start := time.Now()
			_, _ = f.svc.Login(f.ctx, LoginInput{Email: email, Password: "wrong password!!", Meta: SessionMeta{IP: "203.0.114." + itoa(i)}})
			if email == "nobody@example.com" {
				ud = append(ud, time.Since(start))
			} else {
				kd = append(kd, time.Since(start))
			}
		}
	}
	slices.Sort(kd)
	slices.Sort(ud)
	known, unknown := kd[len(kd)/2], ud[len(ud)/2]
	ratio := float64(known) / float64(unknown)
	t.Logf("median known=%s unknown=%s ratio=%.2f", known, unknown, ratio)
	if ratio < 0.75 || ratio > 1.33 {
		t.Fatalf("login timing reveals account existence: known=%s unknown=%s", known, unknown)
	}
}

func TestSessionLifecycle(t *testing.T) {
	f := newFx(t)
	f.bootstrap()
	tok, p := f.loginEnrolled("admin@example.com")
	if !p.VerifyCSRF(p.CSRFToken) || p.VerifyCSRF("forged") || p.VerifyCSRF("") {
		t.Fatal("CSRF verification broken")
	}
	must(t, f.svc.RequireRecentAuth(p, true))
	f.clk.Advance(6 * time.Minute)
	p, err := f.svc.Authenticate(f.ctx, tok)
	must(t, err)
	if err := f.svc.RequireRecentAuth(p, false); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("reauth not required: %v", err)
	}
	f.clk.Advance(30 * time.Second)
	tok2, err := f.svc.Reauth(f.ctx, p, strongPW, f.totpCode(p.Operator.ID), SessionMeta{})
	must(t, err)
	if _, err := f.svc.Authenticate(f.ctx, tok); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("old token valid after rotation")
	}
	p2, err := f.svc.Authenticate(f.ctx, tok2)
	must(t, err)
	must(t, f.svc.RequireRecentAuth(p2, true))
	tok3, err := f.svc.Rotate(f.ctx, p2, SessionMeta{})
	must(t, err)
	if _, err := f.svc.Authenticate(f.ctx, tok2); err == nil {
		t.Fatal("rotation did not revoke")
	}
	// Idle expiry.
	f.clk.Advance(31 * time.Minute)
	if _, err := f.svc.Authenticate(f.ctx, tok3); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("idle session still valid")
	}
	// Absolute expiry even with activity.
	tok4, _ := f.loginEnrolled("admin@example.com")
	for range 30 {
		f.clk.Advance(25 * time.Minute)
		if _, err := f.svc.Authenticate(f.ctx, tok4); err != nil {
			break
		}
	}
	if _, err := f.svc.Authenticate(f.ctx, tok4); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("absolute expiry not enforced")
	}
	tok5, p5 := f.loginEnrolled("admin@example.com")
	list, _ := f.svc.ListSessions(f.ctx, p5.Operator.ID, p5.SessionID)
	if len(list) != 1 || !list[0].Current {
		t.Fatalf("%+v", list)
	}
	must(t, f.svc.Logout(f.ctx, tok5))
	if _, err := f.svc.Authenticate(f.ctx, tok5); err == nil {
		t.Fatal("session valid after logout")
	}
}

// HP-AUTH-015: the last enabled administrator cannot be disabled or demoted.
func TestLastAdminProtection(t *testing.T) {
	f := newFx(t)
	admin := f.bootstrap()
	actor := audit.Actor{Type: audit.ActorOperator, ID: admin.ID}
	if _, err := f.svc.SetEnabled(f.ctx, actor, admin.ID, false); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("last admin disabled: %v", err)
	}
	if _, err := f.svc.SetRoles(f.ctx, actor, admin.ID, []string{RoleViewer}); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("last admin demoted: %v", err)
	}
	second, err := f.svc.Create(f.ctx, actor, CreateInput{Email: "two@example.com", DisplayName: "Two", Roles: []string{RoleAdministrator}, Password: strongPW})
	must(t, err)
	if _, err := f.svc.SetRoles(f.ctx, actor, admin.ID, []string{RoleViewer}); err != nil {
		t.Fatalf("demotion with another admin present: %v", err)
	}
	if _, err := f.svc.SetEnabled(f.ctx, actor, second.ID, false); !errors.Is(err, ErrLastAdmin) {
		t.Fatal("remaining admin disabled")
	}
}

// HP-AUTH-009/010/011: invitations, reset, change and session invalidation.
func TestInviteResetChange(t *testing.T) {
	f := newFx(t)
	admin := f.bootstrap()
	actor := audit.Actor{Type: audit.ActorOperator, ID: admin.ID}
	inv, _, err := f.svc.Invite(f.ctx, actor, "viewer@example.com", []string{RoleViewer})
	must(t, err)
	op, err := f.svc.AcceptInvitation(f.ctx, inv, "Viewer", strongPW)
	must(t, err)
	if !slices.Equal(op.Roles, []string{RoleViewer}) || op.ProvisionedVia != "invite" || op.MFARequired {
		t.Fatalf("%+v", op)
	}
	if _, err := f.svc.AcceptInvitation(f.ctx, inv, "Again", strongPW); !errors.Is(err, ErrTokenInvalid) {
		t.Fatal("invitation reused")
	}
	tokA, _ := f.loginEnrolled("viewer@example.com")
	tokB, pB := f.loginEnrolled("viewer@example.com")
	must(t, f.svc.ChangePassword(f.ctx, pB, strongPW, "a brand new long password"))
	if _, err := f.svc.Authenticate(f.ctx, tokA); err == nil {
		t.Fatal("other session survived password change")
	}
	if _, err := f.svc.Authenticate(f.ctx, tokB); err != nil {
		t.Fatal("current session must survive own password change")
	}
	reset, _, err := f.svc.IssueResetToken(f.ctx, actor, op.ID)
	must(t, err)
	must(t, f.svc.ResetPassword(f.ctx, reset, strongPW))
	if _, err := f.svc.Authenticate(f.ctx, tokB); err == nil {
		t.Fatal("sessions survived reset")
	}
	if err := f.svc.ResetPassword(f.ctx, reset, strongPW); !errors.Is(err, ErrTokenInvalid) {
		t.Fatal("reset token reused")
	}
	f.loginEnrolled("viewer@example.com")
	// Role reduction revokes sessions.
	tokC, _ := f.loginEnrolled("viewer@example.com")
	_, err = f.svc.SetRoles(f.ctx, actor, op.ID, []string{})
	must(t, err)
	if _, err := f.svc.Authenticate(f.ctx, tokC); err == nil {
		t.Fatal("session survived privilege reduction")
	}
}

// HP-AUTH-007: recovery codes are single use.
func TestRecoveryCodes(t *testing.T) {
	f := newFx(t)
	f.bootstrap()
	res, err := f.svc.Login(f.ctx, LoginInput{Email: "admin@example.com", Password: strongPW})
	must(t, err)
	_, err = f.svc.BeginTOTP(f.ctx, res.Principal)
	must(t, err)
	codes, _, err := f.svc.ConfirmTOTP(f.ctx, res.Principal, f.pendingCode(res.Principal.Operator.ID), SessionMeta{})
	must(t, err)
	res2, err := f.svc.Login(f.ctx, LoginInput{Email: "admin@example.com", Password: strongPW})
	must(t, err)
	if _, err := f.svc.VerifyMFA(f.ctx, res2.Principal, strings.ToUpper(codes[0]), SessionMeta{}); err != nil {
		t.Fatalf("recovery code rejected: %v", err)
	}
	res3, _ := f.svc.Login(f.ctx, LoginInput{Email: "admin@example.com", Password: strongPW})
	if _, err := f.svc.VerifyMFA(f.ctx, res3.Principal, codes[0], SessionMeta{}); err == nil {
		t.Fatal("recovery code reused")
	}
	// SR-36: codes issued before a token-key rotation keep working (lookup under every non-retired version).
	if _, err := f.kr.Rotate(f.ctx, f.s, keyring.PurposeToken); err != nil {
		t.Fatal(err)
	}
	res4, _ := f.svc.Login(f.ctx, LoginInput{Email: "admin@example.com", Password: strongPW})
	if _, err := f.svc.VerifyMFA(f.ctx, res4.Principal, codes[1], SessionMeta{}); err != nil {
		t.Fatalf("pre-rotation recovery code rejected: %v", err)
	}
	rows, _ := f.s.R().CountUnusedRecoveryCodes(f.ctx, res.Principal.Operator.ID)
	if rows != RecoveryCodeCount-2 {
		t.Fatalf("unused %d", rows)
	}
	if err := f.svc.DisableTOTP(f.ctx, res.Principal); err == nil {
		t.Fatal("mandatory MFA disabled")
	}
}

// HP-AUTH-016: break-glass issues a recovery login; it is audited.
func TestBreakGlass(t *testing.T) {
	f := newFx(t)
	admin := f.bootstrap()
	tok, _, err := f.svc.IssueRecoveryLogin(f.ctx, "", "rescue@example.com")
	must(t, err)
	rec, err := f.svc.RecoveryLogin(f.ctx, tok, SessionMeta{IP: "127.0.0.1"})
	must(t, err)
	p, err := f.svc.Authenticate(f.ctx, rec.Token)
	must(t, err)
	// The new administrator must enroll a factor before the recovery session is usable, and gets a reset token for
	// the random password the CLI never shows.
	if p.Method != MethodBreakGlass || !p.HasRole(RoleAdministrator) || !p.Limited || !p.NeedsEnroll || rec.ResetToken == "" {
		t.Fatalf("%+v reset=%q", p, rec.ResetToken)
	}
	_, err = f.svc.BeginTOTP(f.ctx, p)
	must(t, err)
	_, _, err = f.svc.ConfirmTOTP(f.ctx, p, f.pendingCode(p.Operator.ID), SessionMeta{})
	must(t, err)
	if p, err = f.svc.Authenticate(f.ctx, rec.Token); err != nil || p.Limited {
		t.Fatalf("after enrollment: %v %+v", err, p)
	}
	if _, err := f.svc.RecoveryLogin(f.ctx, tok, SessionMeta{}); !errors.Is(err, ErrTokenInvalid) {
		t.Fatal("recovery token reused")
	}
	tok2, _, err := f.svc.IssueRecoveryLogin(f.ctx, admin.ID, "")
	must(t, err)
	if _, err := f.svc.RecoveryLogin(f.ctx, tok2, SessionMeta{}); err != nil {
		t.Fatal(err)
	}
	rows, _ := f.s.R().AuditEventsFrom(f.ctx, db.AuditEventsFromParams{Seq: 0, Limit: 1000})
	n := 0
	for _, r := range rows {
		if r.Action == "breakglass.used" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("break-glass audit events: %d", n)
	}
}

// HP-AUTH-018: secrets never appear in audit details or stored plaintext.
func TestNoSecretsStored(t *testing.T) {
	f := newFx(t)
	f.bootstrap()
	f.loginEnrolled("admin@example.com")
	rows, _ := f.s.R().AuditEventsFrom(f.ctx, db.AuditEventsFromParams{Seq: 0, Limit: 1000})
	for _, r := range rows {
		if strings.Contains(r.DetailsJson, "staple") {
			t.Fatalf("password in audit: %s", r.DetailsJson)
		}
	}
	op, _ := f.s.R().GetOperatorByEmail(f.ctx, nullStr("admin@example.com"))
	tot, _ := f.s.R().GetTOTP(f.ctx, op.ID)
	if len(tot.SecretEnc) < 20 || tot.SecretEnc[0] != 0x01 {
		t.Fatal("TOTP secret not sealed")
	}
	cred, _ := f.s.R().GetLocalCredential(f.ctx, op.ID)
	if strings.Contains(cred.PasswordPhc, "staple") {
		t.Fatal("plaintext password stored")
	}
}

func TestMisc(t *testing.T) {
	f := newFx(t)
	admin := f.bootstrap()
	actor := audit.Actor{Type: audit.ActorOperator, ID: admin.ID}
	if _, err := f.svc.Create(f.ctx, actor, CreateInput{Email: "bad", DisplayName: "x"}); err == nil {
		t.Fatal("bad email accepted")
	}
	if _, err := f.svc.Create(f.ctx, actor, CreateInput{Email: "x@example.com", DisplayName: "x", Roles: []string{"god"}}); err == nil {
		t.Fatal("unknown role accepted")
	}
	op, err := f.svc.Create(f.ctx, actor, CreateInput{Email: "g@example.com", DisplayName: "G"})
	must(t, err)
	if len(op.Roles) != 0 {
		t.Fatal("new operator has default privileges (HP-RBAC-007)")
	}
	op, err = f.svc.SetGroups(f.ctx, actor, op.ID, []string{"oncall"})
	must(t, err)
	if op.Groups[0] != "oncall" {
		t.Fatal(op.Groups)
	}
	list, _ := f.svc.List(f.ctx)
	if len(list) != 2 {
		t.Fatal(len(list))
	}
	must(t, f.svc.PurgeExpired(f.ctx))
	must(t, f.svc.RevokeAllSessions(f.ctx, admin.ID, "test"))
}

func nullStr(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestIPThrottle(t *testing.T) {
	f := newFx(t)
	f.bootstrap()
	var err error
	for i := range 6 {
		_, err = f.svc.Login(f.ctx, LoginInput{Email: "user" + itoa(i) + "@example.com", Password: "wrong password!!", Meta: SessionMeta{IP: "2001:db8::" + itoa(i)}})
	}
	if !errors.Is(err, ErrThrottled) {
		t.Fatalf("per-IP (/64) throttle not applied across accounts: %v", err)
	}
}

// HP-AUTH-011: pending invitations are listed (never with the token) and can be revoked; a revoked invitation cannot
// be accepted, and revocation is audited.
func TestInvitationRevocation(t *testing.T) {
	f := newFx(t)
	f.bootstrap()
	token, _, err := f.svc.Invite(f.ctx, audit.System, "new@example.com", []string{RoleViewer})
	must(t, err)
	invs, err := f.svc.ListInvitations(f.ctx)
	must(t, err)
	if len(invs) != 1 || invs[0].Email != "new@example.com" || invs[0].ID == "" || strings.Contains(invs[0].ID, token) {
		t.Fatalf("invitations %+v", invs)
	}
	must(t, f.svc.RevokeInvitation(f.ctx, audit.System, invs[0].ID))
	if _, err := f.svc.AcceptInvitation(f.ctx, token, "New", strongPW); err == nil {
		t.Fatal("revoked invitation accepted")
	}
	if err := f.svc.RevokeInvitation(f.ctx, audit.System, invs[0].ID); err == nil {
		t.Fatal("revoked twice")
	}
	if invs, _ := f.svc.ListInvitations(f.ctx); len(invs) != 0 {
		t.Fatalf("revoked invitation still listed: %+v", invs)
	}
	var n int
	must(t, f.s.ReadDB().QueryRowContext(f.ctx, `SELECT count(*) FROM audit_events WHERE action = 'operator.invitation.revoked'`).Scan(&n))
	if n != 1 {
		t.Fatalf("revocation audits %d", n)
	}
	if err := f.svc.RevokeInvitation(f.ctx, audit.System, "zz-not-hex"); err == nil {
		t.Fatal("malformed id accepted")
	}
}
