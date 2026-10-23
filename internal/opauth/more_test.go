package opauth

import (
	"errors"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
)

func TestOptionalMFAAndCodes(t *testing.T) {
	f := newFx(t)
	admin := f.bootstrap()
	actor := audit.Actor{Type: audit.ActorOperator, ID: admin.ID}
	_, err := f.svc.Create(f.ctx, actor, CreateInput{Email: "aud@example.com", DisplayName: "Aud", Roles: []string{RoleAuditor}, Password: strongPW})
	must(t, err)
	res, err := f.svc.Login(f.ctx, LoginInput{Email: "aud@example.com", Password: strongPW})
	must(t, err)
	if res.MFAPending || res.MustEnroll || res.Principal.Limited {
		t.Fatalf("auditor without MFA policy should not be limited: %+v", res)
	}
	if _, err := f.svc.RegenerateRecoveryCodes(f.ctx, res.Principal); err == nil {
		t.Fatal("regenerated codes without MFA")
	}
	enr, err := f.svc.BeginTOTP(f.ctx, res.Principal)
	must(t, err)
	if enr.Secret == "" || enr.URI == "" {
		t.Fatal("enrollment data missing")
	}
	if _, err := f.svc.ConfirmTOTP(f.ctx, res.Principal, "000000"); err == nil {
		t.Fatal("wrong confirmation code accepted")
	}
	_, err = f.svc.ConfirmTOTP(f.ctx, res.Principal, f.totpCode(res.Principal.Operator.ID))
	must(t, err)
	p, err := f.svc.Authenticate(f.ctx, res.Token)
	must(t, err)
	codes, err := f.svc.RegenerateRecoveryCodes(f.ctx, p)
	if err != nil || len(codes) != RecoveryCodeCount {
		t.Fatal(err)
	}
	must(t, f.svc.DisableTOTP(f.ctx, p))
	op, _ := f.svc.Get(f.ctx, p.Operator.ID)
	if op.MFAEnrolled {
		t.Fatal("TOTP not removed")
	}
}

func TestMFAThrottleAndSessionRevoke(t *testing.T) {
	f := newFx(t)
	f.bootstrap()
	f.loginEnrolled("admin@example.com")
	res, err := f.svc.Login(f.ctx, LoginInput{Email: "admin@example.com", Password: strongPW})
	must(t, err)
	for range 4 {
		_, _ = f.svc.VerifyMFA(f.ctx, res.Principal, "111111", SessionMeta{})
	}
	if _, err := f.svc.VerifyMFA(f.ctx, res.Principal, f.totpCode(res.Principal.Operator.ID), SessionMeta{}); !errors.Is(err, ErrThrottled) {
		t.Fatalf("MFA guessing not throttled: %v", err)
	}
	f.clk.Advance(20 * time.Minute)
	tok, p := f.loginEnrolled("admin@example.com")
	must(t, f.svc.RevokeSession(f.ctx, p.Operator.ID, p.SessionID, "user"))
	if _, err := f.svc.Authenticate(f.ctx, tok); err == nil {
		t.Fatal("revoked session valid")
	}
	if err := f.svc.RevokeSession(f.ctx, p.Operator.ID, "wss_missing", "x"); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := f.svc.Authenticate(f.ctx, ""); err == nil {
		t.Fatal("empty token")
	}
	if _, err := f.svc.Get(f.ctx, "opr_missing"); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := f.svc.Reauth(f.ctx, p, "wrong password!!", "", SessionMeta{}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal(err)
	}
	if err := f.svc.ChangePassword(f.ctx, p, "wrong password!!", "another long password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal(err)
	}
	actor := audit.Actor{Type: audit.ActorOperator, ID: p.Operator.ID}
	if _, _, err := f.svc.Invite(f.ctx, actor, "admin@example.com", nil); !errors.Is(err, apperr.ErrAlreadyExists) {
		t.Fatal("invited an existing email")
	}
	if _, _, err := f.svc.IssueResetToken(f.ctx, actor, "opr_missing"); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatal(err)
	}
	other, err := f.svc.Create(f.ctx, actor, CreateInput{Email: "o@example.com", DisplayName: "O", Roles: []string{RoleViewer}})
	must(t, err)
	_, err = f.svc.SetEnabled(f.ctx, actor, other.ID, false)
	must(t, err)
	if op, err := f.svc.SetEnabled(f.ctx, actor, other.ID, true); err != nil || !op.Enabled {
		t.Fatal(err)
	}
}
