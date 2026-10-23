package opauth

import (
	"errors"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// HP-OIDC-013 support: external sessions re-authenticate upstream or, as a fallback, with local TOTP.
func TestExternalSessionReauth(t *testing.T) {
	f := newFx(t)
	op := f.bootstrap()
	f.loginEnrolled(op.Email) // enrolls TOTP
	var token string
	must(t, f.s.W().Tx(f.ctx, func(tx *store.Tx) error {
		var err error
		token, err = f.svc.CreateSessionTx(f.ctx, tx, op.ID, MethodOIDC, SessionMeta{IP: "192.0.2.1"})
		return err
	}))
	p, err := f.svc.Authenticate(f.ctx, token)
	must(t, err)
	if p.Method != MethodOIDC || p.Limited {
		t.Fatalf("%+v", p)
	}
	f.clk.Advance(10 * time.Minute)
	if err := f.svc.RequireRecentAuth(p, false); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("stale: %v", err)
	}
	if _, err := f.svc.ReauthTOTP(f.ctx, p, "000000", SessionMeta{}); !errors.Is(err, ErrMFARequired) {
		t.Fatalf("wrong code: %v", err)
	}
	t2, err := f.svc.ReauthTOTP(f.ctx, p, f.totpCode(op.ID), SessionMeta{})
	must(t, err)
	if _, err := f.svc.Authenticate(f.ctx, token); err == nil {
		t.Fatal("old session survived rotation")
	}
	p2, err := f.svc.Authenticate(f.ctx, t2)
	must(t, err)
	if err := f.svc.RequireRecentAuth(p2, false); err != nil || p2.MFAAt == nil {
		t.Fatalf("after TOTP reauth: %v", err)
	}
	f.clk.Advance(10 * time.Minute)
	t3, err := f.svc.ReauthExternal(f.ctx, p2, "corp", SessionMeta{})
	must(t, err)
	p3, err := f.svc.Authenticate(f.ctx, t3)
	must(t, err)
	if err := f.svc.RequireRecentAuth(p3, false); err != nil || p3.Method != MethodOIDC {
		t.Fatalf("after upstream reauth: %v", err)
	}
	if _, err := f.svc.ReauthExternal(f.ctx, p2, "corp", SessionMeta{}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked session re-authenticated: %v", err)
	}
	if off, err := f.svc.LocalLoginDisabled(f.ctx); err != nil || off {
		t.Fatalf("default local login: %v %v", off, err)
	}
}

// HP-AUTH-016: a break-glass use raises an alert until acknowledged.
func TestBreakGlassAlert(t *testing.T) {
	f := newFx(t)
	op := f.bootstrap()
	if on, _, err := f.svc.BreakGlassAlert(f.ctx); err != nil || on {
		t.Fatalf("fresh store alert=%v %v", on, err)
	}
	_, _, err := f.svc.IssueRecoveryLogin(f.ctx, op.ID, "")
	must(t, err)
	on, at, err := f.svc.BreakGlassAlert(f.ctx)
	if err != nil || !on || at.IsZero() {
		t.Fatalf("after break-glass alert=%v %v", on, err)
	}
	must(t, f.svc.AcknowledgeBreakGlass(f.ctx, audit.Actor{Type: audit.ActorOperator, ID: op.ID}))
	if on, _, _ := f.svc.BreakGlassAlert(f.ctx); on {
		t.Fatal("alert survived acknowledgement")
	}
}
