package opauth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
)

// Automation tokens: issued once for one of the creator's roles (any role for an administrator), they authenticate as the
// creator limited to that role, and stop working when revoked, expired, or when the creator no longer holds the role
// nor administrator.
func TestAPITokens(t *testing.T) {
	f := newFx(t)
	op := f.bootstrap()
	p := &Principal{Operator: op}
	sys := audit.Actor{Type: audit.ActorOperator, ID: op.ID}

	for name, tc := range map[string]struct {
		name, role string
		ttl        time.Duration
	}{
		"empty name":   {"", RoleAdministrator, 30 * 24 * time.Hour},
		"too short":    {"ci", RoleAdministrator, time.Hour},
		"too long":     {"ci", RoleAdministrator, 400 * 24 * time.Hour},
		"unknown role": {"ci", "root", 30 * 24 * time.Hour},
	} {
		if _, _, err := f.svc.CreateAPIToken(f.ctx, p, tc.name, tc.role, tc.ttl, false); !errors.Is(err, apperr.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}

	tok, raw, err := f.svc.CreateAPIToken(f.ctx, p, "terraform", RoleAdministrator, 30*24*time.Hour, false)
	must(t, err)
	if !strings.HasPrefix(raw, APITokenPrefix) || len(raw) != len(APITokenPrefix)+43 || tok.Hint != raw[len(raw)-4:] {
		t.Fatalf("token %q %+v", raw, tok)
	}
	got, err := f.svc.AuthenticateAPIToken(f.ctx, raw, "198.51.100.9")
	must(t, err)
	if got.TokenID != tok.ID || got.Method != MethodToken || got.Operator.ID != op.ID || len(got.Operator.Roles) != 1 {
		t.Fatalf("principal %+v", got)
	}
	if again, _ := f.svc.GetAPIToken(f.ctx, tok.ID); again.LastUsedAt == nil || again.LastUsedIP != "198.51.100.9" {
		t.Fatalf("last use not recorded: %+v", again)
	}
	for _, bad := range []string{"", raw[:len(raw)-1], "hallpass_at_" + strings.Repeat("A", 43), strings.Replace(raw, APITokenPrefix, "porch_at_", 1)} {
		if _, err := f.svc.AuthenticateAPIToken(f.ctx, bad, ""); !errors.Is(err, ErrUnauthorized) {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}

	// A non-administrator may only use their own roles; a token for a role the operator later loses stops working.
	rita, err := f.svc.Create(f.ctx, sys, CreateInput{Email: "rita@example.com", DisplayName: "Rita", Roles: []string{RoleApprover, RoleViewer}})
	must(t, err)
	if _, _, err := f.svc.CreateAPIToken(f.ctx, &Principal{Operator: rita}, "audit", RoleAuditor, 24*time.Hour, false); !errors.Is(err, apperr.ErrInvalid) {
		t.Fatalf("role not held: %v", err)
	}
	_, viewer, err := f.svc.CreateAPIToken(f.ctx, &Principal{Operator: rita}, "reports", RoleViewer, 24*time.Hour, false)
	must(t, err)
	_, err = f.svc.AuthenticateAPIToken(f.ctx, viewer, "")
	must(t, err)
	_, err = f.svc.SetRoles(f.ctx, sys, rita.ID, []string{RoleApprover})
	must(t, err)
	if _, err := f.svc.AuthenticateAPIToken(f.ctx, viewer, ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("token kept a role its operator lost: %v", err)
	}

	// Expiry and revocation.
	f.clk.Advance(25 * time.Hour)
	_, err = f.svc.AuthenticateAPIToken(f.ctx, raw, "")
	must(t, err)
	revoked, err := f.svc.RevokeAPIToken(f.ctx, sys, tok.ID)
	must(t, err)
	if revoked.RevokedAt == nil {
		t.Fatal("not revoked")
	}
	if _, err := f.svc.AuthenticateAPIToken(f.ctx, raw, ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked token accepted: %v", err)
	}
	_, short, err := f.svc.CreateAPIToken(f.ctx, &Principal{Operator: op}, "short", RoleAdministrator, 24*time.Hour, false)
	must(t, err)
	f.clk.Advance(24 * time.Hour)
	if _, err := f.svc.AuthenticateAPIToken(f.ctx, short, ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired token accepted: %v", err)
	}
	list, err := f.svc.ListAPITokens(f.ctx)
	must(t, err)
	if len(list) != 3 || list[len(list)-1].ID != tok.ID {
		t.Fatalf("list (revoked last): %+v", list)
	}
}

// ADR-0053: a token issued without expiry keeps working past any expiry, still stops when revoked or when its operator
// loses the role, and cannot be combined with an expiry.
func TestAPITokenNeverExpires(t *testing.T) {
	f := newFx(t)
	op := f.bootstrap()
	sys := audit.Actor{Type: audit.ActorOperator, ID: op.ID}
	p := &Principal{Operator: op}
	if _, _, err := f.svc.CreateAPIToken(f.ctx, p, "tf", RoleAdministrator, 30*24*time.Hour, true); !errors.Is(err, apperr.ErrInvalid) {
		t.Fatalf("never-expiring token with an expiry: %v", err)
	}
	tok, raw, err := f.svc.CreateAPIToken(f.ctx, p, "terraform", RoleAdministrator, 0, true)
	must(t, err)
	if !tok.NeverExpires || tok.ExpiresAt != nil {
		t.Fatalf("token %+v", tok)
	}
	f.clk.Advance(5 * 366 * 24 * time.Hour)
	_, err = f.svc.AuthenticateAPIToken(f.ctx, raw, "")
	must(t, err)

	rita, err := f.svc.Create(f.ctx, sys, CreateInput{Email: "rita@example.com", DisplayName: "Rita", Roles: []string{RoleApprover, RoleViewer}})
	must(t, err)
	_, viewer, err := f.svc.CreateAPIToken(f.ctx, &Principal{Operator: rita}, "reports", RoleViewer, 0, true)
	must(t, err)
	_, err = f.svc.SetRoles(f.ctx, sys, rita.ID, []string{RoleApprover})
	must(t, err)
	if _, err := f.svc.AuthenticateAPIToken(f.ctx, viewer, ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("never-expiring token kept a role its operator lost: %v", err)
	}

	_, err = f.svc.RevokeAPIToken(f.ctx, sys, tok.ID)
	must(t, err)
	if _, err := f.svc.AuthenticateAPIToken(f.ctx, raw, ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked never-expiring token accepted: %v", err)
	}
}

// ADR-0058: an administrator issues tokens for roles they do not hold, which work while they stay administrator; an
// administrator token issues child tokens, which cannot issue tokens and are revoked with their parent.
func TestAPITokensIssuedByTokens(t *testing.T) {
	f := newFx(t)
	op := f.bootstrap()
	sys := audit.Actor{Type: audit.ActorOperator, ID: op.ID}
	tf, raw, err := f.svc.CreateAPIToken(f.ctx, &Principal{Operator: op}, "terraform", RoleAdministrator, 0, true)
	must(t, err)
	tfp, err := f.svc.AuthenticateAPIToken(f.ctx, raw, "")
	must(t, err)

	child, childRaw, err := f.svc.CreateAPIToken(f.ctx, tfp, "deed", RoleAuditor, 0, true)
	must(t, err)
	if child.ParentTokenID != tf.ID || child.Role != RoleAuditor || child.OperatorID != op.ID {
		t.Fatalf("child %+v", child)
	}
	cp, err := f.svc.AuthenticateAPIToken(f.ctx, childRaw, "")
	must(t, err)
	if cp.TokenParentID != tf.ID || len(cp.Operator.Roles) != 1 || cp.Operator.Roles[0] != RoleAuditor {
		t.Fatalf("child principal %+v", cp)
	}
	adminChild, _, err := f.svc.CreateAPIToken(f.ctx, tfp, "nested-admin", RoleAdministrator, 24*time.Hour, false)
	must(t, err)
	adminChildP := &Principal{Operator: tfp.Operator, TokenID: adminChild.ID, TokenParentID: tf.ID}
	if _, _, err := f.svc.CreateAPIToken(f.ctx, adminChildP, "grandchild", RoleViewer, 24*time.Hour, false); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("a child token issued a token: %v", err)
	}

	// The auditor token works while its creator is an administrator, not after.
	second, err := f.svc.Create(f.ctx, sys, CreateInput{Email: "second@example.com", DisplayName: "Second", Roles: []string{RoleAdministrator}})
	must(t, err)
	_, err = f.svc.SetRoles(f.ctx, audit.Actor{Type: audit.ActorOperator, ID: second.ID}, op.ID, []string{RoleViewer})
	must(t, err)
	if _, err := f.svc.AuthenticateAPIToken(f.ctx, childRaw, ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("auditor token outlived its creator's administrator role: %v", err)
	}
	_, err = f.svc.SetRoles(f.ctx, audit.Actor{Type: audit.ActorOperator, ID: second.ID}, op.ID, []string{RoleAdministrator})
	must(t, err)
	_, err = f.svc.AuthenticateAPIToken(f.ctx, childRaw, "")
	must(t, err)

	// Revoking the parent revokes its children, each audited.
	_, err = f.svc.RevokeAPIToken(f.ctx, sys, tf.ID)
	must(t, err)
	for _, id := range []string{child.ID, adminChild.ID} {
		if got, _ := f.svc.GetAPIToken(f.ctx, id); got.RevokedAt == nil {
			t.Fatalf("child %s not revoked with its parent", id)
		}
	}
	if _, err := f.svc.AuthenticateAPIToken(f.ctx, childRaw, ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("child of a revoked token accepted: %v", err)
	}
	var n int
	must(t, f.s.ReadDB().QueryRowContext(f.ctx, `SELECT count(*) FROM audit_events WHERE action = 'api_token.revoked'`).Scan(&n))
	if n != 3 {
		t.Fatalf("revocation audit events: %d", n)
	}
}
