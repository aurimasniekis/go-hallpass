package opauth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
)

// Automation tokens: issued once for one of the creator's roles, they authenticate as the creator limited to that role,
// and stop working when revoked, expired, or when the creator no longer holds the role.
func TestAPITokens(t *testing.T) {
	f := newFx(t)
	op := f.bootstrap()
	p := &Principal{Operator: op}
	sys := audit.Actor{Type: audit.ActorOperator, ID: op.ID}

	for name, tc := range map[string]struct {
		name, role string
		ttl        time.Duration
	}{
		"empty name":    {"", RoleAdministrator, 30 * 24 * time.Hour},
		"role not held": {"ci", RoleViewer, 30 * 24 * time.Hour},
		"too short":     {"ci", RoleAdministrator, time.Hour},
		"too long":      {"ci", RoleAdministrator, 400 * 24 * time.Hour},
		"unknown role":  {"ci", "root", 30 * 24 * time.Hour},
	} {
		if _, _, err := f.svc.CreateAPIToken(f.ctx, p, tc.name, tc.role, tc.ttl); !errors.Is(err, apperr.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}

	tok, raw, err := f.svc.CreateAPIToken(f.ctx, p, "terraform", RoleAdministrator, 30*24*time.Hour)
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
	if _, _, err := f.svc.CreateAPIToken(f.ctx, got, "nested", RoleAdministrator, 30*24*time.Hour); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("a token issued a token: %v", err)
	}
	for _, bad := range []string{"", raw[:len(raw)-1], "hallpass_at_" + strings.Repeat("A", 43), strings.Replace(raw, APITokenPrefix, "porch_at_", 1)} {
		if _, err := f.svc.AuthenticateAPIToken(f.ctx, bad, ""); !errors.Is(err, ErrUnauthorized) {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}

	// A token for a role the operator later loses stops working.
	_, err = f.svc.SetRoles(f.ctx, sys, op.ID, []string{RoleAdministrator, RoleViewer})
	must(t, err)
	op, err = f.svc.Get(f.ctx, op.ID)
	must(t, err)
	_, viewer, err := f.svc.CreateAPIToken(f.ctx, &Principal{Operator: op}, "reports", RoleViewer, 24*time.Hour)
	must(t, err)
	_, err = f.svc.AuthenticateAPIToken(f.ctx, viewer, "")
	must(t, err)
	_, err = f.svc.SetRoles(f.ctx, sys, op.ID, []string{RoleAdministrator})
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
	_, short, err := f.svc.CreateAPIToken(f.ctx, &Principal{Operator: op}, "short", RoleAdministrator, 24*time.Hour)
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
