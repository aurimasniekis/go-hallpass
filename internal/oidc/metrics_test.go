package oidc

import (
	"errors"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics/metricstest"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
)

// HP-OBS-004: SSO login completions are counted by provider slug and outcome (login purpose only).
func TestOIDCLoginMetrics(t *testing.T) {
	f := newFx(t)
	m := metrics.New()
	f.svc.opts.Metrics = m
	op := f.operator("alice@corp.example", opauth.RoleApprover)
	if _, err := f.flow(PurposeLogin, nil); !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("unlinked identity: %v", err)
	}
	must(t, f.svc.LinkIdentity(f.ctx, admin, op.ID, f.prov.ID, "user-1"))
	res, err := f.flow(PurposeLogin, nil)
	must(t, err)
	if _, err := f.flow(PurposeStepUp, f.principal(res.SessionToken)); err != nil {
		t.Logf("step-up: %v", err) // outcome irrelevant: step-up is not a login
	}
	for _, c := range []struct {
		outcome string
		want    float64
	}{{"denied", 1}, {"success", 1}} {
		if v := metricstest.Value(t, m, "hallpass_oidc_logins_total", "provider", "corp", "outcome", c.outcome); v != c.want {
			t.Errorf("oidc %s = %v, want %v", c.outcome, v, c.want)
		}
		if v := metricstest.Value(t, m, "hallpass_operator_logins_total", "method", "oidc", "outcome", c.outcome); v != c.want {
			t.Errorf("operator oidc %s = %v, want %v", c.outcome, v, c.want)
		}
	}
	if v := metricstest.Value(t, m, "hallpass_oidc_logins_total"); v != 2 {
		t.Errorf("total = %v", v)
	}
	f.svc.observeLogin("corp", ErrTokenValidation)
	f.svc.observeLogin("corp", ErrProviderUnavailable)
	if a, b := metricstest.Value(t, m, "hallpass_oidc_logins_total", "outcome", "failure"), metricstest.Value(t, m, "hallpass_oidc_logins_total", "outcome", "error"); a != 1 || b != 1 {
		t.Errorf("failure=%v error=%v", a, b)
	}
}
