package metricstest

import (
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
)

func TestValue(t *testing.T) {
	m := metrics.New()
	m.SSHAuthFailed(metrics.AuthUnknownKey)
	m.SSHAuthFailed(metrics.AuthUnknownKey)
	m.SSHAuthFailed(metrics.AuthRevokedKey)
	m.SetOutboxBacklog(3, 1)
	m.EnforcementLatency(time.Second)
	if v := Value(t, m, "hallpass_ssh_auth_failures_total"); v != 3 {
		t.Errorf("sum = %v", v)
	}
	if v := Value(t, m, "hallpass_ssh_auth_failures_total", "reason", "unknown_key"); v != 2 {
		t.Errorf("filtered = %v", v)
	}
	if v := Value(t, m, "hallpass_outbox_pending"); v != 3 {
		t.Errorf("gauge = %v", v)
	}
	if v := Value(t, m, "hallpass_enforcer_latency_seconds"); v != 1 {
		t.Errorf("histogram count = %v", v)
	}
	if v := Value(t, m, "hallpass_missing"); v != 0 {
		t.Errorf("missing = %v", v)
	}
}
