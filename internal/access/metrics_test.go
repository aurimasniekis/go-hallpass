package access

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics/metricstest"
)

func val(t *testing.T, m *metrics.Metrics, name string, labels ...string) float64 {
	t.Helper()
	return metricstest.Value(t, m, name, labels...)
}

// HP-OBS-004: request transitions, decisions and grant lifecycle are counted after commit.
func TestAccessMetrics(t *testing.T) {
	m := metrics.New()
	f := newFxWith(t, func(o *Options) { o.Metrics = m })

	g := f.grant(time.Hour) // pending → approved via web
	if v := val(t, m, "hallpass_access_requests_total", "state", "pending"); v != 1 {
		t.Errorf("pending = %v", v)
	}
	if v := val(t, m, "hallpass_access_requests_total", "state", "approved"); v != 1 {
		t.Errorf("approved = %v", v)
	}
	if v := val(t, m, "hallpass_access_decisions_total", "channel", "web", "outcome", "approved"); v != 1 {
		t.Errorf("decisions = %v", v)
	}
	if v := val(t, m, "hallpass_access_grants_active"); v != 1 {
		t.Errorf("grants active = %v", v)
	}

	// A second decision on the decided request is a conflict; a replay of the same decision is not counted.
	r2 := f.request("second", 0)
	if _, err := f.svc.CancelByAgent(f.ctx, f.agent.ID, r2.Request.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Decide(f.ctx, DecideInput{RequestID: r2.Request.ID, Approve: false, Operator: f.approver, Channel: ChannelSlack}); err == nil {
		t.Fatal("decision on canceled request accepted")
	}
	if v := val(t, m, "hallpass_access_requests_total", "state", "canceled"); v != 1 {
		t.Errorf("canceled = %v", v)
	}
	if v := val(t, m, "hallpass_access_decisions_total", "channel", "slack", "outcome", "conflict"); v != 1 {
		t.Errorf("conflict = %v", v)
	}
	f.approve(g.RequestID, 0) // idempotent replay
	if v := val(t, m, "hallpass_access_decisions_total"); v != 2 {
		t.Errorf("replay counted: %v", v)
	}

	if _, err := f.svc.RevokeGrant(f.ctx, f.approver, g.ID, ""); err != nil {
		t.Fatal(err)
	}
	if v := val(t, m, "hallpass_access_grants_ended_total", "reason", "operator"); v != 1 {
		t.Errorf("ended = %v", v)
	}
	if v := val(t, m, "hallpass_access_grants_active"); v != 0 {
		t.Errorf("grants active = %v", v)
	}

	// Gauges are re-read from the store.
	f.request("pending one", 0)
	m.SetGrantsActive(7)
	f.svc.RefreshGauges(f.ctx)
	if v := val(t, m, "hallpass_access_requests_pending"); v != 1 {
		t.Errorf("pending gauge = %v", v)
	}
	if v := val(t, m, "hallpass_access_grants_active"); v != 0 {
		t.Errorf("grants gauge = %v", v)
	}
}

// HP-OPS-006: below the free-space reserve, new channels are refused (fail closed).
func TestStorageReserveRefusesChannels(t *testing.T) {
	var below atomic.Bool
	f := newFxWith(t, func(o *Options) {
		o.StorageReserve = func() error {
			if below.Load() {
				return errors.New("12 bytes available, reserve 2 GiB")
			}
			return nil
		}
	})
	g := f.grant(time.Hour)
	conn := f.conn()
	if _, err := f.register(conn, g.ID, KindExec, false); err != nil {
		t.Fatalf("above reserve: %v", err)
	}
	below.Store(true)
	if _, err := f.register(conn, g.ID, KindExec, false); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("below reserve: %v", err)
	}
}

// HP-GRT-008: enforcer terminations and the latency from access end to termination are exported.
func TestEnforcerMetrics(t *testing.T) {
	m := metrics.New()
	f := newFxWith(t, func(o *Options) { o.Metrics = m })
	g := f.grant(15 * time.Minute)
	conn := f.conn()
	r1, err := f.register(conn, g.ID, KindExec, false)
	must(t, err)
	e := NewEnforcer(f.svc, f.bus, time.Hour) // ticks driven manually
	rec := newRecorder()
	must(t, e.Register(rec.live(f, r1, conn, g.ExpiresAt)))
	f.clk.Advance(15*time.Minute + 2*time.Second)
	e.expire(f.clk.Now())
	if reason := rec.wait(t, r1.ChannelID, time.Second); reason != ReasonExpired {
		t.Fatalf("reason %q", reason)
	}
	if v := val(t, m, "hallpass_enforcer_terminations_total", "reason", "expired"); v != 1 {
		t.Errorf("terminations = %v", v)
	}
	fams, _ := m.Registry().Gather()
	for _, fam := range fams {
		if fam.GetName() == "hallpass_enforcer_latency_seconds" {
			h := fam.GetMetric()[0].GetHistogram()
			if h.GetSampleCount() != 1 || h.GetSampleSum() < 1.9 || h.GetSampleSum() > 2.1 {
				t.Errorf("latency count=%d sum=%v, want 1 sample of 2s", h.GetSampleCount(), h.GetSampleSum())
			}
		}
	}

	must(t, f.svc.CloseChannel(f.ctx, r1, CloseInfo{Reason: ReasonExpired}))
	g2 := f.grant(time.Hour)
	r2, err := f.register(conn, g2.ID, KindShell, false)
	must(t, err)
	must(t, e.Register(rec.live(f, r2, conn, g2.ExpiresAt)))
	if !e.Terminate(r2.ChannelID, ReasonOperator) || e.Terminate(r2.ChannelID, ReasonOperator) {
		t.Fatal("operator terminate")
	}
	must(t, f.svc.CloseChannel(f.ctx, r2, CloseInfo{Reason: ReasonOperator}))
	r3, err := f.register(conn, g2.ID, KindShell, false)
	must(t, err)
	must(t, e.Register(rec.live(f, r3, conn, g2.ExpiresAt)))
	e.TerminateAll(ReasonShutdown)
	if v := val(t, m, "hallpass_enforcer_terminations_total"); v != 3 {
		t.Errorf("total terminations = %v", v)
	}
	if v := val(t, m, "hallpass_enforcer_latency_seconds"); v != 2 { // shutdown is not an access end
		t.Errorf("latency samples = %v", v)
	}
	if earliest(time.Time{}, f.clk.Now()) != f.clk.Now() || earliest(f.clk.Now().Add(time.Hour), f.clk.Now()) != f.clk.Now() {
		t.Error("earliest clamps zero and future times to now")
	}
}
