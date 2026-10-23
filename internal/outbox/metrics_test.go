package outbox

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/keyring/keyringtest"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics/metricstest"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
)

func waitMetric(t *testing.T, m *metrics.Metrics, want float64, name string, labels ...string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if metricstest.Value(t, m, name, labels...) == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s%v = %v, want %v", name, labels, metricstest.Value(t, m, name, labels...), want)
}

// HP-OBS-004: delivery outcomes by provider and the pending/dead-letter backlog are exported.
func TestDeliveryMetrics(t *testing.T) {
	s := storetest.Open(t)
	m := metrics.New()
	o := New(s, keyringtest.Load(t, s), Options{PollInterval: 10 * time.Millisecond, BaseBackoff: 5 * time.Millisecond,
		MaxBackoff: 20 * time.Millisecond, Metrics: m})
	o.RegisterProvider("slack", &fakeProvider{fn: func(n int32, _ Delivery) (Result, error) {
		if n == 1 {
			return Result{}, errors.New("rate limited")
		}
		return Result{ProviderRef: "ts"}, nil
	}})
	o.RegisterProvider("telegram", &fakeProvider{fn: func(int32, Delivery) (Result, error) {
		return Result{}, fmt.Errorf("%w: chat not found", ErrPermanent)
	}})
	slack, tg := msg(), msg()
	slack.Provider, tg.Provider = "slack", "telegram"
	idDead := enqueue(t, s, o, tg)
	o.RefreshBacklog(context.Background())
	if v := metricstest.Value(t, m, "hallpass_outbox_pending"); v != 1 {
		t.Errorf("pending before delivery = %v", v)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go o.Run(ctx, 2)
	id := enqueue(t, s, o, slack)
	waitState(t, s, id, "delivered")
	waitState(t, s, idDead, "dead")
	waitMetric(t, m, 1, "hallpass_notification_deliveries_total", "provider", "slack", "outcome", "retry")
	waitMetric(t, m, 1, "hallpass_notification_deliveries_total", "provider", "slack", "outcome", "delivered")
	waitMetric(t, m, 1, "hallpass_notification_deliveries_total", "provider", "telegram", "outcome", "dead")

	o.RefreshBacklog(context.Background())
	if p, d := metricstest.Value(t, m, "hallpass_outbox_pending"), metricstest.Value(t, m, "hallpass_outbox_dead"); p != 0 || d != 1 {
		t.Errorf("backlog pending=%v dead=%v", p, d)
	}
	New(s, nil, Options{}).RefreshBacklog(context.Background()) // nil metrics: no-op
}
