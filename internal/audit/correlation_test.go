package audit

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/trace"

	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// HP-OBS-003: audit events carry the request/trace correlation and lifecycle IDs from the context.
func TestAuditCorrelationFromContext(t *testing.T) {
	s, w := setup(t)
	sink := &memSink{}
	w.SetSink(sink)
	tid, _ := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	sid, _ := trace.SpanIDFromHex("00f067aa0ba902b7")
	spanCtx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid}))
	appendCtx := func(ctx context.Context, ev Event) {
		t.Helper()
		if err := s.W().Tx(ctx, func(tx *store.Tx) error {
			_, err := w.Append(ctx, tx, ev)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	details := map[string]any{"k": "v"}
	ctx := obs.WithIDs(spanCtx, obs.HTTPRequestID("req-abc"), obs.AgentID("agt_1"), obs.ConnectionID("con_1"))
	appendCtx(ctx, Event{Actor: System, Action: "a.one", Details: details})
	appendCtx(spanCtx, Event{Actor: System, Action: "a.two"})
	appendCtx(WithMeta(ctx, Meta{CorrelationID: "meta-id"}), Event{Actor: System, Action: "a.three",
		Details: map[string]any{CorrelationKey: "caller"}})
	appendCtx(context.Background(), Event{Actor: System, Action: "a.four"})

	r := sink.recs
	corr, _ := r[0].Details[CorrelationKey].(map[string]any)
	if r[0].CorrelationID != "req-abc" || corr["trace_id"] != tid.String() || corr["agent_id"] != "agt_1" ||
		corr["connection_id"] != "con_1" || corr["http_request_id"] != "req-abc" || r[0].Details["k"] != "v" {
		t.Errorf("event 1: %+v", r[0])
	}
	if _, mutated := details[CorrelationKey]; mutated {
		t.Error("caller's details map was modified")
	}
	if r[1].CorrelationID != tid.String() {
		t.Errorf("event 2 correlation = %q", r[1].CorrelationID)
	}
	if r[2].CorrelationID != "meta-id" || r[2].Details[CorrelationKey] != "caller" {
		t.Errorf("event 3: %+v", r[2])
	}
	if r[3].CorrelationID != "" || r[3].Details != nil {
		t.Errorf("event 4: %+v", r[3])
	}
	res, err := Verify(context.Background(), s.R())
	if err != nil || !res.OK {
		t.Fatalf("chain: %+v %v", res, err)
	}
}
