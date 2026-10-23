package tracing

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
)

const planted = "pl4nted-s3cret"

// useRecorder installs a global SDK provider backed by an in-memory recorder for the test.
func useRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	prev := otel.GetTracerProvider()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prev)
	})
	return rec
}

func TestNoopWhenUnconfigured(t *testing.T) {
	p, err := Setup(context.Background(), config.TelemetryConfig{}, WithGlobal(false))
	if err != nil {
		t.Fatal(err)
	}
	if p.Enabled() {
		t.Error("tracing must be disabled without an endpoint")
	}
	_, span := p.Tracer().Start(context.Background(), "x")
	if span.IsRecording() || span.SpanContext().IsValid() {
		t.Error("no-op provider must not record")
	}
	span.End()
	if err := p.ForceFlush(context.Background()); err != nil {
		t.Error(err)
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Error(err)
	}
	var nilP *Provider
	if nilP.Enabled() || nilP.Tracer() == nil || nilP.Shutdown(context.Background()) != nil {
		t.Error("nil provider must be safe")
	}

	prev := otel.GetTracerProvider()
	defer otel.SetTracerProvider(prev)
	g, err := Setup(context.Background(), config.TelemetryConfig{})
	if err != nil || otel.GetTracerProvider() != g.TracerProvider() {
		t.Errorf("global no-op not installed: %v", err)
	}
}

func TestEndpointOptions(t *testing.T) {
	for _, bad := range []string{"ftp://x", "http://", "://", "http://u:p@host:4318", "http://host:4318/?k=v", "http://h/#f"} {
		if _, err := endpointOptions(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, good := range []string{"http://collector:4318", "https://collector/v1/traces", "http://c:4318/otlp/"} {
		if _, err := endpointOptions(good); err != nil {
			t.Errorf("rejected %q: %v", good, err)
		}
	}
	if _, err := Setup(context.Background(), config.TelemetryConfig{OTLPEndpoint: "ftp://x"}, WithGlobal(false)); err == nil {
		t.Error("Setup accepted a bad endpoint")
	}
}

func TestSafeAttrs(t *testing.T) {
	in := []attribute.KeyValue{
		AgentID("agt_1"), GrantID("gnt_1"), RequestID("req_1"), SessionID("ses_1"), ConnectionID("con_1"), ChannelID("chn_1"),
		ServerID("srv_1"), RoleID("rol_1"), KeyID("key_1"), UserID("op_1"), Outcome("success"),
		attribute.String("hallpass.reason", planted), attribute.String("command", planted), attribute.String("bot_token", planted),
		attribute.String("password", planted), attribute.String("stdout", planted),
	}
	out := SafeAttrs(in...)
	if len(out) != 11 {
		t.Errorf("kept %d attrs: %v", len(out), out)
	}
	for _, a := range out {
		if a.Value.AsString() == planted {
			t.Errorf("sensitive attr kept: %s", a.Key)
		}
	}
	if len(in) != 16 {
		t.Error("SafeAttrs must not modify its input")
	}
}

func TestStartEndHelpers(t *testing.T) {
	rec := useRecorder(t)
	ctx := obs.WithIDs(context.Background(), obs.AgentID("agt_1"), obs.ChannelID("chn_1"))
	_, span := Start(ctx, SpanSSHAuth, append(CorrelationAttrs(ctx), attribute.String("reason", planted))...)
	SetAttributes(span, attribute.String("command", planted), Outcome("failure"))
	End(span, errors.New(strings.Repeat("e", 1000)))
	_, s2 := StartKind(ctx, SpanDial, trace.SpanKindClient, ServerID("srv_1"))
	End(s2, nil)

	spans := rec.Ended()
	if len(spans) != 2 {
		t.Fatalf("got %d spans", len(spans))
	}
	a := spans[0]
	if a.Name() != SpanSSHAuth || a.Status().Code != codes.Error || len(a.Status().Description) != maxStatusLen {
		t.Errorf("auth span: %s %+v", a.Name(), a.Status())
	}
	attrs := map[string]string{}
	for _, kv := range a.Attributes() {
		attrs[string(kv.Key)] = kv.Value.AsString()
	}
	if attrs[obs.FieldAgentID] != "agt_1" || attrs[obs.FieldChannelID] != "chn_1" || attrs[obs.FieldEventOutcome] != "failure" {
		t.Errorf("attrs: %v", attrs)
	}
	if _, bad := attrs["reason"]; bad {
		t.Error("reason attribute recorded")
	}
	if _, bad := attrs["command"]; bad {
		t.Error("command attribute recorded")
	}
	if spans[1].SpanKind() != trace.SpanKindClient || spans[1].Status().Code != codes.Unset {
		t.Errorf("dial span: %v %v", spans[1].SpanKind(), spans[1].Status())
	}
}

func TestHTTPMiddleware(t *testing.T) {
	rec := useRecorder(t)
	var gotReqID, gotTrace string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/actions/{token}", func(w http.ResponseWriter, r *http.Request) {
		gotReqID = obs.ID(r.Context(), obs.FieldHTTPRequestID)
		gotTrace, _ = obs.TraceIDs(r.Context())
		w.WriteHeader(http.StatusInternalServerError)
	})
	h := HTTPMiddleware(mux)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/actions/"+planted+"?sig="+planted, nil)
	req.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	req.Header.Set(RequestIDHeader, "client-chosen")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	id := w.Header().Get(RequestIDHeader)
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(id) || id != gotReqID {
		t.Errorf("request id %q (ctx %q)", id, gotReqID)
	}
	if gotTrace == "" || gotTrace == "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("incoming traceparent must be ignored by default, trace=%q", gotTrace)
	}
	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("spans: %d", len(spans))
	}
	s := spans[0]
	if s.Name() != "GET /api/v1/actions/{token}" || s.SpanKind() != trace.SpanKindServer || s.Status().Code != codes.Error {
		t.Errorf("span %q kind %v status %v", s.Name(), s.SpanKind(), s.Status())
	}
	for _, kv := range s.Attributes() {
		if strings.Contains(kv.Value.String(), planted) {
			t.Errorf("raw path leaked into %s", kv.Key)
		}
	}

	// Trusted proxies may continue the trace; unmatched routes get a fixed name.
	h2 := HTTPMiddleware(mux, TrustIncomingTraceContext())
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/actions/x", nil)
	req2.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	h2.ServeHTTP(httptest.NewRecorder(), req2)
	if gotTrace != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("trusted traceparent not continued: %q", gotTrace)
	}
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/"+planted, nil))
	if last := rec.Ended()[len(rec.Ended())-1]; last.Name() != "GET unmatched" {
		t.Errorf("unmatched span name %q", last.Name())
	}
}

// otlpReceiver is an in-process OTLP/HTTP trace collector.
type otlpReceiver struct {
	mu   sync.Mutex
	reqs []*coltracepb.ExportTraceServiceRequest
	raw  [][]byte
	got  chan struct{}
}

func (o *otlpReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != DefaultURLPath || r.Method != http.MethodPost {
		http.Error(w, "unexpected", http.StatusNotFound)
		return
	}
	var body io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body = zr
	}
	b, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req := &coltracepb.ExportTraceServiceRequest{}
	if err := proto.Unmarshal(b, req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	o.mu.Lock()
	o.reqs = append(o.reqs, req)
	o.raw = append(o.raw, b)
	o.mu.Unlock()
	resp, _ := proto.Marshal(&coltracepb.ExportTraceServiceResponse{})
	w.Header().Set("Content-Type", "application/x-protobuf")
	_, _ = w.Write(resp)
	select {
	case o.got <- struct{}{}:
	default:
	}
}

func TestOTLPExportToInProcessReceiver(t *testing.T) {
	recv := &otlpReceiver{got: make(chan struct{}, 1)}
	srv := httptest.NewServer(recv)
	defer srv.Close()

	var logBuf bytes.Buffer
	p, err := Setup(context.Background(), config.TelemetryConfig{OTLPEndpoint: srv.URL}, WithGlobal(false),
		WithBatchTimeout(10*time.Millisecond), WithSampleRatio(1), WithLogger(slog.New(slog.NewTextHandler(&logBuf, nil))))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Enabled() {
		t.Fatal("tracing must be enabled with an endpoint")
	}
	_, span := p.Tracer().Start(context.Background(), SpanDecision, trace.WithAttributes(
		GrantID("gnt_1"),
		attribute.String("hallpass.reason", planted), // bypasses SafeAttrs on purpose: the exporter must strip it
	))
	span.AddEvent("decided", trace.WithAttributes(attribute.String("comment", planted), Outcome("success")))
	span.End()
	_, clean := p.Tracer().Start(context.Background(), SpanSSHAuth)
	clean.End()

	select {
	case <-recv.got:
	case <-time.After(10 * time.Second):
		t.Fatal("no OTLP export received")
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Error("Shutdown must be idempotent")
	}

	recv.mu.Lock()
	defer recv.mu.Unlock()
	names := map[string]bool{}
	var service, version string
	for _, req := range recv.reqs {
		for _, rs := range req.GetResourceSpans() {
			for _, kv := range rs.GetResource().GetAttributes() {
				switch kv.GetKey() {
				case "service.name":
					service = kv.GetValue().GetStringValue()
				case "service.version":
					version = kv.GetValue().GetStringValue()
				}
			}
			for _, ss := range rs.GetScopeSpans() {
				if ss.GetScope().GetName() != TracerName {
					t.Errorf("scope %q", ss.GetScope().GetName())
				}
				for _, s := range ss.GetSpans() {
					names[s.GetName()] = true
					if s.GetName() == SpanDecision {
						var keys []string
						for _, kv := range s.GetAttributes() {
							keys = append(keys, kv.GetKey())
						}
						if strings.Join(keys, ",") != obs.FieldGrantID {
							t.Errorf("decision attrs = %v", keys)
						}
						if ev := s.GetEvents(); len(ev) != 1 || len(ev[0].GetAttributes()) != 1 {
							t.Errorf("event attrs not filtered: %v", ev)
						}
					}
				}
			}
		}
	}
	if !names[SpanDecision] || !names[SpanSSHAuth] {
		t.Errorf("spans received: %v", names)
	}
	if service != ServiceName || version == "" {
		t.Errorf("resource service.name=%q service.version=%q", service, version)
	}
	for _, b := range recv.raw {
		if bytes.Contains(b, []byte(planted)) {
			t.Fatal("planted secret reached the collector")
		}
	}
}

type failingExporter struct{ calls atomic.Int32 }

func (f *failingExporter) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error {
	f.calls.Add(1)
	return errors.New("collector unavailable")
}
func (f *failingExporter) Shutdown(context.Context) error { return nil }

func TestGlobalSetupRoutesExportErrorsToLogger(t *testing.T) {
	prevTP, prevEH := otel.GetTracerProvider(), otel.GetErrorHandler()
	defer func() {
		otel.SetTracerProvider(prevTP)
		otel.SetErrorHandler(prevEH)
	}()
	var buf bytes.Buffer
	var mu sync.Mutex
	l := slog.New(slog.NewTextHandler(&lockedWriter{w: &buf, mu: &mu}, nil))
	exp := &failingExporter{}
	p, err := Setup(context.Background(), config.TelemetryConfig{}, WithExporter(exp), WithLogger(l), WithSampleRatio(5),
		WithBatchTimeout(5*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Enabled() || otel.GetTracerProvider() != p.TracerProvider() {
		t.Fatal("WithExporter must enable and install the provider globally")
	}
	_, span := Start(context.Background(), SpanRequest)
	span.End()
	logged := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return strings.Contains(buf.String(), "opentelemetry error")
	}
	for deadline := time.Now().Add(5 * time.Second); !logged() && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	_ = p.Shutdown(context.Background())
	if exp.calls.Load() == 0 || !logged() {
		t.Errorf("export error not logged (calls=%d)", exp.calls.Load())
	}
}

type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(b)
}

func TestNewRequestIDUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		id := NewRequestID()
		if seen[id] || len(id) != 32 {
			t.Fatalf("bad or duplicate id %q", id)
		}
		seen[id] = true
	}
}
