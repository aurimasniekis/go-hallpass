// Package tracing sets up OpenTelemetry tracing for Hallpass (HP-OBS-004): an OTLP/HTTP exporter when
// telemetry.otlp_endpoint is configured, and a no-op provider otherwise.
//
// Spans must never carry secrets, reasons, commands, terminal data, tokens or raw URLs. Helpers in this package
// drop attributes whose keys are on the redaction denylist (internal/obs/redact), and the exporter is wrapped
// to strip such attributes again before export (defense in depth).
package tracing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/aurimasniekis/go-hallpass/internal/buildinfo"
	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/obs/redact"
)

// TracerName is the instrumentation scope of Hallpass spans.
const TracerName = "github.com/aurimasniekis/go-hallpass"

// ServiceName is the service.name resource attribute.
const ServiceName = "hallpass"

// DefaultURLPath is appended to telemetry.otlp_endpoint when it has no path (OTLP/HTTP traces signal path).
const DefaultURLPath = "/v1/traces"

// Span names for the instrumented operations (PLAN WP22: HTTP, SSH auth, authorization, dial, decision tx).
const (
	SpanSSHAuth      = "ssh.auth"
	SpanSSHChannel   = "ssh.channel"
	SpanAuthorize    = "access.authorize"
	SpanDial         = "ssh.dial"
	SpanDecision     = "access.decide"
	SpanRequest      = "access.request"
	SpanNotification = "notify.deliver"
	SpanOIDCCallback = "oidc.callback"
)

// Provider owns the tracer provider and its exporter.
type Provider struct {
	tp      trace.TracerProvider
	sdk     *sdktrace.TracerProvider
	once    sync.Once
	errShut error
}

type options struct {
	logger       *slog.Logger
	sampleRatio  float64
	global       bool
	batchTimeout time.Duration
	exporter     sdktrace.SpanExporter
}

// Option customizes Setup.
type Option func(*options)

// WithLogger routes OpenTelemetry export errors to log.
func WithLogger(l *slog.Logger) Option { return func(o *options) { o.logger = l } }

// WithSampleRatio sets the root sampling ratio (0 < r ≤ 1; default 1). Child spans follow their parent.
func WithSampleRatio(r float64) Option { return func(o *options) { o.sampleRatio = r } }

// WithGlobal controls whether Setup installs the provider as the OpenTelemetry global (default true). Start
// and HTTPMiddleware use the global provider.
func WithGlobal(b bool) Option { return func(o *options) { o.global = b } }

// WithBatchTimeout sets the batch span processor's export interval (default 5 s).
func WithBatchTimeout(d time.Duration) Option { return func(o *options) { o.batchTimeout = d } }

// WithExporter replaces the OTLP exporter (tests). The exporter is still wrapped by the redacting filter.
func WithExporter(e sdktrace.SpanExporter) Option { return func(o *options) { o.exporter = e } }

// Setup builds the tracer provider from cfg. With an empty OTLPEndpoint (and no WithExporter) it returns a
// no-op provider: no exporter, no goroutines, no network.
func Setup(ctx context.Context, cfg config.TelemetryConfig, opts ...Option) (*Provider, error) {
	o := options{sampleRatio: 1, global: true}
	for _, fn := range opts {
		fn(&o)
	}
	exp := o.exporter
	if exp == nil {
		if cfg.OTLPEndpoint == "" {
			p := &Provider{tp: noop.NewTracerProvider()}
			if o.global {
				otel.SetTracerProvider(p.tp)
			}
			return p, nil
		}
		eopts, err := endpointOptions(cfg.OTLPEndpoint)
		if err != nil {
			return nil, err
		}
		if exp, err = otlptracehttp.New(ctx, eopts...); err != nil {
			return nil, fmt.Errorf("otlp exporter: %w", err)
		}
	}
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		attribute.String("service.name", ServiceName),
		attribute.String("service.version", buildinfo.Get().Version),
	))
	if err != nil {
		return nil, fmt.Errorf("otel resource: %w", err)
	}
	ratio := o.sampleRatio
	if ratio <= 0 || ratio > 1 {
		ratio = 1
	}
	var bopts []sdktrace.BatchSpanProcessorOption
	if o.batchTimeout > 0 {
		bopts = append(bopts, sdktrace.WithBatchTimeout(o.batchTimeout))
	}
	sdk := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))),
		sdktrace.WithBatcher(&redactingExporter{next: exp}, bopts...),
	)
	p := &Provider{tp: sdk, sdk: sdk}
	if o.global {
		otel.SetTracerProvider(sdk)
		if o.logger != nil {
			l := obs.Component(o.logger, "otel")
			otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
				l.Warn("opentelemetry error", obs.Err(err))
			}))
		}
	}
	return p, nil
}

// endpointOptions turns telemetry.otlp_endpoint (an http(s) base URL) into exporter options.
func endpointOptions(raw string) ([]otlptracehttp.Option, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("telemetry.otlp_endpoint must be an http(s) URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("telemetry.otlp_endpoint must not contain credentials, a query or a fragment")
	}
	path := strings.TrimRight(u.Path, "/")
	if !strings.HasSuffix(path, DefaultURLPath) {
		path += DefaultURLPath
	}
	opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(u.Host), otlptracehttp.WithURLPath(path)}
	if u.Scheme == "http" {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	return opts, nil
}

// Enabled reports whether spans are exported.
func (p *Provider) Enabled() bool { return p != nil && p.sdk != nil }

// TracerProvider returns the provider.
func (p *Provider) TracerProvider() trace.TracerProvider {
	if p == nil {
		return noop.NewTracerProvider()
	}
	return p.tp
}

// Tracer returns the Hallpass tracer of this provider.
func (p *Provider) Tracer() trace.Tracer { return p.TracerProvider().Tracer(TracerName) }

// ForceFlush exports buffered spans.
func (p *Provider) ForceFlush(ctx context.Context) error {
	if !p.Enabled() {
		return nil
	}
	return p.sdk.ForceFlush(ctx)
}

// Shutdown flushes and stops the exporter. It is idempotent and a no-op when tracing is disabled.
func (p *Provider) Shutdown(ctx context.Context) error {
	if !p.Enabled() {
		return nil
	}
	p.once.Do(func() { p.errShut = p.sdk.Shutdown(ctx) })
	return p.errShut
}

// Start starts a span on the global provider with the given attributes; sensitive keys are dropped.
func Start(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return otel.Tracer(TracerName).Start(ctx, name, trace.WithAttributes(SafeAttrs(attrs...)...))
}

// StartKind is Start with a span kind (server for inbound SSH/HTTP, client for outbound dials).
func StartKind(ctx context.Context, name string, kind trace.SpanKind, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return otel.Tracer(TracerName).Start(ctx, name, trace.WithSpanKind(kind), trace.WithAttributes(SafeAttrs(attrs...)...))
}

// SetAttributes sets attributes on span after dropping sensitive keys.
func SetAttributes(span trace.Span, attrs ...attribute.KeyValue) {
	span.SetAttributes(SafeAttrs(attrs...)...)
}

// maxStatusLen bounds error descriptions on spans.
const maxStatusLen = 256

// End ends span, marking it as an error when err is non-nil. Error text follows the logging rule: errors never
// include secrets by construction; it is truncated to a bounded length.
func End(span trace.Span, err error) {
	if err != nil {
		msg := err.Error()
		if len(msg) > maxStatusLen {
			msg = msg[:maxStatusLen]
		}
		span.SetStatus(codes.Error, msg)
	}
	span.End()
}

// SafeAttrs returns attrs without keys on the redaction denylist (reason, command, *_token, password, …).
func SafeAttrs(attrs ...attribute.KeyValue) []attribute.KeyValue {
	out := attrs[:0:0]
	for _, a := range attrs {
		if !redact.IsSensitiveKey(string(a.Key)) {
			out = append(out, a)
		}
	}
	return out
}

// Correlation attributes (same keys as the log fields, HP-OBS-003).
func AgentID(v string) attribute.KeyValue      { return attribute.String(obs.FieldAgentID, v) }
func KeyID(v string) attribute.KeyValue        { return attribute.String(obs.FieldKeyID, v) }
func ServerID(v string) attribute.KeyValue     { return attribute.String(obs.FieldServerID, v) }
func RoleID(v string) attribute.KeyValue       { return attribute.String(obs.FieldRoleID, v) }
func RequestID(v string) attribute.KeyValue    { return attribute.String(obs.FieldRequestID, v) }
func GrantID(v string) attribute.KeyValue      { return attribute.String(obs.FieldGrantID, v) }
func SessionID(v string) attribute.KeyValue    { return attribute.String(obs.FieldSessionID, v) }
func ConnectionID(v string) attribute.KeyValue { return attribute.String(obs.FieldConnectionID, v) }
func ChannelID(v string) attribute.KeyValue    { return attribute.String(obs.FieldChannelID, v) }
func UserID(v string) attribute.KeyValue       { return attribute.String(obs.FieldUserID, v) }

// Outcome is the event.outcome attribute ("success", "failure", "unknown").
func Outcome(v string) attribute.KeyValue { return attribute.String(obs.FieldEventOutcome, v) }

// CorrelationAttrs converts the correlation IDs carried by ctx into span attributes.
func CorrelationAttrs(ctx context.Context) []attribute.KeyValue {
	ids := obs.IDs(ctx)
	out := make([]attribute.KeyValue, 0, len(ids))
	for _, id := range ids {
		out = append(out, attribute.String(id.Key(), id.Value()))
	}
	return out
}

// redactingExporter strips sensitive attributes from spans, events and links before export.
type redactingExporter struct{ next sdktrace.SpanExporter }

func (e *redactingExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	out := make([]sdktrace.ReadOnlySpan, 0, len(spans))
	for _, s := range spans {
		if !needsRedaction(s) {
			out = append(out, s)
			continue
		}
		stub := tracetest.SpanStubFromReadOnlySpan(s)
		stub.Attributes = SafeAttrs(stub.Attributes...)
		for i := range stub.Events {
			stub.Events[i].Attributes = SafeAttrs(stub.Events[i].Attributes...)
		}
		for i := range stub.Links {
			stub.Links[i].Attributes = SafeAttrs(stub.Links[i].Attributes...)
		}
		out = append(out, stub.Snapshot())
	}
	return e.next.ExportSpans(ctx, out)
}

func (e *redactingExporter) Shutdown(ctx context.Context) error { return e.next.Shutdown(ctx) }

func needsRedaction(s sdktrace.ReadOnlySpan) bool {
	bad := func(as []attribute.KeyValue) bool {
		for _, a := range as {
			if redact.IsSensitiveKey(string(a.Key)) {
				return true
			}
		}
		return false
	}
	if bad(s.Attributes()) {
		return true
	}
	for _, ev := range s.Events() {
		if bad(ev.Attributes) {
			return true
		}
	}
	for _, l := range s.Links() {
		if bad(l.Attributes) {
			return true
		}
	}
	return false
}
