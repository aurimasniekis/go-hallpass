package tracing

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/obs/internal/httpwrap"
)

// RequestIDHeader is the response header carrying the generated http.request.id.
const RequestIDHeader = "X-Request-Id"

type mwOptions struct {
	trustIncoming bool
}

// MiddlewareOption customizes HTTPMiddleware.
type MiddlewareOption func(*mwOptions)

// TrustIncomingTraceContext continues traces from an inbound W3C traceparent header. Off by default: the API is
// reachable by untrusted clients, so each request starts a new root span unless a trusted proxy sets the header.
func TrustIncomingTraceContext() MiddlewareOption {
	return func(o *mwOptions) { o.trustIncoming = true }
}

// HTTPMiddleware gives every request a fresh random http.request.id (never taken from the client), returns it in
// X-Request-Id, attaches it to the context for log correlation (HP-OBS-003), and wraps the request in a server
// span named "<METHOD> <route template>". Only the matched http.ServeMux pattern is recorded: raw paths and
// query strings can contain action tokens and are never span names or attributes.
func HTTPMiddleware(next http.Handler, opts ...MiddlewareOption) http.Handler {
	var o mwOptions
	for _, fn := range opts {
		fn(&o)
	}
	prop := propagation.TraceContext{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if o.trustIncoming {
			ctx = prop.Extract(ctx, propagation.HeaderCarrier(r.Header))
		}
		reqID := NewRequestID()
		ctx = obs.WithIDs(ctx, obs.HTTPRequestID(reqID))
		method := httpwrap.Method(r.Method)
		ctx, span := StartKind(ctx, "HTTP "+method, trace.SpanKindServer,
			attribute.String("http.request.method", method),
			attribute.String(obs.FieldHTTPRequestID, reqID),
		)
		w.Header().Set(RequestIDHeader, reqID)
		rec := httpwrap.New(w)
		r2 := r.WithContext(ctx)
		defer func() {
			route := httpwrap.Route(r2.Pattern)
			if route == "" {
				route = "unmatched"
			}
			span.SetName(method + " " + route)
			status := rec.Status()
			span.SetAttributes(attribute.String("http.route", route), attribute.Int("http.response.status_code", status))
			if status >= 500 {
				span.SetStatus(codes.Error, http.StatusText(status))
			}
			span.End()
		}()
		next.ServeHTTP(rec, r2)
	})
}

// NewRequestID returns a random 128-bit hex identifier.
func NewRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never returns an error on supported platforms
	return hex.EncodeToString(b[:])
}
