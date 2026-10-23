package obs

import (
	"context"
	"log/slog"
	"maps"
	"slices"

	"go.opentelemetry.io/otel/trace"
)

// Correlation IDs (HP-OBS-003). Identifiers are attached to a context once (HTTP middleware, SSH connection
// and channel setup) and every log record emitted with that context — via the *Context logging methods —
// carries them, together with trace.id and span.id of the active OpenTelemetry span.

// CorrelationID is one identifier attached to a context. Construct it with the typed helpers below.
type CorrelationID struct {
	key, value string
}

// maxIDLen bounds correlation values; identifiers are short generated strings.
const maxIDLen = 128

func corr(key, v string) CorrelationID {
	if len(v) > maxIDLen {
		v = v[:maxIDLen]
	}
	return CorrelationID{key: key, value: v}
}

// Correlation ID constructors. Only these keys can be attached; values are identifiers, never secrets.
func HTTPRequestID(v string) CorrelationID { return corr(FieldHTTPRequestID, v) }
func UserID(v string) CorrelationID        { return corr(FieldUserID, v) }
func AgentID(v string) CorrelationID       { return corr(FieldAgentID, v) }
func KeyID(v string) CorrelationID         { return corr(FieldKeyID, v) }
func ServerID(v string) CorrelationID      { return corr(FieldServerID, v) }
func RoleID(v string) CorrelationID        { return corr(FieldRoleID, v) }
func RequestID(v string) CorrelationID     { return corr(FieldRequestID, v) }
func GrantID(v string) CorrelationID       { return corr(FieldGrantID, v) }
func SessionID(v string) CorrelationID     { return corr(FieldSessionID, v) }
func ConnectionID(v string) CorrelationID  { return corr(FieldConnectionID, v) }
func ChannelID(v string) CorrelationID     { return corr(FieldChannelID, v) }

// Key returns the log field name.
func (c CorrelationID) Key() string { return c.key }

// Value returns the identifier.
func (c CorrelationID) Value() string { return c.value }

type corrKey struct{}

// WithIDs returns a context carrying ids in addition to those already present; a later value for the same key
// replaces the earlier one. Empty values are ignored.
func WithIDs(ctx context.Context, ids ...CorrelationID) context.Context {
	cur, _ := ctx.Value(corrKey{}).([]CorrelationID)
	next := slices.Clone(cur)
	for _, id := range ids {
		if id.key == "" || id.value == "" {
			continue
		}
		if i := slices.IndexFunc(next, func(c CorrelationID) bool { return c.key == id.key }); i >= 0 {
			next[i] = id
		} else {
			next = append(next, id)
		}
	}
	if len(next) == len(cur) && slices.Equal(next, cur) {
		return ctx
	}
	return context.WithValue(ctx, corrKey{}, next)
}

// IDs returns the correlation IDs carried by ctx.
func IDs(ctx context.Context) []CorrelationID {
	if ctx == nil {
		return nil
	}
	ids, _ := ctx.Value(corrKey{}).([]CorrelationID)
	return slices.Clone(ids)
}

// ID returns the value of one correlation field (e.g. FieldHTTPRequestID) carried by ctx, or "".
func ID(ctx context.Context, key string) string {
	for _, c := range IDs(ctx) {
		if c.key == key {
			return c.value
		}
	}
	return ""
}

// TraceIDs returns the trace and span ID of the span in ctx, or empty strings when there is none.
func TraceIDs(ctx context.Context) (traceID, spanID string) {
	if ctx == nil {
		return "", ""
	}
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return "", ""
	}
	return sc.TraceID().String(), sc.SpanID().String()
}

// ContextHandler adds trace.id, span.id and the correlation IDs from the record's context to every record, always
// at the top level (also under Logger.WithGroup). Top-level attributes the caller set explicitly (on the record or
// via Logger.With) win over context values.
type ContextHandler struct {
	next   slog.Handler    // never has groups applied; groups are rendered by Handle
	fixed  map[string]bool // top-level keys added through WithAttrs
	frames []groupFrame    // open groups, outermost first
}

type groupFrame struct {
	name  string
	attrs []slog.Attr // attrs added after the group was opened
}

// NewContextHandler wraps h.
func NewContextHandler(h slog.Handler) *ContextHandler { return &ContextHandler{next: h} }

// Enabled implements slog.Handler.
func (h *ContextHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

// Handle implements slog.Handler.
func (h *ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	ids := IDs(ctx)
	tid, sid := TraceIDs(ctx)
	if len(ids) == 0 && tid == "" && len(h.frames) == 0 {
		return h.next.Handle(ctx, r)
	}
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	present := make(map[string]bool, r.NumAttrs()+len(h.fixed))
	for k := range h.fixed {
		present[k] = true
	}
	if len(h.frames) == 0 {
		r.Attrs(func(a slog.Attr) bool {
			present[a.Key] = true
			out.AddAttrs(a)
			return true
		})
	} else {
		var inner []slog.Attr
		r.Attrs(func(a slog.Attr) bool {
			inner = append(inner, a)
			return true
		})
		for i := len(h.frames) - 1; i >= 0; i-- {
			content := append(slices.Clone(h.frames[i].attrs), inner...)
			inner = []slog.Attr{{Key: h.frames[i].name, Value: slog.GroupValue(content...)}}
		}
		out.AddAttrs(inner...)
		present[h.frames[0].name] = true
	}
	add := func(k, v string) {
		if !present[k] {
			out.AddAttrs(slog.String(k, v))
		}
	}
	if tid != "" {
		add(FieldTraceID, tid)
		add(FieldSpanID, sid)
	}
	for _, c := range ids {
		add(c.key, c.value)
	}
	return h.next.Handle(ctx, out)
}

// WithAttrs implements slog.Handler.
func (h *ContextHandler) WithAttrs(as []slog.Attr) slog.Handler {
	if len(as) == 0 {
		return h
	}
	if n := len(h.frames); n > 0 {
		frames := slices.Clone(h.frames)
		frames[n-1].attrs = append(slices.Clone(frames[n-1].attrs), as...)
		return &ContextHandler{next: h.next, fixed: h.fixed, frames: frames}
	}
	fixed := maps.Clone(h.fixed)
	if fixed == nil {
		fixed = make(map[string]bool, len(as))
	}
	for _, a := range as {
		fixed[a.Key] = true
	}
	return &ContextHandler{next: h.next.WithAttrs(as), fixed: fixed}
}

// WithGroup implements slog.Handler.
func (h *ContextHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	frames := append(slices.Clone(h.frames), groupFrame{name: name})
	return &ContextHandler{next: h.next, fixed: h.fixed, frames: frames}
}
