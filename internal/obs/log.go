// Package obs provides logging, metrics, tracing and health primitives.
package obs

import (
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/buildinfo"
	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/obs/redact"
)

// ECS-aligned field names used across Hallpass logs (HP-OBS-001). See docs/operator/logging.md.
const (
	FieldTimestamp     = "@timestamp"
	FieldLevel         = "log.level"
	FieldMessage       = "message"
	FieldLogger        = "log.logger"
	FieldServiceName   = "service.name"
	FieldServiceVer    = "service.version"
	FieldEventAction   = "event.action"
	FieldEventOutcome  = "event.outcome"
	FieldEventDuration = "event.duration"
	FieldError         = "error.message"
	FieldTraceID       = "trace.id"
	FieldSpanID        = "span.id"
	FieldHTTPRequestID = "http.request.id"
	FieldSourceIP      = "source.ip"
	FieldUserID        = "user.id"
	FieldAgentID       = "hallpass.agent_id"
	FieldKeyID         = "hallpass.key_id"
	FieldServerID      = "hallpass.server_id"
	FieldRoleID        = "hallpass.role_id"
	FieldRequestID     = "hallpass.request_id"
	FieldGrantID       = "hallpass.grant_id"
	FieldSessionID     = "hallpass.session_id"
	FieldConnectionID  = "hallpass.connection_id"
	FieldChannelID     = "hallpass.channel_id"
	FieldSegmentID     = "hallpass.segment_id"
	FieldComponent     = "hallpass.component"
)

// NewLogger builds the process logger. JSON output uses ECS-aligned top-level keys and every handler
// redacts sensitive attribute keys. The returned LevelVar allows changing the level at runtime.
func NewLogger(w io.Writer, cfg config.LogConfig) (*slog.Logger, *slog.LevelVar) {
	lv := new(slog.LevelVar)
	lv.Set(ParseLevel(cfg.Level))
	opts := &slog.HandlerOptions{Level: lv}
	var h slog.Handler
	if cfg.Format == "text" {
		opts.ReplaceAttr = redact.ReplaceAttr
		h = slog.NewTextHandler(w, opts)
	} else {
		opts.ReplaceAttr = ecsReplace
		h = slog.NewJSONHandler(w, opts)
	}
	l := slog.New(h).With(
		slog.String(FieldServiceName, "hallpass"),
		slog.String(FieldServiceVer, buildinfo.Get().Version),
	)
	return l, lv
}

// ParseLevel converts a config level name; unknown values map to info.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func ecsReplace(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 {
		switch a.Key {
		case slog.TimeKey:
			if t, ok := a.Value.Any().(time.Time); ok {
				return slog.String(FieldTimestamp, t.UTC().Format(time.RFC3339Nano))
			}
			return slog.Attr{Key: FieldTimestamp, Value: a.Value}
		case slog.LevelKey:
			return slog.String(FieldLevel, strings.ToLower(a.Value.String()))
		case slog.MessageKey:
			return slog.Attr{Key: FieldMessage, Value: a.Value}
		}
	}
	return redact.ReplaceAttr(groups, a)
}

// Err returns the standard error attribute.
func Err(err error) slog.Attr {
	if err == nil {
		return slog.Attr{}
	}
	return slog.String(FieldError, err.Error())
}

// Component returns a logger tagged with a component name.
func Component(l *slog.Logger, name string) *slog.Logger {
	return l.With(slog.String(FieldComponent, name))
}
