package obs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/obs/redact"
)

const planted = "pl4nted-s3cret-value"

func TestJSONLoggerECSFields(t *testing.T) {
	var buf bytes.Buffer
	l, _ := NewLogger(&buf, config.LogConfig{Level: "info", Format: "json"})
	l.Info("hello", slog.String(FieldAgentID, "agt_x"), Err(errors.New("boom")))
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("not JSON: %v: %s", err, buf.String())
	}
	for _, k := range []string{FieldTimestamp, FieldLevel, FieldMessage, FieldServiceName, FieldServiceVer, FieldAgentID, FieldError} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing field %q in %s", k, buf.String())
		}
	}
	if m[FieldLevel] != "info" || m[FieldMessage] != "hello" {
		t.Errorf("unexpected level/message: %v", m)
	}
	for _, k := range []string{"time", "level", "msg"} {
		if _, ok := m[k]; ok {
			t.Errorf("non-ECS key %q present", k)
		}
	}
	if ts, _ := m[FieldTimestamp].(string); !strings.HasSuffix(ts, "Z") {
		t.Errorf("timestamp not UTC: %v", ts)
	}
}

// HP-OBS-002: sensitive keys and Secret values never reach any log format.
func TestRedactionNeverLeaks(t *testing.T) {
	for _, format := range []string{"json", "text"} {
		var buf bytes.Buffer
		l, _ := NewLogger(&buf, config.LogConfig{Level: "debug", Format: format})
		l.Info("event",
			slog.String("reason", planted),
			slog.String("hallpass.reason", planted),
			slog.String("password", planted),
			slog.String("client_secret", planted),
			slog.String("bot_token", planted),
			slog.String("command", planted),
			slog.String("Authorization", planted),
			slog.Any("wrapped", redact.NewSecret(planted)),
			slog.Group("req", slog.String("totp", planted), slog.String("cookie", planted)),
		)
		l.With(slog.String("private_key", planted)).Warn("with")
		l.Debug("fmt", slog.String("detail", fmt.Sprintf("%v %s %+v %#v", redact.NewSecret(planted), redact.NewSecret(planted),
			redact.NewSecret(planted), redact.NewSecret(planted))))
		if strings.Contains(buf.String(), planted) {
			t.Fatalf("%s log leaked secret:\n%s", format, buf.String())
		}
		if !strings.Contains(buf.String(), redact.Redacted) {
			t.Fatalf("%s log missing redaction marker", format)
		}
	}
}

func TestNonSensitiveKeysKept(t *testing.T) {
	var buf bytes.Buffer
	l, _ := NewLogger(&buf, config.LogConfig{Level: "info", Format: "json"})
	l.Info("x", slog.String("close_reason", "expired"), slog.Int("exit_code", 87), slog.String("event.outcome", "success"))
	for _, want := range []string{`"close_reason":"expired"`, `"exit_code":87`, `"event.outcome":"success"`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("missing %s in %s", want, buf.String())
		}
	}
}

func TestLevelVar(t *testing.T) {
	var buf bytes.Buffer
	l, lv := NewLogger(&buf, config.LogConfig{Level: "warn", Format: "json"})
	l.Info("hidden")
	if buf.Len() != 0 {
		t.Fatal("info logged at warn level")
	}
	lv.Set(slog.LevelInfo)
	l.Info("shown")
	if buf.Len() == 0 {
		t.Fatal("level change ignored")
	}
}
