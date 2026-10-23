// Package redact keeps secrets and sensitive payloads out of logs and error output (HP-OBS-002).
package redact

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// Redacted is the placeholder written instead of a sensitive value.
const Redacted = "[REDACTED]"

// Secret wraps a sensitive value so that logging, formatting and JSON encoding never reveal it.
// Call Reveal only at the point of use.
type Secret[T any] struct{ v T }

// NewSecret wraps v.
func NewSecret[T any](v T) Secret[T] { return Secret[T]{v: v} }

// Reveal returns the wrapped value.
func (s Secret[T]) Reveal() T { return s.v }

// LogValue implements slog.LogValuer.
func (Secret[T]) LogValue() slog.Value { return slog.StringValue(Redacted) }

// String implements fmt.Stringer.
func (Secret[T]) String() string { return Redacted }

// GoString implements fmt.GoStringer.
func (Secret[T]) GoString() string { return Redacted }

// Format implements fmt.Formatter for every verb.
func (Secret[T]) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, Redacted) }

// MarshalJSON implements json.Marshaler.
func (Secret[T]) MarshalJSON() ([]byte, error) { return json.Marshal(Redacted) }

// MarshalText implements encoding.TextMarshaler.
func (Secret[T]) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// exactKeys are attribute keys whose values are always sensitive.
var exactKeys = map[string]bool{
	"reason":         true,
	"request_reason": true,
	"comment":        true,
	"command":        true,
	"exec_command":   true,
	"terminal_data":  true,
	"input":          true,
	"output":         true,
	"stdin":          true,
	"stdout":         true,
	"stderr":         true,
	"cookie":         true,
	"set-cookie":     true,
	"authorization":  true,
	"otp":            true,
	"code":           false, // generic; not redacted (exit codes, error codes)
}

// sensitiveSuffixes match keys such as "password", "client_secret", "bot_token", "private_key".
var sensitiveSuffixes = []string{
	"password", "passwd", "secret", "token", "private_key", "privatekey", "passphrase", "kek", "dek",
	"api_key", "apikey", "totp", "recovery_code", "recovery_codes", "credential", "credentials", "signature",
}

// IsSensitiveKey reports whether an attribute key names a sensitive value. Matching is case-insensitive and
// considers the last dotted segment ("hallpass.reason" matches "reason").
func IsSensitiveKey(key string) bool {
	k := strings.ToLower(key)
	if i := strings.LastIndexByte(k, '.'); i >= 0 {
		k = k[i+1:]
	}
	k = strings.ReplaceAll(k, "-", "_")
	if v, ok := exactKeys[k]; ok {
		return v
	}
	for _, s := range sensitiveSuffixes {
		if k == s || strings.HasSuffix(k, "_"+s) {
			return true
		}
	}
	return false
}

// ReplaceAttr is an slog.HandlerOptions.ReplaceAttr function that redacts sensitive keys.
func ReplaceAttr(_ []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() != slog.KindGroup && IsSensitiveKey(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	return a
}
