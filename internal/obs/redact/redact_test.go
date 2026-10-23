package redact

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestSecretNeverFormats(t *testing.T) {
	s := NewSecret("hunter2")
	for _, got := range []string{
		fmt.Sprint(s), fmt.Sprintf("%s|%v|%+v|%#v|%q|%x|%d", s, s, s, s, s, s, s), s.String(),
	} {
		if got == "" || containsSecret(got) {
			t.Fatalf("leak: %q", got)
		}
	}
	b, err := json.Marshal(map[string]any{"s": s})
	if err != nil || containsSecret(string(b)) {
		t.Fatalf("json leak: %s %v", b, err)
	}
	if s.Reveal() != "hunter2" {
		t.Fatal("reveal broken")
	}
}

func containsSecret(s string) bool {
	for i := 0; i+7 <= len(s); i++ {
		if s[i:i+7] == "hunter2" {
			return true
		}
	}
	return false
}

func TestIsSensitiveKey(t *testing.T) {
	sensitive := []string{"password", "new_password", "client_secret", "Bot-Token", "private_key", "hallpass.reason",
		"reason", "command", "kek", "signing_secret", "recovery_codes", "authorization", "cookie", "api_key"}
	plain := []string{"close_reason", "exit_code", "code", "agent_id", "fingerprint", "event.outcome", "token_count_metric_name_x"}
	for _, k := range sensitive {
		if !IsSensitiveKey(k) {
			t.Errorf("%q should be sensitive", k)
		}
	}
	for _, k := range plain {
		if IsSensitiveKey(k) {
			t.Errorf("%q should not be sensitive", k)
		}
	}
}
