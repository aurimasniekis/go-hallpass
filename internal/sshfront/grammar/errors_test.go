package grammar

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestExitCodes(t *testing.T) {
	want := map[ExitCode]string{
		0: "ok", 80: "internal", 81: "usage", 82: "not_found_or_forbidden", 83: "denied", 84: "expired",
		85: "canceled", 86: "wait_timeout", 87: "access_ended", 88: "destination_unavailable", 89: "limit_exceeded",
		90: "input_required",
	}
	codes := ExitCodes()
	if len(codes) != len(want) {
		t.Fatalf("got %d codes, want %d", len(codes), len(want))
	}
	for i, c := range codes {
		if i > 0 && codes[i-1] >= c {
			t.Error("codes not ascending")
		}
		if c.Name() != want[c] || !c.Valid() || c.Description() == "" {
			t.Errorf("code %d: name %q desc %q", c, c.Name(), c.Description())
		}
	}
	for _, c := range []ExitCode{1, 79, 91, 255, -1} {
		if c.Valid() || c.Name() != "" || c.Description() != "" {
			t.Errorf("code %d should be invalid", c)
		}
	}
}

func TestErrorJSONExactBytes(t *testing.T) {
	// PLAN §7.7 example, byte for byte.
	want := `{"schema":"hallpass.error/v1","source":"gateway","code":"not_found_or_forbidden","exit_code":82,"message":"server or role not found or not permitted","request_id":null}` + "\n"
	if got := string(ErrorJSON(NotFoundOrForbidden())); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// Every not-found/forbidden variant is byte-identical (HP-POL-010).
func TestNotFoundOrForbiddenUniform(t *testing.T) {
	a := NotFoundOrForbidden()
	b := NewError(ExitNotFoundOrForbidden, MsgNotFoundOrForbidden)
	c := fmt.Errorf("wrapped: %w", NotFoundOrForbidden())
	ja, jb, jc := ErrorJSON(a), ErrorJSON(b), ErrorJSON(c)
	if !bytes.Equal(ja, jb) || !bytes.Equal(ja, jc) {
		t.Errorf("variants differ:\n%s%s%s", ja, jb, jc)
	}
	if ErrorText(a) != ErrorText(c) || ErrorText(a) != "hallpass: "+MsgNotFoundOrForbidden+"\n" {
		t.Errorf("text variants differ: %q %q", ErrorText(a), ErrorText(c))
	}
}

func TestErrorJSON(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorDoc
	}{
		{"usage", Usage("bad"), ErrorDoc{Code: "usage", ExitCode: 81, Message: "bad"}},
		{"foreign error hidden", errors.New("disk /var/lib/hallpass broken"), ErrorDoc{Code: "internal", ExitCode: 80, Message: MsgInternal}},
		{"nil-ish exit", &Error{Exit: ExitOK, Message: "x"}, ErrorDoc{Code: "internal", ExitCode: 80, Message: MsgInternal}},
		{"unknown exit", &Error{Exit: 7, Message: "x"}, ErrorDoc{Code: "internal", ExitCode: 80, Message: MsgInternal}},
		{"request id", NewError(ExitDenied, "request denied").WithRequestID(rid), ErrorDoc{Code: "denied", ExitCode: 83, Message: "request denied", RequestID: rid}},
		{"bad request id dropped", NewError(ExitDenied, "d").WithRequestID("req_x"), ErrorDoc{Code: "denied", ExitCode: 83, Message: "d"}},
		{"wait timeout", WaitTimedOut(rid, 2*time.Minute), ErrorDoc{Code: "wait_timeout", ExitCode: 86, RequestID: rid,
			Message: "request " + rid + " is still pending after 2m; it stays pending. Resume with: status " + rid + " --wait"}},
		{"reason required", ReasonRequired(), ErrorDoc{Code: "input_required", ExitCode: 90, Message: `a reason is required: add --reason "<why you need access>"`}},
		{"ambiguous role", AmbiguousRole("web1", []string{"deploy", "inspect"}), ErrorDoc{Code: "usage", ExitCode: 81,
			Message: "server web1 has several roles; choose one with --role (choices: deploy, inspect)"}},
		{"html and newline", NewError(ExitLimitExceeded, "a<b>&c\nd"), ErrorDoc{Code: "limit_exceeded", ExitCode: 89, Message: "a<b>&c\nd"}},
		{"internal", Internal(), ErrorDoc{Code: "internal", ExitCode: 80, Message: MsgInternal}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := ErrorJSON(tt.err)
			if bytes.Count(line, []byte("\n")) != 1 || line[len(line)-1] != '\n' {
				t.Fatalf("not exactly one line: %q", line)
			}
			var got ErrorDoc
			if err := json.Unmarshal(line, &got); err != nil {
				t.Fatal(err)
			}
			tt.want.Schema, tt.want.Source = SchemaError, "gateway"
			if got != tt.want {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
			if ExitCodeOf(tt.err) != ExitCode(tt.want.ExitCode) {
				t.Errorf("ExitCodeOf = %d", ExitCodeOf(tt.err))
			}
			if strings.Contains(string(line), "\\u003c") {
				t.Error("HTML escaping enabled")
			}
		})
	}
	if ExitCodeOf(nil) != ExitOK {
		t.Error("ExitCodeOf(nil)")
	}
}

func TestErrorHelpers(t *testing.T) {
	e := NewError(0, "x")
	if e.Exit != ExitInternal {
		t.Error("NewError(0) must map to internal")
	}
	orig := NewError(ExitExpired, "expired")
	cp := orig.WithRequestID(rid)
	if orig.RequestID != "" || cp.RequestID != rid || cp.Error() != "expired" {
		t.Error("WithRequestID must copy")
	}
	if got := ErrorText(NewError(ExitUsage, "a\x1b[31mb\u202ec")); got != "hallpass: a?[31mb?c\n" {
		t.Errorf("ErrorText not sanitized: %q", got)
	}
	if got := ErrorText(errors.New("secret path")); got != "hallpass: "+MsgInternal+"\n" {
		t.Errorf("foreign error leaked: %q", got)
	}
	exp := time.Date(2026, 10, 23, 15, 32, 11, 0, time.FixedZone("x", 3600))
	if got := PendingNotice(rid, exp, 2*time.Minute); got != "request "+rid+" pending approval (expires 14:32Z); waiting up to 2m0s" {
		t.Errorf("PendingNotice = %q", got)
	}
}
