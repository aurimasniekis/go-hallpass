package slack

import (
	"encoding/json"
	"html"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat/chattest"
)

// entityRE matches the only '&' sequences the renderer may emit.
var entityRE = regexp.MustCompile(`&(amp|lt|gt);`)

// walk visits every JSON object in v.
func walk(v any, fn func(map[string]any)) {
	switch x := v.(type) {
	case map[string]any:
		fn(x)
		for _, c := range x {
			walk(c, fn)
		}
	case []any:
		for _, c := range x {
			walk(c, fn)
		}
	}
}

// assertSafeBlocks enforces the renderer's invariants on marshaled blocks.
func assertSafeBlocks(t *testing.T, blocks any) {
	t.Helper()
	raw, err := json.Marshal(blocks)
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	walk(v, func(o map[string]any) {
		typ, _ := o["type"].(string)
		if typ == "mrkdwn" {
			t.Fatalf("mrkdwn text object emitted: %v", o)
		}
		if typ == "plain_text" {
			s, _ := o["text"].(string)
			if strings.ContainsAny(s, "<>") {
				t.Fatalf("unescaped angle bracket in %q", s)
			}
			if strings.Count(s, "&") != len(entityRE.FindAllString(s, -1)) {
				t.Fatalf("bare ampersand in %q", s)
			}
			if !utf8.ValidString(s) || len(s) > maxSectionText {
				t.Fatalf("invalid or oversized text (%d bytes)", len(s))
			}
			if o["emoji"] != false {
				t.Fatalf("emoji not disabled: %v", o)
			}
		}
		if typ == "header" {
			if s := o["text"].(map[string]any)["text"].(string); utf8.RuneCountInString(s) > 150 {
				t.Fatal("header too long")
			}
		}
		if typ == "section" {
			if f, ok := o["fields"].([]any); ok {
				if len(f) > 10 {
					t.Fatal("too many fields")
				}
				for _, x := range f {
					if len(x.(map[string]any)["text"].(string)) > maxFieldText {
						t.Fatal("field too long")
					}
				}
			}
		}
		if typ == "button" {
			if s := o["text"].(map[string]any)["text"].(string); utf8.RuneCountInString(s) > 75 {
				t.Fatal("button text too long")
			}
			if id, _ := o["action_id"].(string); len(id) > 255 {
				t.Fatal("action_id too long")
			}
		}
	})
}

func hostileMessage(h string) chat.ApprovalMessage {
	m := chattest.Message()
	m.AgentName, m.AgentID, m.AgentKeyFingerprint = h, h, h
	m.Server, m.ServerDescription, m.Role, m.RoleDescription = h, h, h, h
	m.Capabilities = []string{h, h, h, h, h, h, h, h, h, h, h, h}
	m.Reason = h
	return m
}

func TestRenderHostile(t *testing.T) {
	for _, h := range chattest.Hostile {
		m := hostileMessage(h)
		assertSafeBlocks(t, renderApproval(&m, true))
		u := chat.StatusUpdate{RequestID: m.RequestID, State: chat.StateApproved, DecidedBy: h, Original: &m}
		assertSafeBlocks(t, renderStatus(&u))
		u.Original = nil
		assertSafeBlocks(t, renderStatus(&u))
		fallback, blocks := renderReply(h)
		assertSafeBlocks(t, blocks)
		if fallback != "HallPass" {
			t.Fatal("reply fallback must be static")
		}
		if strings.Contains(fallbackText(m.RequestID), "<") {
			t.Fatal("fallback")
		}
	}
}

func TestRenderContent(t *testing.T) {
	m := chattest.Message()
	m.Reason = "Need <@U999> & <!here> *now*\n\u202eok"
	raw, _ := json.Marshal(renderApproval(&m, true))
	s := allText(raw)
	for _, want := range []string{
		"Agent: build-bot", "Server: db-prod", "Role: readonly", "Requested duration: 1h", "2026-10-23 12:30 UTC",
		"Agent-provided reason (untrusted)", "Need &lt;@U999&gt; &amp; &lt;!here&gt; *now* ok",
		"Capabilities: shell, exec", "Server description: Primary database", "Role description: Read-only shell",
		"Approve 15m", "Approve 1h", "Approve 4h", `"Deny"`, `"style":"danger"`, "hp1:a:" + chattest.Token(1),
		"hp1:d:" + chattest.Token(4), `"url":"https://hallpass.example/requests/x"`, "Request " + m.RequestID,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in %s", want, s)
		}
	}
	// Buttons carry only token IDs.
	var v any
	_ = json.Unmarshal(raw, &v)
	walk(v, func(o map[string]any) {
		if o["type"] == "button" && o["value"] != nil && !chat.ValidActionTokenID(o["value"].(string)) {
			t.Fatalf("button value %v", o["value"])
		}
	})
	// Without actions there is no actions block.
	if strings.Contains(mustJSON(renderApproval(&m, false)), `"actions"`) {
		t.Fatal("actions rendered")
	}
	// No details URL → no details button; empty optional fields are omitted.
	m.DetailsURL, m.ServerDescription, m.RoleDescription, m.Capabilities = "", "", "", nil
	if s := mustJSON(renderApproval(&m, true)); strings.Contains(s, "Details") || strings.Contains(s, "description") ||
		strings.Contains(s, "Capabilities") {
		t.Fatal(s)
	}
	m.AgentName = "\u200b"
	if !strings.Contains(mustJSON(renderApproval(&m, true)), "Agent: - (") {
		t.Fatal("empty name placeholder")
	}
}

func TestCapabilitiesSummary(t *testing.T) {
	caps := make([]string, 13)
	for i := range caps {
		caps[i] = "c"
	}
	caps[0] = "\u200b" // cleaned away
	if got := capabilities(caps); !strings.HasSuffix(got, "(+2 more)") || strings.Count(got, "c") != 10 {
		t.Fatalf("%q", got)
	}
}

func TestStatusLines(t *testing.T) {
	m := chattest.Message()
	for _, c := range []struct {
		u    chat.StatusUpdate
		want string
	}{
		{chat.StatusUpdate{State: chat.StateApproved, DecidedBy: "Ann <b>", Duration: 3600e9, At: m.ExpiresAt}, "✅ Approved by Ann &lt;b&gt; for 1h at 2026-10-23 12:30 UTC"},
		{chat.StatusUpdate{State: chat.StateDenied, DecidedBy: "Bob"}, "⛔ Denied by Bob"},
		{chat.StatusUpdate{State: chat.StateExpired}, "⏹ Expired"},
		{chat.StatusUpdate{State: chat.StateCanceled}, "⏹ Canceled"},
	} {
		if got := statusLine(&c.u); got != c.want {
			t.Errorf("%q != %q", got, c.want)
		}
	}
}

func TestPlainBounded(t *testing.T) {
	s := strings.Repeat("a", 10) + "&amp;" + strings.Repeat("é", 10)
	for limit := 4; limit < len(s)+2; limit++ {
		got := plainBounded(s, limit).Text
		if len(got) > limit || !utf8.ValidString(got) {
			t.Fatalf("limit %d: %q", limit, got)
		}
		if i := strings.LastIndexByte(got, '&'); i >= 0 && !strings.HasPrefix(got[i:], "&amp;") {
			t.Fatalf("split entity at limit %d: %q", limit, got)
		}
	}
}

func TestEscape(t *testing.T) {
	if Escape("a&b<c>d") != "a&amp;b&lt;c&gt;d" || Escape("plain") != "plain" {
		t.Fatal("escape")
	}
}

func FuzzEscape(f *testing.F) {
	for _, h := range chattest.Hostile {
		f.Add(h)
	}
	f.Fuzz(func(t *testing.T, s string) {
		clean := chat.CleanText(s, chat.MaxReasonRunes)
		out := Escape(clean)
		if strings.ContainsAny(out, "<>") || strings.Count(out, "&") != len(entityRE.FindAllString(out, -1)) {
			t.Fatalf("unsafe escape %q", out)
		}
		if html.UnescapeString(out) != clean {
			t.Fatalf("escape not reversible: %q", out)
		}
		m := chattest.Message()
		m.Reason, m.AgentName = s, s
		assertSafeBlocks(t, renderApproval(&m, true))
	})
}

// allText returns raw JSON decoded and re-encoded without HTML escaping, so expectations can use literal text.
func allText(raw []byte) string {
	var v any
	_ = json.Unmarshal(raw, &v)
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return b.String()
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
