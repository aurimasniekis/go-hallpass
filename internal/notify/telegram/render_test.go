package telegram

import (
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat/chattest"
)

const wj = string(wordJoiner)

// checkRendered enforces the renderer invariants: length bound, well-formed non-overlapping entities, and every '@'
// or '/' inside an entity defanged. If isolated is true, the text outside entities must not contain '@' at all
// (all untrusted text lives inside entities).
func checkRendered(t *testing.T, r rendered, isolated bool) {
	t.Helper()
	u := utf16.Encode([]rune(r.Text))
	if len(u) > MaxMessageUTF16 {
		t.Fatalf("text has %d UTF-16 units", len(u))
	}
	end := 0
	inside := make([]bool, len(u))
	for _, e := range r.Entities {
		if e.Offset < end || e.Length <= 0 || e.Offset+e.Length > len(u) {
			t.Fatalf("bad entity %+v (prev end %d, len %d)", e, end, len(u))
		}
		if e.Type != "bold" && e.Type != "code" && e.Type != "pre" {
			t.Fatalf("unexpected entity type %q", e.Type)
		}
		end = e.Offset + e.Length
		for i := e.Offset; i < end; i++ {
			inside[i] = true
		}
		span := string(utf16.Decode(u[e.Offset:end]))
		if e.Type != "bold" {
			if strings.ContainsAny(span, "\n\r") {
				t.Fatalf("newline inside untrusted span %q", span)
			}
			for i, ch := range []rune(span) {
				rs := []rune(span)
				if (ch == '@' || ch == '/') && (i+1 >= len(rs) || rs[i+1] != wordJoiner) {
					t.Fatalf("undefanged %q in %q", ch, span)
				}
			}
		}
	}
	if isolated {
		var outside []uint16
		for i, c := range u {
			if !inside[i] {
				outside = append(outside, c)
			}
		}
		if s := string(utf16.Decode(outside)); strings.ContainsAny(s, "@<>") {
			t.Fatalf("untrusted text outside entities: %q", s)
		}
	}
}

func TestRenderHostile(t *testing.T) {
	for _, h := range chattest.Hostile {
		m := chattest.Message()
		m.DetailsURL = ""
		m.AgentName, m.AgentID, m.AgentKeyFingerprint = h, h, h
		m.Server, m.ServerDescription, m.Role, m.RoleDescription = h, h, h, h
		m.Capabilities = []string{h, h, h, h, h, h, h, h, h, h, h, h}
		m.Reason = h
		r, err := renderApproval(&m)
		if err != nil {
			t.Fatal(err)
		}
		checkRendered(t, r, true)
		u := chat.StatusUpdate{RequestID: m.RequestID, State: chat.StateApproved, DecidedBy: h, Original: &m}
		r, err = renderStatus(&u)
		if err != nil {
			t.Fatal(err)
		}
		checkRendered(t, r, true)
		u.Original = nil
		r, _ = renderStatus(&u)
		checkRendered(t, r, true)
	}
}

func TestRenderTiers(t *testing.T) {
	m := chattest.Message()
	big := strings.Repeat("\U0001D54F@", 1000)
	m.AgentName, m.Server, m.Role, m.ServerDescription, m.RoleDescription, m.Reason = big, big, big, big, big, big
	m.Capabilities = []string{big, big, big, big, big, big, big, big, big, big}
	m.DetailsURL = "https://hallpass.example/requests/" + strings.Repeat("a", 1900)
	var full textBuilder
	writeApproval(&full, &m, tiers[0])
	if full.off <= MaxMessageUTF16 {
		t.Fatalf("fixture should overflow tier 0 (%d)", full.off)
	}
	r, err := renderApproval(&m)
	if err != nil {
		t.Fatal(err)
	}
	checkRendered(t, r, true)
	if !strings.Contains(r.Text, "Agent-provided reason (untrusted)") || !strings.Contains(r.Text, m.RequestID) {
		t.Fatal("compact tier lost essentials")
	}
}

func TestRenderContent(t *testing.T) {
	m := chattest.Message()
	m.Reason = "ping @admin see https://evil.example /link X"
	r, err := renderApproval(&m)
	if err != nil {
		t.Fatal(err)
	}
	checkRendered(t, r, false)
	for _, want := range []string{
		"HallPass access request", "Agent: build-bot (", "Server: db-prod — Primary database", "Role: readonly — Read-only shell",
		"Capabilities: shell, exec", "Requested duration: 1h", "Request expires: 2026-10-23 12:30 UTC",
		"Agent-provided reason (untrusted):\nping @" + wj + "admin see https:/" + wj + "/" + wj + "evil.example /" + wj + "link X",
		"Request " + m.RequestID, "Details: https://hallpass.example/requests/x",
	} {
		if !strings.Contains(r.Text, want) {
			t.Errorf("missing %q in %q", want, r.Text)
		}
	}
	var pre int
	for _, e := range r.Entities {
		if e.Type == "pre" {
			pre++
		}
	}
	if pre != 1 {
		t.Fatal("reason must be in one pre entity")
	}
	m.ServerDescription, m.RoleDescription, m.Capabilities, m.Reason, m.AgentName = "", "", nil, "\u200b", ""
	r, _ = renderApproval(&m)
	if strings.Contains(r.Text, "—") || strings.Contains(r.Text, "Capabilities") || !strings.Contains(r.Text, "(untrusted):\n-") ||
		!strings.Contains(r.Text, "Agent: - (") {
		t.Fatalf("%q", r.Text)
	}
	m.Capabilities = []string{"\u200b", "a", "b"}
	r, _ = renderApproval(&m)
	if !strings.Contains(r.Text, "Capabilities: a, b\n") {
		t.Fatalf("%q", r.Text)
	}
}

func TestKeyboard(t *testing.T) {
	m := chattest.Message()
	m.Actions = append([]chat.Action{
		{Kind: chat.ActionApprove, Duration: 5 * 60e9, TokenID: chattest.Token(10)},
		{Kind: chat.ActionApprove, Duration: 30 * 60e9, TokenID: strings.Repeat("Z", chat.MaxActionTokenIDLen)},
	}, m.Actions...)
	kb, err := keyboard(&m)
	if err != nil {
		t.Fatal(err)
	}
	rows := kb.InlineKeyboard
	if len(rows) != 3 || len(rows[0]) != 3 || len(rows[1]) != 2 || len(rows[2]) != 1 || rows[2][0].Text != "Deny" {
		t.Fatalf("layout %+v", rows)
	}
	for _, row := range rows {
		for _, b := range row {
			if len(b.CallbackData) > MaxCallbackData || !strings.HasPrefix(b.CallbackData, "hp1:") {
				t.Fatalf("callback_data %q", b.CallbackData)
			}
			if _, _, ok := ParseCallbackData(b.CallbackData); !ok {
				t.Fatal("unparseable callback_data")
			}
		}
	}
	m.Actions[0].TokenID = "bad token"
	if _, err := keyboard(&m); !chat.IsPermanent(err) {
		t.Fatal(err)
	}
	m.Actions = []chat.Action{{Kind: chat.ActionApprove, Duration: 60e9, TokenID: chattest.Token(1)}}
	if kb, _ := keyboard(&m); len(kb.InlineKeyboard) != 1 {
		t.Fatal("approve-only layout")
	}
}

func TestStatusRendering(t *testing.T) {
	m := chattest.Message()
	for _, c := range []struct {
		u    chat.StatusUpdate
		want string
	}{
		{chat.StatusUpdate{State: chat.StateApproved, DecidedBy: "Ann", Duration: 3600e9, At: m.ExpiresAt}, "✅ Approved by Ann for 1h at 2026-10-23 12:30 UTC"},
		{chat.StatusUpdate{State: chat.StateDenied, DecidedBy: "@bob"}, "⛔ Denied by @" + wj + "bob"},
		{chat.StatusUpdate{State: chat.StateExpired}, "⏹ Expired"},
	} {
		c.u.RequestID = m.RequestID
		r, err := renderStatus(&c.u)
		if err != nil || !strings.Contains(r.Text, c.want) || !strings.Contains(r.Text, m.RequestID) {
			t.Errorf("%q missing %q (%v)", r.Text, c.want, err)
		}
		checkRendered(t, r, false)
	}
}

func TestDefangAndReply(t *testing.T) {
	if Defang("plain") != "plain" || Defang("a@b/c") != "a@"+wj+"b/"+wj+"c" {
		t.Fatal("Defang")
	}
	if got := replyText("hi\n\u202e"+strings.Repeat("x", 300), MaxCallbackAlert); len([]rune(got)) != MaxCallbackAlert || strings.ContainsAny(got, "\n\u202e") {
		t.Fatalf("%q", got)
	}
}

func FuzzRender(f *testing.F) {
	for _, h := range chattest.Hostile {
		f.Add(h)
	}
	f.Fuzz(func(t *testing.T, s string) {
		m := chattest.Message()
		m.DetailsURL = ""
		m.AgentName, m.Server, m.ServerDescription, m.Reason = s, s, s, s
		m.Capabilities = []string{s}
		r, err := renderApproval(&m)
		if err != nil {
			t.Fatal(err)
		}
		checkRendered(t, r, true)
	})
}
