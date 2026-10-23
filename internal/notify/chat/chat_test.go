package chat_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat/chattest"
)

func TestCleanText(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"plain", 0, "plain"},
		{"  a \n\t b  \r\n c ", 0, "a b c"},
		{"\u202egnp.exe\u202c", 0, "gnp.exe"},
		{"zero\u200bwidth\u200d\ufeff\u2060", 0, "zerowidth"},
		{"\x00\x1b[31mred\x7f\u0085x", 0, "[31mred x"},
		{"\xff\xfeok\xc3\x28", 0, "ok("},
		{"\u3164\u115f\u2800\u034f\ufffc", 0, ""},
		{"Z\u0300\u0301\u0302\u0303\u0304", 0, "Z\u0300\u0301\u0302"},
		{"\u0300leading", 0, "leading"},
		{"\ue000private", 0, "private"},
		{"abcdef", 6, "abcdef"},
		{"abcdefg", 6, "abcde…"},
		{"abc   defg", 5, "abc…"},
		{"abcdef", 1, "…"},
		{"abc\u200b\u200b", 3, "abc"},
		{"ab c", 3, "ab…"},
	}
	for _, c := range cases {
		if got := chat.CleanText(c.in, c.max); got != c.want {
			t.Errorf("CleanText(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
		}
	}
}

func checkClean(t *testing.T, in, out string, maxRunes int) {
	t.Helper()
	if !utf8.ValidString(out) {
		t.Fatalf("invalid utf-8 from %q", in)
	}
	if maxRunes > 0 && utf8.RuneCountInString(out) > maxRunes {
		t.Fatalf("too long: %d > %d", utf8.RuneCountInString(out), maxRunes)
	}
	if out != strings.TrimSpace(out) || strings.Contains(out, "  ") {
		t.Fatalf("whitespace not collapsed: %q", out)
	}
	for _, r := range out {
		if r != ' ' && unicode.IsSpace(r) || unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Co, unicode.Cs) || r == utf8.RuneError {
			t.Fatalf("forbidden rune %U in %q", r, out)
		}
	}
	if again := chat.CleanText(out, maxRunes); again != out {
		t.Fatalf("not idempotent: %q -> %q", out, again)
	}
}

func TestCleanTextHostile(t *testing.T) {
	for _, h := range chattest.Hostile {
		for _, m := range []int{0, 1, 5, 100, chat.MaxReasonRunes} {
			checkClean(t, h, chat.CleanText(h, m), m)
		}
	}
}

func FuzzCleanText(f *testing.F) {
	for _, h := range chattest.Hostile {
		f.Add(h, 50)
	}
	f.Add("", 0)
	f.Fuzz(func(t *testing.T, s string, m int) {
		m %= 2000
		checkClean(t, s, chat.CleanText(s, m), m)
	})
}

func TestTokenAndCodes(t *testing.T) {
	for s, want := range map[string]bool{
		"abcdefgh": true, "AZaz09-_AZaz09-_AZaz09": true, "short": false, strings.Repeat("a", 41): false,
		strings.Repeat("a", 40): true, "abc defgh": false, "abcdefg=": false, "abcdéfgh": false,
	} {
		if chat.ValidActionTokenID(s) != want {
			t.Errorf("ValidActionTokenID(%q) != %v", s, want)
		}
	}
	if c, ok := chat.NormalizeLinkCode(" ab12-cd34 "); !ok || c != "AB12-CD34" {
		t.Fatalf("NormalizeLinkCode = %q %v", c, ok)
	}
	for _, bad := range []string{"", "   ", "ab cd", "ab<cd", strings.Repeat("A", 33), "ÄBC"} {
		if _, ok := chat.NormalizeLinkCode(bad); ok {
			t.Errorf("NormalizeLinkCode(%q) accepted", bad)
		}
	}
}

func TestFormatting(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0: "0m", 15 * time.Minute: "15m", time.Hour: "1h", 90 * time.Minute: "1h30m", 48 * time.Hour: "2d",
		25*time.Hour + time.Minute: "1d1h1m", 1500 * time.Millisecond: "1.5s", -time.Hour: "0m",
	} {
		if got := chat.FormatDuration(d); got != want {
			t.Errorf("FormatDuration(%s) = %q, want %q", d, got, want)
		}
	}
	if chat.FormatTime(time.Time{}) != "unknown" {
		t.Fatal("zero time")
	}
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("x", 3600))
	if got := chat.FormatTime(ts); got != "2026-01-02 02:04 UTC" {
		t.Fatalf("FormatTime = %q", got)
	}
	for s, want := range map[chat.DecisionState]string{
		chat.StateApproved: "Approved", chat.StateDenied: "Denied", chat.StateExpired: "Expired",
		chat.StateCanceled: "Canceled", "weird": "Updated",
	} {
		if chat.StateLabel(s) != want {
			t.Errorf("StateLabel(%s)", s)
		}
	}
	if chat.ButtonLabel(chat.Action{Kind: chat.ActionApprove, Duration: time.Hour}) != "Approve 1h" ||
		chat.ButtonLabel(chat.Action{Kind: chat.ActionDeny}) != "Deny" {
		t.Fatal("ButtonLabel")
	}
}

func TestValidateMessage(t *testing.T) {
	ok := chattest.Message()
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	mut := func(f func(m *chat.ApprovalMessage)) chat.ApprovalMessage {
		m := chattest.Message()
		f(&m)
		return m
	}
	bad := map[string]chat.ApprovalMessage{
		"request id":   mut(func(m *chat.ApprovalMessage) { m.RequestID = "agt_x" }),
		"no actions":   mut(func(m *chat.ApprovalMessage) { m.Actions = nil }),
		"bad token":    mut(func(m *chat.ApprovalMessage) { m.Actions[0].TokenID = "x" }),
		"dup token":    mut(func(m *chat.ApprovalMessage) { m.Actions[1].TokenID = m.Actions[0].TokenID }),
		"no duration":  mut(func(m *chat.ApprovalMessage) { m.Actions[0].Duration = 0 }),
		"unknown kind": mut(func(m *chat.ApprovalMessage) { m.Actions[0].Kind = "maybe" }),
		"two denies": mut(func(m *chat.ApprovalMessage) {
			m.Actions[0] = chat.Action{Kind: chat.ActionDeny, TokenID: chattest.Token(9)}
		}),
		"javascript":    mut(func(m *chat.ApprovalMessage) { m.DetailsURL = "javascript:alert(1)" }),
		"too many":      mut(func(m *chat.ApprovalMessage) { m.Actions = manyApproves(6) }),
		"relative link": mut(func(m *chat.ApprovalMessage) { m.DetailsURL = "/requests/x" }),
	}
	for name, m := range bad {
		if err := m.Validate(); !errors.Is(err, chat.ErrPermanent) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if m := mut(func(m *chat.ApprovalMessage) { m.Actions = manyApproves(5) }); m.Validate() != nil {
		t.Fatal("5 approves must be valid")
	}
}

func manyApproves(n int) []chat.Action {
	var out []chat.Action
	for i := range n {
		out = append(out, chat.Action{Kind: chat.ActionApprove, Duration: time.Duration(i+1) * time.Minute, TokenID: chattest.Token(100 + i)})
	}
	return out
}

func TestValidateStatus(t *testing.T) {
	m := chattest.Message()
	u := chat.StatusUpdate{RequestID: m.RequestID, State: chat.StateApproved, Original: &m}
	if err := u.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]chat.StatusUpdate{
		"id":    {RequestID: "x", State: chat.StateDenied},
		"state": {RequestID: m.RequestID, State: "pending"},
		"orig":  {RequestID: ids.New(ids.Request), State: chat.StateDenied, Original: &m},
	} {
		if err := bad.Validate(); !errors.Is(err, chat.ErrPermanent) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestValidHTTPURL(t *testing.T) {
	for s, want := range map[string]bool{
		"https://a.example/x": true, "http://localhost:8080/": true, "ftp://a/": false, "https://u:p@a/": false,
		"https:///x": false, "javascript:alert(1)": false, "%zz": false, "https://a/" + strings.Repeat("x", 2001): false,
	} {
		if chat.ValidHTTPURL(s) != want {
			t.Errorf("ValidHTTPURL(%q) != %v", s, want)
		}
	}
}

func TestEventIdentity(t *testing.T) {
	id := chat.Identity{Provider: "slack", UserID: "U1"}
	for _, ev := range []chat.Event{
		{Kind: chat.EventInteraction, Interaction: &chat.Interaction{Identity: id}},
		{Kind: chat.EventLink, Link: &chat.LinkRequest{Identity: id}},
		{Kind: chat.EventStatus, Status: &chat.StatusQuery{Identity: id}},
	} {
		if ev.Identity() != id {
			t.Fatalf("%s identity", ev.Kind)
		}
	}
	if (chat.Event{}).Identity() != (chat.Identity{}) {
		t.Fatal("empty event identity")
	}
}

func TestErrors(t *testing.T) {
	err := chat.Reject(chat.RejectReplay, "seen %d", 1)
	if chat.ReasonOf(err) != chat.RejectReplay || !strings.Contains(err.Error(), "replay: seen 1") {
		t.Fatalf("reject: %v", err)
	}
	if chat.ReasonOf(fmt.Errorf("wrap: %w", err)) != chat.RejectReplay || chat.ReasonOf(errors.New("x")) != chat.RejectInternal {
		t.Fatal("ReasonOf")
	}
	if (&chat.RejectError{Reason: chat.RejectStale}).Error() != "chat: rejected: stale_timestamp" {
		t.Fatal("nil inner")
	}
	inner := errors.New("inner")
	if !errors.Is(&chat.RejectError{Reason: chat.RejectMalformed, Err: inner}, inner) {
		t.Fatal("unwrap")
	}
	rl := fmt.Errorf("x: %w", &chat.RateLimitError{Provider: "slack", Method: "m", After: 3 * time.Second})
	if d, ok := chat.RetryAfter(rl); !ok || d != 3*time.Second || !errors.Is(rl, chat.ErrRateLimited) || chat.IsPermanent(rl) {
		t.Fatal("rate limit")
	}
	if !strings.Contains(rl.Error(), "retry after 3s") {
		t.Fatal(rl.Error())
	}
	if _, ok := chat.RetryAfter(errors.New("x")); ok {
		t.Fatal("RetryAfter on plain error")
	}
	if !chat.IsPermanent(fmt.Errorf("x: %w", chat.ErrPermanent)) {
		t.Fatal("IsPermanent")
	}
}

func TestMemoryReplayCache(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFake(time.Unix(1_700_000_000, 0))
	c := chat.NewMemoryReplayCache(clk, 2)
	exp := clk.Now().Add(time.Minute)
	if ok, err := c.Remember(ctx, "a", exp); !ok || err != nil {
		t.Fatal("first insert", ok, err)
	}
	if ok, err := c.Remember(ctx, "a", exp); ok || err != nil {
		t.Fatal("replay accepted", ok, err)
	}
	if ok, _ := c.Remember(ctx, "b", exp); !ok {
		t.Fatal("b")
	}
	if _, err := c.Remember(ctx, "c", exp); !errors.Is(err, chat.ErrReplayCacheFull) {
		t.Fatalf("full: %v", err)
	}
	clk.Advance(2 * time.Minute)
	if ok, err := c.Remember(ctx, "c", clk.Now().Add(time.Minute)); !ok || err != nil {
		t.Fatal("eviction", ok, err)
	}
	if c.Len() != 1 {
		t.Fatalf("len %d", c.Len())
	}
	if ok, _ := c.Remember(ctx, "a", clk.Now().Add(time.Minute)); !ok {
		t.Fatal("expired key must be accepted again")
	}
	if d := chat.NewMemoryReplayCache(nil, 0); d.Len() != 0 {
		t.Fatal("defaults")
	}
}

func TestMemoryReplayCacheConcurrent(t *testing.T) {
	c := chat.NewMemoryReplayCache(nil, 0)
	var wg sync.WaitGroup
	var mu sync.Mutex
	fresh := 0
	for range 32 {
		wg.Go(func() {
			ok, err := c.Remember(context.Background(), "same", time.Now().Add(time.Minute))
			if err != nil {
				t.Error(err)
			}
			if ok {
				mu.Lock()
				fresh++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if fresh != 1 {
		t.Fatalf("%d goroutines saw a fresh key", fresh)
	}
}
