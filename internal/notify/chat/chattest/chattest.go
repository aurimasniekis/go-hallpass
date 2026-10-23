// Package chattest provides fixtures for chat provider tests: valid messages, hostile strings and a recording Sink.
package chattest

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
)

// Token returns a deterministic, valid 22-character action-token ID.
func Token(i int) string {
	s := fmt.Sprintf("tok%019d", i)
	return s[:22]
}

// Message returns a valid approval message with three approve durations and a deny button.
func Message() chat.ApprovalMessage {
	return chat.ApprovalMessage{
		RequestID:           ids.New(ids.Request),
		AgentName:           "build-bot",
		AgentID:             ids.New(ids.Agent),
		AgentKeyFingerprint: "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
		Server:              "db-prod",
		ServerDescription:   "Primary database",
		Role:                "readonly",
		RoleDescription:     "Read-only shell",
		Capabilities:        []string{"shell", "exec"},
		Reason:              "Investigate slow queries",
		RequestedDuration:   time.Hour,
		ExpiresAt:           time.Date(2026, 10, 23, 12, 30, 0, 0, time.UTC),
		Actions: []chat.Action{
			{Kind: chat.ActionApprove, Duration: 15 * time.Minute, TokenID: Token(1)},
			{Kind: chat.ActionApprove, Duration: time.Hour, TokenID: Token(2)},
			{Kind: chat.ActionApprove, Duration: 4 * time.Hour, TokenID: Token(3)},
			{Kind: chat.ActionDeny, TokenID: Token(4)},
		},
		DetailsURL: "https://hallpass.example/requests/x",
	}
}

// Hostile is a corpus of untrusted strings that try to produce mentions, links, markup, spoofed layout or
// oversized output.
var Hostile = []string{
	"<!channel> <!here> <!everyone> @channel @here @everyone",
	"<@U12345> <@W999|admin> <#C12345|general> <!subteam^S123|ops> <!date^1392734382^x|y>",
	"<https://evil.example|click me> https://evil.example <mailto:a@b.c|mail>",
	"*bold* _italic_ ~strike~ `code` ```block``` > quote",
	"&lt;!channel&gt; &amp; &#60;!here&#62;",
	"<b>bold</b><a href=\"https://evil.example\">x</a><script>alert(1)</script>",
	"\u202egnp.exe\u202c \u2066iso\u2069 zero\u200bwidth\u200d\ufeff\u2060joiner",
	"line1\nline2\r\n\u2028\u2029✅ Approved by admin",
	"\x00\x1b[31mred\x1b[0m\x7f\u0085\u009b",
	"/link ABCD1234 @BotFather #tag $CASH /start",
	"\u3164\u115f\u2800\u034f\ufffc",
	"Z\u0300\u0301\u0302\u0303\u0304\u0305\u0306\u0307\u0308\u0309",
	"\xff\xfe\xfd invalid utf-8 \xc3\x28",
	strings.Repeat("A", 10000),
	strings.Repeat("\U0001D54F", 3000),
	strings.Repeat("&<>", 2000),
	strings.Repeat("@x ", 2000),
}

// Sink records events and rejections and replies with a fixed text.
type Sink struct {
	mu         sync.Mutex
	Reply      string
	Events     []chat.Event
	Rejections []chat.Rejection
}

// HandleEvent implements chat.Sink.
func (s *Sink) HandleEvent(_ context.Context, ev chat.Event) chat.Reply {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Events = append(s.Events, ev)
	return chat.Reply{Text: s.Reply}
}

// Rejected implements chat.Sink.
func (s *Sink) Rejected(_ context.Context, r chat.Rejection) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Rejections = append(s.Rejections, r)
}

// Snapshot returns copies of the recorded events and rejections.
func (s *Sink) Snapshot() ([]chat.Event, []chat.Rejection) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]chat.Event(nil), s.Events...), append([]chat.Rejection(nil), s.Rejections...)
}

// LastRejection returns the most recent rejection reason, or "".
func (s *Sink) LastRejection() chat.RejectReason {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.Rejections) == 0 {
		return ""
	}
	return s.Rejections[len(s.Rejections)-1].Reason
}

// FailingReplay is a ReplayCache that always errors.
type FailingReplay struct{}

// Remember implements chat.ReplayCache.
func (FailingReplay) Remember(context.Context, string, time.Time) (bool, error) {
	return false, fmt.Errorf("replay store unavailable")
}
