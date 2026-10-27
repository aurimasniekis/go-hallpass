package slack

import (
	"fmt"
	"strings"

	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
)

// Slack Block Kit limits used by the renderer.
const (
	maxSectionText = 3000
	maxFieldText   = 2000
	maxContextText = 2000
)

// textObject is a Block Kit text object. The renderer only ever produces plain_text.
type textObject struct {
	Type  string `json:"type"`
	Text  string `json:"text"`
	Emoji bool   `json:"emoji"`
}

type block struct {
	Type     string       `json:"type"`
	BlockID  string       `json:"block_id,omitempty"`
	Text     *textObject  `json:"text,omitempty"`
	Fields   []textObject `json:"fields,omitempty"`
	Elements []any        `json:"elements,omitempty"`
}

type button struct {
	Type     string     `json:"type"`
	Text     textObject `json:"text"`
	ActionID string     `json:"action_id"`
	Value    string     `json:"value,omitempty"`
	URL      string     `json:"url,omitempty"`
	Style    string     `json:"style,omitempty"`
}

// Escape escapes the three characters Slack treats as control sequences (&, <, >). Applied after chat.CleanText,
// it guarantees that untrusted text contains no "<…>" sequence, so no mention, channel link, URL link or <!…>
// command can be formed.
func Escape(s string) string {
	if !strings.ContainsAny(s, "&<>") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// untrusted cleans, bounds and escapes untrusted text.
func untrusted(s string, maxRunes int) string {
	out := Escape(chat.CleanText(s, maxRunes))
	if out == "" {
		return "-"
	}
	return out
}

func plain(s string) textObject { return textObject{Type: "plain_text", Text: s, Emoji: false} }

// plainBounded keeps a text object within a Block Kit byte-ish limit (Slack counts characters; bytes are a safe
// over-approximation) without splitting escape entities.
func plainBounded(s string, limit int) textObject {
	if len(s) <= limit {
		return plain(s)
	}
	cut := limit - len(chat.Ellipsis)
	for cut > 0 && (s[cut]&0xC0) == 0x80 { // do not split a UTF-8 sequence
		cut--
	}
	if i := strings.LastIndexByte(s[:cut], '&'); i >= 0 && !strings.Contains(s[i:cut], ";") {
		cut = i // do not split an entity
	}
	return plain(s[:cut] + chat.Ellipsis)
}

// fallbackText is the notification text. It never contains untrusted input.
func fallbackText(requestID string) string {
	return "HallPass access request " + requestID + " awaits approval"
}

// renderApproval builds the Block Kit blocks for a pending request. withActions=false omits the buttons (used when
// the message is updated after a decision).
func renderApproval(m *chat.ApprovalMessage, withActions bool) []block {
	blocks := []block{
		{Type: "header", Text: &textObject{Type: "plain_text", Text: "HallPass access request", Emoji: false}},
		{Type: "section", Fields: []textObject{
			plainBounded("Agent: "+untrusted(m.AgentName, chat.MaxNameRunes)+" ("+untrusted(m.AgentID, 64)+")"+sessionSuffix(m.AgentSession), maxFieldText),
			plainBounded("Key: "+untrusted(m.AgentKeyFingerprint, 100), maxFieldText),
			plainBounded("Server: "+untrusted(m.Server, chat.MaxNameRunes), maxFieldText),
			plainBounded("Role: "+untrusted(m.Role, chat.MaxNameRunes), maxFieldText),
			plain("Requested duration: " + chat.FormatDuration(m.RequestedDuration)),
			plain("Request expires: " + chat.FormatTime(m.ExpiresAt)),
		}},
	}
	var ctx []any
	if m.ServerDescription != "" {
		ctx = append(ctx, plainBounded("Server description: "+untrusted(m.ServerDescription, chat.MaxDescriptionRunes), maxContextText))
	}
	if m.RoleDescription != "" {
		ctx = append(ctx, plainBounded("Role description: "+untrusted(m.RoleDescription, chat.MaxDescriptionRunes), maxContextText))
	}
	if len(ctx) > 0 {
		blocks = append(blocks, block{Type: "context", Elements: ctx})
	}
	if caps := capabilities(m.Capabilities); caps != "" {
		blocks = append(blocks, block{Type: "section", Text: ptr(plainBounded("Capabilities: "+caps, maxSectionText))})
	}
	blocks = append(blocks,
		block{Type: "section", Text: ptr(plainBounded("Agent-provided reason (untrusted):\n“"+
			untrusted(m.Reason, chat.MaxReasonRunes)+"”", maxSectionText))},
		block{Type: "context", Elements: []any{plain("Request " + m.RequestID)}},
	)
	if withActions {
		var els []any
		for _, a := range m.Actions {
			b := button{Type: "button", Text: plain(chat.ButtonLabel(a)), ActionID: ActionID(a.Kind, a.TokenID), Value: a.TokenID}
			if a.Kind == chat.ActionDeny {
				b.Style = "danger"
			}
			els = append(els, b)
		}
		if m.DetailsURL != "" {
			els = append(els, button{Type: "button", Text: plain("Details"), ActionID: detailsActionID, URL: m.DetailsURL})
		}
		blocks = append(blocks, block{Type: "actions", BlockID: "hp_actions", Elements: els})
	}
	return blocks
}

func capabilities(caps []string) string {
	var parts []string
	used := 0
	for _, c := range caps {
		if len(parts) == chat.MaxCapabilities {
			break
		}
		used++
		if s := chat.CleanText(c, chat.MaxCapabilityRunes); s != "" {
			parts = append(parts, Escape(s))
		}
	}
	out := strings.Join(parts, ", ")
	if extra := len(caps) - used; extra > 0 {
		out += fmt.Sprintf(" (+%d more)", extra)
	}
	return out
}

// statusLine renders the outcome of a decision.
func statusLine(u *chat.StatusUpdate) string {
	var b strings.Builder
	switch u.State {
	case chat.StateApproved:
		b.WriteString("✅ ")
	case chat.StateDenied:
		b.WriteString("⛔ ")
	default:
		b.WriteString("⏹ ")
	}
	b.WriteString(chat.StateLabel(u.State))
	if u.DecidedBy != "" {
		b.WriteString(" by " + untrusted(u.DecidedBy, chat.MaxNameRunes))
	}
	if u.State == chat.StateApproved && u.Duration > 0 {
		b.WriteString(" for " + chat.FormatDuration(u.Duration))
	}
	if !u.At.IsZero() {
		b.WriteString(" at " + chat.FormatTime(u.At))
	}
	return b.String()
}

func renderStatus(u *chat.StatusUpdate) []block {
	line := ptr(plainBounded(statusLine(u), maxSectionText))
	if u.Original != nil {
		return append(renderApproval(u.Original, false), block{Type: "section", Text: line})
	}
	return []block{
		{Type: "section", Text: line},
		{Type: "context", Elements: []any{plain("Request " + u.RequestID)}},
	}
}

// renderReply renders a short reply. The fallback text is static so that untrusted text never reaches a
// mrkdwn-interpreted field.
func renderReply(text string) (string, []block) {
	t := untrusted(text, chat.MaxReplyRunes)
	return "HallPass", []block{{Type: "section", Text: ptr(plainBounded(t, maxSectionText))}}
}

func ptr(t textObject) *textObject { return &t }

// sessionSuffix names the agent session in the agent line ("" for the shared default session).
func sessionSuffix(session string) string {
	if session == "" {
		return ""
	}
	return " · session " + untrusted(session, 64)
}
