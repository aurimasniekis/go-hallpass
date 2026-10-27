package telegram

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
)

// Telegram limits.
const (
	MaxMessageUTF16  = 4096 // sendMessage/editMessageText text limit, in UTF-16 code units after entity parsing
	MaxCallbackAlert = 200  // answerCallbackQuery text limit
	buttonsPerRow    = 3
	wordJoiner       = '\u2060'
)

type entity struct {
	Type   string `json:"type"`
	Offset int    `json:"offset"`
	Length int    `json:"length"`
}

type inlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

type inlineKeyboard struct {
	InlineKeyboard [][]inlineButton `json:"inline_keyboard"`
}

// rendered is a message body: plain text plus explicit entities (no parse_mode).
type rendered struct {
	Text     string
	Entities []entity
}

// textBuilder appends text while tracking UTF-16 offsets for entities.
type textBuilder struct {
	b    strings.Builder
	off  int
	ents []entity
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s { // ranging a string yields U+FFFD for invalid bytes, never a surrogate
		n += utf16.RuneLen(r)
	}
	return n
}

func (t *textBuilder) plain(s string) {
	t.b.WriteString(s)
	t.off += utf16Len(s)
}

func (t *textBuilder) styled(typ, s string) {
	if s == "" {
		return
	}
	n := utf16Len(s)
	t.ents = append(t.ents, entity{Type: typ, Offset: t.off, Length: n})
	t.b.WriteString(s)
	t.off += n
}

// untrusted writes cleaned, defanged untrusted text inside a code entity ("-" if empty).
func (t *textBuilder) untrusted(s string, maxRunes int) {
	s = Defang(chat.CleanText(s, maxRunes))
	if s == "" {
		t.plain("-")
		return
	}
	t.styled("code", s)
}

func (t *textBuilder) result() rendered { return rendered{Text: t.b.String(), Entities: t.ents} }

// Defang inserts U+2060 WORD JOINER after '@' and '/' so that Telegram's automatic entity detection cannot form
// mentions, bot commands or URLs, even if entity isolation failed. Input must already be cleaned (CleanText removes
// any word joiner an attacker supplied).
func Defang(s string) string {
	if !strings.ContainsAny(s, "@/") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for _, r := range s {
		b.WriteRune(r)
		if r == '@' || r == '/' {
			b.WriteRune(wordJoiner)
		}
	}
	return b.String()
}

// limits are the per-field bounds for one rendering tier.
type limits struct {
	name, desc, caps, capRunes, reason int
}

var tiers = []limits{
	{name: chat.MaxNameRunes, desc: chat.MaxDescriptionRunes, caps: chat.MaxCapabilities, capRunes: chat.MaxCapabilityRunes, reason: chat.MaxReasonRunes},
	{name: 60, desc: 100, caps: 5, capRunes: 40, reason: 300},
	{name: 40, desc: 0, caps: 0, capRunes: 0, reason: 150},
}

// errTooLong reports that even the most compact tier exceeds the Telegram limit.
var errTooLong = errors.New("telegram: rendered message exceeds 4096 UTF-16 units")

func renderApproval(m *chat.ApprovalMessage) (rendered, error) {
	for _, l := range tiers {
		var t textBuilder
		writeApproval(&t, m, l)
		if t.off <= MaxMessageUTF16 {
			return t.result(), nil
		}
	}
	return rendered{}, fmt.Errorf("%w: %w", chat.ErrPermanent, errTooLong)
}

func writeApproval(t *textBuilder, m *chat.ApprovalMessage, l limits) {
	t.styled("bold", "HallPass access request")
	t.plain("\nAgent: ")
	t.untrusted(m.AgentName, l.name)
	t.plain(" (")
	t.untrusted(m.AgentID, 64)
	t.plain(")")
	if m.AgentSession != "" {
		t.plain(" · session ")
		t.untrusted(m.AgentSession, 64)
	}
	t.plain("\nKey: ")
	t.untrusted(m.AgentKeyFingerprint, 100)
	t.plain("\nServer: ")
	t.untrusted(m.Server, l.name)
	if l.desc > 0 && m.ServerDescription != "" {
		t.plain(" — ")
		t.untrusted(m.ServerDescription, l.desc)
	}
	t.plain("\nRole: ")
	t.untrusted(m.Role, l.name)
	if l.desc > 0 && m.RoleDescription != "" {
		t.plain(" — ")
		t.untrusted(m.RoleDescription, l.desc)
	}
	if l.caps > 0 && len(m.Capabilities) > 0 {
		t.plain("\nCapabilities: ")
		shown, used := 0, 0
		for _, c := range m.Capabilities {
			if shown == l.caps {
				break
			}
			used++
			if chat.CleanText(c, l.capRunes) == "" {
				continue
			}
			if shown > 0 {
				t.plain(", ")
			}
			t.untrusted(c, l.capRunes)
			shown++
		}
		if extra := len(m.Capabilities) - used; extra > 0 {
			t.plain(fmt.Sprintf(" (+%d more)", extra))
		}
	}
	t.plain("\nRequested duration: " + chat.FormatDuration(m.RequestedDuration))
	t.plain("\nRequest expires: " + chat.FormatTime(m.ExpiresAt))
	t.plain("\n\nAgent-provided reason (untrusted):\n")
	if r := Defang(chat.CleanText(m.Reason, l.reason)); r != "" {
		t.styled("pre", r)
	} else {
		t.plain("-")
	}
	t.plain("\n\nRequest " + m.RequestID)
	if m.DetailsURL != "" {
		t.plain("\nDetails: " + m.DetailsURL)
	}
}

func keyboard(m *chat.ApprovalMessage) (inlineKeyboard, error) {
	var rows [][]inlineButton
	var row []inlineButton
	var deny []inlineButton
	for _, a := range m.Actions {
		data, err := CallbackData(a.Kind, a.TokenID)
		if err != nil {
			return inlineKeyboard{}, fmt.Errorf("%w: %w", chat.ErrPermanent, err)
		}
		b := inlineButton{Text: chat.ButtonLabel(a), CallbackData: data}
		if a.Kind == chat.ActionDeny {
			deny = append(deny, b)
			continue
		}
		row = append(row, b)
		if len(row) == buttonsPerRow {
			rows = append(rows, row)
			row = nil
		}
	}
	if len(row) > 0 {
		rows = append(rows, row)
	}
	if len(deny) > 0 {
		rows = append(rows, deny)
	}
	return inlineKeyboard{InlineKeyboard: rows}, nil
}

func writeStatus(t *textBuilder, u *chat.StatusUpdate) {
	switch u.State {
	case chat.StateApproved:
		t.plain("✅ ")
	case chat.StateDenied:
		t.plain("⛔ ")
	default:
		t.plain("⏹ ")
	}
	t.styled("bold", chat.StateLabel(u.State))
	if u.DecidedBy != "" {
		t.plain(" by ")
		t.untrusted(u.DecidedBy, chat.MaxNameRunes)
	}
	if u.State == chat.StateApproved && u.Duration > 0 {
		t.plain(" for " + chat.FormatDuration(u.Duration))
	}
	if !u.At.IsZero() {
		t.plain(" at " + chat.FormatTime(u.At))
	}
}

func renderStatus(u *chat.StatusUpdate) (rendered, error) {
	if u.Original != nil {
		for _, l := range tiers {
			var t textBuilder
			writeApproval(&t, u.Original, l)
			t.plain("\n\n")
			writeStatus(&t, u)
			if t.off <= MaxMessageUTF16 {
				return t.result(), nil
			}
		}
		return rendered{}, fmt.Errorf("%w: %w", chat.ErrPermanent, errTooLong)
	}
	var t textBuilder
	t.styled("bold", "HallPass access request")
	t.plain(" " + u.RequestID + "\n")
	writeStatus(&t, u)
	return t.result(), nil
}

// replyText bounds a plain reply. Replies go to a callback toast (never parsed for entities) or to the private chat
// of the user who wrote to the bot, so no one else can be mentioned; the text is still cleaned.
func replyText(s string, maxRunes int) string { return chat.CleanText(s, maxRunes) }
