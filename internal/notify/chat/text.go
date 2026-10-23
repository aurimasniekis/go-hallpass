package chat

import (
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Ellipsis marks truncated text.
const Ellipsis = "…"

// maxCombiningRun bounds consecutive combining marks so "zalgo" text cannot overflow neighbouring lines.
const maxCombiningRun = 3

// invisible lists letters and symbols that render as blank and are used to spoof empty or misleading text. Format
// characters (Cf: bidi overrides, zero-width space/joiners, BOM, soft hyphen, …) are removed by category.
var invisible = map[rune]bool{
	0x115F: true, 0x1160: true, // Hangul choseong/jungseong fillers
	0x3164: true, 0xFFA0: true, // Hangul filler, halfwidth Hangul filler
	0x2800: true,               // Braille pattern blank
	0x034F: true,               // combining grapheme joiner
	0x17B4: true, 0x17B5: true, // Khmer inherent vowels
	0xFFFC: true, 0xFFFD: true, // object replacement, replacement character
}

// CleanText prepares untrusted text for any chat surface. It drops invalid UTF-8, C0/C1 controls, format characters
// (bidi overrides and isolates, zero-width characters, BOM), private-use and surrogate code points and a list of
// invisible fillers; it collapses all whitespace (including newlines, so text cannot fake message structure) to single
// spaces; it bounds combining-mark runs; and it truncates to maxRunes runes (including the trailing ellipsis).
// maxRunes <= 0 means no length bound. The result still needs provider-specific escaping.
func CleanText(s string, maxRunes int) string {
	out := make([]rune, 0, min(len(s), max(maxRunes, 0)+1))
	space := false
	combining := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == utf8.RuneError, invisible[r]:
			continue // invalid UTF-8 or invisible filler
		case unicode.IsSpace(r):
			space = len(out) > 0
			combining = 0
			continue
		case unicode.IsControl(r), unicode.In(r, unicode.Cf, unicode.Co, unicode.Cs):
			continue
		case unicode.In(r, unicode.Mn, unicode.Me):
			if combining >= maxCombiningRun || len(out) == 0 {
				continue
			}
			combining++
		default:
			combining = 0
		}
		if space {
			out = append(out, ' ')
			space = false
		}
		out = append(out, r)
		if maxRunes > 0 && len(out) > maxRunes {
			break // enough to know that truncation is needed
		}
	}
	if maxRunes > 0 && len(out) > maxRunes {
		out = out[:max(maxRunes-1, 0)]
		for len(out) > 0 && out[len(out)-1] == ' ' {
			out = out[:len(out)-1]
		}
		return string(out) + Ellipsis
	}
	return string(out)
}

// ValidActionTokenID reports whether s is a well-formed opaque action-token ID: base64url alphabet,
// MinActionTokenIDLen..MaxActionTokenIDLen bytes.
func ValidActionTokenID(s string) bool {
	if len(s) < MinActionTokenIDLen || len(s) > MaxActionTokenIDLen {
		return false
	}
	for i := range len(s) {
		if !isTokenByte(s[i]) {
			return false
		}
	}
	return true
}

func isTokenByte(c byte) bool { return isAlnum(c) || c == '-' || c == '_' }

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// NormalizeLinkCode validates a user-typed link code: 1..MaxLinkCodeLen bytes of ASCII letters, digits and '-'. It
// returns the code uppercased. Crockford decoding and verification are the core's job.
func NormalizeLinkCode(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > MaxLinkCodeLen {
		return "", false
	}
	for i := range len(s) {
		if c := s[i]; c != '-' && !isAlnum(c) {
			return "", false
		}
	}
	return strings.ToUpper(s), true
}

// FormatDuration renders a grant duration compactly ("15m", "1h", "1h30m", "2d").
func FormatDuration(d time.Duration) string {
	if d <= 0 {
		return "0m"
	}
	if d%time.Minute != 0 {
		return d.String()
	}
	total := int64(d / time.Minute)
	days, hours, mins := total/(24*60), total%(24*60)/60, total%60
	var b strings.Builder
	if days > 0 {
		b.WriteString(strconv.FormatInt(days, 10) + "d")
	}
	if hours > 0 {
		b.WriteString(strconv.FormatInt(hours, 10) + "h")
	}
	if mins > 0 {
		b.WriteString(strconv.FormatInt(mins, 10) + "m")
	}
	return b.String()
}

// FormatTime renders a timestamp for chat in UTC with minute precision.
func FormatTime(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

// StateLabel returns a human label for a decision state.
func StateLabel(s DecisionState) string {
	switch s {
	case StateApproved:
		return "Approved"
	case StateDenied:
		return "Denied"
	case StateExpired:
		return "Expired"
	case StateCanceled:
		return "Canceled"
	}
	return "Updated"
}

// ButtonLabel returns the button label for an action.
func ButtonLabel(a Action) string {
	if a.Kind == ActionApprove {
		return "Approve " + FormatDuration(a.Duration)
	}
	return "Deny"
}
