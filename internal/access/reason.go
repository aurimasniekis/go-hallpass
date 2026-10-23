package access

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
)

// MaxReasonRunes bounds agent-provided reasons (HP-REQ-008).
const MaxReasonRunes = 1000

// SanitizeReason strips control, format (including bidi overrides and zero-width) and unassigned-surrogate
// characters, collapses whitespace runs, and enforces the length bound. The result is still untrusted text and must
// be rendered as plain text everywhere.
func SanitizeReason(s string) (string, error) {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t' || r == '\r' || unicode.IsSpace(r):
			if !space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			space = true
			continue
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Co, r), r == utf8.RuneError:
			continue
		}
		space = false
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	if n := utf8.RuneCountInString(out); n > MaxReasonRunes {
		return "", apperr.New(apperr.CodeInvalid, "reason too long (%d characters, maximum %d)", n, MaxReasonRunes)
	}
	return out, nil
}
