package access

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
)

// MaxReasonRunes bounds agent-provided reasons (HP-REQ-008).
const MaxReasonRunes = 1000

var agentSessionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

// ValidAgentSession reports whether s is "" (the shared default session) or a session name such as a Claude Code
// session ID: 1-64 characters from A-Z a-z 0-9 . _ : - starting with a letter or digit.
func ValidAgentSession(s string) bool { return s == "" || agentSessionRE.MatchString(s) }

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
