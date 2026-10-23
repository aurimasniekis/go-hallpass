// Package grammar implements the agent-facing SSH command grammar (PLAN §7): the shell-free tokenizer (HP-SSH-016),
// the command parser, gateway exit codes, the versioned --json output documents (HP-SSH-018) and plain-text
// rendering.
//
// The package is pure: it performs no I/O, holds no state and never looks anything up, so parsing can reveal
// nothing about targets (HP-POL-010). It is fuzzed (FuzzTokenize, FuzzParse).
package grammar

import (
	"strings"
	"unicode/utf8"
)

// Input limits (PLAN §7.2).
const (
	// MaxGatewayBytes bounds the gateway-command portion: everything before the first standalone "--" token, or the
	// whole input when there is none.
	MaxGatewayBytes = 16 << 10
	// MaxInputBytes bounds the whole exec string, including the destination command.
	MaxInputBytes = 64 << 10
)

// Token is one gateway-command word.
type Token struct {
	// Value is the word after quote and escape removal.
	Value string
	// Quoted reports whether any part of the word was quoted or backslash-escaped. A quoted "--" never ends gateway
	// parsing, and a quoted word is always accepted as an option value even when it starts with '-'.
	Quoted bool
	// Start and End are the byte offsets of the raw word in the input.
	Start, End int
}

// Tokens is the tokenizer result.
type Tokens struct {
	// Words are the gateway-command words before the first standalone unquoted "--".
	Words []Token
	// HasSeparator reports whether a standalone unquoted "--" token was found.
	HasSeparator bool
	// SeparatorAt is the byte offset of that "--" token, or -1.
	SeparatorAt int
	// Remote is the raw byte substring after the "--" token and the single whitespace run that follows it
	// (HP-SSH-023). It is always a suffix of the input and is never rebuilt from tokens.
	Remote string
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' }

// isForbiddenControl reports C0 controls other than TAB (PLAN §7.2).
func isForbiddenControl(c byte) bool { return c < 0x20 && c != '\t' }

// Tokenize splits an exec-request string per PLAN §7.2. It never expands variables, globs, tildes, braces or command
// substitutions. Errors are usage errors (exit 81).
//
// The NUL/C0 and UTF-8 checks apply to the whole input, including the destination command after "--".
func Tokenize(input string) (Tokens, error) {
	out := Tokens{SeparatorAt: -1}
	if len(input) > MaxInputBytes {
		return out, usage("command too long (maximum 64 KiB)")
	}
	if !utf8.ValidString(input) {
		return out, usage("command is not valid UTF-8")
	}
	for i := range len(input) {
		if isForbiddenControl(input[i]) {
			return out, usage("command contains a control character (only TAB is allowed)")
		}
	}

	n := len(input)
	i := 0
	var b strings.Builder
	for {
		for i < n && isSpace(input[i]) {
			i++
		}
		if i >= n {
			break
		}
		if i > MaxGatewayBytes {
			return Tokens{SeparatorAt: -1}, errGatewayTooLong()
		}
		start := i
		quoted := false
		b.Reset()
		for i < n && !isSpace(input[i]) {
			switch c := input[i]; c {
			case '\'':
				j := strings.IndexByte(input[i+1:], '\'')
				if j < 0 {
					return Tokens{SeparatorAt: -1}, usage("unterminated single quote")
				}
				b.WriteString(input[i+1 : i+1+j])
				i += j + 2
				quoted = true
			case '"':
				i++
				quoted = true
				closed := false
				for i < n {
					c := input[i]
					if c == '"' {
						i++
						closed = true
						break
					}
					if c == '\\' && i+1 < n && (input[i+1] == '"' || input[i+1] == '\\') {
						b.WriteByte(input[i+1])
						i += 2
						continue
					}
					b.WriteByte(c)
					i++
				}
				if !closed {
					return Tokens{SeparatorAt: -1}, usage("unterminated double quote")
				}
			case '\\':
				if i+1 >= n {
					return Tokens{SeparatorAt: -1}, usage("trailing backslash")
				}
				_, size := utf8.DecodeRuneInString(input[i+1:])
				b.WriteString(input[i+1 : i+1+size])
				i += 1 + size
				quoted = true
			default:
				b.WriteByte(c)
				i++
			}
		}
		if !quoted && input[start:i] == "--" {
			if start > MaxGatewayBytes {
				return Tokens{SeparatorAt: -1}, errGatewayTooLong()
			}
			j := i
			for j < n && isSpace(input[j]) {
				j++
			}
			out.HasSeparator = true
			out.SeparatorAt = start
			out.Remote = input[j:]
			return out, nil
		}
		out.Words = append(out.Words, Token{Value: b.String(), Quoted: quoted, Start: start, End: i})
	}
	if n > MaxGatewayBytes {
		return Tokens{SeparatorAt: -1}, errGatewayTooLong()
	}
	return out, nil
}

func errGatewayTooLong() *Error {
	return usage("gateway command too long (maximum 16 KiB before --)")
}
