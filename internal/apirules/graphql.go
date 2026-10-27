package apirules

import (
	"encoding/json"
	"strings"
)

// Ops is the set of GraphQL operation types in a request.
type Ops uint8

// Operation type bits.
const (
	OpQuery Ops = 1 << iota
	OpMutation
	OpSubscription
	opUnknown
)

// Unknown reports whether the operations could not be determined (not GraphQL, unparsable, persisted queries).
func (o Ops) Unknown() bool { return o&opUnknown != 0 }

// Names lists the operation types, or "unknown".
func (o Ops) Names() []string {
	if o.Unknown() || o == 0 {
		return []string{"unknown"}
	}
	var out []string
	for _, t := range []struct {
		b Ops
		n string
	}{{OpQuery, Query}, {OpMutation, Mutation}, {OpSubscription, Subscription}} {
		if o&t.b != 0 {
			out = append(out, t.n)
		}
	}
	return out
}

// Unknown is the classification of a request whose operations cannot be determined.
const Unknown = opUnknown

// ClassifyBody classifies a GraphQL-over-HTTP POST body: one JSON object with a "query" string or a batch (array)
// of them. Every operation in every document counts, whatever operationName says, so a document that also contains
// a mutation is never classified as a query.
func ClassifyBody(body []byte) Ops {
	var one struct {
		Query *string `json:"query"`
	}
	trimmed := strings.TrimLeft(string(body), " \t\r\n")
	if strings.HasPrefix(trimmed, "[") {
		var batch []json.RawMessage
		if json.Unmarshal(body, &batch) != nil || len(batch) == 0 {
			return opUnknown
		}
		var ops Ops
		for _, b := range batch {
			ops |= ClassifyBody(b)
		}
		return ops
	}
	if json.Unmarshal(body, &one) != nil || one.Query == nil {
		return opUnknown
	}
	return ClassifyDocument(*one.Query)
}

// ClassifyDocument returns the operation types defined in a GraphQL document. Anything other than operations and
// fragments (for example type definitions) makes it unknown.
func ClassifyDocument(doc string) Ops {
	lx := lexer{s: doc}
	var ops Ops
	for {
		tok, ok := lx.next()
		if !ok {
			break
		}
		switch tok {
		case "{":
			ops |= OpQuery // shorthand query
			if !lx.skipBlock() {
				return opUnknown
			}
		case Query, Mutation, Subscription, "fragment":
			switch tok {
			case Query:
				ops |= OpQuery
			case Mutation:
				ops |= OpMutation
			case Subscription:
				ops |= OpSubscription
			}
			if !lx.skipDefinition() {
				return opUnknown
			}
		default:
			return opUnknown
		}
	}
	if lx.bad || ops == 0 {
		return opUnknown
	}
	return ops
}

// lexer yields GraphQL punctuators and names, skipping white space, commas, comments and strings.
type lexer struct {
	s   string
	i   int
	bad bool
}

func (l *lexer) next() (string, bool) {
	for l.i < len(l.s) {
		if strings.HasPrefix(l.s[l.i:], "\xef\xbb\xbf") { // byte order mark: ignored like white space
			l.i += len("\xef\xbb\xbf")
			continue
		}
		c := l.s[l.i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',':
			l.i++
		case c == '#':
			for l.i < len(l.s) && l.s[l.i] != '\n' && l.s[l.i] != '\r' {
				l.i++
			}
		case c == '"':
			if !l.skipString() {
				l.bad = true
				return "", false
			}
			return `"`, true
		case c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			start := l.i
			for l.i < len(l.s) && (l.s[l.i] == '_' || l.s[l.i] >= 'a' && l.s[l.i] <= 'z' || l.s[l.i] >= 'A' && l.s[l.i] <= 'Z' || l.s[l.i] >= '0' && l.s[l.i] <= '9') {
				l.i++
			}
			return l.s[start:l.i], true
		default:
			l.i++
			return string(c), true
		}
	}
	return "", false
}

// skipString skips a "string" or """block string""" starting at l.i.
func (l *lexer) skipString() bool {
	if strings.HasPrefix(l.s[l.i:], `"""`) {
		l.i += 3
		for l.i < len(l.s) {
			switch {
			case strings.HasPrefix(l.s[l.i:], `\"""`):
				l.i += 4
			case strings.HasPrefix(l.s[l.i:], `"""`):
				l.i += 3
				return true
			default:
				l.i++
			}
		}
		return false
	}
	l.i++
	for l.i < len(l.s) {
		switch l.s[l.i] {
		case '\\':
			l.i += 2
		case '"':
			l.i++
			return true
		case '\n', '\r':
			return false
		default:
			l.i++
		}
	}
	return false
}

// skipBlock skips to the "}" closing a "{" that was just read.
func (l *lexer) skipBlock() bool {
	depth := 1
	for depth > 0 {
		tok, ok := l.next()
		if !ok {
			return false
		}
		switch tok {
		case "{":
			depth++
		case "}":
			depth--
		}
	}
	return true
}

// skipDefinition skips an operation or fragment definition up to the end of its selection set. Braces inside the
// variable definitions (object default values) are skipped with the parentheses.
func (l *lexer) skipDefinition() bool {
	parens := 0
	for {
		tok, ok := l.next()
		if !ok {
			return false
		}
		switch tok {
		case "(":
			parens++
		case ")":
			parens--
		case "{":
			if parens == 0 {
				return l.skipBlock()
			}
		}
	}
}
