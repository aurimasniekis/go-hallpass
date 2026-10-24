package gitproto

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Pattern limits: brace alternatives are expanded, so their product is bounded.
const (
	maxPatternLen   = 256
	maxExpansions   = 64
	maxBraceNesting = 4
)

// Pattern is a path glob over '/'-separated names (repositories, branches, tags):
//
//   - any characters within one segment
//     **     any number of whole segments: none or more as a prefix ("**/x"), one or more as a suffix ("x/**")
//     ?      one character within a segment
//     {a,b}  either alternative; alternatives may contain the other operators and nest
//
// Everything else matches literally.
type Pattern struct {
	src string
	re  *regexp.Regexp
}

// ErrInvalidPattern wraps every pattern compilation error.
var ErrInvalidPattern = errors.New("invalid pattern")

// CompilePattern compiles p. foldCase makes matching case-insensitive (repository names on most hosts).
func CompilePattern(p string, foldCase bool) (*Pattern, error) {
	if p == "" || len(p) > maxPatternLen {
		return nil, fmt.Errorf("%w: length must be 1..%d", ErrInvalidPattern, maxPatternLen)
	}
	if strings.ContainsAny(p, "\\[]") {
		return nil, fmt.Errorf("%w: %q: '\\', '[' and ']' are not supported", ErrInvalidPattern, p)
	}
	alts, err := expandBraces(p, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPattern, p, err)
	}
	parts := make([]string, len(alts))
	for i, a := range alts {
		if strings.Contains(a, "***") {
			return nil, fmt.Errorf("%w: %q: use * or **", ErrInvalidPattern, p)
		}
		parts[i] = globToRegexp(a)
	}
	expr := "^(?:" + strings.Join(parts, "|") + ")$"
	if foldCase {
		expr = "(?i)" + expr
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("%w: %q", ErrInvalidPattern, p)
	}
	return &Pattern{src: p, re: re}, nil
}

// String returns the pattern source.
func (p *Pattern) String() string { return p.src }

// Match reports whether name matches.
func (p *Pattern) Match(name string) bool { return p.re.MatchString(name) }

// expandBraces returns every alternative of p's brace groups.
func expandBraces(p string, depth int) ([]string, error) {
	if depth > maxBraceNesting {
		return nil, errors.New("braces nested too deeply")
	}
	open := strings.IndexByte(p, '{')
	if open < 0 {
		if strings.ContainsAny(p, "},") {
			return nil, errors.New("unbalanced braces or a comma outside braces")
		}
		return []string{p}, nil
	}
	if strings.ContainsAny(p[:open], "},") {
		return nil, errors.New("unbalanced braces or a comma outside braces")
	}
	// Find the matching close brace and the top-level commas inside it.
	level, closeAt := 0, -1
	var commas []int
	for i := open; i < len(p) && closeAt < 0; i++ {
		switch p[i] {
		case '{':
			level++
		case '}':
			level--
			if level == 0 {
				closeAt = i
			}
		case ',':
			if level == 1 {
				commas = append(commas, i)
			}
		}
	}
	if closeAt < 0 {
		return nil, errors.New("unbalanced braces")
	}
	var choices []string
	start := open + 1
	for _, c := range append(commas, closeAt) {
		choices = append(choices, p[start:c])
		start = c + 1
	}
	if len(choices) < 2 {
		return nil, errors.New("braces need at least two alternatives, e.g. {a,b}")
	}
	tails, err := expandBraces(p[closeAt+1:], depth)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ch := range choices {
		heads, err := expandBraces(ch, depth+1)
		if err != nil {
			return nil, err
		}
		for _, h := range heads {
			for _, t := range tails {
				if len(out) == maxExpansions {
					return nil, fmt.Errorf("more than %d alternatives", maxExpansions)
				}
				out = append(out, p[:open]+h+t)
			}
		}
	}
	return out, nil
}

// globToRegexp converts one brace-free glob.
func globToRegexp(g string) string {
	var b strings.Builder
	for i := 0; i < len(g); {
		switch {
		case strings.HasPrefix(g[i:], "**/"):
			b.WriteString("(?:[^/]+/)*")
			i += 3
		case strings.HasPrefix(g[i:], "/**") && i+3 == len(g):
			b.WriteString("(?:/[^/]+)+") // at least one more segment: "agent/**" does not match "agent"
			i += 3
		case strings.HasPrefix(g[i:], "**"):
			b.WriteString(".*")
			i += 2
		case g[i] == '*':
			b.WriteString("[^/]*")
			i++
		case g[i] == '?':
			b.WriteString("[^/]")
			i++
		default:
			b.WriteString(regexp.QuoteMeta(g[i : i+1]))
			i++
		}
	}
	return b.String()
}

// PatternSet matches if any of its patterns match.
type PatternSet []*Pattern

// CompilePatterns compiles every pattern; errors name the offending pattern.
func CompilePatterns(ps []string, foldCase bool) (PatternSet, error) {
	out := make(PatternSet, 0, len(ps))
	for _, p := range ps {
		c, err := CompilePattern(p, foldCase)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// Match reports whether any pattern matches name.
func (s PatternSet) Match(name string) bool {
	for _, p := range s {
		if p.Match(name) {
			return true
		}
	}
	return false
}
