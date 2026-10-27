// Package apirules decides which HTTP requests an API access profile allows: rules match the method, the API host,
// the path (segment globs) and, for GraphQL endpoints, the operation type. A matching deny rule wins over any allow
// rule, and a request no allow rule matches is refused (default deny).
package apirules

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// Rule effects.
const (
	Allow = "allow"
	Deny  = "deny"
)

// GraphQL operation types.
const (
	Query        = "query"
	Mutation     = "mutation"
	Subscription = "subscription"
)

// Limits.
const (
	MaxRules        = 100
	MaxPatterns     = 50  // per list in one rule
	maxExpansions   = 256 // brace expansions of one path pattern
	MaxPatternBytes = 512
)

// Rule allows or denies requests. Empty Methods, Hosts or Paths match every method, host or path. A rule with
// GraphQL matches only GraphQL requests whose operations are of the listed types; see Policy.Decide.
type Rule struct {
	Effect  string   `json:"effect"`
	Methods []string `json:"methods,omitempty"`
	Hosts   []string `json:"hosts,omitempty"`
	Paths   []string `json:"paths,omitempty"`
	GraphQL []string `json:"graphql,omitempty"`
}

// Request is what the rules look at.
type Request struct {
	Method string
	Host   string
	// Segments is the request path split at "/" with each segment unescaped (see SplitPath).
	Segments []string
	// GraphQL is the classification of the request body, computed only when Policy.NeedsGraphQL says so.
	GraphQL Ops
}

// Decision is the outcome of Policy.Decide.
type Decision struct {
	Allowed bool
	// Rule is the index of the deciding rule, or -1 when no rule matched.
	Rule int
}

type compiled struct {
	effect  string
	methods []string
	hosts   []string
	paths   [][]string // segment patterns, braces expanded
	graphql Ops
}

// Policy is a compiled rule list.
type Policy struct {
	rules []compiled
}

// ErrInvalidPath is returned by SplitPath for paths that could be read in more than one way.
var ErrInvalidPath = errors.New("invalid request path")

// SplitPath splits an escaped request path at "/" and unescapes each segment, so "a%2Fb" stays one segment. Dot
// segments ("." and "..", in any encoding) are refused: HallPass and the API could resolve them differently.
func SplitPath(escaped string) ([]string, error) {
	if !strings.HasPrefix(escaped, "/") {
		return nil, ErrInvalidPath
	}
	raw := strings.Split(escaped[1:], "/")
	out := make([]string, len(raw))
	for i, s := range raw {
		u, err := url.PathUnescape(s)
		if err != nil || u == "." || u == ".." || strings.ContainsAny(u, "\\\x00") {
			return nil, ErrInvalidPath
		}
		out[i] = u
	}
	return out, nil
}

// ValidHost reports whether h is a host name or a "*.suffix" wildcard with at least two labels after the "*".
func ValidHost(h string) bool {
	if rest, ok := strings.CutPrefix(h, "*."); ok {
		return strings.Count(rest, ".") >= 1 && validHostname(rest)
	}
	return validHostname(h)
}

func validHostname(h string) bool {
	if len(h) == 0 || len(h) > 253 || strings.HasSuffix(h, ".") {
		return false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	// A name of digits and dots is an IPv4 address, not a host name.
	return strings.Trim(h, "0123456789.") != ""
}

// HostMatches reports whether host (lower case) matches pattern: exactly, or as a subdomain of a "*." pattern.
func HostMatches(pattern, host string) bool {
	if rest, ok := strings.CutPrefix(pattern, "*."); ok {
		return strings.HasSuffix(host, "."+rest)
	}
	return host == pattern
}

var validMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

// Compile validates rules and prepares them for matching.
func Compile(rules []Rule) (*Policy, error) {
	if len(rules) > MaxRules {
		return nil, fmt.Errorf("at most %d rules", MaxRules)
	}
	p := &Policy{}
	for i, r := range rules {
		c, err := compileRule(r)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		p.rules = append(p.rules, c)
	}
	return p, nil
}

func compileRule(r Rule) (compiled, error) {
	c := compiled{effect: r.Effect}
	if r.Effect != Allow && r.Effect != Deny {
		return c, errors.New("effect must be allow or deny")
	}
	if len(r.Methods) > MaxPatterns || len(r.Hosts) > MaxPatterns || len(r.Paths) > MaxPatterns {
		return c, fmt.Errorf("at most %d methods, hosts or paths per rule", MaxPatterns)
	}
	for _, m := range r.Methods {
		m = strings.ToUpper(m)
		if !slices.Contains(validMethods, m) {
			return c, fmt.Errorf("unknown method %q (valid: %s)", m, strings.Join(validMethods, ", "))
		}
		c.methods = append(c.methods, m)
	}
	for _, h := range r.Hosts {
		h = strings.ToLower(h)
		if !ValidHost(h) {
			return c, fmt.Errorf("invalid host %q", h)
		}
		c.hosts = append(c.hosts, h)
	}
	for _, pat := range r.Paths {
		segs, err := compilePath(pat)
		if err != nil {
			return c, fmt.Errorf("path %q: %w", pat, err)
		}
		c.paths = append(c.paths, segs...)
	}
	for _, t := range r.GraphQL {
		switch strings.ToLower(t) {
		case Query:
			c.graphql |= OpQuery
		case Mutation:
			c.graphql |= OpMutation
		case Subscription:
			c.graphql |= OpSubscription
		default:
			return c, fmt.Errorf("unknown GraphQL operation type %q (valid: query, mutation, subscription)", t)
		}
	}
	return c, nil
}

// compilePath expands braces and splits the pattern into lower-case segment patterns.
func compilePath(pat string) ([][]string, error) {
	if len(pat) > MaxPatternBytes {
		return nil, fmt.Errorf("longer than %d bytes", MaxPatternBytes)
	}
	if !strings.HasPrefix(pat, "/") {
		return nil, errors.New(`must start with "/"`)
	}
	expanded, err := expandBraces(strings.ToLower(pat))
	if err != nil {
		return nil, err
	}
	out := make([][]string, 0, len(expanded))
	for _, e := range expanded {
		segs := strings.Split(e[1:], "/")
		for _, s := range segs {
			if s == "." || s == ".." {
				return nil, errors.New("dot segments are not allowed")
			}
			if strings.Contains(s, "**") && s != "**" {
				return nil, errors.New(`"**" must be a whole segment`)
			}
		}
		out = append(out, segs)
	}
	return out, nil
}

// expandBraces expands one level of {a,b,c} alternatives (several groups allowed, no nesting).
func expandBraces(p string) ([]string, error) {
	open := strings.IndexByte(p, '{')
	if open < 0 {
		if strings.IndexByte(p, '}') >= 0 {
			return nil, errors.New("unbalanced braces")
		}
		return []string{p}, nil
	}
	end := strings.IndexByte(p[open:], '}')
	if end < 0 {
		return nil, errors.New("unbalanced braces")
	}
	end += open
	inner := p[open+1 : end]
	if strings.ContainsAny(inner, "{/") {
		return nil, errors.New("braces cannot nest or contain /")
	}
	rest, err := expandBraces(p[end+1:])
	if err != nil {
		return nil, err
	}
	var out []string
	for _, alt := range strings.Split(inner, ",") {
		for _, r := range rest {
			out = append(out, p[:open]+alt+r)
			if len(out) > maxExpansions {
				return nil, fmt.Errorf("more than %d alternatives", maxExpansions)
			}
		}
	}
	return out, nil
}

// matchSegments matches request segments against a pattern; "**" matches any number of segments and "*" inside a
// segment any run of characters.
func matchSegments(pat, segs []string) bool {
	if len(pat) == 0 {
		return len(segs) == 0
	}
	if pat[0] == "**" {
		for i := 0; i <= len(segs); i++ {
			if matchSegments(pat[1:], segs[i:]) {
				return true
			}
		}
		return false
	}
	return len(segs) > 0 && globMatch(pat[0], segs[0]) && matchSegments(pat[1:], segs[1:])
}

// globMatch matches s against a pattern where "*" matches any run of characters (including none).
func globMatch(pat, s string) bool {
	star, back := -1, 0
	i, j := 0, 0
	for j < len(s) {
		switch {
		case i < len(pat) && pat[i] == '*':
			star, back = i, j
			i++
		case i < len(pat) && pat[i] == s[j]:
			i++
			j++
		case star >= 0:
			back++
			i, j = star+1, back
		default:
			return false
		}
	}
	for i < len(pat) && pat[i] == '*' {
		i++
	}
	return i == len(pat)
}

func (c *compiled) matchesTarget(method, host string, segs []string) bool {
	if len(c.methods) > 0 && !slices.Contains(c.methods, method) {
		return false
	}
	if len(c.hosts) > 0 && !slices.ContainsFunc(c.hosts, func(h string) bool { return HostMatches(h, host) }) {
		return false
	}
	if len(c.paths) == 0 {
		return true
	}
	for _, p := range c.paths {
		if matchSegments(p, segs) {
			return true
		}
	}
	return false
}

func lower(r Request) (string, string, []string) {
	segs := make([]string, len(r.Segments))
	for i, s := range r.Segments {
		segs[i] = strings.ToLower(s)
	}
	return strings.ToUpper(r.Method), strings.ToLower(r.Host), segs
}

// NeedsGraphQL reports whether deciding the request depends on its GraphQL operations.
func (p *Policy) NeedsGraphQL(r Request) bool {
	method, host, segs := lower(r)
	for i := range p.rules {
		if p.rules[i].graphql != 0 && p.rules[i].matchesTarget(method, host, segs) {
			return true
		}
	}
	return false
}

// Decide applies the rules. Matching is case-insensitive. A deny rule with GraphQL types matches when any
// operation is of a listed type or the operations are unknown; an allow rule with GraphQL types matches only when
// the operations are known and all of a listed type.
func (p *Policy) Decide(r Request) Decision {
	method, host, segs := lower(r)
	allowed := -1
	for i := range p.rules {
		c := &p.rules[i]
		if !c.matchesTarget(method, host, segs) {
			continue
		}
		if c.effect == Deny {
			if c.graphql == 0 || r.GraphQL.Unknown() || r.GraphQL&c.graphql != 0 {
				return Decision{Rule: i}
			}
			continue
		}
		if allowed < 0 && (c.graphql == 0 || (!r.GraphQL.Unknown() && r.GraphQL != 0 && r.GraphQL&^c.graphql == 0)) {
			allowed = i
		}
	}
	return Decision{Allowed: allowed >= 0, Rule: allowed}
}

// HasAllow reports whether the policy has at least one allow rule.
func (p *Policy) HasAllow() bool {
	return slices.ContainsFunc(p.rules, func(c compiled) bool { return c.effect == Allow })
}
