package grammar

import (
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/inventory/alias"
)

// Wait defaults and bounds (PLAN §7.3, HP-SSH-020).
const (
	DefaultWaitTimeout = 120 * time.Second
	MaxWaitTimeout     = 15 * time.Minute
	// MaxReasonRunes bounds --reason after trimming; the access layer sanitizes further (HP-REQ-008).
	MaxReasonRunes = 1000
)

// Command is a parsed gateway command: one of List, Roles, Request, Status, Cancel, Connect, Exec, Sessions, Help,
// Version or WhoAmI.
type Command interface {
	// CommandName is the canonical command word ("list", "connect", …).
	CommandName() string
	isCommand()
}

// Opts are the request/connect options (PLAN §7.3 req-opt and conn-opt). Zero values mean "not given".
type Opts struct {
	// Role is the --role alias, or "".
	Role string
	// Reason is the --reason text after trimming surrounding whitespace, or "".
	Reason string
	// Duration is the --duration value, or 0. When set it is > 0; policy checks presets and maxima.
	Duration time.Duration
	// Wait is --wait[=bool] / --no-wait, or nil when not given (defaults differ per command).
	Wait *bool
	// WaitTimeout is --wait-timeout (0s..15m), or nil when not given.
	WaitTimeout *time.Duration
	// IdempotencyKey is --idempotency-key, or "".
	IdempotencyKey string
	// JSON is --json.
	JSON bool
}

// WaitOr returns the --wait setting, or def when it was not given.
func (o Opts) WaitOr(def bool) bool {
	if o.Wait == nil {
		return def
	}
	return *o.Wait
}

// EffectiveWaitTimeout returns --wait-timeout, or DefaultWaitTimeout when it was not given.
func (o Opts) EffectiveWaitTimeout() time.Duration {
	if o.WaitTimeout == nil {
		return DefaultWaitTimeout
	}
	return *o.WaitTimeout
}

// List is "list"/"ls" or empty input.
type List struct {
	JSON   bool
	Server string // --server filter, or ""
}

// Roles is "roles <alias>".
type Roles struct {
	Alias string
	JSON  bool
}

// Request is "request <alias> {req-opt}". Wait defaults to false.
type Request struct {
	Alias string
	Opts  Opts
}

// Status is "status <request-id>". Wait defaults to false.
type Status struct {
	RequestID   string
	JSON        bool
	Wait        bool
	WaitTimeout *time.Duration
}

// Cancel is "cancel <request-id>".
type Cancel struct {
	RequestID string
	JSON      bool
}

// Connect is "connect <alias> {conn-opt}" or the shorthand "<alias> {conn-opt}". Wait defaults to true.
type Connect struct {
	Alias     string
	Opts      Opts
	Shorthand bool
}

// Exec is "exec <alias> {conn-opt} -- <remote>". Wait defaults to true. Remote is the raw input suffix after the
// first standalone "--" (HP-SSH-023) and is never empty.
type Exec struct {
	Alias  string
	Opts   Opts
	Remote string
}

// Sessions is "sessions [--json] [--all]".
type Sessions struct {
	JSON bool
	All  bool
}

// Help is "help [topic]". Topic is "" or one of HelpTopics().
type Help struct {
	Topic string
}

// Version is "version [--json]".
type Version struct {
	JSON bool
}

// WhoAmI is "whoami [--json]".
type WhoAmI struct {
	JSON bool
}

// API subcommands.
const (
	APICA       = "ca"
	APIEnv      = "env"
	APIRequests = "requests"
)

var invocationRE = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

// DefaultAPIProxyPort is the local port "api env" assumes for the proxy tunnel.
const DefaultAPIProxyPort = 18080

// API is "api ca" (the CA bundle of the API targets visible to the agent), "api env [--port n]" (shell lines that
// install that bundle and point HTTPS clients at a local proxy tunnel) or "api requests <invocation>" (the access
// requests the proxy filed during a hallpass-api run, one ID per line).
type API struct {
	Sub        string
	Port       int
	Invocation string
}

func (List) CommandName() string     { return "list" }
func (Roles) CommandName() string    { return "roles" }
func (Request) CommandName() string  { return "request" }
func (Status) CommandName() string   { return "status" }
func (Cancel) CommandName() string   { return "cancel" }
func (Connect) CommandName() string  { return "connect" }
func (Exec) CommandName() string     { return "exec" }
func (Sessions) CommandName() string { return "sessions" }
func (Help) CommandName() string     { return "help" }
func (Version) CommandName() string  { return "version" }
func (WhoAmI) CommandName() string   { return "whoami" }
func (API) CommandName() string      { return "api" }

func (List) isCommand()     {}
func (Roles) isCommand()    {}
func (Request) isCommand()  {}
func (Status) isCommand()   {}
func (Cancel) isCommand()   {}
func (Connect) isCommand()  {}
func (Exec) isCommand()     {}
func (Sessions) isCommand() {}
func (Help) isCommand()     {}
func (Version) isCommand()  {}
func (WhoAmI) isCommand()   {}
func (API) isCommand()      {}

// EffectiveWait is the --wait setting with the request default (false).
func (r Request) EffectiveWait() bool { return r.Opts.WaitOr(false) }

// EffectiveWait is the --wait setting with the connect default (true).
func (c Connect) EffectiveWait() bool { return c.Opts.WaitOr(true) }

// EffectiveWait is the --wait setting with the exec default (true).
func (e Exec) EffectiveWait() bool { return e.Opts.WaitOr(true) }

// EffectiveWaitTimeout returns --wait-timeout, or DefaultWaitTimeout.
func (s Status) EffectiveWaitTimeout() time.Duration {
	if s.WaitTimeout == nil {
		return DefaultWaitTimeout
	}
	return *s.WaitTimeout
}

// JSONOutput reports whether --json was given for any command.
func JSONOutput(c Command) bool {
	switch c := c.(type) {
	case List:
		return c.JSON
	case Roles:
		return c.JSON
	case Request:
		return c.Opts.JSON
	case Status:
		return c.JSON
	case Cancel:
		return c.JSON
	case Connect:
		return c.Opts.JSON
	case Exec:
		return c.Opts.JSON
	case Sessions:
		return c.JSON
	case Version:
		return c.JSON
	case WhoAmI:
		return c.JSON
	}
	return false
}

var (
	idemRE  = regexp.MustCompile(`^[A-Za-z0-9._-]{8,128}$`)
	reqIDRE = regexp.MustCompile(`^req_[0-9a-hjkmnp-tv-z]{26}$`)
)

// ValidRequestID reports whether s is a well-formed request ID: "req_" and 26 lowercase Crockford base32 characters
// encoding a 128-bit value.
func ValidRequestID(s string) bool { return reqIDRE.MatchString(s) && ids.Valid(ids.Request, s) }

// Parse tokenizes and parses an exec-request string. Empty input (also a shell request) is List{}. Every error is an
// *Error with ExitUsage. Parsing never consults any state.
func Parse(input string) (Command, error) {
	t, err := Tokenize(input)
	if err != nil {
		return nil, err
	}
	return parseTokens(input, t)
}

// option names; --no-wait shares the "wait" slot.
const (
	oRole        = "role"
	oReason      = "reason"
	oDuration    = "duration"
	oWait        = "wait"
	oWaitTimeout = "wait-timeout"
	oIdem        = "idempotency-key"
	oJSON        = "json"
	oServer      = "server"
	oAll         = "all"
)

var (
	reqOpts     = []string{oRole, oReason, oDuration, oWait, oWaitTimeout, oIdem, oJSON}
	statusOpts  = []string{oJSON, oWait, oWaitTimeout}
	listOpts    = []string{oJSON, oServer}
	jsonOnly    = []string{oJSON}
	sessionOpts = []string{oJSON, oAll}
)

// valueOpts take a value ("--opt v" or "--opt=v").
var valueOpts = map[string]bool{oRole: true, oReason: true, oDuration: true, oWaitTimeout: true, oIdem: true, oServer: true}

type parser struct {
	input string
	t     Tokens
}

func parseTokens(input string, t Tokens) (Command, error) {
	p := &parser{input: input, t: t}
	if len(t.Words) == 0 {
		if t.HasSeparator {
			return nil, usage(`missing command before --; to run a remote command use: exec <server> -- <command>`)
		}
		return List{}, nil
	}
	first := t.Words[0]
	name := first.Value
	rest := t.Words[1:]
	switch name {
	case "list", "ls":
		return p.list(rest)
	case "roles":
		return p.roles(rest)
	case "request":
		return p.request(rest)
	case "status":
		return p.status(rest)
	case "cancel":
		return p.cancel(rest)
	case "connect":
		return p.connect(rest)
	case "exec":
		return p.exec(rest)
	case "sessions":
		return p.sessions(rest)
	case "help":
		return p.help(rest)
	case "version":
		o, err := p.simple("version", rest, jsonOnly)
		return Version{JSON: o.JSON}, err
	case "whoami":
		o, err := p.simple("whoami", rest, jsonOnly)
		return WhoAmI{JSON: o.JSON}, err
	case "api":
		return p.api(rest)
	}
	switch {
	case strings.HasPrefix(name, "-"):
		if name == "--json" || name == "--server" || strings.HasPrefix(name, "--server=") {
			return nil, usagef("expected a command before %s; use: list %s", quote(name), quote(name))
		}
		return nil, usagef("expected a command, got option %s; run \"help\" for usage", quote(name))
	case alias.IsReserved(name):
		return nil, usagef("%s is reserved and is not a command; run \"help\" for usage", quote(name))
	case !alias.Valid(name):
		return nil, usagef("unknown command or invalid server alias %s; run \"help\" for usage", quote(name))
	}
	return p.shorthand(first, rest)
}

// noSeparator rejects "--" for commands other than exec.
func (p *parser) noSeparator(cmd string) error {
	if p.t.HasSeparator {
		return usagef("-- is only valid with exec (%s does not take a remote command)", cmd)
	}
	return nil
}

func (p *parser) list(rest []Token) (Command, error) {
	if err := p.noSeparator("list"); err != nil {
		return nil, err
	}
	var o parsedOpts
	if err := o.parse("list", rest, listOpts, nil); err != nil {
		return nil, err
	}
	return List{JSON: o.JSON, Server: o.server}, nil
}

func (p *parser) roles(rest []Token) (Command, error) {
	if err := p.noSeparator("roles"); err != nil {
		return nil, err
	}
	aliasTok, rest, err := positionalAlias("roles", rest)
	if err != nil {
		return nil, err
	}
	var o parsedOpts
	if err := o.parse("roles", rest, jsonOnly, nil); err != nil {
		return nil, err
	}
	return Roles{Alias: aliasTok.Value, JSON: o.JSON}, nil
}

func (p *parser) request(rest []Token) (Command, error) {
	if err := p.noSeparator("request"); err != nil {
		return nil, err
	}
	aliasTok, rest, err := positionalAlias("request", rest)
	if err != nil {
		return nil, err
	}
	var o parsedOpts
	if err := o.parse("request", rest, reqOpts, nil); err != nil {
		return nil, err
	}
	return Request{Alias: aliasTok.Value, Opts: o.Opts}, nil
}

func (p *parser) status(rest []Token) (Command, error) {
	if err := p.noSeparator("status"); err != nil {
		return nil, err
	}
	id, rest, err := positionalRequestID("status", rest)
	if err != nil {
		return nil, err
	}
	var o parsedOpts
	o.noWaitForbidden = true
	if err := o.parse("status", rest, statusOpts, nil); err != nil {
		return nil, err
	}
	return Status{RequestID: id, JSON: o.JSON, Wait: o.WaitOr(false), WaitTimeout: o.WaitTimeout}, nil
}

func (p *parser) cancel(rest []Token) (Command, error) {
	if err := p.noSeparator("cancel"); err != nil {
		return nil, err
	}
	id, rest, err := positionalRequestID("cancel", rest)
	if err != nil {
		return nil, err
	}
	var o parsedOpts
	if err := o.parse("cancel", rest, jsonOnly, nil); err != nil {
		return nil, err
	}
	return Cancel{RequestID: id, JSON: o.JSON}, nil
}

func (p *parser) connect(rest []Token) (Command, error) {
	aliasTok, rest, err := positionalAlias("connect", rest)
	if err != nil {
		return nil, err
	}
	return p.connectOpts(aliasTok, rest, false)
}

// connectOpts parses connect/shorthand options. Non-option words and "--" get a hint to use exec.
func (p *parser) connectOpts(aliasTok Token, rest []Token, shorthand bool) (Command, error) {
	if p.t.HasSeparator {
		return nil, usage("-- is only valid with exec; " + p.execHint(aliasTok, p.t.SeparatorAt, p.t.Remote))
	}
	var o parsedOpts
	if err := o.parse("connect", rest, reqOpts, func(tok Token) error {
		return usagef("unexpected argument %s after the server alias; %s", quote(tok.Value),
			p.execHint(aliasTok, tok.Start, p.input[tok.Start:]))
	}); err != nil {
		return nil, err
	}
	return Connect{Alias: aliasTok.Value, Opts: o.Opts, Shorthand: shorthand}, nil
}

func (p *parser) shorthand(first Token, rest []Token) (Command, error) {
	return p.connectOpts(first, rest, true)
}

// execHint suggests the exec form, "use: exec <alias> [options typed before cut] -- <remote>", built from the raw
// input the agent typed. Overlong or unprintable hints fall back to a generic one.
func (p *parser) execHint(aliasTok Token, cut int, remote string) string {
	const generic = "use: exec <server> -- <command>"
	remote = strings.TrimSpace(remote)
	h := "use: exec " + aliasTok.Value
	if aliasTok.End <= cut {
		if opts := strings.TrimSpace(p.input[aliasTok.End:cut]); opts != "" {
			h += " " + opts
		}
	}
	h += " -- " + remote
	if remote == "" || len(h) > 200 || !printable(h) {
		return generic
	}
	return h
}

func (p *parser) exec(rest []Token) (Command, error) {
	aliasTok, rest, err := positionalAlias("exec", rest)
	if err != nil {
		return nil, err
	}
	var o parsedOpts
	if err := o.parse("exec", rest, reqOpts, func(tok Token) error {
		return usagef("unexpected argument %s; the remote command goes after --: %s", quote(tok.Value),
			p.execHint(aliasTok, tok.Start, p.input[tok.Start:]))
	}); err != nil {
		return nil, err
	}
	if !p.t.HasSeparator {
		return nil, usagef("exec needs -- before the remote command; use: exec %s -- <command>", aliasTok.Value)
	}
	if p.t.Remote == "" {
		return nil, usage("exec: the remote command after -- is empty")
	}
	return Exec{Alias: aliasTok.Value, Opts: o.Opts, Remote: p.t.Remote}, nil
}

func (p *parser) sessions(rest []Token) (Command, error) {
	o, err := p.simple("sessions", rest, sessionOpts)
	return Sessions{JSON: o.JSON, All: o.all}, err
}

func (p *parser) api(rest []Token) (Command, error) {
	if err := p.noSeparator("api"); err != nil {
		return nil, err
	}
	const use = "use: api ca | api env [--port <port>] | api requests <invocation>"
	if len(rest) == 0 {
		return nil, usage("missing subcommand; " + use)
	}
	sub, rest := rest[0].Value, rest[1:]
	switch sub {
	case APIRequests:
		if len(rest) != 1 || !invocationRE.MatchString(rest[0].Value) {
			return nil, usage("use: api requests <invocation> (16-64 characters from A-Z a-z 0-9 _ -)")
		}
		return API{Sub: APIRequests, Invocation: rest[0].Value}, nil
	case APICA:
		if len(rest) > 0 {
			return nil, usagef("unexpected argument %s; %s", quote(rest[0].Value), use)
		}
		return API{Sub: APICA}, nil
	case APIEnv:
		port := DefaultAPIProxyPort
		for i := 0; i < len(rest); i++ {
			v := rest[i].Value
			name, val, hasVal := strings.Cut(v, "=")
			if name != "--port" {
				return nil, usagef("unexpected argument %s; %s", quote(v), use)
			}
			if !hasVal {
				if i+1 >= len(rest) {
					return nil, usage("--port needs a value")
				}
				i++
				val = rest[i].Value
			}
			n, err := strconv.Atoi(val)
			if err != nil || n < 1 || n > 65535 {
				return nil, usagef("invalid --port %s: use 1-65535", quote(val))
			}
			port = n
		}
		return API{Sub: APIEnv, Port: port}, nil
	}
	return nil, usagef("unknown subcommand %s; %s", quote(sub), use)
}

func (p *parser) help(rest []Token) (Command, error) {
	if err := p.noSeparator("help"); err != nil {
		return nil, err
	}
	switch len(rest) {
	case 0:
		return Help{}, nil
	case 1:
		topic := rest[0].Value
		if !isHelpTopic(topic) {
			return nil, usagef("unknown help topic %s; topics: %s", quote(topic), strings.Join(HelpTopics(), ", "))
		}
		if topic == "ls" {
			topic = "list"
		}
		return Help{Topic: topic}, nil
	default:
		return nil, usagef("unexpected argument %s; use: help [topic]", quote(rest[1].Value))
	}
}

// simple parses a command that takes only flags.
func (p *parser) simple(cmd string, rest []Token, allowed []string) (parsedOpts, error) {
	var o parsedOpts
	if err := p.noSeparator(cmd); err != nil {
		return o, err
	}
	err := o.parse(cmd, rest, allowed, nil)
	return o, err
}

func positionalAlias(cmd string, rest []Token) (Token, []Token, error) {
	if len(rest) == 0 || (!rest[0].Quoted && strings.HasPrefix(rest[0].Value, "-")) {
		return Token{}, nil, usagef("%s: missing server alias; use: %s <server> [options]", cmd, cmd)
	}
	if a := rest[0].Value; !alias.Valid(a) {
		return Token{}, nil, usagef("%s: invalid server alias %s (%s)", cmd, quote(a), alias.Rule)
	}
	return rest[0], rest[1:], nil
}

func positionalRequestID(cmd string, rest []Token) (string, []Token, error) {
	if len(rest) == 0 || (!rest[0].Quoted && strings.HasPrefix(rest[0].Value, "-")) {
		return "", nil, usagef("%s: missing request ID; use: %s req_<id> [options]", cmd, cmd)
	}
	id := rest[0].Value
	if !ValidRequestID(id) {
		return "", nil, usagef("%s: invalid request ID %s (expected req_ followed by 26 lowercase characters)", cmd, quote(id))
	}
	return id, rest[1:], nil
}

// parsedOpts collects options for every command.
type parsedOpts struct {
	Opts
	server string
	all    bool
	seen   map[string]bool
	// noWaitForbidden rejects --no-wait (status accepts only --wait[=bool]).
	noWaitForbidden bool
}

// parse consumes option tokens. positional handles a non-option word; nil makes it an "unexpected argument" error.
func (o *parsedOpts) parse(cmd string, toks []Token, allowed []string, positional func(Token) error) error {
	o.seen = map[string]bool{}
	for i := 0; i < len(toks); i++ {
		tok := toks[i]
		v := tok.Value
		switch {
		case v == "--":
			return usagef("%s: a quoted -- does not end gateway parsing; write -- unquoted", cmd)
		case strings.HasPrefix(v, "-") && !strings.HasPrefix(v, "--"):
			return usagef("%s: unknown option %s", cmd, quote(v))
		case !strings.HasPrefix(v, "--"):
			if positional != nil {
				return positional(tok)
			}
			return usagef("%s: unexpected argument %s", cmd, quote(v))
		}
		name, val, hasVal := strings.Cut(v[2:], "=")
		display := "--" + name
		slot := name
		if name == "no-wait" {
			slot = oWait
		}
		if !contains(allowed, slot) || (name == "no-wait" && o.noWaitForbidden) {
			return usagef("%s: unknown option %s", cmd, quote(display))
		}
		if o.seen[slot] {
			return usagef("%s: option %s given more than once", cmd, display)
		}
		o.seen[slot] = true
		if valueOpts[name] && !hasVal {
			if i+1 >= len(toks) || (!toks[i+1].Quoted && strings.HasPrefix(toks[i+1].Value, "-")) {
				return usagef("%s: option %s needs a value", cmd, display)
			}
			i++
			val = toks[i].Value
			hasVal = true
		}
		if err := o.set(cmd, name, display, val, hasVal); err != nil {
			return err
		}
	}
	return nil
}

func (o *parsedOpts) set(cmd, name, display, val string, hasVal bool) error {
	switch name {
	case oJSON, oAll, "no-wait":
		if hasVal {
			return usagef("%s: option %s does not take a value", cmd, display)
		}
		switch name {
		case oJSON:
			o.JSON = true
		case oAll:
			o.all = true
		default:
			f := false
			o.Wait = &f
		}
	case oWait:
		b := true
		if hasVal {
			var ok bool
			if b, ok = parseBool(val); !ok {
				return usagef("%s: --wait takes true or false", cmd)
			}
		}
		o.Wait = &b
	case oRole:
		if !alias.Valid(val) {
			return usagef("%s: invalid --role %s (%s)", cmd, quote(val), alias.Rule)
		}
		o.Role = val
	case oServer:
		if !alias.Valid(val) {
			return usagef("%s: invalid --server %s (%s)", cmd, quote(val), alias.Rule)
		}
		o.server = val
	case oReason:
		r := strings.TrimFunc(val, unicode.IsSpace)
		if n := utf8.RuneCountInString(r); n < 1 || n > MaxReasonRunes {
			return usagef("%s: --reason must be 1 to %d characters", cmd, MaxReasonRunes)
		}
		o.Reason = r
	case oDuration:
		d, err := time.ParseDuration(val)
		if err != nil || d <= 0 {
			return usagef("%s: invalid --duration %s (use a Go duration such as 30m or 1h)", cmd, quote(val))
		}
		o.Duration = d
	case oWaitTimeout:
		d, err := time.ParseDuration(val)
		if err != nil || d < 0 || d > MaxWaitTimeout {
			return usagef("%s: invalid --wait-timeout %s (use a Go duration from 0s to 15m)", cmd, quote(val))
		}
		o.WaitTimeout = &d
	case oIdem:
		if !idemRE.MatchString(val) {
			return usagef("%s: invalid --idempotency-key (8-128 characters from A-Z a-z 0-9 . _ -)", cmd)
		}
		o.IdempotencyKey = val
	}
	return nil
}

func parseBool(s string) (bool, bool) {
	switch s {
	case "true", "yes", "1":
		return true, true
	case "false", "no", "0":
		return false, true
	}
	return false, false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// quote renders an agent-supplied word for an error message: truncated and Go-quoted so control, format and bidi
// characters are escaped.
func quote(s string) string {
	const maxBytes = 64
	if len(s) > maxBytes {
		cut := maxBytes
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return strconv.Quote(s)
}

// printable reports whether s has only printable runes (spaces allowed).
func printable(s string) bool {
	for _, r := range s {
		if r != ' ' && !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
