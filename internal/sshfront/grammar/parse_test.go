package grammar

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/inventory/alias"
)

const rid = "req_01jabcdefghjkmnpqrstvwxyz0"

func bp(b bool) *bool                   { return &b }
func dp(d time.Duration) *time.Duration { return &d }
func mustParse(t *testing.T, in string) Command {
	t.Helper()
	c, err := Parse(in)
	if err != nil {
		t.Fatalf("Parse(%q): %v", in, err)
	}
	return c
}

func TestParse(t *testing.T) {
	tests := []struct {
		in   string
		want Command
	}{
		{"", List{}},
		{"   ", List{}},
		{"list", List{}},
		{"ls", List{}},
		{"list --json", List{JSON: true}},
		{"ls --server web1 --json", List{JSON: true, Server: "web1"}},
		{"list --server=web1", List{Server: "web1"}},
		{"roles web1", Roles{Alias: "web1"}},
		{"roles web1 --json", Roles{Alias: "web1", JSON: true}},
		{"roles 'web1'", Roles{Alias: "web1"}},
		{"request web1", Request{Alias: "web1"}},
		{
			`request web1 --role inspect --reason "check disk usage" --duration 30m --wait --wait-timeout=5m --idempotency-key abc.DEF_12-3 --json`,
			Request{Alias: "web1", Opts: Opts{
				Role: "inspect", Reason: "check disk usage", Duration: 30 * time.Minute, Wait: bp(true),
				WaitTimeout: dp(5 * time.Minute), IdempotencyKey: "abc.DEF_12-3", JSON: true, // gitleaks:allow (test idempotency key, not a secret)
			}},
		},
		{"request web1 --json --role=inspect --duration=1h30m", Request{Alias: "web1", Opts: Opts{Role: "inspect", Duration: 90 * time.Minute, JSON: true}}},
		{"request web1 --wait=false", Request{Alias: "web1", Opts: Opts{Wait: bp(false)}}},
		{"request web1 --no-wait", Request{Alias: "web1", Opts: Opts{Wait: bp(false)}}},
		{"request web1 --wait=yes", Request{Alias: "web1", Opts: Opts{Wait: bp(true)}}},
		{"request web1 --wait=0", Request{Alias: "web1", Opts: Opts{Wait: bp(false)}}},
		{"request web1 --reason '  spaced  '", Request{Alias: "web1", Opts: Opts{Reason: "spaced"}}},
		{"request web1 --reason '-starts with dash'", Request{Alias: "web1", Opts: Opts{Reason: "-starts with dash"}}},
		{"request web1 --reason=--json", Request{Alias: "web1", Opts: Opts{Reason: "--json"}}},
		{"request web1 --reason " + strings.Repeat("ž", 1000), Request{Alias: "web1", Opts: Opts{Reason: strings.Repeat("ž", 1000)}}},
		{"request web1 --wait-timeout 0s", Request{Alias: "web1", Opts: Opts{WaitTimeout: dp(0)}}},
		{"request web1 --wait-timeout 15m", Request{Alias: "web1", Opts: Opts{WaitTimeout: dp(15 * time.Minute)}}},
		{"request web1 --idempotency-key " + strings.Repeat("k", 128), Request{Alias: "web1", Opts: Opts{IdempotencyKey: strings.Repeat("k", 128)}}},
		{"status " + rid, Status{RequestID: rid}},
		{"status " + rid + " --json --wait", Status{RequestID: rid, JSON: true, Wait: true}},
		{"status " + rid + " --wait=false --wait-timeout 10m", Status{RequestID: rid, WaitTimeout: dp(10 * time.Minute)}},
		{"status " + rid + " --wait-timeout=1m --wait", Status{RequestID: rid, Wait: true, WaitTimeout: dp(time.Minute)}},
		{"cancel " + rid, Cancel{RequestID: rid}},
		{"cancel " + rid + " --json", Cancel{RequestID: rid, JSON: true}},
		{"connect web1", Connect{Alias: "web1"}},
		{"connect web1 --role inspect --reason x --no-wait", Connect{Alias: "web1", Opts: Opts{Role: "inspect", Reason: "x", Wait: bp(false)}}},
		{"web1", Connect{Alias: "web1", Shorthand: true}},
		{"web1 --role=deploy --reason 'ship it' --json", Connect{Alias: "web1", Shorthand: true, Opts: Opts{Role: "deploy", Reason: "ship it", JSON: true}}},
		{"exec web1 -- uptime", Exec{Alias: "web1", Remote: "uptime"}},
		{"exec web1 --role inspect --reason 'disk' --wait-timeout 1m -- df -h /", Exec{Alias: "web1", Opts: Opts{Role: "inspect", Reason: "disk", WaitTimeout: dp(time.Minute)}, Remote: "df -h /"}},
		{`exec web1 --   echo "a  b" 'c' -- $HOME`, Exec{Alias: "web1", Remote: `echo "a  b" 'c' -- $HOME`}},
		{"exec web1 -- échò 日本 ", Exec{Alias: "web1", Remote: "échò 日本 "}},
		{"exec web1 --json -- --json", Exec{Alias: "web1", Opts: Opts{JSON: true}, Remote: "--json"}},
		{"sessions", Sessions{}},
		{"sessions --all --json", Sessions{JSON: true, All: true}},
		{"help", Help{}},
		{"help exec", Help{Topic: "exec"}},
		{"help ls", Help{Topic: "list"}},
		{"help exit-codes", Help{Topic: "exit-codes"}},
		{"version", Version{}},
		{"version --json", Version{JSON: true}},
		{"whoami", WhoAmI{}},
		{"whoami --json", WhoAmI{JSON: true}},
		{"api ca", API{Sub: APICA}},
		{"api requests inv_0123456789abcdef", API{Sub: APIRequests, Invocation: "inv_0123456789abcdef"}},
		{"api env", API{Sub: APIEnv, Port: DefaultAPIProxyPort}},
		{"api env --port 19000", API{Sub: APIEnv, Port: 19000}},
		{"api env --port=19001", API{Sub: APIEnv, Port: 19001}},
		{"'list'", List{}},
	}
	for _, tt := range tests {
		t.Run(tt.in[:min(len(tt.in), 60)], func(t *testing.T) {
			got := mustParse(t, tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse(%q)\n got %#v\nwant %#v", tt.in, got, tt.want)
			}
			if got.CommandName() == "" {
				t.Error("empty CommandName")
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		in, msg string
	}{
		// unknown and repeated options
		{"list --bogus", `unknown option "--bogus"`},
		{"list -j", `unknown option "-j"`},
		{"list --json --json", "more than once"},
		{"list --server web1 --server=web2", "more than once"},
		{"list --server", "needs a value"},
		{"list --server --json", "needs a value"},
		{"list --server Web1", "invalid --server"},
		{"list --json=true", "does not take a value"},
		{"list web1", `unexpected argument "web1"`},
		{"roles", "missing server alias"},
		{"roles --json", "missing server alias"},
		{"roles web1 extra", `unexpected argument "extra"`},
		{"roles web1 --role x", `unknown option "--role"`},
		{"request web1 --wait --no-wait", "more than once"},
		{"request web1 --no-wait --wait=true", "more than once"},
		{"request web1 --no-wait=1", "does not take a value"},
		{"request web1 --wait=maybe", "--wait takes true or false"},
		{"request web1 --wait true", `unexpected argument "true"`},
		{"request web1 --reason", "needs a value"},
		{"request web1 --reason ''", "--reason must be 1 to 1000"},
		{"request web1 --reason '   '", "--reason must be 1 to 1000"},
		{"request web1 --reason " + strings.Repeat("x", 1001), "--reason must be 1 to 1000"},
		{"request web1 --reason --json", "needs a value"},
		{"request web1 --role Inspect", "invalid --role"},
		{"request web1 --role list", "invalid --role"},
		{"request web1 --duration abc", "invalid --duration"},
		{"request web1 --duration 0s", "invalid --duration"},
		{"request web1 --duration=-5m", "invalid --duration"},
		{"request web1 --wait-timeout 16m", "invalid --wait-timeout"},
		{"request web1 --wait-timeout=-1s", "invalid --wait-timeout"},
		{"request web1 --wait-timeout soon", "invalid --wait-timeout"},
		{"request web1 --idempotency-key short", "invalid --idempotency-key"},
		{"request web1 --idempotency-key " + strings.Repeat("k", 129), "invalid --idempotency-key"},
		{"request web1 --idempotency-key 'has space'", "invalid --idempotency-key"},
		{"request web1 --server web2", `unknown option "--server"`},
		{"request web1 --all", `unknown option "--all"`},
		{"request web1 '--'", "quoted -- does not end"},
		{"request web1 --=x", `unknown option "--"`},
		{"status", "missing request ID"},
		{"status req_123", "invalid request ID"},
		{"status REQ_01JABCDEFGHJKMNPQRSTVWXYZ0", "invalid request ID"},
		{"status req_01JABCDEFGHJKMNPQRSTVWXYZ0", "invalid request ID"},
		{"status req_81jabcdefghjkmnpqrstvwxyz0", "invalid request ID"},
		{"status req_01jabcdefghjkmnpqrstvwxyzi", "invalid request ID"},
		{"status grt_01jabcdefghjkmnpqrstvwxyz0", "invalid request ID"},
		{"status " + rid + " --no-wait", `unknown option "--no-wait"`},
		{"status " + rid + " --role x", `unknown option "--role"`},
		{"status " + rid + " " + rid, "unexpected argument"},
		{"cancel", "missing request ID"},
		{"cancel " + rid + " --wait", `unknown option "--wait"`},
		{"connect", "missing server alias"},
		{"connect list", "invalid server alias"},
		{"connect web1 uptime", "use: exec web1 -- uptime"},
		{"connect web1 -- uptime", "-- is only valid with exec; use: exec web1 -- uptime"},
		{"exec", "missing server alias"},
		{"exec web1", "exec needs --"},
		{"exec web1 uptime", "use: exec web1 -- uptime"},
		{"exec web1 --", "remote command after -- is empty"},
		{"exec web1 --   ", "remote command after -- is empty"},
		{"exec web1 --bogus -- x", `unknown option "--bogus"`},
		{"exec WEB1 -- x", "invalid server alias"},
		{"sessions web1", "unexpected argument"},
		{"sessions --all=1", "does not take a value"},
		{"sessions -- x", "-- is only valid with exec"},
		{"help nope", "unknown help topic"},
		{"help exec list", "unexpected argument"},
		{"help -- x", "-- is only valid with exec"},
		{"version web1", "unexpected argument"},
		{"version --all", `unknown option "--all"`},
		{"whoami --json --json", "more than once"},
		{"api", "missing subcommand"},
		{"api token", "unknown subcommand"},
		{"api requests short", "api requests <invocation>"},
		{"api ca --json", "unexpected argument"},
		{"api env --port", "needs a value"},
		{"api env --port 0", "invalid --port"},
		{"api env --port 70000", "invalid --port"},
		{"api env -- x", "only valid with exec"},
		{"list -- x", "-- is only valid with exec"},
		{"-- uptime", "missing command before --"},
		{"--json", "use: list"},
		{"--server=web1", "use: list"},
		{"--help", `expected a command, got option "--help"`},
		{"-h", `expected a command, got option "-h"`},
		{"Web1", "unknown command or invalid server alias"},
		{"web_1", "unknown command or invalid server alias"},
		{"web-", "unknown command or invalid server alias"},
		{"shell", `"shell" is reserved`},
		{"admin", `"admin" is reserved`},
		{"hallpass", `"hallpass" is reserved`},
		// shorthand alias followed by words
		{"web1 uptime", `unexpected argument "uptime" after the server alias; use: exec web1 -- uptime`},
		{"web1 ls -l /tmp", "use: exec web1 -- ls -l /tmp"},
		{"web1 --role inspect uptime", "use: exec web1 --role inspect -- uptime"},
		{"web1 -- uptime", "-- is only valid with exec; use: exec web1 -- uptime"},
		{"web1 --reason 'a b' cat 'x y'", "use: exec web1 --reason 'a b' -- cat 'x y'"},
		{"web1 -t", `unknown option "-t"`},
		{"web1 --role", "needs a value"},
		{"web1 \u202e", "use: exec <server> -- <command>"}, // unprintable hint falls back
		{"web1 " + strings.Repeat("x", 300), "use: exec <server> -- <command>"},
	}
	for _, tt := range tests {
		t.Run(tt.in[:min(len(tt.in), 60)], func(t *testing.T) {
			c, err := Parse(tt.in)
			if err == nil {
				t.Fatalf("Parse(%q) = %#v, want error", tt.in, c)
			}
			var e *Error
			if !errors.As(err, &e) || e.Exit != ExitUsage || e.Code() != "usage" {
				t.Fatalf("err = %#v, want usage error", err)
			}
			if !strings.Contains(e.Message, tt.msg) {
				t.Errorf("message %q does not contain %q", e.Message, tt.msg)
			}
			if !printable(e.Message) {
				t.Errorf("message has unprintable characters: %q", e.Message)
			}
		})
	}
}

// Reserved words are never accepted as aliases anywhere an alias appears.
func TestReservedWordsRejectedAsAliases(t *testing.T) {
	if len(alias.ReservedWords) == 0 {
		t.Fatal("no reserved words")
	}
	for _, w := range alias.ReservedWords {
		for _, in := range []string{
			"roles " + w, "request " + w, "connect " + w, "exec " + w + " -- x",
			"list --server " + w, "request web1 --role " + w, "connect web1 --role=" + w,
		} {
			if _, err := Parse(in); ExitCodeOf(err) != ExitUsage {
				t.Errorf("Parse(%q) err = %v, want usage error", in, err)
			}
		}
		// As a bare first word a reserved word is either a command or rejected, never a shorthand connect.
		if c, err := Parse(w); err == nil {
			if _, ok := c.(Connect); ok {
				t.Errorf("reserved word %q parsed as shorthand connect", w)
			}
		}
	}
	for _, in := range []string{"connect -x", "roles --x"} {
		if _, err := Parse(in); ExitCodeOf(err) != ExitUsage {
			t.Errorf("Parse(%q) accepted a dash word as alias", in)
		}
	}
}

// Error messages never contain more of the input than the agent typed and never the destination command, except in
// the exec hint for words the agent placed before "--".
func TestErrorsDoNotLeakBeyondInput(t *testing.T) {
	secret := "s3cr3t-remote-payload"
	for _, in := range []string{
		"list -- " + secret,
		"roles web1 -- " + secret,
		"exec web1 --bogus -- " + secret,
		"request web1 --reason '' -- " + secret,
	} {
		_, err := Parse(in)
		if err == nil {
			t.Fatalf("Parse(%q) succeeded", in)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error for %q echoes the remote command: %q", in, err.Error())
		}
	}
	// The reason value is never echoed.
	_, err := Parse("request web1 --reason " + strings.Repeat("Q", 1001))
	if err == nil || strings.Contains(err.Error(), "QQ") {
		t.Errorf("reason echoed: %v", err)
	}
	// Echoed words are bounded.
	_, err = Parse("connect " + strings.Repeat("A", 5000))
	if err == nil || len(err.Error()) > 400 {
		t.Errorf("unbounded error: %d bytes", len(err.Error()))
	}
}

func TestDefaults(t *testing.T) {
	r := mustParse(t, "request web1").(Request)
	if r.EffectiveWait() || r.Opts.Wait != nil {
		t.Error("request must default to no wait, with Wait unset")
	}
	if r.Opts.EffectiveWaitTimeout() != DefaultWaitTimeout {
		t.Error("default wait timeout")
	}
	c := mustParse(t, "connect web1").(Connect)
	if !c.EffectiveWait() || c.Opts.Wait != nil {
		t.Error("connect must default to wait, with Wait unset")
	}
	if !mustParse(t, "web1").(Connect).EffectiveWait() {
		t.Error("shorthand must default to wait")
	}
	if mustParse(t, "connect web1 --no-wait").(Connect).EffectiveWait() {
		t.Error("--no-wait ignored")
	}
	e := mustParse(t, "exec web1 -- x").(Exec)
	if !e.EffectiveWait() {
		t.Error("exec must default to wait")
	}
	if mustParse(t, "exec web1 --wait=false -- x").(Exec).EffectiveWait() {
		t.Error("--wait=false ignored")
	}
	if !mustParse(t, "request web1 --wait").(Request).EffectiveWait() {
		t.Error("--wait ignored")
	}
	if got := mustParse(t, "request web1 --wait-timeout 0s").(Request).Opts.EffectiveWaitTimeout(); got != 0 {
		t.Errorf("explicit 0s wait timeout = %v", got)
	}
	s := mustParse(t, "status "+rid).(Status)
	if s.Wait || s.EffectiveWaitTimeout() != DefaultWaitTimeout {
		t.Error("status defaults")
	}
	if mustParse(t, "status "+rid+" --wait-timeout 3s").(Status).EffectiveWaitTimeout() != 3*time.Second {
		t.Error("status wait timeout")
	}
}

func TestJSONOutput(t *testing.T) {
	for in, want := range map[string]bool{
		"list --json": true, "list": false, "roles web1 --json": true, "request web1 --json": true,
		"status " + rid + " --json": true, "cancel " + rid + " --json": true, "connect web1 --json": true,
		"web1 --json": true, "exec web1 --json -- x": true, "exec web1 -- --json": false, "sessions --json": true,
		"version --json": true, "whoami --json": true, "help": false,
	} {
		if got := JSONOutput(mustParse(t, in)); got != want {
			t.Errorf("JSONOutput(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestValidRequestID(t *testing.T) {
	if !ValidRequestID(rid) {
		t.Error("valid id rejected")
	}
	for _, s := range []string{"", "req_", rid + "0", "REQ" + rid[3:], "req-01jabcdefghjkmnpqrstvwxyz0"} {
		if ValidRequestID(s) {
			t.Errorf("ValidRequestID(%q) = true", s)
		}
	}
}

func TestHelpTopicsParse(t *testing.T) {
	for _, topic := range HelpTopics() {
		h := mustParse(t, "help "+topic).(Help)
		if h.Topic != topic {
			t.Errorf("help %s → %q", topic, h.Topic)
		}
		txt, err := HelpText(topic)
		if err != nil || txt == "" {
			t.Errorf("HelpText(%q) = %q, %v", topic, txt, err)
		}
	}
	if _, err := HelpText("nope"); ExitCodeOf(err) != ExitUsage {
		t.Error("unknown topic accepted")
	}
	txt, err := HelpText("")
	if err != nil || !strings.Contains(txt, "exec <server> [options] -- <command>") || strings.Contains(txt, "%TOPICS%") {
		t.Errorf("overview: %v\n%s", err, txt)
	}
	txt, _ = HelpText("ls")
	if !strings.HasPrefix(txt, "list") {
		t.Error("help ls")
	}
	txt, _ = HelpText("exit-codes")
	for _, c := range ExitCodes() {
		if !strings.Contains(txt, c.Name()) {
			t.Errorf("exit-codes help misses %s", c.Name())
		}
	}
}
