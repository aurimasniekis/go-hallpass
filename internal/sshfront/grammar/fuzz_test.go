package grammar

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/aurimasniekis/go-hallpass/internal/inventory/alias"
)

var fuzzSeeds = []string{
	"", "list", "ls --json", "list --server web1", "roles web1 --json",
	`request web1 --role inspect --reason "check disk" --duration 30m --wait=true --wait-timeout 1m --idempotency-key abcdefgh`,
	"status " + rid + " --wait", "cancel " + rid, "connect web1 --no-wait", "web1", "web1 uptime",
	"exec web1 -- uptime", `exec web1 --  echo "a  b" -- 'c'`, "exec web1 --", `exec web1 '--' x`, `a\ b "c\"d" 'e'`,
	"exec web1 -- échò 日本", "help exec", "version --json", "whoami", "sessions --all", "'unterminated", `"x`, `\`,
	"list\x00", "\xff", "-- x", "web1 \u202e", "exec web1\t--\tls",
}

func FuzzTokenize(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		toks, err := Tokenize(in)
		if err != nil {
			var e *Error
			if !errors.As(err, &e) || e.Exit != ExitUsage {
				t.Fatalf("non-usage error %v", err)
			}
			return
		}
		if !utf8.ValidString(in) || len(in) > MaxInputBytes {
			t.Fatal("accepted invalid input")
		}
		last := -1
		for _, w := range toks.Words {
			if strings.IndexByte(w.Value, 0) >= 0 {
				t.Fatalf("token contains NUL: %q", w.Value)
			}
			if w.Start <= last || w.End <= w.Start || w.End > len(in) {
				t.Fatalf("bad offsets %+v", w)
			}
			last = w.End
			if !w.Quoted && w.Value != in[w.Start:w.End] {
				t.Fatalf("unquoted token %q differs from raw %q", w.Value, in[w.Start:w.End])
			}
			if !w.Quoted && w.Value == "--" {
				t.Fatal("unquoted -- returned as a word")
			}
			if !w.Quoted && (strings.ContainsAny(w.Value, " \t")) {
				t.Fatal("unquoted token contains whitespace")
			}
		}
		if !strings.HasSuffix(in, toks.Remote) {
			t.Fatalf("remote %q is not a suffix", toks.Remote)
		}
		if toks.HasSeparator {
			if in[toks.SeparatorAt:toks.SeparatorAt+2] != "--" || toks.SeparatorAt > MaxGatewayBytes {
				t.Fatalf("bad separator at %d", toks.SeparatorAt)
			}
			if toks.Remote != "" && isSpace(toks.Remote[0]) {
				t.Fatal("remote starts with whitespace")
			}
		} else if toks.Remote != "" || len(in) > MaxGatewayBytes {
			t.Fatal("remote without separator or oversized gateway command")
		}
	})
}

func FuzzParse(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		c, err := Parse(in)
		if err != nil {
			var e *Error
			if !errors.As(err, &e) || e.Exit != ExitUsage || e.Message == "" {
				t.Fatalf("bad error %#v", err)
			}
			line := ErrorJSON(err)
			if bytes.Count(line, []byte("\n")) != 1 || !json.Valid(line) {
				t.Fatalf("bad error line %q", line)
			}
			if !printable(ErrorText(err)[:len(ErrorText(err))-1]) {
				t.Fatalf("unprintable error text %q", ErrorText(err))
			}
			return
		}
		if c == nil {
			t.Fatal("nil command without error")
		}
		switch c := c.(type) {
		case Exec:
			if c.Remote == "" || !strings.HasSuffix(in, c.Remote) {
				t.Fatalf("exec remote %q is empty or not a suffix of %q", c.Remote, in)
			}
			if strings.IndexByte(c.Remote, 0) >= 0 {
				t.Fatal("remote contains NUL")
			}
		case Connect:
			if !alias.Valid(c.Alias) {
				t.Fatalf("connect alias %q invalid", c.Alias)
			}
		case Roles:
			if !alias.Valid(c.Alias) {
				t.Fatalf("roles alias %q invalid", c.Alias)
			}
		case Request:
			if !alias.Valid(c.Alias) || (c.Opts.Role != "" && !alias.Valid(c.Opts.Role)) {
				t.Fatalf("request alias %q / role %q invalid", c.Alias, c.Opts.Role)
			}
			if c.Opts.WaitTimeout != nil && (*c.Opts.WaitTimeout < 0 || *c.Opts.WaitTimeout > MaxWaitTimeout) {
				t.Fatal("wait timeout out of range")
			}
		case Status:
			if !ValidRequestID(c.RequestID) {
				t.Fatal("bad request id")
			}
		case Cancel:
			if !ValidRequestID(c.RequestID) {
				t.Fatal("bad request id")
			}
		}
		if strings.Contains(in, "\x00") {
			t.Fatal("accepted input containing NUL")
		}
	})
}
