package grammar

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func values(ts []Token) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Value
	}
	return out
}

func TestTokenize(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		words  []string
		sep    bool
		remote string
	}{
		{"empty", "", []string{}, false, ""},
		{"spaces only", "  \t ", []string{}, false, ""},
		{"simple", "list --json", []string{"list", "--json"}, false, ""},
		{"tabs and runs", "\tlist \t  --json\t", []string{"list", "--json"}, false, ""},
		{"single quotes literal", `a 'b c' 'x\y' '"'`, []string{"a", "b c", `x\y`, `"`}, false, ""},
		{"double quotes escapes", `"a \"b\" \\ \n \$"`, []string{`a "b" \ \n \$`}, false, ""},
		{"backslash outside", `a\ b \'c \"d \\e`, []string{"a b", "'c", `"d`, `\e`}, false, ""},
		{"backslash multibyte", `\é`, []string{"é"}, false, ""},
		{"adjacent quoting", `ab'c d'"e f"g`, []string{"abc de fg"}, false, ""},
		{"empty quoted", `'' ""`, []string{"", ""}, false, ""},
		{"no expansion", `$HOME ~ * {a,b} $(id) ` + "`id`", []string{"$HOME", "~", "*", "{a,b}", "$(id)", "`id`"}, false, ""},
		{"unicode", "connect wéb --reason 'žr 日本'", []string{"connect", "wéb", "--reason", "žr 日本"}, false, ""},
		{"separator", "exec web1 -- uptime", []string{"exec", "web1"}, true, "uptime"},
		{"separator raw quotes", `exec web1 -- echo "a  b" 'c'`, []string{"exec", "web1"}, true, `echo "a  b" 'c'`},
		{"separator multiple spaces", "exec web1 --  \t  ls   -l  ", []string{"exec", "web1"}, true, "ls   -l  "},
		{"second separator kept", "exec web1 -- a -- b", []string{"exec", "web1"}, true, "a -- b"},
		{"separator at end", "exec web1 --", []string{"exec", "web1"}, true, ""},
		{"separator at end with space", "exec web1 --   ", []string{"exec", "web1"}, true, ""},
		{"separator first", "-- x", []string{}, true, "x"},
		{"separator unicode remote", "exec web1 -- echo 'žaliūkas' \"日本\"", []string{"exec", "web1"}, true, "echo 'žaliūkas' \"日本\""},
		{"quoted separator is a word", `exec web1 '--' x`, []string{"exec", "web1", "--", "x"}, false, ""},
		{"double quoted separator", `exec web1 "--" x`, []string{"exec", "web1", "--", "x"}, false, ""},
		{"escaped separator", `exec web1 \-- x`, []string{"exec", "web1", "--", "x"}, false, ""},
		{"separator glued", `exec web1 --x -- y`, []string{"exec", "web1", "--x"}, true, "y"},
		{"separator glued quote", `exec web1 --'' y`, []string{"exec", "web1", "--", "y"}, false, ""},
		{"remote keeps backslashes", `exec h -- printf '%s\n' "$HOME" \; x`, []string{"exec", "h"}, true, `printf '%s\n' "$HOME" \; x`},
		{"remote has unbalanced quote", `exec h -- echo "oops`, []string{"exec", "h"}, true, `echo "oops`},
		{"tab in remote", "exec h --\techo\ta", []string{"exec", "h"}, true, "echo\ta"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Tokenize(tt.in)
			if err != nil {
				t.Fatalf("Tokenize(%q): %v", tt.in, err)
			}
			if !slices.Equal(values(got.Words), tt.words) {
				t.Errorf("words = %q, want %q", values(got.Words), tt.words)
			}
			if got.HasSeparator != tt.sep || got.Remote != tt.remote {
				t.Errorf("sep=%v remote=%q, want sep=%v remote=%q", got.HasSeparator, got.Remote, tt.sep, tt.remote)
			}
			if !strings.HasSuffix(tt.in, got.Remote) {
				t.Errorf("remote %q is not a suffix of the input", got.Remote)
			}
			if got.HasSeparator && tt.in[got.SeparatorAt:got.SeparatorAt+2] != "--" {
				t.Errorf("SeparatorAt=%d does not point at --", got.SeparatorAt)
			}
			if !got.HasSeparator && got.SeparatorAt != -1 {
				t.Errorf("SeparatorAt = %d without separator", got.SeparatorAt)
			}
		})
	}
}

func TestTokenizeOffsets(t *testing.T) {
	in := `  ab 'c d'  e\ f`
	got, err := Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	raw := []string{"ab", "'c d'", `e\ f`}
	for i, w := range got.Words {
		if in[w.Start:w.End] != raw[i] {
			t.Errorf("word %d raw = %q, want %q", i, in[w.Start:w.End], raw[i])
		}
	}
	if got.Words[0].Quoted || !got.Words[1].Quoted || !got.Words[2].Quoted {
		t.Errorf("quoted flags wrong: %+v", got.Words)
	}
}

func TestTokenizeErrors(t *testing.T) {
	tests := []struct {
		name, in, msg string
	}{
		{"unterminated single", "list 'abc", "unterminated single quote"},
		{"unterminated double", `list "abc`, "unterminated double quote"},
		{"unterminated double escaped quote", `list "abc\"`, "unterminated double quote"},
		{"trailing backslash", `list \`, "trailing backslash"},
		{"nul", "list\x00", "control character"},
		{"newline", "list\n", "control character"},
		{"cr", "list\r--json", "control character"},
		{"escape", "list \x1b[31m", "control character"},
		{"nul in remote", "exec h -- a\x00b", "control character"},
		{"newline in remote", "exec h -- a\nb", "control character"},
		{"invalid utf8", "list \xff", "UTF-8"},
		{"invalid utf8 remote", "exec h -- \xc3", "UTF-8"},
		{"too long", strings.Repeat("a", MaxInputBytes+1), "64 KiB"},
		{"gateway too long", strings.Repeat("a ", MaxGatewayBytes/2+1), "16 KiB"},
		{"gateway too long one word", strings.Repeat("a", MaxGatewayBytes+1), "16 KiB"},
		{"gateway too long before separator", strings.Repeat("a", MaxGatewayBytes+1) + " -- x", "16 KiB"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Tokenize(tt.in)
			var e *Error
			if !errors.As(err, &e) || e.Exit != ExitUsage {
				t.Fatalf("err = %v, want usage error", err)
			}
			if !strings.Contains(e.Message, tt.msg) {
				t.Errorf("message %q does not contain %q", e.Message, tt.msg)
			}
		})
	}
}

func TestTokenizeLimitsBoundary(t *testing.T) {
	// Exactly 16 KiB of gateway command and 64 KiB in total are accepted.
	gw := "exec h " + strings.Repeat("a", MaxGatewayBytes-len("exec h ")-1) + " "
	if len(gw) != MaxGatewayBytes {
		t.Fatalf("setup: len %d", len(gw))
	}
	in := gw + "-- " + strings.Repeat("b", MaxInputBytes-len(gw)-3)
	if len(in) != MaxInputBytes {
		t.Fatalf("setup: len %d", len(in))
	}
	got, err := Tokenize(in)
	if err != nil {
		t.Fatalf("boundary input rejected: %v", err)
	}
	if !got.HasSeparator || len(got.Remote) != MaxInputBytes-MaxGatewayBytes-3 {
		t.Errorf("remote len %d", len(got.Remote))
	}
	if _, err := Tokenize(strings.Repeat("a", MaxGatewayBytes)); err != nil {
		t.Errorf("16 KiB word rejected: %v", err)
	}
}
