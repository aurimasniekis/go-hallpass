package gitproto

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestParseCommand(t *testing.T) {
	for _, c := range []struct {
		in      string
		service string
		path    string
		ok, bad bool
	}{
		{in: "git-upload-pack 'github/acme/api.git'", service: UploadPack, path: "github/acme/api.git", ok: true},
		{in: "git-receive-pack '/github/acme/api.git'", service: ReceivePack, path: "/github/acme/api.git", ok: true},
		{in: "git upload-archive 'github/acme/api'", service: UploadArchive, path: "github/acme/api", ok: true},
		{in: "git-upload-pack github/acme/api.git", service: UploadPack, path: "github/acme/api.git", ok: true},
		{in: `git-upload-pack 'it'\''s/x'`, service: UploadPack, path: "it's/x", ok: true},
		{in: "git-upload-pack", ok: true, bad: true},
		{in: "git-upload-pack ''", ok: true, bad: true},
		{in: "git-upload-pack 'unterminated", ok: true, bad: true},
		{in: "git-upload-pack 'a' 'b'", ok: true, bad: true},
		{in: "git-upload-pack a b", ok: true, bad: true},
		{in: "git-upload-pack 'a\nb'", ok: true, bad: true},
		{in: "list", ok: false},
		{in: "exec web1 -- git-upload-pack 'x'", ok: false},
		{in: "git-upload-packs 'x'", ok: false},
		{in: "git status", ok: false},
	} {
		got, ok, err := ParseCommand(c.in)
		if ok != c.ok || (err != nil) != c.bad {
			t.Errorf("%q: ok=%v err=%v", c.in, ok, err)
			continue
		}
		if c.ok && !c.bad && (got.Service != c.service || got.Path != c.path) {
			t.Errorf("%q: got %+v", c.in, got)
		}
	}
	if !(Command{Service: ReceivePack}).Write() || (Command{Service: UploadPack}).Write() {
		t.Error("Write classification")
	}
	if Quote("it's") != `'it'\''s'` {
		t.Errorf("Quote: %s", Quote("it's"))
	}
}

func TestSplitPath(t *testing.T) {
	for _, c := range []struct {
		in, remote, repo, fwd string
		bad                   bool
	}{
		{in: "github/acme/api.git", remote: "github", repo: "acme/api", fwd: "acme/api.git"},
		{in: "/github/acme/api.git", remote: "github", repo: "acme/api", fwd: "/acme/api.git"},
		{in: "gitlab/group/sub/Project", remote: "gitlab", repo: "group/sub/project", fwd: "group/sub/Project"},
		{in: "github/acme/api.git/", remote: "github", repo: "acme/api", fwd: "acme/api.git"},
		{in: "github", bad: true},
		{in: "github/", bad: true},
		{in: "/acme", bad: true},
		{in: "github/../etc/passwd", bad: true},
		{in: "github/acme/./api", bad: true},
		{in: "github//api", bad: true},
		{in: "github/acme/-upload-pack", bad: true},
		{in: "github/acme/api name", bad: true},
		{in: "github/acme/.git", bad: true},
		{in: "~/github/acme/api", bad: true},
	} {
		got, err := SplitPath(c.in)
		if (err != nil) != c.bad {
			t.Errorf("%q: err=%v", c.in, err)
			continue
		}
		if !c.bad && (got.Remote != c.remote || got.Repo != c.repo || got.Forward != c.fwd) {
			t.Errorf("%q: got %+v", c.in, got)
		}
	}
}

func TestPatterns(t *testing.T) {
	for _, c := range []struct {
		pattern  string
		fold     bool
		match    []string
		nonMatch []string
	}{
		{pattern: "acme/{api,web}", fold: true, match: []string{"acme/api", "ACME/Web"}, nonMatch: []string{"acme/apis", "acme/api/x", "other/api"}},
		{pattern: "acme/*", fold: true, match: []string{"acme/api", "acme/x-y.z"}, nonMatch: []string{"acme", "acme/a/b"}},
		{pattern: "team-*/infra", match: []string{"team-a/infra", "team-/infra"}, nonMatch: []string{"team-a/b/infra"}},
		{pattern: "acme/**", match: []string{"acme/a", "acme/a/b/c"}, nonMatch: []string{"acme", "acmex/a"}},
		{pattern: "**/infra", match: []string{"infra", "a/infra", "a/b/infra"}, nonMatch: []string{"a/infra2"}},
		{pattern: "agent/**", match: []string{"agent/x", "agent/x/y"}, nonMatch: []string{"agent", "main"}},
		{pattern: "v?.*", match: []string{"v1.2", "v2.0-rc.1"}, nonMatch: []string{"v10.1", "v1"}},
		{pattern: "{a,b{1,2}}/x", match: []string{"a/x", "b1/x", "b2/x"}, nonMatch: []string{"b/x", "b3/x"}},
		{pattern: "**", match: []string{"anything/at/all"}},
		{pattern: "a.b+c(d)", match: []string{"a.b+c(d)"}, nonMatch: []string{"aXb+c(d)"}},
		{pattern: "Main", match: []string{"Main"}, nonMatch: []string{"main"}},
	} {
		p, err := CompilePattern(c.pattern, c.fold)
		if err != nil {
			t.Fatalf("%q: %v", c.pattern, err)
		}
		for _, m := range c.match {
			if !p.Match(m) {
				t.Errorf("%q should match %q", c.pattern, m)
			}
		}
		for _, m := range c.nonMatch {
			if p.Match(m) {
				t.Errorf("%q should not match %q", c.pattern, m)
			}
		}
	}
	for _, bad := range []string{"", "{a}", "{a,b", "a,b", "a}b", "x[ab]", `a\b`, "a/***", "{a,{b,{c,{d,{e,{f,g}}}}}}", strings.Repeat("x", 300),
		"{a,b}{c,d}{e,f}{g,h}{i,j}{k,l}{m,n}"} {
		if _, err := CompilePattern(bad, false); !errors.Is(err, ErrInvalidPattern) {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
	set, err := CompilePatterns([]string{"a/*", "b"}, false)
	if err != nil || !set.Match("b") || !set.Match("a/x") || set.Match("c") || (PatternSet{}).Match("x") {
		t.Fatalf("pattern set: %v", err)
	}
}

const (
	zero = "0000000000000000000000000000000000000000"
	oidA = "1111111111111111111111111111111111111111"
	oidB = "2222222222222222222222222222222222222222"
)

func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

func TestReadPushCommands(t *testing.T) {
	wire := pkt("shallow "+oidA+"\n") + pkt(oidA+" "+oidB+" refs/heads/agent/x\x00report-status side-band-64k\n") +
		pkt(zero+" "+oidB+" refs/tags/v1.0-rc.1\n") + "0000" + "PACK...binary"
	r := strings.NewReader(wire)
	pc, err := ReadPushCommands(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(pc.Updates) != 2 || pc.Updates[0].Ref != "refs/heads/agent/x" || !pc.Updates[1].Create() || pc.Updates[0].Create() {
		t.Fatalf("%+v", pc.Updates)
	}
	if strings.Join(pc.Capabilities, ",") != "report-status,side-band-64k" {
		t.Fatalf("caps %v", pc.Capabilities)
	}
	if !strings.HasSuffix(string(pc.Raw), "0000") || len(pc.Raw) != len(wire)-len("PACK...binary") {
		t.Fatal("raw bytes do not end at the flush packet")
	}
	if rest, _ := io.ReadAll(r); string(rest) != "PACK...binary" {
		t.Fatalf("pack data consumed: %q", rest)
	}

	if pc, err := ReadPushCommands(strings.NewReader("0000")); err != nil || len(pc.Updates) != 0 {
		t.Fatalf("empty push: %v", err)
	}
	if _, err := ReadPushCommands(strings.NewReader("")); !errors.Is(err, io.EOF) {
		t.Fatalf("nothing sent: %v", err)
	}
	for name, bad := range map[string]string{
		"truncated header":   "00",
		"truncated payload":  "0010abc",
		"bad length":         "zzzz",
		"length below four":  "0003",
		"too long":           "fff0" + strings.Repeat("x", 10),
		"no flush":           pkt(oidA + " " + oidB + " refs/heads/x\n"),
		"bad id":             pkt("xyz "+oidB+" refs/heads/x\n") + "0000",
		"mixed id lengths":   pkt(oidA+" "+strings.Repeat("2", 64)+" refs/heads/x\n") + "0000",
		"caps on later line": pkt(oidA+" "+oidB+" refs/heads/x\x00a\n") + pkt(oidA+" "+oidB+" refs/heads/y\x00b\n") + "0000",
		"late shallow":       pkt(oidA+" "+oidB+" refs/heads/x\n") + pkt("shallow "+oidA+"\n") + "0000",
		"push cert":          pkt("push-cert\x00report-status\n") + "0000",
	} {
		if _, err := ReadPushCommands(strings.NewReader(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ReadPushCommands(strings.NewReader(pkt("push-cert\x00x\n"))); !errors.Is(err, ErrSignedPush) {
		t.Errorf("push cert: %v", err)
	}
	var many bytes.Buffer
	for range maxUpdates + 1 {
		many.WriteString(pkt(oidA + " " + oidB + " refs/heads/x\n"))
	}
	many.WriteString("0000")
	if _, err := ReadPushCommands(&many); !errors.Is(err, ErrProtocol) {
		t.Errorf("too many updates: %v", err)
	}
}

func TestRefPolicy(t *testing.T) {
	p, err := RefRules{Branches: []string{"agent/**", "fix-*"}, ProtectedBranches: []string{"agent/locked"}, Tags: []string{"v*-rc.*"}, AllowDelete: true}.Compile()
	if err != nil {
		t.Fatal(err)
	}
	ok := []RefUpdate{
		{Old: zero, New: oidB, Ref: "refs/heads/agent/x"},
		{Old: oidA, New: oidB, Ref: "refs/heads/agent/a/b"},
		{Old: oidA, New: zero, Ref: "refs/heads/fix-1"},
		{Old: zero, New: oidB, Ref: "refs/tags/v1.2-rc.1"},
	}
	for _, u := range ok {
		if err := p.Check(u); err != nil {
			t.Errorf("%s refused: %v", u.Ref, err)
		}
	}
	denied := map[string]RefUpdate{
		"protected branch":                    {Old: oidA, New: oidB, Ref: "refs/heads/agent/locked"},
		"branch not allowed":                  {Old: oidA, New: oidB, Ref: "refs/heads/main"},
		"tags can only be created":            {Old: oidA, New: oidB, Ref: "refs/tags/v1.2-rc.1"},
		"tag not allowed":                     {Old: zero, New: oidB, Ref: "refs/tags/v1.2"},
		"only branches and tags":              {Old: zero, New: oidB, Ref: "refs/notes/commits"},
		"invalid ref name":                    {Old: zero, New: oidB, Ref: "refs/heads/agent/../main"},
		"invalid ref name (lock)":             {Old: zero, New: oidB, Ref: "refs/heads/agent/x.lock"},
		"invalid ref name (control char)":     {Old: zero, New: oidB, Ref: "refs/heads/agent/\x01"},
		"invalid ref name (hidden component)": {Old: zero, New: oidB, Ref: "refs/heads/agent/.x"},
	}
	for name, u := range denied {
		var d *RefDenied
		if err := p.Check(u); !errors.As(err, &d) || d.Ref != u.Ref {
			t.Errorf("%s: %v", name, err)
		}
	}
	strict, _ := RefRules{Branches: []string{"agent/**"}}.Compile()
	if err := strict.Check(RefUpdate{Old: oidA, New: zero, Ref: "refs/heads/agent/x"}); err == nil || !strings.Contains(err.Error(), "deleting") {
		t.Errorf("delete without AllowDelete: %v", err)
	}
	if got := p.CheckAll([]RefUpdate{ok[0], denied["branch not allowed"], denied["protected branch"]}); len(got) != 2 {
		t.Errorf("CheckAll = %v", got)
	}
	none, _ := RefRules{}.Compile()
	if none.Check(ok[0]) == nil || none.Check(ok[3]) == nil {
		t.Error("empty rules must refuse every ref")
	}
	if _, err := (RefRules{Branches: []string{"{a"}}).Compile(); err == nil {
		t.Error("bad branch pattern accepted")
	}
}

func FuzzReadPushCommands(f *testing.F) {
	f.Add([]byte(pkt(oidA+" "+oidB+" refs/heads/x\x00report-status\n") + "0000PACK"))
	f.Add([]byte("0000"))
	f.Add([]byte(pkt("shallow "+oidA+"\n") + "0000"))
	f.Fuzz(func(t *testing.T, b []byte) {
		pc, err := ReadPushCommands(bytes.NewReader(b))
		if err != nil {
			return
		}
		if !bytes.HasPrefix(b, pc.Raw) || !bytes.HasSuffix(pc.Raw, []byte("0000")) {
			t.Fatalf("raw is not the consumed prefix ending in a flush")
		}
		for _, u := range pc.Updates {
			if !validObjectID(u.Old) || !validObjectID(u.New) {
				t.Fatalf("invalid object id accepted: %+v", u)
			}
		}
	})
}

func FuzzParseCommand(f *testing.F) {
	for _, s := range []string{"git-upload-pack 'a/b.git'", "git receive-pack '/x/y'", "list", `git-upload-pack 'a'\''b'`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c, ok, err := ParseCommand(s)
		if !ok || err != nil {
			return
		}
		if c.Path == "" || len(c.Path) > MaxPathLen || strings.ContainsAny(c.Path, "\n\r\x00") {
			t.Fatalf("bad path accepted: %q", c.Path)
		}
		if tgt, err := SplitPath(c.Path); err == nil {
			if strings.Contains(tgt.Forward, "..") || strings.ContainsAny(tgt.Forward, "'\" \\") {
				t.Fatalf("unsafe forward path: %q", tgt.Forward)
			}
		}
	})
}

func FuzzPattern(f *testing.F) {
	f.Add("acme/{api,web}", "acme/api")
	f.Add("**/x", "a/b/x")
	f.Fuzz(func(t *testing.T, pattern, name string) {
		p, err := CompilePattern(pattern, true)
		if err != nil {
			return
		}
		_ = p.Match(name)
	})
}
