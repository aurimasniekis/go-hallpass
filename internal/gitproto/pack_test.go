package gitproto

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// gitRepo is a throwaway repository driven with the git CLI.
type gitRepo struct {
	t   *testing.T
	dir string
}

func newGitRepo(t *testing.T) *gitRepo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	r := &gitRepo{t: t, dir: t.TempDir()}
	r.run(nil, "init", "-q", "-b", "main")
	return r
}

func (r *gitRepo) run(stdin []byte, args ...string) string {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = r.dir
	cmd.Env = append(cmd.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test", "GIT_COMMITTER_NAME=t",
		"GIT_COMMITTER_EMAIL=t@example.test", "GIT_CONFIG_NOSYSTEM=1", "HOME="+r.dir)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, errb.String())
	}
	return out.String()
}

func (r *gitRepo) commit(msg string) string {
	r.run(nil, "commit", "-q", "--allow-empty", "-m", msg)
	return strings.TrimSpace(r.run(nil, "rev-parse", "HEAD"))
}

// pack builds the pack git would push for revs (e.g. "new", "^old").
func (r *gitRepo) pack(thin bool, revs ...string) []byte {
	args := []string{"pack-objects", "--revs", "--stdout", "-q"}
	if thin {
		args = append(args, "--thin")
	}
	return []byte(r.run([]byte(strings.Join(revs, "\n")+"\n"), args...))
}

func scan(t *testing.T, pack []byte) *CommitGraph {
	t.Helper()
	var fwd bytes.Buffer
	g, trailer, err := ScanPack(bufio.NewReader(bytes.NewReader(pack)), &fwd, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(fwd.Bytes(), trailer...), pack) {
		t.Fatal("forwarded bytes plus withheld checksum differ from the pack")
	}
	if len(trailer) != 20 {
		t.Fatalf("trailer length %d", len(trailer))
	}
	return g
}

func TestScanPackAncestry(t *testing.T) {
	r := newGitRepo(t)
	a := r.commit("a")
	b := r.commit("b")
	c := r.commit("c")
	for _, thin := range []bool{false, true} {
		g := scan(t, r.pack(thin, c, "^"+a))
		if got := g.AncestryOf(a, c); got != FastForward {
			t.Errorf("thin=%v: a -> c = %s", thin, got)
		}
		if got := g.AncestryOf(b, c); got != FastForward {
			t.Errorf("thin=%v: b -> c = %s", thin, got)
		}
	}
	// Rewrite history: d replaces b and c on top of a, so c is not an ancestor of d.
	r.run(nil, "reset", "-q", "--hard", a)
	d := r.commit("d (rewritten)")
	g := scan(t, r.pack(true, d, "^"+c))
	if got := g.AncestryOf(c, d); got == FastForward {
		t.Errorf("rewritten history reported as fast-forward")
	}
	// Pushing a commit the host already has (no pack objects for it) cannot be proven.
	if got := scan(t, r.pack(false, a, "^"+a)).AncestryOf(c, a); got != Unknown {
		t.Errorf("existing commit = %s", got)
	}
	// A brand-new root unrelated to the old tip: the whole history is in the pack.
	r.run(nil, "checkout", "-q", "--orphan", "other")
	e := r.commit("e (new root)")
	if got := scan(t, r.pack(false, e)).AncestryOf(c, e); got != NotFastForward {
		t.Errorf("new root = %s", got)
	}
	if got := scan(t, r.pack(false, e)).AncestryOf(e, e); got != FastForward {
		t.Errorf("same id = %s", got)
	}
}

// pushCapture runs a real "git push" from r to the bare repository host and returns what git sent to
// git-receive-pack: the command list, then the pack.
func (r *gitRepo) pushCapture(host, refspec string, flags ...string) []byte {
	r.t.Helper()
	dir := r.t.TempDir()
	capture, wrapper := filepath.Join(dir, "push"), filepath.Join(dir, "receive-pack")
	script := "#!/bin/sh\ntee '" + capture + "' | git-receive-pack \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o700); err != nil { //nolint:gosec // test helper script
		r.t.Fatal(err)
	}
	r.run(nil, append(append([]string{"push", "-q", "--receive-pack=" + wrapper}, flags...), host, refspec)...)
	b, err := os.ReadFile(capture) //nolint:gosec // test file
	if err != nil {
		r.t.Fatal(err)
	}
	return b
}

// scanPush reads a captured push like the gateway does and returns its updates and the pack's commit graph.
func scanPush(t *testing.T, stream []byte) ([]RefUpdate, *CommitGraph) {
	t.Helper()
	br := bufio.NewReader(bytes.NewReader(stream))
	pc, err := ReadPushCommands(br)
	if err != nil {
		t.Fatal(err)
	}
	g, _, err := ScanPack(br, io.Discard, 20)
	if err != nil {
		t.Fatal(err)
	}
	return pc.Updates, g
}

// A real fast-forward pushed after a repack with reachability bitmaps: git reuses the stored delta of a new commit
// against a commit the host already has (a thin pack), so the commit cannot be read from the pack. Its ancestry stays
// Unknown (never guessed) and the graph reports the pack as thin; "git push --no-thin" makes it provable.
func TestScanPackThinPushAfterBitmapRepack(t *testing.T) {
	host := newGitRepo(t)
	host.run(nil, "config", "receive.denyCurrentBranch", "ignore")
	r := newGitRepo(t)
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(r.dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		r.run(nil, "add", name)
	}
	// Long messages make the old commits bigger than the new ones, so a repack stores the new ones as deltas
	// against them.
	long := strings.Repeat(" with a long description", 20)
	for i := range 4 {
		write("f", strings.Repeat(fmt.Sprintf("line %d\n", i), i+1))
		r.run(nil, "commit", "-q", "-m", fmt.Sprintf("change %d%s", i, long))
	}
	r.run(nil, "push", "-q", host.dir, "main")
	r.run(nil, "checkout", "-q", "-b", "other")
	write("g", "other\n")
	r.run(nil, "commit", "-q", "-m", "other work")
	r.run(nil, "push", "-q", host.dir, "other")
	r.run(nil, "checkout", "-q", "main")
	write("f", "new work\n")
	r.run(nil, "commit", "-q", "-m", "new work")
	c := strings.TrimSpace(r.run(nil, "rev-parse", "HEAD"))
	r.run(nil, "merge", "-q", "--no-edit", "other") // a merge of a branch the host already has
	m := strings.TrimSpace(r.run(nil, "rev-parse", "HEAD"))
	r.run(nil, "fetch", "-q", host.dir, "+refs/heads/*:refs/remotes/host/*")
	r.run(nil, "repack", "-q", "-a", "-d", "-f", "-b")

	old := strings.TrimSpace(host.run(nil, "rev-parse", "main"))
	// push sends tip to the host's main (still at old) and resets it afterwards: the plain host accepts any push.
	push := func(tip string, flags ...string) (RefUpdate, *CommitGraph) {
		updates, g := scanPush(t, r.pushCapture(host.dir, tip+":refs/heads/main", flags...))
		host.run(nil, "update-ref", "refs/heads/main", old)
		if len(updates) != 1 || updates[0].Old != old || updates[0].New != tip {
			t.Fatalf("push %s: updates %v", tip, updates)
		}
		return updates[0], g
	}
	for name, tip := range map[string]string{"merge": m, "single commit": c} {
		u, g := push(tip)
		if got := g.AncestryOf(u.Old, u.New); got != Unknown || !g.Thin() {
			t.Fatalf("%s: thin push after a bitmap repack = %s, thin %v; want unknown, thin", name, got, g.Thin())
		}
		u, g = push(tip, "--no-thin")
		if got := g.AncestryOf(u.Old, u.New); got != FastForward || g.Thin() {
			t.Fatalf("%s: --no-thin push = %s, thin %v; want fast-forward", name, got, g.Thin())
		}
	}
}

func TestApplyDelta(t *testing.T) {
	base := []byte("tree 0123\nparent aaaa\n\nmessage one\n")
	// src size, dst size, copy 0..23 from base, insert "msg two\n".
	want := append([]byte(nil), base[:23]...)
	want = append(want, "msg two\n"...)
	delta := []byte{byte(len(base)), byte(len(want)), 0x80 | 0x10, 23, 8}
	delta = append(delta, "msg two\n"...)
	got, err := applyDelta(base, delta)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("applyDelta = %q, %v", got, err)
	}
	for name, d := range map[string][]byte{
		"wrong base size":  {1, 1, 1, 'x'},
		"copy past base":   {byte(len(base)), 60, 0x80 | 0x01 | 0x10, 200, 10},
		"insert past data": {byte(len(base)), 5, 9, 'a'},
		"opcode zero":      {byte(len(base)), 1, 0},
		"short result":     {byte(len(base)), 9, 1, 'a'},
	} {
		if _, err := applyDelta(base, d); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestScanPackRejectsGarbage(t *testing.T) {
	for name, b := range map[string][]byte{
		"empty":       {},
		"signature":   []byte("PAKC\x00\x00\x00\x02\x00\x00\x00\x00"),
		"version":     []byte("PACK\x00\x00\x00\x09\x00\x00\x00\x00"),
		"no objects":  []byte("PACK\x00\x00\x00\x02\x00\x00\x00\x01"),
		"no checksum": []byte("PACK\x00\x00\x00\x02\x00\x00\x00\x00"),
	} {
		if _, _, err := ScanPack(bufio.NewReader(bytes.NewReader(b)), &bytes.Buffer{}, 20); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func FuzzScanPack(f *testing.F) {
	f.Add([]byte("PACK\x00\x00\x00\x02\x00\x00\x00\x00" + strings.Repeat("\x00", 20)))
	f.Fuzz(func(t *testing.T, b []byte) {
		var fwd bytes.Buffer
		g, trailer, err := ScanPack(bufio.NewReader(bytes.NewReader(b)), &fwd, 20)
		if err != nil {
			return
		}
		if !bytes.HasPrefix(b, append(fwd.Bytes(), trailer...)) {
			t.Fatal("forwarded bytes are not the consumed prefix")
		}
		_ = g.AncestryOf(strings.Repeat("1", 40), strings.Repeat("2", 40))
	})
}
