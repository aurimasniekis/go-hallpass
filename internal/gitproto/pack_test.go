package gitproto

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1" //nolint:gosec // git object IDs, as in pack.go
	"encoding/binary"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

// gitRepo is a throwaway repository driven with the git CLI.
type gitRepo struct {
	t   testing.TB
	dir string
}

func newGitRepo(t testing.TB, initArgs ...string) *gitRepo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	r := &gitRepo{t: t, dir: t.TempDir()}
	r.run(nil, append([]string{"init", "-q", "-b", "main"}, initArgs...)...)
	return r
}

func (r *gitRepo) run(stdin []byte, args ...string) string {
	r.t.Helper()
	out, err := r.try(stdin, args...)
	if err != nil {
		r.t.Fatalf("git %v: %v", args, err)
	}
	return out
}

// try runs git and returns its output, or an error with its stderr.
func (r *gitRepo) try(stdin []byte, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = r.dir
	cmd.Env = append(cmd.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test", "GIT_COMMITTER_NAME=t",
		"GIT_COMMITTER_EMAIL=t@example.test", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "HOME="+r.dir)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, errb.String())
	}
	return out.String(), nil
}

// rawCommit stores body as a commit object without any checks and returns its ID.
func (r *gitRepo) rawCommit(body string) string {
	r.t.Helper()
	return strings.TrimSpace(r.run([]byte(body), "hash-object", "-t", "commit", "-w", "--literally", "--stdin"))
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
	return scanHash(t, pack, 20)
}

func scanHash(t *testing.T, pack []byte, hashLen int) *CommitGraph {
	t.Helper()
	var fwd bytes.Buffer
	g, trailer, err := ScanPack(bufio.NewReader(bytes.NewReader(pack)), &fwd, hashLen)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(fwd.Bytes(), trailer...), pack) {
		t.Fatal("forwarded bytes plus withheld checksum differ from the pack")
	}
	if len(trailer) != hashLen {
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
	// Packs of commits whose headers git reads in different ways.
	for _, c := range commitHeaderCases(sha1Fixture) {
		f.Add(commitPack([]byte(c.body)))
	}
	f.Add(commitPack([]byte(sha1Fixture.expand("tree {T}\n"+who+"\n\nroot\n")),
		[]byte(sha1Fixture.expand("tree {T}\nparent {A}\n"+who+"\n\nchild\n"))))
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

// Only the parent lines directly after the tree line count, as in git. A commit with its parent line after the other
// headers has no parents to git, so it does not prove a fast-forward.
func TestScanPackParentOnlyWhereGitReadsIt(t *testing.T) {
	for _, format := range []struct {
		name    string
		hashLen int
	}{{"sha1", 20}, {"sha256", 32}} {
		t.Run(format.name, func(t *testing.T) {
			r := newGitRepo(t, "--object-format="+format.name)
			a := r.commit("a")
			tree := strings.TrimSpace(r.run(nil, "rev-parse", a+"^{tree}"))
			u := r.rawCommit("tree " + tree + "\n" + who + "\nparent " + a + "\n\nunrelated history\n")
			if got := strings.TrimSpace(r.run(nil, "rev-list", "--parents", "-n1", u)); got != u {
				t.Fatalf("git reads the parents of the late-parent commit as %q, want a root", got)
			}
			r.run(nil, "fsck", "--strict", "--no-dangling") // git accepts the object
			for _, thin := range []bool{false, true} {
				g := scanHash(t, r.pack(thin, u, "^"+a), format.hashLen)
				if got := g.AncestryOf(a, u); got != Unknown {
					t.Errorf("thin=%v: ancestry of the late-parent commit = %s, want %s", thin, got, Unknown)
				}
			}
			// A well-formed commit on top of it cannot prove anything through it either.
			v := r.rawCommit("tree " + tree + "\nparent " + u + "\n" + who + "\n\non top\n")
			if got := scanHash(t, r.pack(false, v, "^"+a), format.hashLen).AncestryOf(a, v); got != Unknown {
				t.Errorf("ancestry through the late-parent commit = %s, want %s", got, Unknown)
			}
			// The same history written the way git reads it is still proven.
			w := r.rawCommit("tree " + tree + "\nparent " + a + "\n" + who + "\n\nchild\n")
			if got := scanHash(t, r.pack(false, w, "^"+a), format.hashLen).AncestryOf(a, w); got != FastForward {
				t.Errorf("well-formed child = %s, want %s", got, FastForward)
			}
		})
	}
}

const who = "author t <t@example.test> 1700000000 +0000\ncommitter t <t@example.test> 1700000000 +0000"

// headerFixture names object IDs for commitHeaderCases: T a tree, A and B commits, Z an ID of the other object format.
type headerFixture struct{ t, a, b, z string }

func (f headerFixture) expand(s string) string {
	return strings.NewReplacer("{T}", f.t, "{A}", f.a, "{B}", f.b, "{Z}", f.z, "{UA}", strings.ToUpper(f.a)).Replace(s)
}

// sha1Fixture uses IDs of objects that need not exist (enough for parsing and for packs).
var sha1Fixture = headerFixture{t: "4b825dc642cb6eb9a060e54bf8d69288fbee4904", a: strings.Repeat("a1", 20),
	b: strings.Repeat("b2", 20), z: strings.Repeat("c3", 32)}

type headerCase struct {
	name string
	body string
	ok   bool // commitParents must accept it (git reads it the same way); otherwise it must refuse it
}

// commitHeaderCases are commit objects whose headers git reads in different ways.
func commitHeaderCases(f headerFixture) []headerCase {
	sig := "gpgsig -----BEGIN PGP SIGNATURE-----\n \n parent {B}\n tree {T}\n -----END PGP SIGNATURE-----"
	mergetag := "mergetag object {B}\n type commit\n tag v1\n tagger t <t@example.test> 1700000000 +0000\n \n parent {A}\n"
	cs := []headerCase{
		{"root", "tree {T}\n" + who + "\n\nmsg\n", true},
		{"one parent", "tree {T}\nparent {A}\n" + who + "\n\nmsg\n", true},
		{"merge", "tree {T}\nparent {A}\nparent {B}\n" + who + "\n\nmsg\n", true},
		{"no message", "tree {T}\nparent {A}\n" + who + "\n", true},
		{"parent in message", "tree {T}\n" + who + "\n\nparent {A}\n", true},
		{"empty line before parent", "tree {T}\n\nparent {A}\n" + who + "\n", true},
		{"gpgsig continuation", "tree {T}\nparent {A}\n" + who + "\n" + sig + "\n\nmsg\n", true},
		{"mergetag continuation", "tree {T}\nparent {A}\nparent {B}\n" + who + "\n" + mergetag + "\nmsg\n", true},
		{"indented parent", "tree {T}\n" + who + "\n parent {A}\n\nmsg\n", true},
		{"late parent", "tree {T}\n" + who + "\nparent {A}\n\nmsg\n", false},
		{"late second parent", "tree {T}\nparent {A}\n" + who + "\nparent {B}\n\nmsg\n", false},
		{"late parent without newline", "tree {T}\nparent {A}", false},
		{"parent before tree", "parent {A}\ntree {T}\n" + who + "\n\nmsg\n", false},
		{"two tree lines", "tree {T}\ntree {T}\nparent {A}\n" + who + "\n\nmsg\n", false},
		{"tree after parent", "tree {T}\nparent {A}\ntree {T}\n" + who + "\n\nmsg\n", false},
		{"no tree", "parent {A}\n" + who + "\n\nmsg\n", false},
		{"CRLF", "tree {T}\r\nparent {A}\r\n" + who + "\r\n\r\nmsg\r\n", false},
		{"CR after parent", "tree {T}\nparent {A}\r\n" + who + "\n\nmsg\n", false},
		{"upper-case parent", "tree {T}\nparent {UA}\n" + who + "\n\nmsg\n", false},
		{"short parent", "tree {T}\nparent " + f.a[:20] + "\n" + who + "\n\nmsg\n", false},
		{"parent of the other format", "tree {T}\nparent {Z}\n" + who + "\n\nmsg\n", false},
		{"parent with trailing text", "tree {T}\nparent {A} x\n" + who + "\n\nmsg\n", false},
		{"parent with two spaces", "tree {T}\nparent  {A}\n" + who + "\n\nmsg\n", false},
		{"tab instead of space", "tree {T}\nparent\t{A}\n" + who + "\n\nmsg\n", false},
		{"tree with trailing text", "tree {T} x\nparent {A}\n" + who + "\n\nmsg\n", false},
		{"only a tree line", "tree {T}\n", false},
		{"parent is the tree", "tree {T}\nparent {T}\n" + who + "\n\nmsg\n", false},
		{"ends after a parent line", "tree {T}\nparent {A}\n", false},
		{"empty", "", false},
	}
	for i := range cs {
		cs[i].body = f.expand(cs[i].body)
	}
	return cs
}

// commitParents is compared with git itself (git rev-list --parents) on real objects, for both object formats: when it
// accepts a commit, git must read exactly the same parents.
func TestCommitParentsMatchesGit(t *testing.T) {
	for _, format := range []struct {
		name    string
		hashLen int
		other   int
	}{{"sha1", 20, 64}, {"sha256", 32, 40}} {
		t.Run(format.name, func(t *testing.T) {
			r := newGitRepo(t, "--object-format="+format.name)
			a := r.commit("a")
			b := r.commit("b")
			f := headerFixture{t: strings.TrimSpace(r.run(nil, "rev-parse", a+"^{tree}")), a: a, b: b,
				z: strings.Repeat("c", format.other)}
			for _, c := range commitHeaderCases(f) {
				got, ok := commitParents([]byte(c.body), format.hashLen)
				if ok != c.ok {
					t.Errorf("%s: ok = %v, want %v", c.name, ok, c.ok)
				}
				if c.body == "" {
					continue
				}
				id := r.rawCommit(c.body)
				out, err := r.try(nil, "rev-list", "--parents", "-n1", id)
				if !ok {
					continue // refusing is always safe; the cases above say where refusing is expected
				}
				if err != nil {
					t.Errorf("%s: accepted, but git cannot read it: %v", c.name, err)
					continue
				}
				if want := strings.Fields(out)[1:]; !slices.Equal(got, want) {
					t.Errorf("%s: parents %q, git reads %q", c.name, got, want)
				}
			}
		})
	}
}

// FuzzCommitParents compares commitParents with git on arbitrary commit objects: whenever it accepts one, git must read
// the same parents ("git log --no-walk" does not need the parents to exist).
func FuzzCommitParents(f *testing.F) {
	for _, c := range commitHeaderCases(sha1Fixture) {
		f.Add([]byte(c.body))
	}
	r := newGitRepo(f)
	f.Fuzz(func(t *testing.T, body []byte) {
		got, ok := commitParents(body, 20)
		if !ok {
			return
		}
		rt := &gitRepo{t: t, dir: r.dir}
		id := rt.rawCommit(string(body))
		out, err := rt.try(nil, "log", "--no-walk", "--format=%P", id)
		if err != nil {
			t.Fatalf("accepted %q, but git cannot read it: %v", body, err)
		}
		if want := strings.Fields(out); !slices.Equal(got, want) {
			t.Fatalf("%q: parents %q, git reads %q", body, got, want)
		}
	})
}

// commitPack builds a version 2 SHA-1 pack holding the given commit objects, undeltified.
func commitPack(commits ...[]byte) []byte {
	var b bytes.Buffer
	b.WriteString("PACK")
	_ = binary.Write(&b, binary.BigEndian, uint32(2))
	_ = binary.Write(&b, binary.BigEndian, uint32(len(commits))) //nolint:gosec // test input
	for _, c := range commits {
		size := len(c)
		hdr := byte(objCommit<<4) | byte(size&0x0f)
		size >>= 4
		for size > 0 {
			b.WriteByte(hdr | 0x80)
			hdr = byte(size & 0x7f)
			size >>= 7
		}
		b.WriteByte(hdr)
		zw := zlib.NewWriter(&b)
		_, _ = zw.Write(c)
		_ = zw.Close()
	}
	sum := sha1.Sum(b.Bytes()) //nolint:gosec // pack checksum
	return append(b.Bytes(), sum[:]...)
}

func TestCommitPackScans(t *testing.T) {
	root := []byte(sha1Fixture.expand("tree {T}\n" + who + "\n\nroot\n"))
	child := []byte("tree " + sha1Fixture.t + "\nparent " + objectID(20, root) + "\n" + who + "\n\nchild\n")
	late := []byte("tree " + sha1Fixture.t + "\n" + who + "\nparent " + objectID(20, root) + "\n\nlate\n")
	g := scan(t, commitPack(root, child, late))
	if got := g.AncestryOf(objectID(20, root), objectID(20, child)); got != FastForward {
		t.Errorf("child = %s", got)
	}
	if got := g.AncestryOf(objectID(20, root), objectID(20, late)); got != Unknown {
		t.Errorf("late parent = %s", got)
	}
}
