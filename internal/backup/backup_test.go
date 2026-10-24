package backup

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/recording/hprec"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// HP-OPS-003/004, HP-CRY-009: create → verify → restore into a different directory → the app opens with the same
// KEK and every recording verifies, including the integrity chain MACs.
func TestRoundTrip(t *testing.T) {
	f := newFixture(t)
	for _, c := range []string{"uptime", "df -h", "id"} {
		f.finished(c)
	}
	ctx := f.ctx
	seq, head, err := f.a.Recording.ChainHead(ctx)
	must(t, err)
	out := filepath.Join(t.TempDir(), "nested", "b1")
	res, err := Create(ctx, f.a.Store, out, Options{})
	must(t, err)
	m := res.Manifest
	if len(res.Problems) != 0 || m.Segments.Copied != 3 || len(m.Files) != 4 || m.KEKIncluded || m.KEKID != f.a.Keyring.KEKID() ||
		m.ChainHead.Seq != seq || m.ChainHead.Hash != hex.EncodeToString(head) || m.SchemaVersion == 0 || m.SourceDataDir != f.a.Store.Dir() {
		t.Fatalf("unexpected result: %+v manifest %+v", res, m)
	}
	assertPrivateTree(t, out)
	// Nothing but the manifest, the database and segment ciphertext: no KEK, no dev key, no lock file.
	must(t, filepath.WalkDir(out, func(p string, d fs.DirEntry, err error) error {
		must(t, err)
		rel, _ := filepath.Rel(out, p)
		if !d.IsDir() && rel != ManifestFile && rel != ManifestSumFile && rel != DBFile && !strings.HasSuffix(rel, ".hprec") {
			t.Errorf("unexpected file in backup: %s", rel)
		}
		return nil
	}))
	rep, err := Verify(ctx, out)
	must(t, err)
	if !rep.OK || rep.Files != 4 || rep.ChainLength != 3 || len(rep.Warnings) != 0 {
		t.Fatalf("verify: %+v", rep)
	}
	must(t, f.a.Close())

	target := filepath.Join(t.TempDir(), "restored")
	rr, err := Restore(ctx, out, target, RestoreOptions{KEKID: m.KEKID})
	must(t, err)
	if rr.Files != 4 || rr.MovedAside != "" {
		t.Fatalf("restore: %+v", rr)
	}
	a2 := openApp(t, testConfig(target, f.cfg.KEK.File))
	defer a2.Close()
	vr, err := a2.Recording.Verify(ctx, "")
	must(t, err)
	if !vr.OK || !vr.ChainOK || vr.ChainLen != 3 || len(vr.Segments) != 3 {
		t.Fatalf("restored verify: %+v", vr)
	}
	for _, s := range vr.Segments {
		if s.Status != "ok" {
			t.Fatalf("segment %+v", s)
		}
	}
	paths, err := a2.Store.R().AllSegmentPaths(ctx)
	must(t, err)
	for _, p := range paths {
		if !strings.HasPrefix(p.Path, a2.Store.Path(store.RecordingsDir)) {
			t.Fatalf("segment path not rewritten: %s", p.Path)
		}
	}
	seq2, head2, err := a2.Recording.ChainHead(ctx)
	must(t, err)
	if seq2 != seq || hex.EncodeToString(head2) != hex.EncodeToString(head) {
		t.Fatal("chain head changed by restore")
	}
}

func assertPrivateTree(t *testing.T, root string) {
	t.Helper()
	must(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		must(t, err)
		fi, err := d.Info()
		must(t, err)
		want := fs.FileMode(0o600)
		if d.IsDir() {
			want = 0o700
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s has mode %04o, want %04o", p, fi.Mode().Perm(), want)
		}
		return nil
	}))
}

// HP-OPS-003, PLAN §13.10 step 2: a backup taken through the lock-free read-only source while the server holds
// the lock copies a segment that is still open; after restore, reconciliation marks it interrupted.
func TestOpenSegmentAndReadOnlySource(t *testing.T) {
	f := newFixture(t)
	f.finished("uptime")
	rec := f.record("tail -f /var/log/syslog")
	src, err := OpenReadOnly(f.ctx, f.cfg.DataDir)
	must(t, err)
	if src.DB() == nil || src.Dir() != f.a.Store.Dir() {
		t.Fatal("read-only source")
	}
	out := filepath.Join(t.TempDir(), "b")
	res, err := Create(f.ctx, src, out, Options{})
	must(t, err)
	must(t, src.Close())
	if res.Manifest.Segments.Copied != 2 || res.Manifest.Segments.OpenAtSnapshot != 1 {
		t.Fatalf("segments: %+v", res.Manifest.Segments)
	}
	var open *File
	for i := range res.Manifest.Files {
		if res.Manifest.Files[i].OpenAtSnapshot {
			open = &res.Manifest.Files[i]
		}
	}
	if open == nil || !strings.HasSuffix(open.Path, hprec.PartialSuffix) || open.State != "open" {
		t.Fatalf("open segment entry: %+v", open)
	}
	// The live recording continues and finishes after the snapshot; the backup is unaffected.
	status := 0
	must(t, rec.Exit(&status, ""))
	must(t, rec.Finalize("exit_status"))
	_, err = Verify(f.ctx, out)
	must(t, err)
	must(t, f.a.Close())

	target := filepath.Join(t.TempDir(), "r")
	_, err = Restore(f.ctx, out, target, RestoreOptions{})
	must(t, err)
	a2 := openApp(t, testConfig(target, f.cfg.KEK.File))
	defer a2.Close()
	vr, err := a2.Recording.Verify(f.ctx, "")
	must(t, err)
	counts := map[string]int{}
	for _, s := range vr.Segments {
		counts[s.Status]++
	}
	if !vr.OK || counts["ok"] != 1 || counts["interrupted"] != 1 || vr.ChainLen != 2 {
		t.Fatalf("restored verify: %+v", vr)
	}
}

// backupOf creates a backup with n finalized recordings and returns its directory and the closed fixture.
func backupOf(t *testing.T, n int) (string, *fixture) {
	t.Helper()
	f := newFixture(t)
	for i := range n {
		f.finished("cmd" + string(rune('a'+i)))
	}
	out := filepath.Join(t.TempDir(), "b")
	_, err := Create(f.ctx, f.a.Store, out, Options{})
	must(t, err)
	must(t, f.a.Close())
	return out, f
}

func readManifestT(t *testing.T, dir string) *Manifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	must(t, err)
	var m Manifest
	must(t, json.Unmarshal(b, &m))
	return &m
}

// rewriteManifest applies fn and writes a consistent manifest.json and manifest.sha256, as an attacker or a
// careless operator could.
func rewriteManifest(t *testing.T, dir string, fn func(*Manifest)) {
	t.Helper()
	m := readManifestT(t, dir)
	fn(m)
	must(t, os.Remove(filepath.Join(dir, ManifestFile)))
	must(t, os.Remove(filepath.Join(dir, ManifestSumFile)))
	must(t, writeManifest(dir, m))
}

// rehash updates the manifest entry of rel to the file's current size and hash.
func rehash(t *testing.T, dir, rel string) {
	t.Helper()
	size, sum, err := hashFile(filepath.Join(dir, filepath.FromSlash(rel)))
	must(t, err)
	rewriteManifest(t, dir, func(m *Manifest) {
		for i := range m.Files {
			if m.Files[i].Path == rel {
				m.Files[i].Size, m.Files[i].SHA256 = size, hex.EncodeToString(sum[:])
			}
		}
	})
}

func firstSegment(t *testing.T, dir string) string {
	t.Helper()
	for _, f := range readManifestT(t, dir).Files {
		if f.Kind == KindSegment {
			return f.Path
		}
	}
	t.Fatal("no segment in backup")
	return ""
}

func flipByteAt(t *testing.T, p string, off int64) {
	t.Helper()
	fh, err := os.OpenFile(p, os.O_RDWR, 0)
	must(t, err)
	defer fh.Close()
	if off < 0 {
		fi, err := fh.Stat()
		must(t, err)
		off += fi.Size()
	}
	b := make([]byte, 1)
	_, err = fh.ReadAt(b, off)
	must(t, err)
	b[0] ^= 0xff
	_, err = fh.WriteAt(b, off)
	must(t, err)
}

func copyTree(t *testing.T, src string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "copy")
	must(t, filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		must(t, err)
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o700)
		}
		b, err := os.ReadFile(p)
		must(t, err)
		return os.WriteFile(filepath.Join(dst, rel), b, 0o600)
	}))
	return dst
}

func expectProblem(t *testing.T, dir, want string) *Report {
	t.Helper()
	rep, err := Verify(context.Background(), dir)
	if err == nil || !errors.Is(err, ErrInvalid) || rep.OK {
		t.Fatalf("verify passed, want problem %q: %+v", want, rep)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not mention %q", err, want)
	}
	return rep
}

// HP-OPS-003: tampering, missing files, unlisted files and manifest damage are detected.
func TestVerifyDetectsTampering(t *testing.T) {
	base, _ := backupOf(t, 2)
	cases := []struct {
		name string
		mod  func(t *testing.T, dir string)
		want string
	}{
		{"segment byte flipped", func(t *testing.T, dir string) { flipByteAt(t, filepath.Join(dir, firstSegment(t, dir)), -3) }, "does not match the manifest"},
		{"database byte flipped", func(t *testing.T, dir string) { flipByteAt(t, filepath.Join(dir, DBFile), 200) }, "hallpass.db does not match"},
		{"segment missing", func(t *testing.T, dir string) { must(t, os.Remove(filepath.Join(dir, firstSegment(t, dir)))) }, "is missing"},
		{"unlisted file", func(t *testing.T, dir string) {
			must(t, os.WriteFile(filepath.Join(dir, "recordings", "extra.hprec"), []byte("x"), 0o600))
		}, "not listed in the manifest"},
		{"symlink", func(t *testing.T, dir string) {
			must(t, os.Symlink("/etc/hosts", filepath.Join(dir, "link")))
		}, "not a regular file"},
		{"manifest edited without checksum", func(t *testing.T, dir string) {
			p := filepath.Join(dir, ManifestFile)
			b, err := os.ReadFile(p)
			must(t, err)
			must(t, os.WriteFile(p, append(b, ' '), 0o600))
		}, "does not match manifest.sha256"},
		{"checksum file missing", func(t *testing.T, dir string) { must(t, os.Remove(filepath.Join(dir, ManifestSumFile))) }, "manifest checksum"},
		{"manifest missing", func(t *testing.T, dir string) { must(t, os.Remove(filepath.Join(dir, ManifestFile))) }, "read manifest"},
		{"segment replaced consistently in manifest", func(t *testing.T, dir string) {
			rel := firstSegment(t, dir)
			flipByteAt(t, filepath.Join(dir, rel), -3)
			rehash(t, dir, rel)
		}, "ciphertext hash differs from the database"},
		{"segment header replaced consistently in manifest", func(t *testing.T, dir string) {
			rel := firstSegment(t, dir)
			flipByteAt(t, filepath.Join(dir, rel), 20)
			rehash(t, dir, rel)
		}, "header hash differs"},
		{"segment dropped from manifest", func(t *testing.T, dir string) {
			rel := firstSegment(t, dir)
			must(t, os.Remove(filepath.Join(dir, rel)))
			rewriteManifest(t, dir, func(m *Manifest) {
				var keep []File
				for _, f := range m.Files {
					if f.Path != rel {
						keep = append(keep, f)
					}
				}
				m.Files = keep
			})
		}, "neither in the backup nor recorded as missing"},
		{"path traversal", func(t *testing.T, dir string) {
			rewriteManifest(t, dir, func(m *Manifest) { m.Files[1].Path = "recordings/../../etc/passwd" })
		}, "invalid path"},
		{"duplicate entry", func(t *testing.T, dir string) {
			rewriteManifest(t, dir, func(m *Manifest) { m.Files = append(m.Files, m.Files[1]) })
		}, "twice"},
		{"wrong kind", func(t *testing.T, dir string) {
			rewriteManifest(t, dir, func(m *Manifest) { m.Files[1].Kind = KindDatabase })
		}, "inconsistent kind"},
		{"kek claimed", func(t *testing.T, dir string) { rewriteManifest(t, dir, func(m *Manifest) { m.KEKIncluded = true }) }, "never contain"},
		{"wrong format", func(t *testing.T, dir string) { rewriteManifest(t, dir, func(m *Manifest) { m.Format = "tar" }) }, "not a HallPass backup"},
		{"wrong version", func(t *testing.T, dir string) { rewriteManifest(t, dir, func(m *Manifest) { m.Version = 9 }) }, "unsupported backup format"},
		{"wrong kek id", func(t *testing.T, dir string) { rewriteManifest(t, dir, func(m *Manifest) { m.KEKID = "0000" }) }, "wrapped under KEK"},
		{"wrong chain head", func(t *testing.T, dir string) { rewriteManifest(t, dir, func(m *Manifest) { m.ChainHead.Seq = 1 }) }, "chain head"},
		{"open flag mismatch", func(t *testing.T, dir string) {
			rewriteManifest(t, dir, func(m *Manifest) { m.Files[1].OpenAtSnapshot = true })
		}, "disagree about its state"},
		{"unknown segment", func(t *testing.T, dir string) {
			rewriteManifest(t, dir, func(m *Manifest) { m.Files[1].SegmentID = "seg_nope" })
		}, "has no row"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := copyTree(t, base)
			c.mod(t, dir)
			expectProblem(t, dir, c.want)
			_, err := Restore(context.Background(), dir, filepath.Join(t.TempDir(), "r"), RestoreOptions{})
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("restore of a bad backup: %v", err)
			}
		})
	}
}

// HP-DB-005, HP-OPS-005: schema mismatches are refused; a backup from a newer binary cannot be restored.
func TestSchemaVersionChecks(t *testing.T) {
	base, _ := backupOf(t, 1)
	t.Run("manifest disagrees with database", func(t *testing.T) {
		dir := copyTree(t, base)
		rewriteManifest(t, dir, func(m *Manifest) { m.SchemaVersion++ })
		expectProblem(t, dir, "manifest says")
	})
	t.Run("newer than binary", func(t *testing.T) {
		dir := copyTree(t, base)
		d, err := sql.Open("sqlite", "file:"+filepath.Join(dir, DBFile))
		must(t, err)
		_, err = d.ExecContext(context.Background(), "INSERT INTO goose_db_version (version_id, is_applied) VALUES (9999, 1)")
		must(t, err)
		must(t, d.Close())
		rehash(t, dir, DBFile)
		rewriteManifest(t, dir, func(m *Manifest) { m.SchemaVersion = 9999 })
		expectProblem(t, dir, "newer than this binary")
		_, err = Restore(context.Background(), dir, filepath.Join(t.TempDir(), "r"), RestoreOptions{})
		if !errors.Is(err, store.ErrSchemaTooNew) || !errors.Is(err, ErrInvalid) {
			t.Fatalf("restore: %v", err)
		}
	})
	t.Run("corrupt database copy", func(t *testing.T) {
		dir := copyTree(t, base)
		p := filepath.Join(dir, DBFile)
		b, err := os.ReadFile(p)
		must(t, err)
		// Damage a b-tree page beyond the header; the manifest is made consistent so only SQLite notices.
		for i := 4096 + 8; i < 4096+64 && i < len(b); i++ {
			b[i] = 0xff
		}
		must(t, os.WriteFile(p, b, 0o600))
		rehash(t, dir, DBFile)
		expectProblem(t, dir, "database copy")
	})
}

// HP-OPS-004, ADR-0023: restore only into an empty directory unless forced; never while the lock is held; only with
// the matching KEK.
func TestRestoreTargetRules(t *testing.T) {
	base, f := backupOf(t, 1)
	ctx := context.Background()
	m := readManifestT(t, base)

	t.Run("kek mismatch", func(t *testing.T) {
		_, err := Restore(ctx, base, filepath.Join(t.TempDir(), "r"), RestoreOptions{KEKID: "deadbeef"})
		if !errors.Is(err, ErrKEKMismatch) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("prepared empty dir is accepted", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "r")
		must(t, store.PrepareDataDir(target))
		must(t, os.WriteFile(filepath.Join(target, store.LockFile), nil, 0o600))
		_, err := Restore(ctx, base, target, RestoreOptions{KEKID: m.KEKID})
		must(t, err)
	})
	t.Run("non-empty refused, then forced", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "r")
		_, err := Restore(ctx, base, target, RestoreOptions{})
		must(t, err)
		// A second restore over live data is refused and changes nothing.
		before, err := os.ReadFile(filepath.Join(target, store.DBFile))
		must(t, err)
		_, err = Restore(ctx, base, target, RestoreOptions{})
		if !errors.Is(err, ErrNotEmpty) || !strings.Contains(err.Error(), "hallpass.db") {
			t.Fatalf("got %v", err)
		}
		after, err := os.ReadFile(filepath.Join(target, store.DBFile))
		must(t, err)
		if sha256.Sum256(before) != sha256.Sum256(after) {
			t.Fatal("refused restore modified the target")
		}
		must(t, os.WriteFile(filepath.Join(target, store.QuarantineDir, "q"), []byte("evidence"), 0o600))
		rr, err := Restore(ctx, base, target, RestoreOptions{Force: true})
		must(t, err)
		if rr.MovedAside == "" || len(rr.Warnings) == 0 {
			t.Fatalf("force: %+v", rr)
		}
		for _, name := range []string{store.DBFile, store.RecordingsDir, filepath.Join(store.QuarantineDir, "q")} {
			if _, err := os.Stat(filepath.Join(rr.MovedAside, name)); err != nil {
				t.Errorf("%s not moved aside: %v", name, err)
			}
		}
		a := openApp(t, testConfig(target, f.cfg.KEK.File))
		vr, err := a.Recording.Verify(ctx, "")
		must(t, err)
		must(t, a.Close())
		if !vr.OK || len(vr.Segments) != 1 {
			t.Fatalf("verify after forced restore: %+v", vr)
		}
	})
	t.Run("lock held", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "r")
		must(t, store.PrepareDataDir(target))
		l, err := store.AcquireLock(filepath.Join(target, store.LockFile))
		must(t, err)
		defer func() { _ = l.Release() }()
		_, err = Restore(ctx, base, target, RestoreOptions{})
		if !errors.Is(err, store.ErrLocked) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("same data dir path", func(t *testing.T) {
		// Restoring onto the original location (after moving it away) needs no path rewrite.
		must(t, os.Rename(f.cfg.DataDir, f.cfg.DataDir+".old"))
		_, err := Restore(ctx, base, f.cfg.DataDir, RestoreOptions{KEKID: m.KEKID})
		must(t, err)
		a := openApp(t, f.cfg)
		vr, err := a.Recording.Verify(ctx, "")
		must(t, err)
		must(t, a.Close())
		if !vr.OK {
			t.Fatalf("verify: %+v", vr)
		}
	})
}

// PLAN §13.10: problems found while copying live files are recorded, not fatal, and reported again by Verify.
func TestCreateRecordsLiveProblems(t *testing.T) {
	f := newFixture(t)
	f.finished("a")
	f.finished("b")
	paths, err := f.a.Store.R().AllSegmentPaths(f.ctx)
	must(t, err)
	if len(paths) != 2 {
		t.Fatalf("paths %+v", paths)
	}
	flipByteAt(t, paths[0].Path, -3)
	must(t, os.Remove(paths[1].Path))
	out := filepath.Join(t.TempDir(), "b")
	res, err := Create(f.ctx, f.a.Store, out, Options{})
	must(t, err)
	if len(res.Problems) != 1 || len(res.Manifest.Segments.Missing) != 1 || len(res.Manifest.Warnings) != 1 {
		t.Fatalf("result: %+v", res)
	}
	rep, err := Verify(f.ctx, out)
	must(t, err)
	if len(rep.Warnings) != 2 {
		t.Fatalf("warnings: %+v", rep.Warnings)
	}
	if _, err := Create(f.ctx, f.a.Store, out, Options{}); !errors.Is(err, ErrExists) {
		t.Fatalf("existing destination: %v", err)
	}
}

func TestSegHasher(t *testing.T) {
	body := func(n int) []byte {
		b := append([]byte(hprec.Magic), 0, 0, 0, byte(n))
		b = append(b, make([]byte, n+2*hprec.SlotSize)...)
		return append(b, []byte("frames")...)
	}
	full := body(10)
	h := sha256.Sum256(full[:12+10])
	ct := sha256.Sum256([]byte("frames"))
	run := func(b []byte, rec sql.NullInt64, chunk int) string {
		s := newSegHasher(rec)
		for len(b) > 0 {
			k := min(chunk, len(b))
			_, _ = s.Write(b[:k])
			b = b[k:]
		}
		return s.check(h[:], ct[:])
	}
	for _, chunk := range []int{1, 7, 4096} {
		if p := run(full, sql.NullInt64{}, chunk); p != "" {
			t.Fatalf("chunk %d: %s", chunk, p)
		}
		if p := run(full, sql.NullInt64{Int64: int64(len(full)), Valid: true}, chunk); p != "" {
			t.Fatalf("limit chunk %d: %s", chunk, p)
		}
	}
	// Trailing bytes beyond the recorded size are not part of the frames region.
	if p := run(append(full, 'x'), sql.NullInt64{Int64: int64(len(full)), Valid: true}, 5); p != "" {
		t.Fatal(p)
	}
	for name, c := range map[string]struct {
		b    []byte
		rec  sql.NullInt64
		want string
	}{
		"short":       {full[:5], sql.NullInt64{}, "not an HPREC1"},
		"bad magic":   {append([]byte("XXXXXXXX"), full[8:]...), sql.NullInt64{}, "not an HPREC1"},
		"no slots":    {full[:40], sql.NullInt64{}, "truncated"},
		"zero header": {body(0), sql.NullInt64{}, "truncated"},
		"shorter":     {full, sql.NullInt64{Int64: int64(len(full)) + 5, Valid: true}, "shorter than recorded"},
		"frames":      {append(full[:len(full)-1], 'X'), sql.NullInt64{}, "ciphertext hash"},
	} {
		if p := run(c.b, c.rec, 3); !strings.Contains(p, c.want) {
			t.Errorf("%s: got %q want %q", name, p, c.want)
		}
	}
}

func TestOpenReadOnlyMissing(t *testing.T) {
	if _, err := OpenReadOnly(context.Background(), t.TempDir()); err == nil {
		t.Fatal("expected error for a directory without a database")
	}
}

func TestReadOnlySnapshotRefusals(t *testing.T) {
	f := newFixture(t)
	src, err := OpenReadOnly(f.ctx, f.cfg.DataDir)
	must(t, err)
	defer src.Close()
	dir := t.TempDir()
	existing := filepath.Join(dir, "exists.db")
	must(t, os.WriteFile(existing, nil, 0o600))
	if err := src.Snapshot(f.ctx, existing); err == nil {
		t.Fatal("overwrote an existing file")
	}
	if err := src.Snapshot(f.ctx, filepath.Join(dir, "it's.db")); err == nil {
		t.Fatal("accepted a quote in the path")
	}
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if _, err := Create(ctx, src, filepath.Join(dir, "b"), Options{}); err == nil {
		t.Fatal("canceled context accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "b")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("failed backup left a destination behind")
	}
	entries, err := os.ReadDir(dir)
	must(t, err)
	if len(entries) != 1 {
		t.Fatalf("staging directory not cleaned up: %v", entries)
	}
}
