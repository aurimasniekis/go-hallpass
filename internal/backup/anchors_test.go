package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"strings"
	"testing"
)

func exportAll(t *testing.T, f *fixture, since int64) (string, int) {
	t.Helper()
	var buf bytes.Buffer
	n, err := ExportAnchors(f.ctx, f.a.Store.ReadDB(), since, &buf)
	must(t, err)
	return buf.String(), n
}

func anchoredFixture(t *testing.T) (*fixture, string) {
	t.Helper()
	f := newFixture(t)
	for _, c := range []string{"a", "b", "c"} {
		f.finished(c)
	}
	out, n := exportAll(t, f, 0)
	if n != 3 || strings.Count(out, "\n") != 3 || !strings.Contains(out, `"seq":3`) {
		t.Fatalf("export: %d %q", n, out)
	}
	return f, out
}

func verifyAnchors(t *testing.T, f *fixture, anchors string) *AnchorReport {
	t.Helper()
	rep, err := VerifyAnchors(f.ctx, f.a.Store.ReadDB(), strings.NewReader(anchors))
	must(t, err)
	return rep
}

func exec(t *testing.T, f *fixture, q string, args ...any) {
	t.Helper()
	must(t, f.a.Store.W().Exec(f.ctx, q, args...))
}

func hasProblem(rep *AnchorReport, s string) bool {
	for _, p := range rep.Problems {
		if strings.Contains(p, s) {
			return true
		}
	}
	return false
}

// HP-CRY-008: anchors export, verify against an intact chain, and detect rewritten or truncated history.
func TestAnchors(t *testing.T) {
	t.Run("intact and incremental", func(t *testing.T) {
		f, anchors := anchoredFixture(t)
		rep := verifyAnchors(t, f, anchors)
		if !rep.OK || rep.Matched != 3 || rep.LastAnchorSeq != 3 || rep.LocalHeadSeq != 3 {
			t.Fatalf("report %+v", rep)
		}
		tail, n := exportAll(t, f, 2)
		if n != 1 || !strings.Contains(tail, `"seq":3`) {
			t.Fatalf("since 2: %q", tail)
		}
		// History after the latest anchor is allowed to grow.
		f.finished("d")
		if rep := verifyAnchors(t, f, anchors); !rep.OK || rep.LocalHeadSeq != 4 {
			t.Fatalf("after growth: %+v", rep)
		}
		// A row relabeled "deleted" without the retention job's tombstone is reported (SR-17); real retention is
		// covered by TestAnchorsDeletedNeedsTombstone.
		exec(t, f, "UPDATE recording_segments SET state = 'deleted' WHERE id = (SELECT segment_id FROM integrity_chain WHERE seq = 1)")
		if rep := verifyAnchors(t, f, anchors+"\n"); rep.OK || !hasProblem(rep, "without a retention tombstone") {
			t.Fatalf("after relabeling: %+v", rep)
		}
		if _, err := ExportAnchors(f.ctx, f.a.Store.ReadDB(), -1, &bytes.Buffer{}); err == nil {
			t.Fatal("negative since accepted")
		}
	})
	t.Run("hash overwritten", func(t *testing.T) {
		f, anchors := anchoredFixture(t)
		exec(t, f, "UPDATE integrity_chain SET hash = randomblob(32) WHERE seq = 2")
		rep := verifyAnchors(t, f, anchors)
		if rep.OK || !hasProblem(rep, "local chain") {
			t.Fatalf("report %+v", rep)
		}
		if _, err := ExportAnchors(f.ctx, f.a.Store.ReadDB(), 0, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Fatalf("export of a broken chain: %v", err)
		}
	})
	t.Run("history rewritten consistently", func(t *testing.T) {
		// An attacker recomputes every link after forging entry 1; only the external anchors reveal it.
		f, anchors := anchoredFixture(t)
		forged := sha256.Sum256([]byte("forged manifest"))
		prev := make([]byte, 32)
		for seq := int64(1); seq <= 3; seq++ {
			var ms []byte
			must(t, f.a.Store.ReadDB().QueryRowContext(f.ctx, "SELECT manifest_sha256 FROM integrity_chain WHERE seq = ?", seq).Scan(&ms))
			if seq == 1 {
				ms = forged[:]
			}
			h := sha256.New()
			h.Write(prev)
			h.Write(ms)
			hash := h.Sum(nil)
			exec(t, f, "UPDATE integrity_chain SET manifest_sha256 = ?, prev_hash = ?, hash = ? WHERE seq = ?", ms, prev, hash, seq)
			prev = hash
		}
		rep := verifyAnchors(t, f, anchors)
		if rep.OK || !hasProblem(rep, "history rewritten") || !hasProblem(rep, "no longer matches its chain entry") || hasProblem(rep, "local chain") {
			t.Fatalf("report %+v", rep)
		}
	})
	t.Run("truncated", func(t *testing.T) {
		f, anchors := anchoredFixture(t)
		exec(t, f, "DELETE FROM integrity_chain WHERE seq = 3")
		if rep := verifyAnchors(t, f, anchors); rep.OK || !hasProblem(rep, "not in the local chain") {
			t.Fatalf("report %+v", rep)
		}
	})
	t.Run("segment metadata changed", func(t *testing.T) {
		f, anchors := anchoredFixture(t)
		exec(t, f, "UPDATE recording_segments SET frames = frames + 1 WHERE id = (SELECT segment_id FROM integrity_chain WHERE seq = 2)")
		if rep := verifyAnchors(t, f, anchors); rep.OK || !hasProblem(rep, "seq 2") {
			t.Fatalf("report %+v", rep)
		}
	})
	t.Run("segment row removed", func(t *testing.T) {
		f, anchors := anchoredFixture(t)
		exec(t, f, "DELETE FROM recording_segments WHERE id = (SELECT segment_id FROM integrity_chain WHERE seq = 1)")
		exec(t, f, "PRAGMA foreign_keys = ON")
		if rep := verifyAnchors(t, f, anchors); rep.OK || !hasProblem(rep, "no longer exists") {
			t.Fatalf("report %+v", rep)
		}
	})
	t.Run("conflicting anchors", func(t *testing.T) {
		f, anchors := anchoredFixture(t)
		line := strings.SplitN(anchors, "\n", 2)[0]
		other := strings.Replace(line, `"hash":"`, `"hash":"00`, 1)
		other = other[:strings.Index(other, `"hash":"`)+8+64] + `","at":"x"}`
		if rep := verifyAnchors(t, f, anchors+other+"\n"); rep.OK || !hasProblem(rep, "two different hashes") {
			t.Fatalf("report %+v", rep)
		}
	})
	t.Run("malformed input", func(t *testing.T) {
		f, _ := anchoredFixture(t)
		for _, in := range []string{"", "\n\n", "not json\n", `{"seq":0,"hash":"00"}`, `{"seq":1,"hash":"zz"}`, `{"seq":1,"hash":"` + strings.Repeat("0", 64) + `","x":1}`} {
			if _, err := VerifyAnchors(context.Background(), f.a.Store.ReadDB(), strings.NewReader(in)); err == nil {
				t.Errorf("accepted %q", in)
			}
		}
	})
}
