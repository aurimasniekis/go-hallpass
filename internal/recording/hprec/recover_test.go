package hprec

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// crashedSegment writes recs, flushing after flushed records, appends the rest without flushing or finalizing and
// "crashes" (closes the file). It returns the final path and the number of records in sealed frames.
func crashedSegment(t *testing.T, dir string, w DEKWrapper, recs []Record, flushed int) (string, int) {
	t.Helper()
	path := filepath.Join(dir, "seg.hprec")
	sw, err := Create(path, testHeader(KindPTY), w)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range recs {
		if err := sw.Append(r); err != nil {
			t.Fatal(err)
		}
		if i+1 == flushed {
			if err := sw.Flush(); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Records still pending in memory are lost in the crash.
	if err := sw.Close(); err != nil {
		t.Fatal(err)
	}
	return path, flushed
}

func TestRecoverTrailingGarbage(t *testing.T) {
	w := newTestWrapper(t, "k")
	recs := genRecords(newRand(), KindPTY, 200, 512)
	for _, tail := range map[string]func(valid []byte) []byte{
		"half frame": func(valid []byte) []byte {
			// The start of a real frame from the same file: a torn append.
			l := parseLayout(t, valid)
			f := l.frame(valid, 0)
			return f[:len(f)/2]
		},
		"zero fill": func([]byte) []byte { return make([]byte, 4096) },
		"length only": func([]byte) []byte {
			return []byte{0, 0, 1, 0}
		},
		"garbage": func([]byte) []byte { return bytes.Repeat([]byte{0x5a}, 100) },
		"none":    func([]byte) []byte { return nil },
	} {
		dir := t.TempDir()
		path, flushed := crashedSegment(t, dir, w, recs, 120)
		partial := path + PartialSuffix
		valid := readFile(t, partial)
		orig := slices.Concat(valid, tail(valid))
		if err := os.WriteFile(partial, orig, 0o600); err != nil {
			t.Fatal(err)
		}
		q := filepath.Join(dir, "quarantine", "seg.hprec.orig")
		if err := os.MkdirAll(filepath.Dir(q), 0o700); err != nil {
			t.Fatal(err)
		}
		res, err := Recover(partial, w, q)
		if err != nil {
			t.Fatal(err)
		}
		if res.Complete || res.Path != path || res.Bytes != int64(len(valid)) || res.DiscardedBytes != int64(len(orig)-len(valid)) {
			t.Fatalf("result %+v", res)
		}
		if res.Records != uint64(flushed) || res.LastSeq != recs[flushed-1].Seq || res.FirstSeq != recs[0].Seq {
			t.Fatalf("records %d last %d", res.Records, res.LastSeq)
		}
		if res.CiphertextSHA256 != sha256.Sum256(valid[parseLayout(t, valid).frames[0]:]) {
			t.Fatal("ciphertext hash does not cover the valid prefix")
		}
		if _, err := os.Stat(partial); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("partial file still present")
		}
		if got := readFile(t, path); !bytes.Equal(got, valid) {
			t.Fatal("recovered file is not the valid prefix")
		}
		if res.DiscardedBytes > 0 {
			if res.QuarantinePath != q || !bytes.Equal(readFile(t, q), orig) {
				t.Fatal("quarantine copy differs from the original")
			}
		} else if res.QuarantinePath != "" {
			t.Fatal("quarantined although nothing was discarded")
		}
		rep, err := Verify(path, w)
		if err != nil || rep.Status != StatusInterrupted || rep.Records != uint64(flushed) || rep.ValidOffset != rep.FileSize {
			t.Fatalf("%+v %v", rep, err)
		}
		pg, err := ReadPage(path, w, 0, 0)
		if err != nil || !pg.Incomplete || pg.Complete {
			t.Fatalf("page %+v %v", pg.Incomplete, err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		got, err := readAllFrom(f, w)
		_ = f.Close()
		if !errors.Is(err, ErrIncomplete) {
			t.Fatal(err)
		}
		requireRecords(t, got, recs[:flushed])
	}
}

func TestRecoverCompleteBeforeRename(t *testing.T) {
	w := newTestWrapper(t, "k")
	recs := genRecords(newRand(), KindExec, 30, 64)
	dir := t.TempDir()
	path := filepath.Join(dir, "seg.hprec")
	m := writeSegment(t, path, testHeader(KindExec), w, recs, 0)
	// Simulate a crash between the final fsync and the rename.
	if err := os.Rename(path, path+PartialSuffix); err != nil {
		t.Fatal(err)
	}
	res, err := Recover(path+PartialSuffix, w, "", ExpectHeaderSHA256(m.HeaderSHA256))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete || res.Problem != nil || res.DiscardedBytes != 0 || res.CiphertextSHA256 != m.CiphertextSHA256 ||
		res.Frames != m.Frames || res.EndReason != "channel.closed" || res.Bytes != m.Bytes {
		t.Fatalf("%+v", res)
	}
	if rep, err := Verify(path, w); err != nil || rep.Status != StatusOK {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestRecoverEdgeCases(t *testing.T) {
	w := newTestWrapper(t, "k")
	dir := t.TempDir()

	// Crash right after Create: zero frames, still a valid interrupted segment.
	path := filepath.Join(dir, "empty.hprec")
	sw, err := Create(path, testHeader(KindPTY), w)
	if err != nil {
		t.Fatal(err)
	}
	_ = sw.Close()
	res, err := Recover(path+PartialSuffix, w, filepath.Join(dir, "q0"))
	if err != nil || res.Complete || res.Frames != 0 || res.Records != 0 || res.DiscardedBytes != 0 {
		t.Fatalf("%+v %v", res, err)
	}

	// Trailing bytes but no quarantine path: nothing changes.
	path = filepath.Join(dir, "noq.hprec")
	sw, err = Create(path, testHeader(KindPTY), w)
	if err != nil {
		t.Fatal(err)
	}
	_ = sw.Close()
	appendBytesToFile(t, path+PartialSuffix, []byte{1, 2, 3})
	if _, err := Recover(path+PartialSuffix, w, ""); err == nil {
		t.Fatal("recovered without a quarantine path")
	}
	// Existing quarantine file: O_EXCL refuses to overwrite it.
	q := filepath.Join(dir, "q-existing")
	if err := os.WriteFile(q, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Recover(path+PartialSuffix, w, q); err == nil {
		t.Fatal("overwrote an existing quarantine file")
	}
	if _, err := os.Stat(path + PartialSuffix); err != nil {
		t.Fatal("partial file was modified after a failed quarantine copy")
	}

	// Unusable header: no changes.
	bad := filepath.Join(dir, "bad.hprec"+PartialSuffix)
	if err := os.WriteFile(bad, []byte("not a segment at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Recover(bad, w, filepath.Join(dir, "q1")); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(bad); err != nil {
		t.Fatal("unusable partial was touched")
	}
	// Wrong key: no changes.
	if _, err := Recover(path+PartialSuffix, newTestWrapper(t, "k"), filepath.Join(dir, "q2")); !errors.Is(err, ErrNoKey) {
		t.Fatalf("%v", err)
	}

	// Argument checks.
	if _, err := Recover(filepath.Join(dir, "x.hprec"), w, ""); err == nil {
		t.Fatal("accepted a non-partial path")
	}
	if _, err := Recover(PartialSuffix, w, ""); err == nil {
		t.Fatal("accepted a bare suffix")
	}
	final := filepath.Join(dir, "both.hprec")
	if err := os.WriteFile(final, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(final+PartialSuffix, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Recover(final+PartialSuffix, w, ""); err == nil {
		t.Fatal("overwrote an existing final file")
	}
	if _, err := Recover(filepath.Join(dir, "missing.hprec"+PartialSuffix), w, ""); err == nil {
		t.Fatal("recovered a missing file")
	}
}

func TestRecoverCorruptMiddleFrame(t *testing.T) {
	// A frame that fails authentication in the middle: recovery keeps only the prefix before it (PLAN §13.6),
	// quarantining the original so that nothing is lost.
	w := newTestWrapper(t, "k")
	recs := genRecords(newRand(), KindPTY, 60, 32)
	dir := t.TempDir()
	path, _ := crashedSegment(t, dir, w, recs, 60)
	partial := path + PartialSuffix
	data := readFile(t, partial)
	l := parseLayout(t, data)
	data[l.frames[0]+10] ^= 1
	if err := os.WriteFile(partial, data, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Recover(partial, w, filepath.Join(dir, "q"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Frames != 0 || !errors.Is(res.Problem, ErrCorrupt) || res.DiscardedBytes != int64(len(data)-l.frames[0]) {
		t.Fatalf("%+v", res)
	}
}

func appendBytesToFile(t *testing.T, path string, b []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRewrapWhileWriting(t *testing.T) {
	w1, w2 := newTestWrapper(t, "v1"), newTestWrapper(t, "v2")
	recs := genRecords(newRand(), KindPTY, 100, 256)
	path := tempPath(t, "seg.hprec")
	sw, err := Create(path, testHeader(KindPTY), w1)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range recs {
		if err := sw.Append(r); err != nil {
			t.Fatal(err)
		}
		if i == 50 {
			if err := sw.Flush(); err != nil {
				t.Fatal(err)
			}
			if _, err := RewrapSlot(sw.PartialPath(), w1, w2); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := sw.Finalize("closed"); err != nil {
		t.Fatal(err)
	}
	requireReadable(t, path, w2, recs, 1, 2)
}

func TestNonceUniqueness(t *testing.T) {
	seen := map[[12]byte]bool{}
	add := func(i uint64, final bool) {
		n := frameNonce(i, final)
		if seen[n] {
			t.Fatalf("nonce repeated for frame %d final=%v", i, final)
		}
		seen[n] = true
		if n[0] != 0 || n[1] != 0 || n[2] != 0 || n[11] > 1 {
			t.Fatalf("nonce layout %x", n)
		}
	}
	rnd := newRand()
	for i := range uint64(100000) {
		add(i, false)
		add(i, true)
	}
	for range 100000 {
		i := rnd.Uint64()
		if i < 100000 {
			continue
		}
		n := frameNonce(i, false)
		if seen[n] {
			continue // the same random counter drawn twice
		}
		add(i, false)
		add(i, true)
	}

	// In a real file each frame authenticates only under its own counter and flag.
	w := newTestWrapper(t, "k")
	data, _, _ := smallSegment(t, w, testHeader(KindExec), 40, 4)
	l := parseLayout(t, data)
	r, err := NewReader(bytes.NewReader(data), w)
	if err != nil {
		t.Fatal(err)
	}
	h := r.HeaderSHA256()
	last := uint64(len(l.frames) - 1)
	for i := range len(l.frames) {
		ct := l.frame(data, i)[frameLenSize:]
		for j := range uint64(len(l.frames)) {
			for _, final := range []bool{false, true} {
				n := frameNonce(j, final)
				_, err := r.aead.Open(nil, n[:], ct, h[:])
				want := j == uint64(i) && final == (j == last)
				if (err == nil) != want {
					t.Fatalf("frame %d opened with nonce (%d,%v): %v", i, j, final, err)
				}
			}
		}
	}
}

func TestReadPage(t *testing.T) {
	w := newTestWrapper(t, "k")
	recs := genRecords(newRand(), KindPTY, 1500, 4096)
	path := tempPath(t, "seg.hprec")
	writeSegment(t, path, testHeader(KindPTY), w, recs, 25)

	for _, maxBytes := range []int{0, 10_000, 64 << 10, MaxPageBytes, 10 * MaxPageBytes} {
		var got []Record
		from := uint64(0)
		pages := 0
		for {
			pg, err := ReadPage(path, w, from, maxBytes)
			if err != nil {
				t.Fatal(err)
			}
			pages++
			size := 0
			for i := range pg.Records {
				size += pageCost(&pg.Records[i])
			}
			limit := maxBytes
			if limit <= 0 || limit > MaxPageBytes {
				limit = MaxPageBytes
			}
			if size > limit && len(pg.Records) > 1 {
				t.Fatalf("page of %d bytes exceeds %d", size, limit)
			}
			got = append(got, pg.Records...)
			if !pg.More {
				if !pg.Complete || pg.Incomplete {
					t.Fatalf("last page %+v", pg)
				}
				break
			}
			if pg.NextSeq <= pg.Records[len(pg.Records)-1].Seq {
				t.Fatal("NextSeq does not advance")
			}
			from = pg.NextSeq
		}
		requireRecords(t, got, recs)
		if pages < 2 {
			t.Fatalf("maxBytes %d: only %d page(s)", maxBytes, pages)
		}
	}

	// A budget smaller than any record still makes progress: one record per page.
	r1, err := Open(path, w)
	if err != nil {
		t.Fatal(err)
	}
	defer r1.Close()
	var tiny []Record
	for {
		pg, err := r1.ReadPage(0, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(pg.Records) > 1 {
			t.Fatalf("page of %d records with a 1-byte budget", len(pg.Records))
		}
		tiny = append(tiny, pg.Records...)
		if !pg.More {
			break
		}
	}
	requireRecords(t, tiny, recs)

	// Sequential paging on one reader, from the middle.
	r, err := Open(path, w)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	mid := recs[700].Seq
	pg, err := r.ReadPage(mid, 0)
	if err != nil || pg.Records[0].Seq != mid {
		t.Fatalf("%v %v", pg.Records[0].Seq, err)
	}
	pg2, err := r.ReadPage(pg.NextSeq, 0)
	if err != nil || pg2.Records[0].Seq != pg.NextSeq {
		t.Fatal("sequential page does not continue")
	}

	// Corrupt segment: the authentic records before the failure come back with the error.
	data := readFile(t, path)
	l := parseLayout(t, data)
	data[l.frames[3]+20] ^= 1
	bad := tempPath(t, "bad.hprec")
	if err := os.WriteFile(bad, data, 0o600); err != nil {
		t.Fatal(err)
	}
	r2, err := Open(bad, w)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	var paged []Record
	for {
		pg, err := r2.ReadPage(0, 0)
		paged = append(paged, pg.Records...)
		if err != nil {
			if !errors.Is(err, ErrCorrupt) {
				t.Fatal(err)
			}
			break
		}
		if !pg.More {
			t.Fatal("corrupt segment paged to the end")
		}
	}
	if len(paged) == 0 || !isPrefix(paged, recs) {
		t.Fatal("no authentic prefix returned")
	}
	if _, err := ReadPage(tempPath(t, "missing"), w, 0, 0); err == nil {
		t.Fatal("paged a missing file")
	}
}

func TestAllYieldsError(t *testing.T) {
	w := newTestWrapper(t, "k")
	data, recs, _ := smallSegment(t, w, testHeader(KindPTY), 30, 5)
	l := parseLayout(t, data)
	r, err := NewReader(bytes.NewReader(data[:l.frames[2]]), w)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	var last error
	for rec, err := range r.All() {
		if err != nil {
			last = err
			continue
		}
		if !sameRecord(rec, recs[n]) {
			t.Fatal("record mismatch")
		}
		n++
	}
	if !errors.Is(last, ErrIncomplete) || n == 0 {
		t.Fatalf("%d %v", n, last)
	}
	// Breaking out of the loop early is allowed.
	r2, _ := NewReader(bytes.NewReader(data), w)
	for _, err := range r2.All() {
		if err != nil {
			t.Fatal(err)
		}
		break
	}
	if err := r2.Close(); err != nil {
		t.Fatal(err)
	}
	_, ok := r2.Footer()
	if ok {
		t.Fatal("footer before the end")
	}
}
