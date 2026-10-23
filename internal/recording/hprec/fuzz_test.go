package hprec

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// fuzzSeeds builds valid segments under w: they seed the corpus and are the only sources of authentic records.
func fuzzSeeds(f *testing.F, w *testWrapper) [][]Record {
	f.Helper()
	dir := f.TempDir()
	var all [][]Record
	add := func(name string, kind Kind, n, maxPayload, flushEvery int, rewrap bool, cut int) {
		recs := genRecords(newRand(), kind, n, maxPayload)
		path := filepath.Join(dir, name)
		writeSegment(f, path, testHeader(kind), w, recs, flushEvery)
		if rewrap {
			if _, err := RewrapSlot(path, w, w); err != nil {
				f.Fatal(err)
			}
		}
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		if cut > 0 {
			data = data[:len(data)-cut]
		}
		f.Add(data)
		all = append(all, recs)
	}
	add("pty", KindPTY, 12, 40, 3, false, 0)
	add("exec", KindExec, 8, 20, 2, true, 0)
	add("empty", KindExec, 0, 0, 0, false, 0)
	add("truncated", KindPTY, 10, 30, 2, false, 7)
	return all
}

// FuzzReader feeds arbitrary bytes to the reader. It must never panic, never use more than one frame of memory per
// step, and never yield a record that was not written by an authentic segment under the fuzz key: every record
// sequence it yields must be a prefix of a seed segment's records.
func FuzzReader(f *testing.F) {
	w := newTestWrapper(f, "fuzz")
	seeds := fuzzSeeds(f, w)
	f.Add([]byte(Magic))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := NewReader(bytes.NewReader(data), w)
		var got []Record
		var end error
		if err == nil {
			for {
				rec, err := r.Next()
				if err != nil {
					end = err
					break
				}
				got = append(got, rec)
			}
			if !errors.Is(end, io.EOF) && !errors.Is(end, ErrIncomplete) && !errors.Is(end, ErrCorrupt) {
				t.Fatalf("unexpected terminal error %v", end)
			}
		} else if !formatError(err) {
			t.Fatalf("unexpected open error %v", err)
		}
		if len(got) > 0 {
			ok := false
			for _, s := range seeds {
				if isPrefix(got, s) {
					ok = true
					break
				}
			}
			if !ok {
				t.Fatalf("yielded %d records that are not an authentic prefix", len(got))
			}
		}
		rep, err := VerifyReader(bytes.NewReader(data), w)
		if err != nil {
			t.Fatalf("verify returned an I/O error for in-memory input: %v", err)
		}
		if rep.Status == StatusOK != errors.Is(end, io.EOF) {
			t.Fatalf("verify status %s disagrees with reader end %v", rep.Status, end)
		}
		if rep.ValidOffset > int64(len(data)) {
			t.Fatalf("valid offset %d beyond input %d", rep.ValidOffset, len(data))
		}
	})
}

// FuzzRecordDecode checks that the record codec never panics, is canonical (every accepted encoding re-encodes to the
// same bytes) and that typed payload parsers round-trip.
func FuzzRecordDecode(f *testing.F) {
	base := testEpoch.Truncate(1000).UnixMicro()
	for _, r := range genRecords(newRand(), KindPTY, 30, 16) {
		enc, err := appendRecord(nil, &r, base)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(enc, base)
	}
	fr := footerRecord(Footer{Records: 1, FirstSeq: 1, LastSeq: 1, EndReason: "x"})
	enc, _ := appendRecord(nil, &fr, 0)
	f.Add(enc, int64(0))
	f.Add([]byte{byte(RecExit), 1, 0, 0, 4, 2, 0, 1}, int64(-5))
	f.Fuzz(func(t *testing.T, data []byte, prev int64) {
		rec, us, n, err := decodeRecord(data, prev)
		if err == nil {
			if n <= 0 || n > len(data) {
				t.Fatalf("consumed %d of %d", n, len(data))
			}
			re, err := appendRecord(nil, &rec, prev)
			if err != nil {
				t.Fatalf("decoded record does not re-encode: %v", err)
			}
			if !bytes.Equal(re, data[:n]) {
				t.Fatalf("non-canonical encoding accepted:\n in %x\nout %x", data[:n], re)
			}
			if rec.Time.UnixMicro() != us {
				t.Fatal("time mismatch")
			}
		}
		// Typed payload parsers: accept only canonical encodings.
		if v, err := ParsePTYRequest(data); err == nil && !bytes.Equal(v.Marshal(), data) {
			t.Fatalf("pty request not canonical: %x", data)
		}
		if v, err := ParseResize(data); err == nil && !bytes.Equal(v.Marshal(), data) {
			t.Fatalf("resize not canonical: %x", data)
		}
		if v, err := ParseEnv(data); err == nil && !bytes.Equal(v.Marshal(), data) {
			t.Fatalf("env not canonical: %x", data)
		}
		if v, err := ParseSignal(data); err == nil && !bytes.Equal(v.Marshal(), data) {
			t.Fatalf("signal not canonical: %x", data)
		}
		if v, err := ParseExit(data); err == nil && !bytes.Equal(v.Marshal(), data) {
			t.Fatalf("exit not canonical: %x", data)
		}
		if v, err := ParseNotice(data); err == nil && !bytes.Equal(v.Marshal(), data) {
			t.Fatalf("notice not canonical: %x", data)
		}
		if v, err := ParseFooter(data); err == nil && !bytes.Equal(v.Marshal(), data) {
			t.Fatalf("footer not canonical: %x", data)
		}
		if _, err := decodeSlot(data); err == nil && len(data) != SlotSize {
			t.Fatal("slot of wrong size accepted")
		}
		if h, err := parseHeader(data); err == nil {
			if b, err := encodeHeader(&h); err != nil || !bytes.Equal(b, data) {
				t.Fatalf("header not canonical: %q", data)
			}
		}
	})
}
