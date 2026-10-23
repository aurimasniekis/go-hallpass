package hprec

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"slices"
	"testing"
)

// smallSegment writes a segment with many small frames and returns its bytes and records.
func smallSegment(t *testing.T, w DEKWrapper, hdr Header, n, flushEvery int) ([]byte, []Record, Manifest) {
	t.Helper()
	recs := genRecords(newRand(), hdr.Kind, n, 24)
	path := tempPath(t, "seg.hprec")
	m := writeSegment(t, path, hdr, w, recs, flushEvery)
	return readFile(t, path), recs, m
}

// requireDetected asserts that a modified file is not reported ok and that no unauthentic record is yielded.
func requireDetected(t *testing.T, what string, data []byte, w DEKWrapper, orig []Record, opts ...Option) Report {
	t.Helper()
	rep, err := VerifyReader(bytes.NewReader(data), w, opts...)
	if err != nil {
		t.Fatalf("%s: verify error %v", what, err)
	}
	if rep.Status == StatusOK || rep.Problem == nil {
		t.Fatalf("%s: modification not detected: %+v", what, rep)
	}
	got, err := readAllFrom(bytes.NewReader(data), w, opts...)
	if errors.Is(err, io.EOF) || err == nil {
		t.Fatalf("%s: reader reached a clean end", what)
	}
	if !isPrefix(got, orig) {
		t.Fatalf("%s: reader yielded records that are not an authentic prefix", what)
	}
	return rep
}

func TestTamperEveryByte(t *testing.T) {
	w := newTestWrapper(t, "k")
	data, recs, _ := smallSegment(t, w, testHeader(KindPTY), 12, 3)
	l := parseLayout(t, data)
	if len(l.frames) < 4 {
		t.Fatalf("want >= 4 frames, got %d", len(l.frames))
	}
	for pos := range data {
		mut := bytes.Clone(data)
		mut[pos] ^= 1 << (pos % 8)
		if pos >= l.slotB && pos < l.slotB+SlotSize {
			// Slot B is empty and unused: the content is unaffected, but verification reports the damaged slot.
			rep, err := VerifyReader(bytes.NewReader(mut), w)
			if err != nil || rep.Status != StatusOK || !rep.Slots[1].Present || rep.Slots[1].Decoded {
				t.Fatalf("slot B byte %d: %+v %v", pos, rep, err)
			}
			continue
		}
		rep := requireDetected(t, "byte", mut, w, recs)
		switch {
		case pos < l.slotA:
			if rep.Frames != 0 {
				t.Fatalf("header byte %d: frames authenticated", pos)
			}
		case pos < l.slotB:
			if !errors.Is(rep.Problem, ErrNoKey) || rep.Slots[0].Unwraps {
				t.Fatalf("slot A byte %d: %+v", pos, rep)
			}
		}
	}
}

func TestTamperRegions(t *testing.T) {
	w := newTestWrapper(t, "k")
	data, recs, m := smallSegment(t, w, testHeader(KindExec), 40, 5)
	l := parseLayout(t, data)
	last := len(l.frames) - 1
	nonFinalRecs := 0
	{ // count records outside the final frame
		got, _ := readAllFrom(bytes.NewReader(data[:l.frames[last]]), w)
		nonFinalRecs = len(got)
	}

	t.Run("drop final frame", func(t *testing.T) {
		mut := data[:l.frames[last]]
		rep := requireDetected(t, "drop final", mut, w, recs)
		if rep.Status != StatusInterrupted || !errors.Is(rep.Problem, ErrIncomplete) || rep.Frames != uint64(last) {
			t.Fatalf("%+v", rep)
		}
		got, err := readAllFrom(bytes.NewReader(mut), w)
		if !errors.Is(err, ErrIncomplete) || len(got) != nonFinalRecs {
			t.Fatalf("got %d records, err %v", len(got), err)
		}
	})
	t.Run("truncate everywhere", func(t *testing.T) {
		for cut := 0; cut < len(data); cut++ {
			mut := data[:cut]
			rep := requireDetected(t, "truncate", mut, w, recs)
			if cut >= l.frames[0] && rep.Status != StatusInterrupted {
				t.Fatalf("cut %d: %+v", cut, rep)
			}
			if cut < l.frames[0] && rep.Status != StatusCorrupt {
				t.Fatalf("cut %d in prefix: %+v", cut, rep)
			}
		}
	})
	t.Run("reorder frames", func(t *testing.T) {
		mut := slices.Concat(data[:l.frames[1]], l.frame(data, 2), l.frame(data, 1), data[l.frames[3]:])
		rep := requireDetected(t, "reorder", mut, w, recs)
		if rep.Status != StatusCorrupt || rep.Frames != 1 {
			t.Fatalf("%+v", rep)
		}
	})
	t.Run("duplicate frame", func(t *testing.T) {
		mut := slices.Concat(data[:l.frames[2]], l.frame(data, 1), data[l.frames[2]:])
		if rep := requireDetected(t, "duplicate", mut, w, recs); rep.Status != StatusCorrupt {
			t.Fatalf("%+v", rep)
		}
	})
	t.Run("delete middle frame", func(t *testing.T) {
		mut := slices.Concat(data[:l.frames[1]], data[l.frames[2]:])
		if rep := requireDetected(t, "delete", mut, w, recs); rep.Status != StatusCorrupt {
			t.Fatalf("%+v", rep)
		}
	})
	t.Run("final frame moved earlier", func(t *testing.T) {
		mut := slices.Concat(data[:l.frames[1]], l.frame(data, last))
		if rep := requireDetected(t, "final moved", mut, w, recs); rep.Status != StatusCorrupt {
			t.Fatalf("%+v", rep)
		}
	})
	t.Run("data after final frame", func(t *testing.T) {
		mut := slices.Concat(data, []byte{0})
		rep := requireDetected(t, "trailing", mut, w, recs)
		if rep.Status != StatusCorrupt || !rep.Final || rep.ValidOffset != int64(len(data)) || rep.CiphertextSHA256 != m.CiphertextSHA256 {
			t.Fatalf("%+v", rep)
		}
		got, err := readAllFrom(bytes.NewReader(mut), w)
		if !errors.Is(err, ErrCorrupt) || len(got) != len(recs) {
			t.Fatalf("got %d, %v", len(got), err)
		}
	})
	t.Run("frame length", func(t *testing.T) {
		for _, v := range []uint32{0, 1, minCTLen - 1, maxCTLen + 1, 1 << 31} {
			mut := bytes.Clone(data)
			binary.BigEndian.PutUint32(mut[l.frames[1]:], v)
			requireDetected(t, "length", mut, w, recs)
		}
	})
	t.Run("final frame tag", func(t *testing.T) {
		mut := bytes.Clone(data)
		mut[len(mut)-1] ^= 0x80
		rep := requireDetected(t, "tag", mut, w, recs)
		if rep.Status != StatusCorrupt || rep.Frames != uint64(last) {
			t.Fatalf("%+v", rep)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		other := newTestWrapper(t, "k") // same key ID, different key
		rep, err := VerifyReader(bytes.NewReader(data), other)
		if err != nil || rep.Status != StatusCorrupt || !errors.Is(rep.Problem, ErrNoKey) || !rep.HeaderParsed {
			t.Fatalf("%+v %v", rep, err)
		}
	})
}

func TestSwapFramesBetweenSegments(t *testing.T) {
	w := newTestWrapper(t, "k")
	// Two segments of the same channel with identical IDs: only the DEK, salt and H differ.
	a, recsA, _ := smallSegment(t, w, testHeader(KindPTY), 30, 5)
	b, _, _ := smallSegment(t, w, testHeader(KindPTY), 30, 5)
	la, lb := parseLayout(t, a), parseLayout(t, b)
	if bytes.Equal(a[la.frames[1]:], b[lb.frames[1]:]) {
		t.Fatal("segments are identical")
	}
	mut := slices.Concat(a[:la.frames[1]], lb.frame(b, 1), a[la.frames[2]:])
	if rep := requireDetected(t, "frame swap", mut, w, recsA); rep.Status != StatusCorrupt || rep.Frames != 1 {
		t.Fatalf("%+v", rep)
	}
	// Header of A with the slots and frames of B.
	mut = slices.Concat(a[:la.slotA], b[lb.slotA:])
	if rep := requireDetected(t, "header swap", mut, w, recsA); !errors.Is(rep.Problem, ErrNoKey) {
		t.Fatalf("%+v", rep)
	}
	// Header and slots of A with all frames of B.
	mut = slices.Concat(a[:la.frames[0]], b[lb.frames[0]:])
	if rep := requireDetected(t, "frames swap", mut, w, recsA); rep.Status != StatusCorrupt || rep.Frames != 0 {
		t.Fatalf("%+v", rep)
	}
	// Slot A of B in A.
	mut = slices.Concat(a[:la.slotA], b[lb.slotA:lb.slotB], a[la.slotB:])
	if rep := requireDetected(t, "slot swap", mut, w, recsA); !errors.Is(rep.Problem, ErrNoKey) {
		t.Fatalf("%+v", rep)
	}
}

func TestSwapSegmentFilesBetweenSessions(t *testing.T) {
	w := newTestWrapper(t, "k")
	h1, h2 := testHeader(KindPTY), testHeader(KindPTY)
	h2.SessionID, h2.SegmentID, h2.ChannelID = "ses_other", "seg_other", "chn_other"
	p1, p2 := tempPath(t, "s1.hprec"), tempPath(t, "s2.hprec")
	recs := genRecords(newRand(), KindPTY, 10, 16)
	m1 := writeSegment(t, p1, h1, w, recs, 0)
	m2 := writeSegment(t, p2, h2, w, recs, 0)
	// Swap the files on disk.
	d1, d2 := readFile(t, p1), readFile(t, p2)
	if err := os.WriteFile(p1, d2, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p2, d1, 0o600); err != nil {
		t.Fatal(err)
	}
	// Each file is internally consistent, so detection relies on the expectations the database provides.
	for _, opts := range [][]Option{
		{ExpectSessionID(h1.SessionID)},
		{ExpectSegmentID(h1.SegmentID)},
		{ExpectChannelID(h1.ChannelID)},
		{ExpectHeaderSHA256(m1.HeaderSHA256)},
	} {
		if _, err := Open(p1, w, opts...); !errors.Is(err, ErrHeaderMismatch) || !errors.Is(err, ErrCorrupt) {
			t.Fatalf("swap not detected: %v", err)
		}
		rep, err := Verify(p1, w, opts...)
		if err != nil || rep.Status != StatusCorrupt || !errors.Is(rep.Problem, ErrHeaderMismatch) || rep.ValidOffset != 0 {
			t.Fatalf("%+v %v", rep, err)
		}
	}
	if rep, err := Verify(p1, w, ExpectHeaderSHA256(m2.HeaderSHA256), ExpectSessionID(h2.SessionID)); err != nil || rep.Status != StatusOK {
		t.Fatalf("%+v %v", rep, err)
	}
}

// forge seals arbitrary plaintext frames with the segment key, as only a key holder could. It checks that the
// reader's structural validation rejects authenticated but malformed frames.
func TestForgedFramesWithKey(t *testing.T) {
	w := newTestWrapper(t, "k")
	rec := func(seq uint64) []byte {
		b, err := appendRecord(nil, &Record{Type: RecStdout, Seq: seq, Time: testEpoch, Stream: StreamStdout, Payload: []byte("x")}, testEpoch.Truncate(1000).UnixMicro())
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	footer := func(ft Footer) []byte {
		fr := footerRecord(ft)
		b, _ := appendRecord(nil, &fr, 0)
		return b
	}
	type frame struct {
		pt    []byte
		final bool
	}
	cases := []struct {
		name   string
		frames []frame
		want   error
	}{
		{"empty frame", []frame{{nil, false}}, ErrCorrupt},
		{"final without footer", []frame{{rec(1), true}}, ErrCorrupt},
		{"footer in non-final", []frame{{footer(Footer{EndReason: "x"}), false}}, ErrCorrupt},
		{"footer not last", []frame{{slices.Concat(footer(Footer{EndReason: "x"}), rec(1)), true}}, ErrCorrupt},
		{"seq not increasing", []frame{{slices.Concat(rec(2), rec(2)), false}}, ErrCorrupt},
		{"seq zero", []frame{{rec(0), false}}, ErrCorrupt},
		{"seq decreasing across frames", []frame{{rec(5), false}, {rec(4), false}}, ErrCorrupt},
		{"footer count wrong", []frame{{slices.Concat(rec(1), footer(Footer{Records: 2, FirstSeq: 1, LastSeq: 2, EndReason: "x"})), true}}, ErrCorrupt},
		{"footer hash wrong", []frame{{slices.Concat(rec(1), footer(Footer{Records: 1, FirstSeq: 1, LastSeq: 1, EndReason: "x"})), true}}, ErrCorrupt},
		{"garbage record", []frame{{[]byte{0xff, 1, 2}, false}}, ErrCorrupt},
		{"non-canonical footer", []frame{{slices.Concat(rec(1), []byte{byte(RecSegmentFooter), 1, 0, 0, 4, 0}), true}}, ErrCorrupt},
		{"valid prefix then nothing", []frame{{rec(1), false}}, ErrIncomplete},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := tempPath(t, "f.hprec")
			sw, err := Create(path, testHeader(KindExec), w)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range tc.frames {
				sw.pending = append(sw.pending[:0], f.pt...)
				if err := sw.seal(f.final); err != nil {
					t.Fatal(err)
				}
			}
			_ = sw.Close()
			data := readFile(t, path+PartialSuffix)
			_, err = readAllFrom(bytes.NewReader(data), w)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestHeaderParsing(t *testing.T) {
	h := testHeader(KindPTY)
	h.normalize()
	h.PayloadSalt = [SaltSize]byte{1, 2, 3}
	canon, err := encodeHeader(&h)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseHeader(canon)
	if err != nil {
		t.Fatal(err)
	}
	if got.SegmentID != h.SegmentID || !got.CreatedAt.Equal(h.CreatedAt) || got.PayloadSalt != h.PayloadSalt {
		t.Fatalf("%+v", got)
	}
	want := `{"aead":"chacha20poly1305-stream","channel_id":"chn_01jabcdefghjkmnpqrstvwxyz0","created_at":"2026-10-23T12:00:00.123456Z","frame_max":65536,"kind":"pty","ordinal":0,"payload_salt":"AQIDAAAAAAAAAAAAAAAAAA==","prev_segment_sha256":"","segment_id":"seg_01jabcdefghjkmnpqrstvwxyz0","session_id":"ses_01jabcdefghjkmnpqrstvwxyz0","v":1}`
	if string(canon) != want {
		t.Fatalf("canonical header:\n%s\nwant\n%s", canon, want)
	}
	s := string(canon)
	replace := func(old, new string) []byte { return []byte(bytesReplace(s, old, new)) }
	bad := map[string][]byte{
		"whitespace":   replace(`"v":1`, `"v": 1`),
		"extra field":  replace(`"v":1`, `"v":1,"x":1`),
		"duplicate":    replace(`"v":1`, `"v":1,"v":1`),
		"key case":     replace(`"aead"`, `"AEAD"`),
		"salt short":   replace(`AQIDAAAAAAAAAAAAAAAAAA==`, `AQID`),
		"salt bad b64": replace(`AQIDAAAAAAAAAAAAAAAAAA==`, `AQIDAAAAAAAAAAAAAAAAAA=!`),
		"time format":  replace(`2026-10-23T12:00:00.123456Z`, `2026-10-23T12:00:00.123Z`),
		"kind":         replace(`"pty"`, `"tty"`),
		"prev hex":     replace(`"prev_segment_sha256":""`, `"prev_segment_sha256":"zz"`),
		"prev on ord0": replace(`"prev_segment_sha256":""`, `"prev_segment_sha256":"00"`),
		"not json":     []byte("{"),
		"wrong type":   replace(`"ordinal":0`, `"ordinal":"0"`),
	}
	for name, b := range bad {
		if _, err := parseHeader(b); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, b := range map[string][]byte{
		"version":   replace(`"v":1`, `"v":2`),
		"aead":      replace(`chacha20poly1305-stream`, `aes-gcm`),
		"frame_max": replace(`65536`, `1024`),
	} {
		if _, err := parseHeader(b); !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Magic variants.
	w := newTestWrapper(t, "k")
	for _, prefix := range []string{"HPREC2\n\x00", "NOTHPREC"} {
		data := slices.Concat([]byte(prefix), []byte{0, 0, 0, 2}, []byte("{}"))
		_, err := NewReader(bytes.NewReader(data), w)
		if !errors.Is(err, ErrUnsupportedVersion) && !errors.Is(err, ErrCorrupt) {
			t.Fatalf("%q: %v", prefix, err)
		}
	}
	for _, n := range []uint32{0, MaxHeaderLen + 1} {
		data := binary.BigEndian.AppendUint32([]byte(Magic), n)
		if _, err := NewReader(bytes.NewReader(data), w); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("header_len %d: %v", n, err)
		}
	}
}

func bytesReplace(s, old, new string) string {
	return string(bytes.Replace([]byte(s), []byte(old), []byte(new), 1))
}

type errReader struct {
	data []byte
	err  error
}

func (e *errReader) Read(p []byte) (int, error) {
	if len(e.data) == 0 {
		return 0, e.err
	}
	n := copy(p, e.data)
	e.data = e.data[n:]
	return n, nil
}

func TestReaderIOErrors(t *testing.T) {
	w := newTestWrapper(t, "k")
	data, _, _ := smallSegment(t, w, testHeader(KindPTY), 30, 5)
	l := parseLayout(t, data)
	ioErr := errors.New("disk on fire")
	for _, cut := range []int{4, l.slotA + 10, l.frames[0] + 2, l.frames[1] + 10, len(data)} {
		_, err := readAllFrom(&errReader{data: bytes.Clone(data[:cut]), err: ioErr}, w)
		if !errors.Is(err, ioErr) {
			t.Fatalf("cut %d: %v", cut, err)
		}
		if _, err := VerifyReader(&errReader{data: bytes.Clone(data[:cut]), err: ioErr}, w); !errors.Is(err, ioErr) {
			t.Fatalf("verify cut %d: %v", cut, err)
		}
	}
	if _, err := Verify(tempPath(t, "missing.hprec"), w); err == nil {
		t.Fatal("verify of a missing file succeeded")
	}
	if _, err := Open(tempPath(t, "missing.hprec"), w); err == nil {
		t.Fatal("open of a missing file succeeded")
	}
}
