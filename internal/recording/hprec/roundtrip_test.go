package hprec

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	cases := []struct {
		name       string
		kind       Kind
		n          int
		maxPayload int
		flushEvery int
		minFrames  uint64
	}{
		{"pty many frames", KindPTY, 3000, 2048, 37, 20},
		{"pty no flush", KindPTY, 2000, 4096, 0, 40},
		{"exec", KindExec, 500, 8192, 10, 10},
		{"exec large payloads", KindExec, 40, MaxRecordPayload, 0, 10},
		{"empty", KindExec, 0, 0, 0, 1},
		{"single", KindPTY, 1, 0, 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newTestWrapper(t, "rec-v1")
			recs := genRecords(newRand(), tc.kind, tc.n, tc.maxPayload)
			path := tempPath(t, "seg.hprec")
			m := writeSegment(t, path, testHeader(tc.kind), w, recs, tc.flushEvery)

			if _, err := os.Stat(path + PartialSuffix); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("partial file still exists: %v", err)
			}
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o600 {
				t.Fatalf("mode %v", fi.Mode().Perm())
			}
			if m.Bytes != fi.Size() || m.Records != uint64(tc.n) || m.Frames < tc.minFrames || m.Path != path ||
				m.EndReason != "channel.closed" || m.SegmentID != testHeader(tc.kind).SegmentID {
				t.Fatalf("manifest %+v (size %d)", m, fi.Size())
			}
			if tc.n > 0 && (m.FirstSeq != recs[0].Seq || m.LastSeq != recs[tc.n-1].Seq) {
				t.Fatalf("seq range %d..%d", m.FirstSeq, m.LastSeq)
			}
			data := readFile(t, path)
			l := parseLayout(t, data)
			if uint64(len(l.frames)) != m.Frames {
				t.Fatalf("layout has %d frames, manifest %d", len(l.frames), m.Frames)
			}
			if sha256.Sum256(data[l.frames[0]:]) != m.CiphertextSHA256 {
				t.Fatal("ciphertext_sha256 does not cover the frames region")
			}
			if headerHash(data[prefixFixed:prefixFixed+l.headerLen]) != m.HeaderSHA256 {
				t.Fatal("header_sha256 mismatch")
			}

			r, err := Open(path, w, ExpectSegmentID(m.SegmentID), ExpectHeaderSHA256(m.HeaderSHA256),
				ExpectSessionID(testHeader(tc.kind).SessionID), ExpectChannelID(testHeader(tc.kind).ChannelID))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			var got []Record
			for rec, err := range r.All() {
				if err != nil {
					t.Fatal(err)
				}
				if rec.Time.Location() != time.UTC {
					t.Fatal("record time not UTC")
				}
				got = append(got, rec)
			}
			requireRecords(t, got, recs)
			if _, err := r.Next(); !errors.Is(err, io.EOF) {
				t.Fatalf("Next after end: %v", err)
			}
			ft, ok := r.Footer()
			if !ok || ft.Records != m.Records || ft.EndReason != "channel.closed" {
				t.Fatalf("footer %+v %v", ft, ok)
			}
			if r.Frames() != m.Frames || r.CiphertextSHA256() != m.CiphertextSHA256 || r.ValidOffset() != m.Bytes {
				t.Fatal("reader stats differ from manifest")
			}
			hdr := r.Header()
			if hdr.Kind != tc.kind || !hdr.CreatedAt.Equal(testEpoch.Truncate(time.Microsecond)) || r.Slot().Gen != 1 ||
				r.Slot().KeyID != "rec-v1" || r.HeaderSHA256() != m.HeaderSHA256 {
				t.Fatalf("header %+v slot %+v", hdr, r.Slot())
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}

			rep, err := Verify(path, w, ExpectHeaderSHA256(m.HeaderSHA256))
			if err != nil {
				t.Fatal(err)
			}
			if rep.Status != StatusOK || rep.Problem != nil || !rep.Final || rep.Frames != m.Frames ||
				rep.CiphertextSHA256 != m.CiphertextSHA256 || rep.ValidOffset != rep.FileSize || rep.Records != m.Records ||
				rep.FirstSeq != m.FirstSeq || rep.LastSeq != m.LastSeq || rep.EndReason != "channel.closed" ||
				rep.ActiveSlot != 0 || !rep.Slots[0].Active || !rep.Slots[0].Unwraps || rep.Slots[1].Present {
				t.Fatalf("report %+v", rep)
			}
		})
	}
}

func TestPrepareThenCreate(t *testing.T) {
	w := newTestWrapper(t, "k1")
	hdr := testHeader(KindPTY)
	hdr.Ordinal = 3
	hdr.PrevSegmentSHA256 = bytes.Repeat([]byte{0xab}, 32)
	p, err := Prepare(hdr, w)
	if err != nil {
		t.Fatal(err)
	}
	if p.Slot().KeyID != "k1" || p.Slot().Gen != 1 || len(p.Slot().Wrapped) == 0 {
		t.Fatalf("slot %+v", p.Slot())
	}
	if p.Header().PayloadSalt == ([SaltSize]byte{}) {
		t.Fatal("payload salt not generated")
	}
	// The database copy of the wrapped DEK unwraps under the segment AAD.
	if _, err := w.Unwrap(p.Slot().KeyID, p.Slot().Wrapped, DEKAAD(hdr.SegmentID, p.HeaderSHA256())); err != nil {
		t.Fatal(err)
	}
	path := tempPath(t, "seg.hprec")
	sw, err := p.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if sw.HeaderSHA256() != p.HeaderSHA256() || sw.PartialPath() != path+PartialSuffix || sw.Header().Ordinal != 3 {
		t.Fatal("writer does not match prepared segment")
	}
	if _, err := p.Create(path + "2"); err == nil {
		t.Fatal("prepared segment reused")
	}
	if _, err := os.Stat(path + PartialSuffix); err != nil {
		t.Fatalf("partial missing after Create: %v", err)
	}
	if sw.Size() != int64(prefixFixed+len(mustHeader(t, p.Header()))+2*SlotSize) {
		t.Fatalf("size after create %d", sw.Size())
	}
	m, err := sw.Finalize("done")
	if err != nil {
		t.Fatal(err)
	}
	r, err := Open(path, w)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got := r.Header(); !bytes.Equal(got.PrevSegmentSHA256, hdr.PrevSegmentSHA256) || got.Ordinal != 3 ||
		got.PayloadSalt != p.Header().PayloadSalt {
		t.Fatalf("header %+v", got)
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) || m.Records != 0 {
		t.Fatalf("expected empty segment: %v", err)
	}

	p2, err := Prepare(hdr, w)
	if err != nil {
		t.Fatal(err)
	}
	p2.Discard()
	if _, err := p2.Create(tempPath(t, "x.hprec")); err == nil {
		t.Fatal("discarded prepared segment created")
	}
}

func mustHeader(t *testing.T, h Header) []byte {
	t.Helper()
	b, err := encodeHeader(&h)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFrameBoundaries(t *testing.T) {
	w := newTestWrapper(t, "k")
	path := tempPath(t, "seg.hprec")
	sw, err := Create(path, testHeader(KindExec), w)
	if err != nil {
		t.Fatal(err)
	}
	big := Record{Type: RecStdout, Seq: 1, Time: testEpoch, Stream: StreamStdout, Payload: bytes.Repeat([]byte{'x'}, MaxRecordPayload)}
	if err := sw.Append(big); err != nil {
		t.Fatal(err)
	}
	if sw.Pending() <= FrameMax-maxRecordOverhead || sw.Pending() > FrameMax {
		t.Fatalf("pending %d", sw.Pending())
	}
	big.Seq = 2
	if err := sw.Append(big); err != nil { // does not fit: seals frame 0 first
		t.Fatal(err)
	}
	if sw.Size() <= int64(FrameMax) {
		t.Fatalf("frame 0 not written: size %d", sw.Size())
	}
	// Fill frame 1 so that the footer no longer fits: Finalize must seal a non-final frame first.
	if err := sw.Append(Record{Type: RecStdout, Seq: 3, Time: testEpoch, Stream: StreamStdout, Payload: make([]byte, 40)}); err != nil {
		t.Fatal(err)
	}
	if room := FrameMax - sw.Pending(); room >= 46 {
		t.Fatalf("frame not full enough for the test: %d bytes left", room)
	}
	m, err := sw.Finalize("eof")
	if err != nil {
		t.Fatal(err)
	}
	if m.Frames != 3 || m.Records != 3 {
		t.Fatalf("manifest %+v", m)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := readAllFrom(f, w)
	if !errors.Is(err, io.EOF) || len(got) != 3 || len(got[1].Payload) != MaxRecordPayload {
		t.Fatalf("read %d records: %v", len(got), err)
	}
}

func TestAppendValidation(t *testing.T) {
	w := newTestWrapper(t, "k")
	sw, err := Create(tempPath(t, "seg.hprec"), testHeader(KindPTY), w)
	if err != nil {
		t.Fatal(err)
	}
	defer sw.Close()
	ok := Record{Type: RecTerminalOutput, Seq: 5, Time: testEpoch, Payload: []byte("hi")}
	if err := sw.Append(ok); err != nil {
		t.Fatal(err)
	}
	bad := []Record{
		{Type: 0, Seq: 6, Time: testEpoch},
		{Type: 99, Seq: 6, Time: testEpoch},
		{Type: RecSegmentFooter, Seq: 6, Time: testEpoch, Payload: Footer{EndReason: "x"}.Marshal()},
		{Type: RecTerminalOutput, Seq: 5, Time: testEpoch},
		{Type: RecTerminalOutput, Seq: 0, Time: testEpoch},
		{Type: RecTerminalOutput, Seq: 6, Time: testEpoch, Stream: 5},
		{Type: RecTerminalOutput, Seq: 6, Time: testEpoch, Mono: -1},
		{Type: RecTerminalOutput, Seq: 6, Time: time.Time{}},
		{Type: RecTerminalOutput, Seq: 6, Time: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
		{Type: RecTerminalOutput, Seq: 6, Time: testEpoch, Payload: make([]byte, MaxRecordPayload+1)},
		{Type: RecTerminalResized, Seq: 6, Time: testEpoch, Payload: []byte{1}},
		{Type: RecEOF, Seq: 6, Time: testEpoch, Payload: []byte{1}},
		{Type: RecSignal, Seq: 6, Time: testEpoch, Payload: []byte("bad name")},
	}
	for i, r := range bad {
		err := sw.Append(r)
		if !errors.Is(err, ErrInvalidRecord) && !errors.Is(err, ErrRecordTooLarge) {
			t.Errorf("case %d: got %v", i, err)
		}
	}
	// Validation errors leave the writer usable.
	if err := sw.Append(Record{Type: RecTerminalOutput, Seq: 6, Time: testEpoch}); err != nil {
		t.Fatal(err)
	}
	if _, err := sw.Finalize("Bad Reason"); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("bad end reason accepted: %v", err)
	}
	if _, err := sw.Finalize(strings.Repeat("a", 65)); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("long end reason accepted: %v", err)
	}
}

func TestCreateErrors(t *testing.T) {
	w := newTestWrapper(t, "k")
	dir := t.TempDir()
	mod := func(f func(*Header)) Header {
		h := testHeader(KindPTY)
		f(&h)
		return h
	}
	badHeaders := []Header{
		mod(func(h *Header) { h.SegmentID = "" }),
		mod(func(h *Header) { h.SessionID = "has space" }),
		mod(func(h *Header) { h.ChannelID = strings.Repeat("a", maxIDLen+1) }),
		mod(func(h *Header) { h.SegmentID = "seg/../x" }),
		mod(func(h *Header) { h.Kind = "shell" }),
		mod(func(h *Header) { h.CreatedAt = time.Time{} }),
		mod(func(h *Header) { h.PrevSegmentSHA256 = make([]byte, 32) }),
		mod(func(h *Header) { h.Ordinal = 1 }),
		mod(func(h *Header) { h.Ordinal = 1; h.PrevSegmentSHA256 = make([]byte, 31) }),
	}
	for i, h := range badHeaders {
		if _, err := Create(filepath.Join(dir, "bad.hprec"), h, w); !errors.Is(err, ErrInvalidHeader) {
			t.Errorf("header %d: %v", i, err)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("files left behind: %v", entries)
	}

	path := filepath.Join(dir, "seg.hprec")
	if _, err := Create(path+PartialSuffix, testHeader(KindPTY), w); err == nil {
		t.Fatal("accepted a .partial final path")
	}
	sw, err := Create(path, testHeader(KindPTY), w)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Create(path, testHeader(KindPTY), w); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("O_EXCL not enforced: %v", err)
	}
	if _, err := sw.Finalize("done"); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(path, testHeader(KindPTY), w); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("existing final file not detected: %v", err)
	}
	if _, err := Create(filepath.Join(dir, "missing", "seg.hprec"), testHeader(KindPTY), w); err == nil {
		t.Fatal("created in a missing directory")
	}

	wrapErr := errors.New("kms down")
	failing := funcWrapper{wrap: func([]byte, []byte) (string, []byte, error) { return "", nil, wrapErr }}
	if _, err := Prepare(testHeader(KindPTY), failing); !errors.Is(err, wrapErr) {
		t.Fatalf("wrap error: %v", err)
	}
	lying := funcWrapper{
		wrap:   func([]byte, []byte) (string, []byte, error) { return "k", []byte{1}, nil },
		unwrap: func(string, []byte, []byte) ([]byte, error) { return make([]byte, DEKSize), nil },
	}
	if _, err := Prepare(testHeader(KindPTY), lying); err == nil {
		t.Fatal("accepted a wrapper whose output unwraps to a different key")
	}
	badID := funcWrapper{
		wrap:   func(dek, _ []byte) (string, []byte, error) { return "bad id", dek, nil },
		unwrap: func(_ string, w, _ []byte) ([]byte, error) { return w, nil },
	}
	if _, err := Prepare(testHeader(KindPTY), badID); !errors.Is(err, ErrInvalidSlot) {
		t.Fatalf("bad key id: %v", err)
	}
	tooBig := funcWrapper{
		wrap:   func([]byte, []byte) (string, []byte, error) { return "k", make([]byte, MaxWrappedDEK+70), nil },
		unwrap: func(_ string, w, _ []byte) ([]byte, error) { return w[:DEKSize], nil },
	}
	if _, err := Prepare(testHeader(KindPTY), tooBig); err == nil {
		t.Fatal("accepted an oversized wrapped DEK")
	}
	shortKey := funcWrapper{
		wrap:   func([]byte, []byte) (string, []byte, error) { return "k", []byte{1}, nil },
		unwrap: func(string, []byte, []byte) ([]byte, error) { return []byte{1}, nil },
	}
	if _, err := Prepare(testHeader(KindPTY), shortKey); !errors.Is(err, ErrNoKey) {
		t.Fatalf("short unwrapped key: %v", err)
	}
}

func TestWriterIOErrorsAreSticky(t *testing.T) {
	w := newTestWrapper(t, "k")
	path := tempPath(t, "seg.hprec")
	sw, err := Create(path, testHeader(KindExec), w)
	if err != nil {
		t.Fatal(err)
	}
	if err := sw.Append(Record{Type: RecStdout, Seq: 1, Time: testEpoch, Stream: StreamStdout, Payload: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	_ = sw.f.Close() // simulate the file descriptor failing underneath the writer
	err = sw.Flush()
	if err == nil {
		t.Fatal("Flush succeeded on a closed file")
	}
	if err2 := sw.Append(Record{Type: RecStdout, Seq: 2, Time: testEpoch}); !errors.Is(err2, err) && err2.Error() != err.Error() {
		t.Fatalf("error not sticky: %v", err2)
	}
	if _, err2 := sw.Finalize("x"); err2 == nil {
		t.Fatal("Finalize succeeded after failure")
	}
	if err2 := sw.Flush(); err2 == nil {
		t.Fatal("Flush succeeded after failure")
	}
	_ = sw.Close()

	// fsync failure during Flush of an already sealed frame.
	sw2, err := Create(tempPath(t, "b.hprec"), testHeader(KindExec), w)
	if err != nil {
		t.Fatal(err)
	}
	if err := sw2.Append(Record{Type: RecStdout, Seq: 1, Time: testEpoch, Stream: StreamStdout, Payload: make([]byte, MaxRecordPayload)}); err != nil {
		t.Fatal(err)
	}
	if err := sw2.Append(Record{Type: RecStdout, Seq: 2, Time: testEpoch, Stream: StreamStdout}); err != nil {
		t.Fatal(err)
	}
	_ = sw2.f.Close()
	if err := sw2.Flush(); err == nil {
		t.Fatal("Flush succeeded on a closed file")
	}
	if err := sw2.Close(); err == nil {
		t.Log("double close reported no error")
	}

	// Writer closed without finalizing.
	sw3, err := Create(tempPath(t, "c.hprec"), testHeader(KindExec), w)
	if err != nil {
		t.Fatal(err)
	}
	if err := sw3.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sw3.Append(Record{Type: RecStdout, Seq: 1, Time: testEpoch}); !errors.Is(err, ErrWriterClosed) {
		t.Fatalf("append after close: %v", err)
	}
	if err := sw3.Flush(); !errors.Is(err, ErrWriterClosed) {
		t.Fatalf("flush after close: %v", err)
	}
	if err := sw3.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFlushWithoutDataDoesNotWrite(t *testing.T) {
	w := newTestWrapper(t, "k")
	sw, err := Create(tempPath(t, "seg.hprec"), testHeader(KindExec), w)
	if err != nil {
		t.Fatal(err)
	}
	defer sw.Close()
	before := sw.Size()
	if err := sw.Flush(); err != nil {
		t.Fatal(err)
	}
	if sw.Size() != before {
		t.Fatal("empty Flush wrote a frame")
	}
}
