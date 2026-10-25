package hprec

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"os"
	"testing"
)

func TestRewrapSlot(t *testing.T) {
	w1, w2, w3 := newTestWrapper(t, "rec-v1"), newTestWrapper(t, "rec-v2"), newTestWrapper(t, "rec-v3")
	recs := genRecords(newRand(), KindPTY, 50, 64)
	path := tempPath(t, "seg.hprec")
	m := writeSegment(t, path, testHeader(KindPTY), w1, recs, 7)

	s2, err := RewrapSlot(path, w1, w2)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Index != 1 || s2.Gen != 2 || s2.KeyID != "rec-v2" {
		t.Fatalf("new slot %+v", s2)
	}
	requireReadable(t, path, w2, recs, 1, 2)
	requireReadable(t, path, w1, recs, 0, 1) // the old slot still works until it is overwritten
	requireReadable(t, path, union(w1, w2), recs, 1, 2)
	// The frames and therefore the manifest hashes are unchanged by a rewrap.
	if rep, err := Verify(path, w2, ExpectHeaderSHA256(m.HeaderSHA256)); err != nil || rep.Status != StatusOK || rep.CiphertextSHA256 != m.CiphertextSHA256 {
		t.Fatalf("%+v %v", rep, err)
	}
	// The returned slot is the database copy and unwraps on its own.
	if _, err := w2.Unwrap(s2.KeyID, s2.Wrapped, DEKAAD(m.SegmentID, m.HeaderSHA256)); err != nil {
		t.Fatal(err)
	}

	s3, err := RewrapSlot(path, w2, w3)
	if err != nil {
		t.Fatal(err)
	}
	if s3.Index != 0 || s3.Gen != 3 {
		t.Fatalf("third slot %+v", s3)
	}
	requireReadable(t, path, w3, recs, 0, 3)
	requireReadable(t, path, w2, recs, 1, 2)
	if _, err := Open(path, w1); !errors.Is(err, ErrNoKey) {
		t.Fatalf("overwritten slot still opens: %v", err)
	}
	rep, err := Verify(path, union(w3, w1))
	if err != nil || rep.Status != StatusOK || !rep.Slots[0].Active || rep.Slots[1].Unwraps || !rep.Slots[1].Decoded {
		t.Fatalf("%+v %v", rep, err)
	}
	if _, err := RewrapSlot(path, w1, w2); !errors.Is(err, ErrNoKey) {
		t.Fatalf("rewrap with an unknown key: %v", err)
	}
	if _, err := RewrapSlot(tempPath(t, "missing"), w1, w2); err == nil {
		t.Fatal("rewrap of a missing file succeeded")
	}
}

func requireReadable(t *testing.T, path string, w DEKWrapper, want []Record, slot int, gen uint32) {
	t.Helper()
	r, err := Open(path, w)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer r.Close()
	if r.Slot().Index != slot || r.Slot().Gen != gen {
		t.Fatalf("using slot %+v, want index %d gen %d", r.Slot(), slot, gen)
	}
	var got []Record
	for {
		rec, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, rec)
	}
	requireRecords(t, got, want)
}

func TestRewrapTornWrite(t *testing.T) {
	w1, w2 := newTestWrapper(t, "rec-v1"), newTestWrapper(t, "rec-v2")
	recs := genRecords(newRand(), KindExec, 20, 64)
	path := tempPath(t, "seg.hprec")
	writeSegment(t, path, testHeader(KindExec), w1, recs, 0)
	orig := readFile(t, path)
	l := parseLayout(t, orig)

	// Compute what a complete rewrap would write, then apply only part of it (a torn write).
	if _, err := RewrapSlot(path, w1, w2); err != nil {
		t.Fatal(err)
	}
	full := readFile(t, path)
	newSlot := full[l.slotB : l.slotB+SlotSize]
	for _, cut := range []int{1, 64, SlotSize / 2, SlotSize - 1} {
		torn := bytes.Clone(orig)
		copy(torn[l.slotB:], newSlot[:cut])
		if err := os.WriteFile(path, torn, 0o600); err != nil {
			t.Fatal(err)
		}
		requireReadable(t, path, union(w1, w2), recs, 0, 1)
		requireReadable(t, path, w1, recs, 0, 1)
		if _, err := Open(path, w2); !errors.Is(err, ErrNoKey) {
			t.Fatalf("cut %d: torn slot unwrapped: %v", cut, err)
		}
		// Retrying the rewrap after the crash succeeds and overwrites the torn slot.
		s, err := RewrapSlot(path, w1, w2)
		if err != nil || s.Index != 1 || s.Gen != 2 {
			t.Fatalf("retry: %+v %v", s, err)
		}
		requireReadable(t, path, w2, recs, 1, 2)
	}

	// A torn write over a previously valid, older slot (second rewrap overwriting slot A).
	if err := os.WriteFile(path, full, 0o600); err != nil {
		t.Fatal(err)
	}
	w3 := newTestWrapper(t, "rec-v3")
	if _, err := RewrapSlot(path, w2, w3); err != nil {
		t.Fatal(err)
	}
	third := readFile(t, path)[l.slotA : l.slotA+SlotSize]
	torn := bytes.Clone(full)
	copy(torn[l.slotA+SlotSize/2:], third[SlotSize/2:])
	if err := os.WriteFile(path, torn, 0o600); err != nil {
		t.Fatal(err)
	}
	requireReadable(t, path, union(w1, w2, w3), recs, 1, 2)
}

func TestRepairSlot(t *testing.T) {
	w := newTestWrapper(t, "rec-v1")
	recs := genRecords(newRand(), KindPTY, 20, 64)
	hdr := testHeader(KindPTY)
	p, err := Prepare(hdr, w)
	if err != nil {
		t.Fatal(err)
	}
	dbCopy := p.Slot()
	path := tempPath(t, "seg.hprec")
	sw, err := p.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if err := sw.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := sw.Finalize("closed"); err != nil {
		t.Fatal(err)
	}
	data := readFile(t, path)
	l := parseLayout(t, data)

	// Slot B is empty and does not unwrap, so repair fills it from the copy: routine, not a restore.
	s, outcome, err := MaintainSlots(path, w, dbCopy.KeyID, dbCopy.Wrapped)
	if err != nil || s.Index != 1 || s.Gen != 2 || outcome != RepairFilledEmpty {
		t.Fatalf("%+v %v %v", s, outcome, err)
	}
	// Both slots unwrap now: no write.
	before := readFile(t, path)
	if s, err = RepairSlot(path, w, dbCopy.KeyID, dbCopy.Wrapped); err != nil || s.Index != 1 {
		t.Fatalf("%+v %v", s, err)
	}
	if !bytes.Equal(before, readFile(t, path)) {
		t.Fatal("repair of a healthy file wrote to it")
	}

	// Destroy both slots: the DB copy restores access.
	broken := bytes.Clone(data)
	for i := l.slotA; i < l.slotB+SlotSize; i++ {
		broken[i] = 0xee
	}
	if err := os.WriteFile(path, broken, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, w); !errors.Is(err, ErrNoKey) {
		t.Fatal(err)
	}
	if s, outcome, err = MaintainSlots(path, w, dbCopy.KeyID, dbCopy.Wrapped); err != nil || s.Gen != 1 || outcome != RepairRestored {
		t.Fatalf("%+v %v %v", s, outcome, err)
	}
	requireReadable(t, path, w, recs, s.Index, 1)

	// A DB copy for another segment is rejected.
	other, err := Prepare(testHeader(KindPTY), w)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RepairSlot(path, w, other.Slot().KeyID, other.Slot().Wrapped); !errors.Is(err, ErrNoKey) {
		t.Fatalf("foreign copy accepted: %v", err)
	}
	if _, err := RepairSlot(tempPath(t, "missing"), w, dbCopy.KeyID, dbCopy.Wrapped); err == nil {
		t.Fatal("repair of a missing file succeeded")
	}
}

func TestSlotGenerationExhausted(t *testing.T) {
	w := newTestWrapper(t, "k")
	path := tempPath(t, "seg.hprec")
	p, err := Prepare(testHeader(KindExec), w)
	if err != nil {
		t.Fatal(err)
	}
	slot := p.Slot()
	sw, err := p.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sw.Finalize("x"); err != nil {
		t.Fatal(err)
	}
	data := readFile(t, path)
	l := parseLayout(t, data)
	enc, err := encodeSlot(math.MaxUint32, slot.KeyID, slot.Wrapped)
	if err != nil {
		t.Fatal(err)
	}
	copy(data[l.slotA:], enc[:])
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RewrapSlot(path, w, w); !errors.Is(err, ErrInvalidSlot) {
		t.Fatalf("%v", err)
	}
	// Repair would need gen MaxUint32+1 for the empty slot B and refuses too.
	if _, err := RepairSlot(path, w, slot.KeyID, slot.Wrapped); !errors.Is(err, ErrInvalidSlot) {
		t.Fatalf("repair: %v", err)
	}
	requireReadable(t, path, w, nil, 0, math.MaxUint32)
}

func TestSlotCodec(t *testing.T) {
	enc, err := encodeSlot(7, "rec-v1", []byte("wrapped"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := decodeSlot(enc[:])
	if err != nil || s.Gen != 7 || s.KeyID != "rec-v1" || string(s.Wrapped) != "wrapped" {
		t.Fatalf("%+v %v", s, err)
	}
	if _, err := encodeSlot(0, "k", []byte{1}); !errors.Is(err, ErrInvalidSlot) {
		t.Fatal("gen 0 accepted")
	}
	if _, err := encodeSlot(1, "", []byte{1}); !errors.Is(err, ErrInvalidSlot) {
		t.Fatal("empty key ID accepted")
	}
	if _, err := encodeSlot(1, "k", nil); !errors.Is(err, ErrInvalidSlot) {
		t.Fatal("empty wrapped accepted")
	}
	if _, err := encodeSlot(1, "k", make([]byte, MaxWrappedDEK+maxKeyIDLen)); !errors.Is(err, ErrInvalidSlot) {
		t.Fatal("oversized wrapped accepted")
	}
	if _, err := encodeSlot(1, string(make([]byte, maxKeyIDLen)), make([]byte, MaxWrappedDEK)); !errors.Is(err, ErrInvalidSlot) {
		t.Fatal("non-printable key ID accepted")
	}
	maxID := string(bytes.Repeat([]byte{'k'}, maxKeyIDLen))
	if _, err := encodeSlot(1, maxID, make([]byte, MaxWrappedDEK)); err != nil {
		t.Fatalf("maximal slot rejected: %v", err)
	}

	// Structurally invalid slots with a valid checksum.
	reseal := func(b [SlotSize]byte) []byte {
		sum := sha256.Sum256(b[:slotBodySize])
		copy(b[slotBodySize:], sum[:])
		return b[:]
	}
	mut := func(f func(b *[SlotSize]byte)) []byte {
		b := enc
		f(&b)
		return reseal(b)
	}
	for name, b := range map[string][]byte{
		"magic":       mut(func(b *[SlotSize]byte) { b[0] = 'X' }),
		"gen 0":       mut(func(b *[SlotSize]byte) { b[7] = 0 }),
		"key len 0":   mut(func(b *[SlotSize]byte) { b[8] = 0 }),
		"key len big": mut(func(b *[SlotSize]byte) { b[8] = maxKeyIDLen + 1 }),
		"key char":    mut(func(b *[SlotSize]byte) { b[9] = ' ' }),
		"wrap len 0":  mut(func(b *[SlotSize]byte) { b[15], b[16] = 0, 0 }),
		"wrap len big": mut(func(b *[SlotSize]byte) {
			b[15], b[16] = 0xff, 0xff
		}),
		"padding":  mut(func(b *[SlotSize]byte) { b[slotBodySize-1] = 1 }),
		"checksum": func() []byte { b := enc; b[SlotSize-1] ^= 1; return b[:] }(),
		"short":    enc[:10],
	} {
		if _, err := decodeSlot(b); !errors.Is(err, ErrInvalidSlot) {
			t.Errorf("%s: %v", name, err)
		}
	}
	var zero [SlotSize]byte
	if _, err := decodeSlot(zero[:]); !errors.Is(err, errEmptySlot) {
		t.Fatal("empty slot not reported as empty")
	}
}

// SR-16/SR-39: slot maintenance checks the caller's header expectations before writing, so a substituted file (a
// different segment at the expected path) is never modified.
func TestSlotMaintenanceChecksHeader(t *testing.T) {
	w1, w2 := newTestWrapper(t, "rec-v1"), newTestWrapper(t, "rec-v2")
	recs := genRecords(newRand(), KindPTY, 5, 64)
	path := tempPath(t, "seg.hprec")
	m := writeSegment(t, path, testHeader(KindPTY), w1, recs, 2)
	before := readFile(t, path)
	var other [32]byte
	other[0] = 1
	if _, err := RewrapSlot(path, w1, w2, ExpectHeaderSHA256(other)); !errors.Is(err, ErrHeaderMismatch) {
		t.Fatalf("rewrap of a substituted file: %v", err)
	}
	if _, _, err := RepairSlotIfNeeded(path, w1, "rec-v1", nil, ExpectSegmentID("seg_other")); !errors.Is(err, ErrHeaderMismatch) {
		t.Fatalf("repair of a substituted file: %v", err)
	}
	if !bytes.Equal(before, readFile(t, path)) {
		t.Fatal("file modified despite the header mismatch")
	}
	if _, err := RewrapSlot(path, w1, w2, ExpectHeaderSHA256(m.HeaderSHA256), ExpectSegmentID(m.SegmentID)); err != nil {
		t.Fatal(err)
	}
}
