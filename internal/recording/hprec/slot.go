package hprec

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
)

// Key slot layout (SlotSize bytes, all integers big-endian):
//
//	0   4  slot magic "HPK1"
//	4   4  gen (>= 1)
//	8   1  key_id length k (1..64)
//	9   k  key_id (printable ASCII 0x21..0x7e)
//	..  2  wrapped length w (>= 1)
//	..  w  wrapped DEK (opaque, produced by DEKWrapper.Wrap)
//	..     zero padding up to offset 224
//	224 32 SHA-256 of bytes 0..223 (torn-write detection only; not a MAC)
const (
	slotMagic     = "HPK1"
	slotBodySize  = SlotSize - sha256.Size
	maxKeyIDLen   = 64
	slotFixedSize = len(slotMagic) + 4 + 1 + 2
	// MaxWrappedDEK is the largest wrapped DEK that fits in a slot with a maximum-length key ID.
	MaxWrappedDEK = slotBodySize - slotFixedSize - maxKeyIDLen
)

// SlotInfo describes one key slot.
type SlotInfo struct {
	Index   int // 0 = slot A, 1 = slot B
	Gen     uint32
	KeyID   string
	Wrapped []byte
}

func validKeyID(s string) bool {
	if s == "" || len(s) > maxKeyIDLen {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func encodeSlot(gen uint32, keyID string, wrapped []byte) ([SlotSize]byte, error) {
	var out [SlotSize]byte
	if gen == 0 {
		return out, fmt.Errorf("%w: gen must be >= 1", ErrInvalidSlot)
	}
	if !validKeyID(keyID) {
		return out, fmt.Errorf("%w: key ID must be 1-%d printable ASCII characters", ErrInvalidSlot, maxKeyIDLen)
	}
	if len(wrapped) == 0 || slotFixedSize+len(keyID)+len(wrapped) > slotBodySize {
		return out, fmt.Errorf("%w: wrapped DEK length %d does not fit", ErrInvalidSlot, len(wrapped))
	}
	b := out[:0]
	b = append(b, slotMagic...)
	b = binary.BigEndian.AppendUint32(b, gen)
	b = append(b, byte(len(keyID))) //nolint:gosec // G115: validKeyID bounds the length to maxKeyIDLen (64)
	b = append(b, keyID...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(wrapped))) //nolint:gosec // G115: bounded by slotBodySize above
	_ = append(b, wrapped...)
	sum := sha256.Sum256(out[:slotBodySize])
	copy(out[slotBodySize:], sum[:])
	return out, nil
}

// decodeSlot parses a slot. An all-zero slot (never written) returns errEmptySlot.
func decodeSlot(b []byte) (SlotInfo, error) {
	if len(b) != SlotSize {
		return SlotInfo{}, ErrInvalidSlot
	}
	if isZero(b) {
		return SlotInfo{}, errEmptySlot
	}
	sum := sha256.Sum256(b[:slotBodySize])
	if subtle.ConstantTimeCompare(sum[:], b[slotBodySize:]) != 1 {
		return SlotInfo{}, fmt.Errorf("%w: checksum mismatch (torn or modified)", ErrInvalidSlot)
	}
	if string(b[:4]) != slotMagic {
		return SlotInfo{}, fmt.Errorf("%w: bad slot magic", ErrInvalidSlot)
	}
	s := SlotInfo{Gen: binary.BigEndian.Uint32(b[4:8])}
	k := int(b[8])
	p := 9
	if s.Gen == 0 || k == 0 || k > maxKeyIDLen {
		return SlotInfo{}, fmt.Errorf("%w: bad gen or key ID length", ErrInvalidSlot)
	}
	s.KeyID = string(b[p : p+k])
	p += k
	if !validKeyID(s.KeyID) {
		return SlotInfo{}, fmt.Errorf("%w: bad key ID", ErrInvalidSlot)
	}
	w := int(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2
	if w == 0 || p+w > slotBodySize {
		return SlotInfo{}, fmt.Errorf("%w: bad wrapped length", ErrInvalidSlot)
	}
	s.Wrapped = bytes.Clone(b[p : p+w])
	if !isZero(b[p+w : slotBodySize]) {
		return SlotInfo{}, fmt.Errorf("%w: non-zero padding", ErrInvalidSlot)
	}
	return s, nil
}

var errEmptySlot = fmt.Errorf("%w: empty", ErrInvalidSlot)

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// slotOrder returns the decodable slots, highest gen first (slot A first on a tie).
func slotOrder(raw *[2][SlotSize]byte) []SlotInfo {
	var out []SlotInfo
	for i := range 2 {
		s, err := decodeSlot(raw[i][:])
		if err != nil {
			continue
		}
		s.Index = i
		out = append(out, s)
	}
	if len(out) == 2 && out[1].Gen > out[0].Gen {
		out[0], out[1] = out[1], out[0]
	}
	return out
}

func unwrapSlot(w DEKWrapper, s SlotInfo, aad []byte) ([]byte, error) {
	dek, err := w.Unwrap(s.KeyID, s.Wrapped, aad)
	if err != nil {
		return nil, err
	}
	if len(dek) != DEKSize {
		clear(dek)
		return nil, fmt.Errorf("%w: unwrapped DEK has length %d", ErrNoKey, len(dek))
	}
	return dek, nil
}

// selectSlot unwraps the valid slot with the highest gen, falling back to the other slot.
func selectSlot(raw *[2][SlotSize]byte, aad []byte, w DEKWrapper) ([]byte, SlotInfo, error) {
	for _, s := range slotOrder(raw) {
		dek, err := unwrapSlot(w, s, aad)
		if err == nil {
			return dek, s, nil
		}
	}
	return nil, SlotInfo{}, ErrNoKey
}

func maxGen(raw *[2][SlotSize]byte) uint32 {
	var g uint32
	for _, s := range slotOrder(raw) {
		g = max(g, s.Gen)
	}
	return g
}

// SlotCheck is the verification result of one key slot.
type SlotCheck struct {
	Present bool   // the slot is not all zero
	Decoded bool   // the slot parsed and its checksum matched
	Unwraps bool   // the wrapper unwrapped it with this segment's AAD
	Active  bool   // the reader uses this slot
	Gen     uint32 // valid when Decoded
	KeyID   string // valid when Decoded
	Problem string // why the slot is unusable, if it is
}

func checkSlots(raw *[2][SlotSize]byte, aad []byte, w DEKWrapper, active int) [2]SlotCheck {
	var out [2]SlotCheck
	for i := range 2 {
		c := &out[i]
		c.Present = !isZero(raw[i][:])
		s, err := decodeSlot(raw[i][:])
		if err != nil {
			c.Problem = err.Error()
			continue
		}
		c.Decoded, c.Gen, c.KeyID = true, s.Gen, s.KeyID
		dek, err := unwrapSlot(w, s, aad)
		if err != nil {
			c.Problem = "unwrap failed: " + err.Error()
			continue
		}
		clear(dek)
		c.Unwraps = true
		c.Active = i == active
	}
	return out
}

// segmentFile is an opened segment's prefix, used by slot maintenance.
type segmentFile struct {
	f       *os.File
	hdr     Header
	h       [32]byte
	slotOff int64
	raw     [2][SlotSize]byte
}

func openSegmentRW(path string, opts []Option) (*segmentFile, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0) //nolint:gosec // G304: path is a recording segment chosen by the caller
	if err != nil {
		return nil, err
	}
	sf := &segmentFile{f: f}
	br := bufio.NewReader(io.NewSectionReader(f, 0, math.MaxInt64))
	hdr, raw, h, err := readPrefixHeader(br)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := o.check(&hdr, h); err != nil {
		_ = f.Close()
		return nil, err
	}
	sf.hdr, sf.h = hdr, h
	sf.slotOff = int64(prefixFixed + len(raw))
	for i := range 2 {
		if _, err := io.ReadFull(br, sf.raw[i][:]); err != nil {
			_ = f.Close()
			return nil, shortRead(err, "key slots")
		}
	}
	return sf, nil
}

func (sf *segmentFile) writeSlot(idx int, slot [SlotSize]byte) error {
	if _, err := sf.f.WriteAt(slot[:], sf.slotOff+int64(idx*SlotSize)); err != nil {
		return err
	}
	return sf.f.Sync()
}

// RewrapSlot re-wraps the segment DEK under newWrapper (PLAN §13.4). It unwraps the active slot with wrapper, writes
// the inactive slot as a full SlotSize block with gen = highest gen + 1, and fsyncs. A torn write leaves the
// previously active slot usable. The returned SlotInfo is the new slot, for updating the database copy of the
// wrapped DEK after this function returns. It is safe to call while a Writer is appending to the same file, because
// writers never touch the slots after Create. opts (ExpectSegmentID, ExpectHeaderSHA256, …) are checked against the
// header before anything is written, so a substituted file is refused.
func RewrapSlot(path string, wrapper, newWrapper DEKWrapper, opts ...Option) (SlotInfo, error) {
	sf, err := openSegmentRW(path, opts)
	if err != nil {
		return SlotInfo{}, err
	}
	defer sf.f.Close()
	aad := DEKAAD(sf.hdr.SegmentID, sf.h)
	dek, active, err := selectSlot(&sf.raw, aad, wrapper)
	if err != nil {
		return SlotInfo{}, err
	}
	defer clear(dek)
	gen := maxGen(&sf.raw)
	if gen == math.MaxUint32 {
		return SlotInfo{}, fmt.Errorf("%w: slot generation exhausted", ErrInvalidSlot)
	}
	ns, slot, err := wrapForSlot(newWrapper, dek, aad, gen+1)
	if err != nil {
		return SlotInfo{}, err
	}
	ns.Index = 1 - active.Index
	if err := sf.writeSlot(ns.Index, slot); err != nil {
		return SlotInfo{}, err
	}
	return ns, sf.f.Close()
}

// wrapForSlot wraps dek, checks that the result unwraps to the same key, and encodes the slot.
func wrapForSlot(w DEKWrapper, dek, aad []byte, gen uint32) (SlotInfo, [SlotSize]byte, error) {
	keyID, wrapped, err := w.Wrap(dek, aad)
	if err != nil {
		return SlotInfo{}, [SlotSize]byte{}, err
	}
	check, err := unwrapSlot(w, SlotInfo{KeyID: keyID, Wrapped: wrapped}, aad)
	if err != nil {
		return SlotInfo{}, [SlotSize]byte{}, fmt.Errorf("hprec: wrapped DEK does not unwrap: %w", err)
	}
	same := subtle.ConstantTimeCompare(check, dek) == 1
	clear(check)
	if !same {
		return SlotInfo{}, [SlotSize]byte{}, errors.New("hprec: wrapped DEK unwraps to a different key")
	}
	slot, err := encodeSlot(gen, keyID, wrapped)
	if err != nil {
		return SlotInfo{}, [SlotSize]byte{}, err
	}
	return SlotInfo{Gen: gen, KeyID: keyID, Wrapped: bytes.Clone(wrapped)}, slot, nil
}

// repairTarget picks the slot RepairSlot overwrites: one that does not unwrap, preferring a slot that does not
// even decode, then the lower generation. It returns -1 when both slots unwrap.
func repairTarget(c *[2]SlotCheck) int {
	switch {
	case c[0].Unwraps && c[1].Unwraps:
		return -1
	case c[0].Unwraps:
		return 1
	case c[1].Unwraps:
		return 0
	case c[0].Decoded != c[1].Decoded:
		if c[0].Decoded {
			return 1
		}
		return 0
	case c[1].Gen < c[0].Gen:
		return 1
	default:
		return 0
	}
}

// RepairSlot restores a key slot from a copy of the wrapped DEK kept elsewhere (the database, PLAN §13.4). The copy
// must unwrap with w under this segment's AAD. If both slots already unwrap nothing is written and the active slot is
// returned. Otherwise the copy is written into a slot that does not unwrap, with gen = highest gen + 1, and fsynced.
// If one slot does unwrap, its DEK must equal the copy's, or ErrCorrupt is returned. opts are checked against the
// header before anything is written.
func RepairSlot(path string, w DEKWrapper, keyID string, wrapped []byte, opts ...Option) (SlotInfo, error) {
	s, _, err := RepairSlotIfNeeded(path, w, keyID, wrapped, opts...)
	return s, err
}

// RepairSlotIfNeeded is RepairSlot that also reports whether a slot was written.
func RepairSlotIfNeeded(path string, w DEKWrapper, keyID string, wrapped []byte, opts ...Option) (SlotInfo, bool, error) {
	return repairSlot(path, w, keyID, wrapped, opts)
}

func repairSlot(path string, w DEKWrapper, keyID string, wrapped []byte, opts []Option) (SlotInfo, bool, error) {
	sf, err := openSegmentRW(path, opts)
	if err != nil {
		return SlotInfo{}, false, err
	}
	defer sf.f.Close()
	aad := DEKAAD(sf.hdr.SegmentID, sf.h)
	dek, err := unwrapSlot(w, SlotInfo{KeyID: keyID, Wrapped: wrapped}, aad)
	if err != nil {
		return SlotInfo{}, false, fmt.Errorf("%w: database copy: %w", ErrNoKey, err)
	}
	defer clear(dek)
	checks := checkSlots(&sf.raw, aad, w, -1)
	for i := range 2 {
		if !checks[i].Unwraps {
			continue
		}
		s, _ := decodeSlot(sf.raw[i][:])
		cur, err := unwrapSlot(w, s, aad)
		if err != nil {
			return SlotInfo{}, false, err
		}
		same := subtle.ConstantTimeCompare(cur, dek) == 1
		clear(cur)
		if !same {
			return SlotInfo{}, false, fmt.Errorf("%w: key slot %d holds a different DEK than the copy", ErrCorrupt, i)
		}
	}
	target := repairTarget(&checks)
	if target < 0 {
		_, active, err := selectSlot(&sf.raw, aad, w)
		return active, false, err
	}
	gen := maxGen(&sf.raw)
	if gen == math.MaxUint32 {
		return SlotInfo{}, false, fmt.Errorf("%w: slot generation exhausted", ErrInvalidSlot)
	}
	slot, err := encodeSlot(gen+1, keyID, wrapped)
	if err != nil {
		return SlotInfo{}, false, err
	}
	if err := sf.writeSlot(target, slot); err != nil {
		return SlotInfo{}, false, err
	}
	return SlotInfo{Index: target, Gen: gen + 1, KeyID: keyID, Wrapped: bytes.Clone(wrapped)}, true, sf.f.Close()
}
