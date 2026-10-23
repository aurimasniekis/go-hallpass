// Package hprec implements the HPREC1 encrypted recording segment format (PLAN §13.3–13.7, ADR-0005, HP-CRY-004/005).
//
// A segment file is a plaintext, canonical-JSON header, two fixed-size key slots holding the caller-wrapped data
// encryption key (DEK), and a sequence of frames sealed with ChaCha20-Poly1305 in the STREAM construction (11-byte
// big-endian frame counter plus a final-frame flag as the nonce, header hash as associated data). The byte-level
// specification lives in docs/formats/hprec1.md.
//
// The package is deliberately pure: it does file and stream I/O only. It has no database, keyring or logging
// dependencies, so it can be fuzzed and reviewed in isolation. Key wrapping is delegated to the caller through
// [DEKWrapper].
//
// This format has not had external cryptographic review yet (DECISIONS.md R-02).
package hprec

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// Format constants. Changing any of them requires a new format version (see docs/formats/hprec1.md §Versioning).
const (
	// Magic is the 8-byte file signature.
	Magic = "HPREC1\n\x00"
	// Version is the header "v" value written and accepted by this package.
	Version = 1
	// AEADName is the header "aead" value.
	AEADName = "chacha20poly1305-stream"
	// FrameMax is the maximum frame plaintext length in bytes (header "frame_max").
	FrameMax = 65536
	// MaxHeaderLen bounds header_len.
	MaxHeaderLen = 4096
	// SlotSize is the size of each of the two key slots.
	SlotSize = 256
	// DEKSize is the length of the per-segment data encryption key.
	DEKSize = 32
	// SaltSize is the length of the header payload_salt.
	SaltSize = 16
	// MaxRecordPayload is the largest record payload accepted by the writer; it guarantees that any single record
	// fits in one frame together with its encoding overhead.
	MaxRecordPayload = FrameMax - maxRecordOverhead
	// MaxPageBytes caps the decoded size of one replay page (PLAN §13.3).
	MaxPageBytes = 256 << 10
	// PartialSuffix is appended to the final path while a segment is being written.
	PartialSuffix = ".partial"

	maxRecordOverhead = 64 // generous bound on type+seq+t_us+mono_ns+stream+len encodings (actual max 35)
	tagSize           = chacha20poly1305.Overhead
	maxCTLen          = FrameMax + tagSize
	minCTLen          = 1 + tagSize // frames are never empty
	frameLenSize      = 4
	prefixFixed       = len(Magic) + 4 // magic + header_len
)

// Labels used for domain separation. They are part of the format.
const (
	payloadKeyInfo = "hallpass/rec/payload/v1"
	dekAADPrefix   = "hallpass/rec/dek/v1|"
)

// Errors returned by readers, verification and recovery. Format failures wrap ErrCorrupt so callers can classify
// them with errors.Is.
var (
	// ErrCorrupt means the file failed authentication or structural validation.
	ErrCorrupt = errors.New("hprec: corrupt segment")
	// ErrIncomplete means every frame present authenticated but the file ends without a final frame (a crash or
	// truncation). All authentic records have been yielded before it is returned.
	ErrIncomplete = errors.New("hprec: segment incomplete: no final frame")
	// ErrNoKey means neither key slot could be unwrapped (unknown or retired key, or the slots or header were modified).
	ErrNoKey = errors.New("hprec: no key slot could be unwrapped")
	// ErrHeaderMismatch means the header does not match what the caller expected (a swapped or substituted file).
	ErrHeaderMismatch = errors.New("hprec: header does not match the expected segment")
	// ErrUnsupportedVersion means the file is a different HPREC version.
	ErrUnsupportedVersion = errors.New("hprec: unsupported format version")
	// ErrInvalidHeader means a caller-supplied header is invalid.
	ErrInvalidHeader = errors.New("hprec: invalid header")
	// ErrInvalidRecord means a record is invalid (writer input or decoded data).
	ErrInvalidRecord = errors.New("hprec: invalid record")
	// ErrRecordTooLarge means a record payload exceeds MaxRecordPayload.
	ErrRecordTooLarge = errors.New("hprec: record payload too large")
	// ErrWriterClosed means the writer was finalized, closed or failed.
	ErrWriterClosed = errors.New("hprec: writer closed")
	// ErrInvalidSlot means a key slot could not be encoded or decoded.
	ErrInvalidSlot = errors.New("hprec: invalid key slot")
)

// DEKWrapper wraps and unwraps segment DEKs. Implementations must use an authenticated encryption scheme that binds
// aad (the keyring's recording purpose key with AES-256-GCM in production): Unwrap must fail if wrapped, aad or the
// key differ from what Wrap used. keyID identifies the wrapping key (for example the recording purpose-key version)
// and is stored next to the wrapped bytes; it must be 1–64 printable ASCII characters without spaces, and the
// wrapped value must fit in a slot (see docs/formats/hprec1.md).
type DEKWrapper interface {
	Wrap(dek, aad []byte) (keyID string, wrapped []byte, err error)
	Unwrap(keyID string, wrapped, aad []byte) ([]byte, error)
}

// DEKAAD returns the associated data that binds a wrapped DEK to its segment:
// "hallpass/rec/dek/v1|" + segment_id + "|" + hex(H).
func DEKAAD(segmentID string, headerSHA256 [32]byte) []byte {
	b := make([]byte, 0, len(dekAADPrefix)+len(segmentID)+1+64)
	b = append(b, dekAADPrefix...)
	b = append(b, segmentID...)
	b = append(b, '|')
	return hex.AppendEncode(b, headerSHA256[:])
}

// headerHash computes H = SHA-256(magic || header_len || header).
func headerHash(header []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(Magic))
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(header))) //nolint:gosec // G115: len(header) <= MaxHeaderLen, checked by callers
	h.Write(l[:])
	h.Write(header)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// payloadAEAD derives K = HKDF-SHA256(ikm=DEK, salt=payload_salt, info="hallpass/rec/payload/v1") and returns the
// ChaCha20-Poly1305 instance keyed with it.
func payloadAEAD(dek []byte, salt [SaltSize]byte) (cipher.AEAD, error) {
	if len(dek) != DEKSize {
		return nil, ErrNoKey
	}
	k, err := hkdf.Key(sha256.New, dek, salt[:], payloadKeyInfo, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	return chacha20poly1305.New(k)
}

// frameNonce returns BE88(i) || flag, the STREAM nonce of frame i.
func frameNonce(i uint64, final bool) [chacha20poly1305.NonceSize]byte {
	var n [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint64(n[3:11], i) // bytes 0..2 are the (always zero) high bits of the 88-bit counter
	if final {
		n[11] = 1
	}
	return n
}
