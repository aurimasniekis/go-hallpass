package backup

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/aurimasniekis/go-hallpass/internal/keyring"
)

// HPBAK1 seals a database snapshot or manifest for remote backup storage (ADR-0054). The bucket only ever holds
// ciphertext. The construction mirrors HPREC1 (docs/formats/hprec1.md):
//
//	magic "HPBAK1\n\x00" || BE32(header_len) || header (JSON) || frames
//	frame = BE32(ct_len) || ChaCha20-Poly1305(K, nonce = BE88(i) || final, plaintext <= 64 KiB, aad = H)
//
// H is SHA-256(magic || header_len || header). The header carries the KEK ID, a 16-byte salt and the 32-byte data key
// (DEK) wrapped directly by the KEK, with "hallpass/bak/dek/v1|" + kind + "|" + backup_id as associated data, so a
// key cannot be moved to another object. K = HKDF-SHA256(DEK, salt, "hallpass/bak/payload/v1"). The last frame has the
// final flag, so truncation and appended data are detected. The DEK is not stored in the database, because the
// database snapshot is what it protects: opening a sealed object needs only the KEK, like a restore.
//
// This format has not had external cryptographic review (DECISIONS.md R-02).
const (
	SealedMagic = "HPBAK1\n\x00"
	// SealedKindDatabase and SealedKindManifest are the header kinds.
	SealedKindDatabase = "database"
	SealedKindManifest = "manifest"

	sealedVersion   = 1
	sealedFrameMax  = 65536
	sealedMaxHeader = 4096
	sealedDEKSize   = 32
	sealedSaltSize  = 16
)

var (
	sealedPayloadInfo = []byte("hallpass/bak/payload/v1")
	// ErrSealed means a sealed object is malformed, truncated, tampered with or under another key.
	ErrSealed = errors.New("sealed backup object is invalid")
)

type sealedHeader struct {
	V          int    `json:"v"`
	Kind       string `json:"kind"`
	BackupID   string `json:"backup_id"`
	KEKID      string `json:"kek_id"`
	Salt       []byte `json:"salt"`
	WrappedDEK []byte `json:"wrapped_dek"`
}

func sealedDEKAAD(kind, backupID string) []byte {
	return []byte("hallpass/bak/dek/v1|" + kind + "|" + backupID)
}

func sealedHeaderHash(header []byte) []byte {
	h := sha256.New()
	h.Write([]byte(SealedMagic))
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(header))) //nolint:gosec // G115: header length is bounded by sealedMaxHeader
	h.Write(l[:])
	h.Write(header)
	return h.Sum(nil)
}

func sealedAEAD(dek, salt []byte) (cipher.AEAD, error) {
	k, err := hkdf.Key(sha256.New, dek, salt, string(sealedPayloadInfo), chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	return chacha20poly1305.New(k)
}

func sealedNonce(i uint64, final bool) []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(n[3:11], i)
	if final {
		n[11] = 1
	}
	return n
}

// Seal writes src to dst as an HPBAK1 object of the given kind for backupID, wrapping a fresh DEK with kek.
func Seal(dst io.Writer, src io.Reader, kek keyring.KeyWrapper, kind, backupID string) error {
	dek := make([]byte, sealedDEKSize)
	salt := make([]byte, sealedSaltSize)
	if _, err := rand.Read(dek); err != nil {
		return err
	}
	defer clear(dek)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	wrapped, err := kek.Wrap(dek, sealedDEKAAD(kind, backupID))
	if err != nil {
		return fmt.Errorf("wrap backup key: %w", err)
	}
	header, err := json.Marshal(sealedHeader{V: sealedVersion, Kind: kind, BackupID: backupID, KEKID: kek.ID(), Salt: salt, WrappedDEK: wrapped})
	if err != nil {
		return err
	}
	if len(header) > sealedMaxHeader {
		return errors.New("sealed header too large")
	}
	aead, err := sealedAEAD(dek, salt)
	if err != nil {
		return err
	}
	aad := sealedHeaderHash(header)
	bw := bufio.NewWriterSize(dst, 256<<10)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(header))) //nolint:gosec // G115: bounded above
	if _, err := bw.WriteString(SealedMagic); err != nil {
		return err
	}
	if _, err := bw.Write(l[:]); err != nil {
		return err
	}
	if _, err := bw.Write(header); err != nil {
		return err
	}
	// Read one frame ahead so the last frame can carry the final flag.
	cur := make([]byte, sealedFrameMax)
	next := make([]byte, sealedFrameMax)
	n, err := io.ReadFull(src, cur)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}
	ct := make([]byte, 0, sealedFrameMax+aead.Overhead())
	for i := uint64(0); ; i++ {
		final := n < sealedFrameMax
		var m int
		if !final {
			m, err = io.ReadFull(src, next)
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				return err
			}
			final = m == 0
		}
		ct = aead.Seal(ct[:0], sealedNonce(i, final), cur[:n], aad)
		binary.BigEndian.PutUint32(l[:], uint32(len(ct))) //nolint:gosec // G115: at most sealedFrameMax + tag
		if _, err := bw.Write(l[:]); err != nil {
			return err
		}
		if _, err := bw.Write(ct); err != nil {
			return err
		}
		if final {
			return bw.Flush()
		}
		cur, next, n = next, cur, m
	}
}

// SealedInfo describes a sealed object's header.
type SealedInfo struct {
	Kind     string
	BackupID string
	KEKID    string
}

// OpenSealed returns a reader of the plaintext of an HPBAK1 object. It checks that the object is of wantKind for
// wantBackupID (empty accepts any) and was sealed under kek. The reader returns ErrSealed on tampering, truncation or
// trailing data; callers must read to io.EOF before trusting the content.
func OpenSealed(src io.Reader, kek keyring.KeyWrapper, wantKind, wantBackupID string) (io.Reader, SealedInfo, error) {
	br := bufio.NewReaderSize(src, 256<<10)
	prefix := make([]byte, len(SealedMagic)+4)
	if _, err := io.ReadFull(br, prefix); err != nil {
		return nil, SealedInfo{}, fmt.Errorf("%w: short header", ErrSealed)
	}
	if string(prefix[:len(SealedMagic)]) != SealedMagic {
		return nil, SealedInfo{}, fmt.Errorf("%w: not an HPBAK1 object", ErrSealed)
	}
	hl := binary.BigEndian.Uint32(prefix[len(SealedMagic):])
	if hl == 0 || hl > sealedMaxHeader {
		return nil, SealedInfo{}, fmt.Errorf("%w: header length %d", ErrSealed, hl)
	}
	header := make([]byte, hl)
	if _, err := io.ReadFull(br, header); err != nil {
		return nil, SealedInfo{}, fmt.Errorf("%w: short header", ErrSealed)
	}
	var h sealedHeader
	dec := json.NewDecoder(bytes.NewReader(header))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil || h.V != sealedVersion || len(h.Salt) != sealedSaltSize || h.Kind == "" || h.BackupID == "" {
		return nil, SealedInfo{}, fmt.Errorf("%w: bad header", ErrSealed)
	}
	info := SealedInfo{Kind: h.Kind, BackupID: h.BackupID, KEKID: h.KEKID}
	if (wantKind != "" && h.Kind != wantKind) || (wantBackupID != "" && h.BackupID != wantBackupID) {
		return nil, info, fmt.Errorf("%w: object is %s of %s, expected %s of %s", ErrSealed, h.Kind, h.BackupID, wantKind, wantBackupID)
	}
	if h.KEKID != kek.ID() {
		return nil, info, fmt.Errorf("%w: sealed under KEK %s, the supplied KEK is %s", ErrKEKMismatch, h.KEKID, kek.ID())
	}
	dek, err := kek.Unwrap(h.WrappedDEK, sealedDEKAAD(h.Kind, h.BackupID))
	if err != nil || len(dek) != sealedDEKSize {
		return nil, info, fmt.Errorf("%w: cannot unwrap the data key", ErrSealed)
	}
	defer clear(dek)
	aead, err := sealedAEAD(dek, h.Salt)
	if err != nil {
		return nil, info, err
	}
	return &sealedReader{r: br, aead: aead, aad: sealedHeaderHash(header)}, info, nil
}

type sealedReader struct {
	r     *bufio.Reader
	aead  cipher.AEAD
	aad   []byte
	i     uint64
	buf   []byte
	ct    []byte
	done  bool
	err   error
	plain []byte
}

func (s *sealedReader) Read(p []byte) (int, error) {
	for len(s.buf) == 0 {
		if s.err != nil {
			return 0, s.err
		}
		if s.done {
			// Nothing may follow the final frame.
			if _, err := s.r.ReadByte(); err == nil {
				s.err = fmt.Errorf("%w: data after the final frame", ErrSealed)
			} else {
				s.err = io.EOF
			}
			return 0, s.err
		}
		s.err = s.next()
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

func (s *sealedReader) next() error {
	var l [4]byte
	if _, err := io.ReadFull(s.r, l[:]); err != nil {
		return fmt.Errorf("%w: truncated (no final frame)", ErrSealed)
	}
	n := binary.BigEndian.Uint32(l[:])
	if n < uint32(s.aead.Overhead()) || n > uint32(sealedFrameMax+s.aead.Overhead()) { //nolint:gosec // G115: constants
		return fmt.Errorf("%w: frame length %d", ErrSealed, n)
	}
	if cap(s.ct) < int(n) {
		s.ct = make([]byte, n)
	}
	s.ct = s.ct[:n]
	if _, err := io.ReadFull(s.r, s.ct); err != nil {
		return fmt.Errorf("%w: truncated frame", ErrSealed)
	}
	// A frame opens with exactly one of the two flags; the final flag ends the stream.
	pt, err := s.aead.Open(s.plain[:0], sealedNonce(s.i, false), s.ct, s.aad)
	if err != nil {
		pt, err = s.aead.Open(s.plain[:0], sealedNonce(s.i, true), s.ct, s.aad)
		if err != nil {
			return fmt.Errorf("%w: frame %d does not authenticate", ErrSealed, s.i)
		}
		s.done = true
	} else if len(pt) != sealedFrameMax {
		// Non-final frames are always full.
		return fmt.Errorf("%w: short non-final frame %d", ErrSealed, s.i)
	}
	s.plain = pt
	s.buf = pt
	s.i++
	return nil
}
