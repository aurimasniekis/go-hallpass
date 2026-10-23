package hprec

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Manifest summarizes a finalized (or recovered) segment for the database and the integrity chain (PLAN §13.5).
type Manifest struct {
	SegmentID    string
	Path         string   // final path of the segment file
	HeaderSHA256 [32]byte // H
	// CiphertextSHA256 is SHA-256 over the frames region (every ct_len||ciphertext from the first frame to the end of
	// the last valid frame). It excludes the header, which H covers, and the key slots, which change on rewrap.
	CiphertextSHA256 [32]byte
	Frames           uint64
	Bytes            int64 // file size, header and slots included
	Records          uint64
	FirstSeq         uint64
	LastSeq          uint64
	EndReason        string // empty for a recovered segment without a final frame
}

// Prepared is a segment whose header, DEK and key slot have been generated but whose file does not exist yet. It
// lets the caller register the segment (header hash, key ID, wrapped DEK) in the database before creating the file
// (PLAN §13.5 step 1).
type Prepared struct {
	hdr     Header
	prefix  []byte // magic || header_len || header || slot A || slot B
	h       [32]byte
	dek     []byte
	slot    SlotInfo
	created bool
}

// Prepare validates h, draws a random DEK and payload salt, and wraps the DEK with w into slot A (gen 1). Slot B is
// left empty (all zero). CreatedAt is truncated to microseconds; h.PayloadSalt is ignored.
func Prepare(h Header, w DEKWrapper) (*Prepared, error) {
	h.normalize()
	h.PrevSegmentSHA256 = append([]byte(nil), h.PrevSegmentSHA256...)
	if len(h.PrevSegmentSHA256) == 0 {
		h.PrevSegmentSHA256 = nil
	}
	_, _ = rand.Read(h.PayloadSalt[:]) // crypto/rand.Read never returns an error
	hdr, err := encodeHeader(&h)
	if err != nil {
		return nil, err
	}
	p := &Prepared{hdr: h, h: headerHash(hdr), dek: make([]byte, DEKSize)}
	_, _ = rand.Read(p.dek)
	slotA, slot, err := wrapForSlot(w, p.dek, DEKAAD(h.SegmentID, p.h), 1)
	if err != nil {
		clear(p.dek)
		return nil, err
	}
	p.slot = slotA
	p.prefix = make([]byte, 0, prefixFixed+len(hdr)+2*SlotSize)
	p.prefix = append(p.prefix, Magic...)
	p.prefix = binary.BigEndian.AppendUint32(p.prefix, uint32(len(hdr))) //nolint:gosec // G115: <= MaxHeaderLen
	p.prefix = append(p.prefix, hdr...)
	p.prefix = append(p.prefix, slot[:]...)
	p.prefix = append(p.prefix, make([]byte, SlotSize)...)
	return p, nil
}

// Header returns the header that will be written, including the generated payload salt.
func (p *Prepared) Header() Header { return p.hdr }

// HeaderSHA256 returns H.
func (p *Prepared) HeaderSHA256() [32]byte { return p.h }

// Slot returns the initial key slot (slot A, gen 1): the key ID and wrapped DEK to store in the database.
func (p *Prepared) Slot() SlotInfo { return p.slot }

// Discard wipes the DEK of a segment that will not be created.
func (p *Prepared) Discard() {
	clear(p.dek)
	p.created = true
}

// Create is Prepare followed by Prepared.Create.
func Create(path string, h Header, w DEKWrapper) (*Writer, error) {
	p, err := Prepare(h, w)
	if err != nil {
		return nil, err
	}
	return p.Create(path)
}

// Create writes the segment prefix to path+".partial" (O_CREATE|O_EXCL, mode 0600) and fsyncs the file and its
// directory. When it returns nil the recording is established (PLAN §13.5 step 2). path is the final name, used by
// Finalize; it must not already exist. On failure the partial file is removed and the error returned. A Prepared
// can be used for at most one Create.
func (p *Prepared) Create(path string) (*Writer, error) {
	if p.created {
		return nil, errors.New("hprec: prepared segment already used")
	}
	p.created = true
	defer clear(p.dek)
	if strings.HasSuffix(path, PartialSuffix) {
		return nil, fmt.Errorf("hprec: final path must not end in %q", PartialSuffix)
	}
	if _, err := os.Lstat(path); err == nil {
		return nil, fmt.Errorf("hprec: %s: %w", path, fs.ErrExist)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	aead, err := payloadAEAD(p.dek, p.hdr.PayloadSalt)
	if err != nil {
		return nil, err
	}
	partial := path + PartialSuffix
	f, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: caller-chosen segment path
	if err != nil {
		return nil, err
	}
	err = writeAll(f, p.prefix)
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = syncDir(filepath.Dir(partial))
	}
	if err != nil {
		_ = f.Close()
		return nil, errors.Join(err, os.Remove(partial))
	}
	w := &Writer{
		f: f, path: path, partial: partial, aead: aead, h: p.h, hdr: p.hdr,
		baseUS:  p.hdr.CreatedAt.UnixMicro(),
		offset:  int64(len(p.prefix)),
		pending: make([]byte, 0, FrameMax),
		sealBuf: make([]byte, 0, frameLenSize+maxCTLen),
		ctHash:  sha256.New(),
		ptHash:  sha256.New(),
	}
	w.prevUS = w.baseUS
	return w, nil
}

func writeAll(f *os.File, b []byte) error {
	_, err := f.Write(b) // os.File.Write returns an error whenever it writes less than len(b)
	return err
}

func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: directory of the caller-chosen segment path
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return fmt.Errorf("hprec: fsync dir %s: %w", dir, err)
	}
	return d.Close()
}

// Writer appends records to a segment. It is not safe for concurrent use; PLAN §13.5 assigns one writer goroutine
// per segment. Any write or fsync error is returned and makes the writer permanently failed: nothing is retried.
type Writer struct {
	f       *os.File
	path    string
	partial string
	aead    cipher.AEAD
	h       [32]byte
	hdr     Header

	baseUS  int64 // created_at in UTC microseconds; the t_us base of every frame
	prevUS  int64 // timestamp of the previous record in the current frame
	pending []byte
	sealBuf []byte
	frame   uint64 // index of the next frame
	offset  int64  // bytes written to the file
	dirty   bool   // written since the last fsync

	ctHash, ptHash hash.Hash
	records        uint64
	firstSeq       uint64
	lastSeq        uint64

	err  error // sticky failure or closed state
	done bool
}

// Header returns the segment header.
func (w *Writer) Header() Header { return w.hdr }

// HeaderSHA256 returns H.
func (w *Writer) HeaderSHA256() [32]byte { return w.h }

// PartialPath returns the path being written.
func (w *Writer) PartialPath() string { return w.partial }

// Size returns the number of bytes written to the file so far (pending records excluded).
func (w *Writer) Size() int64 { return w.offset }

// Pending returns the number of plaintext bytes buffered for the next frame.
func (w *Writer) Pending() int { return len(w.pending) }

func (w *Writer) fail(err error) error {
	if w.err == nil {
		w.err = err
	}
	return err
}

// Append adds a record to the current frame. If the record does not fit, the pending frame is sealed (non-final) and
// written first; that write is not fsynced until Flush or Finalize. Seq must be >= 1 and greater than the previous
// record's, and structured payloads must parse. Validation errors leave the writer usable; I/O errors do not.
func (w *Writer) Append(r Record) error {
	if w.err != nil {
		return w.err
	}
	if !r.Type.Valid() || r.Type == RecSegmentFooter {
		return fmt.Errorf("%w: type %d", ErrInvalidRecord, r.Type)
	}
	if r.Seq == 0 || r.Seq <= w.lastSeq {
		return fmt.Errorf("%w: seq %d not greater than %d", ErrInvalidRecord, r.Seq, w.lastSeq)
	}
	if err := validatePayload(r.Type, r.Payload); err != nil {
		return err
	}
	mark := len(w.pending)
	enc, err := appendRecord(w.pending, &r, w.prevUS)
	if err != nil {
		return err
	}
	if len(enc) > FrameMax {
		w.pending = enc[:mark]
		if err := w.seal(false); err != nil {
			return err
		}
		if enc, err = appendRecord(w.pending, &r, w.prevUS); err != nil {
			return err
		}
	}
	w.ptHash.Write(enc[len(w.pending):])
	w.pending = enc
	w.prevUS = r.Time.UnixMicro()
	if w.records == 0 {
		w.firstSeq = r.Seq
	}
	w.records++
	w.lastSeq = r.Seq
	return nil
}

// seal encrypts the pending plaintext as frame w.frame and writes it.
func (w *Writer) seal(final bool) error {
	nonce := frameNonce(w.frame, final)
	buf := w.aead.Seal(w.sealBuf[:frameLenSize], nonce[:], w.pending, w.h[:])
	binary.BigEndian.PutUint32(buf, uint32(len(buf)-frameLenSize)) //nolint:gosec // G115: <= maxCTLen
	w.sealBuf = buf[:0]
	if err := writeAll(w.f, buf); err != nil {
		return w.fail(fmt.Errorf("hprec: write frame %d: %w", w.frame, err))
	}
	w.ctHash.Write(buf)
	w.offset += int64(len(buf))
	w.frame++
	w.dirty = true
	w.pending = w.pending[:0]
	w.prevUS = w.baseUS
	return nil
}

// Flush seals any pending records as a non-final frame and fsyncs the file. The caller drives group-commit timing
// (PLAN §13.5 step 3).
func (w *Writer) Flush() error {
	if w.err != nil {
		return w.err
	}
	if len(w.pending) > 0 {
		if err := w.seal(false); err != nil {
			return err
		}
	}
	if !w.dirty {
		return nil
	}
	if err := w.f.Sync(); err != nil {
		return w.fail(fmt.Errorf("hprec: fsync: %w", err))
	}
	w.dirty = false
	return nil
}

// Finalize writes the final frame ending with a segment.footer record, fsyncs, renames the partial file to the final
// path and fsyncs the directory (PLAN §13.5 step 4). endReason is 1-64 characters of [a-z0-9_.-]. The segment is
// durable and complete only after the caller has also committed the returned manifest.
func (w *Writer) Finalize(endReason string) (Manifest, error) {
	if w.err != nil {
		return Manifest{}, w.err
	}
	if !validCode(endReason) {
		return Manifest{}, fmt.Errorf("%w: end reason must be 1-%d characters of [a-z0-9_.-]", ErrInvalidRecord, maxCodeLen)
	}
	ft := Footer{Records: w.records, FirstSeq: w.firstSeq, LastSeq: w.lastSeq, EndReason: endReason}
	w.ptHash.Sum(ft.PlaintextSHA256[:0])
	fr := footerRecord(ft)
	mark := len(w.pending)
	enc, _ := appendRecord(w.pending, &fr, 0) // footer fields are always in range; t_us is always encoded as delta 0
	if len(enc) > FrameMax {
		w.pending = enc[:mark]
		if err := w.seal(false); err != nil {
			return Manifest{}, err
		}
		enc, _ = appendRecord(w.pending, &fr, 0)
	}
	w.pending = enc
	if err := w.seal(true); err != nil {
		return Manifest{}, err
	}
	if err := w.f.Sync(); err != nil {
		return Manifest{}, w.fail(fmt.Errorf("hprec: fsync: %w", err))
	}
	if err := w.f.Close(); err != nil {
		return Manifest{}, w.fail(fmt.Errorf("hprec: close: %w", err))
	}
	w.done = true
	if err := os.Rename(w.partial, w.path); err != nil {
		return Manifest{}, w.fail(fmt.Errorf("hprec: rename: %w", err))
	}
	if err := syncDir(filepath.Dir(w.path)); err != nil {
		return Manifest{}, w.fail(err)
	}
	w.err = ErrWriterClosed
	m := Manifest{
		SegmentID: w.hdr.SegmentID, Path: w.path, HeaderSHA256: w.h, Frames: w.frame, Bytes: w.offset,
		Records: w.records, FirstSeq: w.firstSeq, LastSeq: w.lastSeq, EndReason: endReason,
	}
	w.ctHash.Sum(m.CiphertextSHA256[:0])
	return m, nil
}

// footerRecord builds the footer record. Its seq, mono_ns and t_us delta are 0 and its stream is meta; readers
// require exactly these values.
func footerRecord(ft Footer) Record {
	return Record{Type: RecSegmentFooter, Time: minTime, Stream: StreamMeta, Payload: ft.Marshal()}
}

// Close releases the file without finalizing. Records not yet sealed are discarded; sealed frames stay in the
// partial file, which recovery later marks interrupted. Close after Finalize is a no-op.
func (w *Writer) Close() error {
	if w.done {
		return nil
	}
	w.done = true
	if w.err == nil {
		w.err = ErrWriterClosed
	}
	return w.f.Close()
}
