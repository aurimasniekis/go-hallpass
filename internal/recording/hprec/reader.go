package hprec

import (
	"bufio"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"iter"
	"os"
)

// Option adds an expectation that Open, NewReader, Verify and Recover check against the header before using the key
// slots. Each file is self-consistent, so detecting a substituted or swapped segment file requires comparing its
// header with what the database says it should be.
type Option func(*options)

type options struct {
	segmentID, sessionID, channelID string
	headerSHA256                    *[32]byte
}

// ExpectSegmentID requires the header segment_id to equal id.
func ExpectSegmentID(id string) Option { return func(o *options) { o.segmentID = id } }

// ExpectSessionID requires the header session_id to equal id.
func ExpectSessionID(id string) Option { return func(o *options) { o.sessionID = id } }

// ExpectChannelID requires the header channel_id to equal id.
func ExpectChannelID(id string) Option { return func(o *options) { o.channelID = id } }

// ExpectHeaderSHA256 requires H to equal h (the header_sha256 stored in the database).
func ExpectHeaderSHA256(h [32]byte) Option { return func(o *options) { o.headerSHA256 = &h } }

func (o *options) check(hdr *Header, h [32]byte) error {
	switch {
	case o.segmentID != "" && o.segmentID != hdr.SegmentID:
		return fmt.Errorf("%w: %w: segment_id %q", ErrCorrupt, ErrHeaderMismatch, hdr.SegmentID)
	case o.sessionID != "" && o.sessionID != hdr.SessionID:
		return fmt.Errorf("%w: %w: session_id %q", ErrCorrupt, ErrHeaderMismatch, hdr.SessionID)
	case o.channelID != "" && o.channelID != hdr.ChannelID:
		return fmt.Errorf("%w: %w: channel_id %q", ErrCorrupt, ErrHeaderMismatch, hdr.ChannelID)
	case o.headerSHA256 != nil && subtle.ConstantTimeCompare(o.headerSHA256[:], h[:]) != 1:
		return fmt.Errorf("%w: %w: header_sha256", ErrCorrupt, ErrHeaderMismatch)
	}
	return nil
}

// Reader decodes a segment frame by frame. Each frame is authenticated in full before any of its records is
// returned, and memory use is bounded by one frame. A Reader is not safe for concurrent use.
type Reader struct {
	src    io.Reader
	closer io.Closer
	hdr    Header
	h      [32]byte
	aead   cipher.AEAD
	slot   SlotInfo
	raw    [2][SlotSize]byte
	aad    []byte

	frame  uint64 // number of authenticated frames
	offset int64  // end of the last authenticated frame (or of the key slots)
	lenBuf [frameLenSize]byte
	ctBuf  []byte

	queue []Record
	qi    int
	term  error // returned once the queue drains: io.EOF, ErrIncomplete, ErrCorrupt or an I/O error

	ctHash, ptHash hash.Hash
	records        uint64
	firstSeq       uint64
	lastSeq        uint64
	footer         *Footer
}

// Open opens the segment file at path. The caller must Close the reader.
func Open(path string, w DEKWrapper, opts ...Option) (*Reader, error) {
	f, err := os.Open(path) //nolint:gosec // G304: caller-chosen segment path
	if err != nil {
		return nil, err
	}
	r, err := NewReader(f, w, opts...)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	r.closer = f
	return r, nil
}

// NewReader reads the header and key slots from src, checks the options, and unwraps the DEK from the valid slot
// with the highest gen (falling back to the other slot).
func NewReader(src io.Reader, w DEKWrapper, opts ...Option) (*Reader, error) {
	r, err := newReader(src, w, opts)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// newReader is NewReader, but it also returns the partially initialized reader (header and raw slots) when only the
// option check or key-slot stage fails, for verification reports.
func newReader(src io.Reader, w DEKWrapper, opts []Option) (*Reader, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	br := bufio.NewReaderSize(src, 2*(frameLenSize+maxCTLen))
	hdr, raw, h, err := readPrefixHeader(br)
	if err != nil {
		return nil, err
	}
	r := &Reader{src: br, hdr: hdr, h: h, ctHash: sha256.New(), ptHash: sha256.New(), aad: DEKAAD(hdr.SegmentID, h)}
	if err := o.check(&hdr, h); err != nil {
		return r, err
	}
	for i := range 2 {
		if _, err := io.ReadFull(br, r.raw[i][:]); err != nil {
			return r, shortRead(err, "key slots")
		}
	}
	dek, slot, err := selectSlot(&r.raw, r.aad, w)
	if err != nil {
		return r, err
	}
	defer clear(dek)
	if r.aead, err = payloadAEAD(dek, hdr.PayloadSalt); err != nil {
		return r, err
	}
	r.slot = slot
	r.offset = int64(prefixFixed + len(raw) + 2*SlotSize)
	return r, nil
}

// Close closes the underlying file if the reader was created by Open.
func (r *Reader) Close() error {
	if r.closer == nil {
		return nil
	}
	c := r.closer
	r.closer = nil
	return c.Close()
}

// Header returns the segment header. It is authenticated once NewReader succeeds, because the DEK only unwraps under
// an AAD containing H, and every frame is additionally sealed with H as associated data.
func (r *Reader) Header() Header { return r.hdr }

// HeaderSHA256 returns H.
func (r *Reader) HeaderSHA256() [32]byte { return r.h }

// Slot returns the key slot used to unwrap the DEK.
func (r *Reader) Slot() SlotInfo { return r.slot }

// Frames returns the number of frames authenticated so far.
func (r *Reader) Frames() uint64 { return r.frame }

// ValidOffset returns the file offset just past the last authenticated frame (or past the key slots before the
// first frame).
func (r *Reader) ValidOffset() int64 { return r.offset }

// CiphertextSHA256 returns SHA-256 over the frames authenticated so far (see Manifest.CiphertextSHA256).
func (r *Reader) CiphertextSHA256() [32]byte {
	var out [32]byte
	r.ctHash.Sum(out[:0])
	return out
}

// Footer returns the segment footer once the final frame has been read.
func (r *Reader) Footer() (Footer, bool) {
	if r.footer == nil {
		return Footer{}, false
	}
	return *r.footer, true
}

// Next returns the next record. At the end it returns io.EOF if the final frame was present and valid,
// ErrIncomplete if the file ends before a final frame, or an error wrapping ErrCorrupt. Records are returned only
// from frames that authenticated; after an error, every record returned before it is authentic.
func (r *Reader) Next() (Record, error) {
	rec, err := r.peek()
	if err == nil {
		r.qi++
	}
	return rec, err
}

// All iterates over the records. A final non-nil error (anything but io.EOF) is yielded with a zero Record.
func (r *Reader) All() iter.Seq2[Record, error] {
	return func(yield func(Record, error) bool) {
		for {
			rec, err := r.Next()
			if errors.Is(err, io.EOF) {
				return
			}
			if !yield(rec, err) || err != nil {
				return
			}
		}
	}
}

func (r *Reader) peek() (Record, error) {
	for r.qi >= len(r.queue) {
		if r.term != nil {
			return Record{}, r.term
		}
		r.queue, r.qi = r.queue[:0], 0
		r.term = r.readFrame()
	}
	return r.queue[r.qi], nil
}

// readFrame reads, authenticates and decodes one frame into r.queue. It returns a terminal error when the segment
// ends (io.EOF after a valid final frame) or fails; records of a frame that authenticated are queued even then.
func (r *Reader) readFrame() error {
	if _, err := io.ReadFull(r.src, r.lenBuf[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("%w: %d frames, ends at offset %d", ErrIncomplete, r.frame, r.offset)
		}
		return err
	}
	n := binary.BigEndian.Uint32(r.lenBuf[:])
	if n < minCTLen || n > maxCTLen {
		return r.corrupt("frame length %d", n)
	}
	if cap(r.ctBuf) < int(n) {
		r.ctBuf = make([]byte, maxCTLen)
	}
	ct := r.ctBuf[:n]
	if _, err := io.ReadFull(r.src, ct); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("%w: frame %d truncated at offset %d", ErrIncomplete, r.frame, r.offset)
		}
		return err
	}
	final := false
	nonce := frameNonce(r.frame, false)
	pt, err := r.aead.Open(make([]byte, 0, len(ct)-tagSize), nonce[:], ct, r.h[:])
	if err != nil {
		final = true
		nonce = frameNonce(r.frame, true)
		if pt, err = r.aead.Open(pt[:0], nonce[:], ct, r.h[:]); err != nil {
			return r.corrupt("frame %d authentication failed", r.frame)
		}
	}
	recs, footer, err := r.decodeFrame(pt, final)
	if err != nil {
		return err
	}
	r.ctHash.Write(r.lenBuf[:])
	r.ctHash.Write(ct)
	r.offset += int64(frameLenSize) + int64(n)
	r.frame++
	r.queue = append(r.queue, recs...)
	if !final {
		return nil
	}
	r.footer = footer
	var one [1]byte
	switch _, err := io.ReadFull(r.src, one[:]); {
	case errors.Is(err, io.EOF):
		return io.EOF
	case err != nil:
		return err
	default:
		return r.corrupt("data after the final frame")
	}
}

func (r *Reader) corrupt(format string, args ...any) error {
	return fmt.Errorf("%w: at offset %d: %s", ErrCorrupt, r.offset, fmt.Sprintf(format, args...))
}

// decodeFrame decodes and validates every record of an authenticated frame plaintext. Nothing is committed to the
// reader state unless the whole frame is valid.
func (r *Reader) decodeFrame(pt []byte, final bool) ([]Record, *Footer, error) {
	if len(pt) == 0 {
		return nil, nil, r.corrupt("frame %d is empty", r.frame)
	}
	var recs []Record
	prevUS := r.hdr.CreatedAt.UnixMicro()
	lastSeq, count, firstSeq := r.lastSeq, r.records, r.firstSeq
	p := 0
	for p < len(pt) {
		rec, us, n, err := decodeRecord(pt[p:], prevUS)
		if err != nil {
			return nil, nil, r.corrupt("frame %d record at %d: %v", r.frame, p, err)
		}
		if rec.Type == RecSegmentFooter {
			if !final || p+n != len(pt) {
				return nil, nil, r.corrupt("frame %d: footer is not the last record of the final frame", r.frame)
			}
			if rec.Seq != 0 || rec.Mono != 0 || rec.Stream != StreamMeta || us != prevUS {
				return nil, nil, r.corrupt("frame %d: footer fields are not canonical", r.frame)
			}
			ft, _ := ParseFooter(rec.Payload) // validated by decodeRecord
			r.ptHash.Write(pt[:p])
			var sum [32]byte
			r.ptHash.Sum(sum[:0])
			if ft.Records != count || ft.FirstSeq != firstSeq || ft.LastSeq != lastSeq ||
				subtle.ConstantTimeCompare(sum[:], ft.PlaintextSHA256[:]) != 1 {
				return nil, nil, r.corrupt("footer does not match the segment contents")
			}
			r.records, r.firstSeq, r.lastSeq = count, firstSeq, lastSeq
			return recs, &ft, nil
		}
		if rec.Seq == 0 || rec.Seq <= lastSeq {
			return nil, nil, r.corrupt("frame %d: seq %d not increasing", r.frame, rec.Seq)
		}
		if count == 0 {
			firstSeq = rec.Seq
		}
		lastSeq = rec.Seq
		count++
		prevUS = us
		recs = append(recs, rec)
		p += n
	}
	if final {
		return nil, nil, r.corrupt("final frame %d has no footer", r.frame)
	}
	r.ptHash.Write(pt)
	r.records, r.firstSeq, r.lastSeq = count, firstSeq, lastSeq
	return recs, nil, nil
}

// Page is one page of replay records.
type Page struct {
	Records []Record
	// NextSeq is the fromSeq to request the following page with (meaningful when More is true).
	NextSeq uint64
	// More is true when the page stopped because of its size budget.
	More bool
	// Complete is true when the end of a segment with a valid final frame was reached.
	Complete bool
	// Incomplete is true when the end of a segment without a final frame was reached (an interrupted recording,
	// HP-REC-009); every returned record is still authentic.
	Incomplete bool
}

// pageCost estimates a record's decoded size for page budgeting.
func pageCost(rec *Record) int { return len(rec.Payload) + maxRecordOverhead }

// ReadPage returns the next records with Seq >= fromSeq, continuing from the reader's position, up to maxBytes of
// estimated decoded size (clamped to MaxPageBytes; at least one record is always returned when one is available).
// Reaching the end of an interrupted segment is not an error: the page has Incomplete set. Authentication or
// structural failures return the records gathered so far together with the error.
func (r *Reader) ReadPage(fromSeq uint64, maxBytes int) (Page, error) {
	if maxBytes <= 0 || maxBytes > MaxPageBytes {
		maxBytes = MaxPageBytes
	}
	var pg Page
	used := 0
	for {
		rec, err := r.peek()
		switch {
		case errors.Is(err, io.EOF):
			pg.Complete = true
			return pg, nil
		case errors.Is(err, ErrIncomplete):
			pg.Incomplete = true
			return pg, nil
		case err != nil:
			return pg, err
		}
		if rec.Seq < fromSeq {
			r.qi++
			continue
		}
		c := pageCost(&rec)
		if len(pg.Records) > 0 && used+c > maxBytes {
			pg.More, pg.NextSeq = true, rec.Seq
			return pg, nil
		}
		used += c
		pg.Records = append(pg.Records, rec)
		r.qi++
	}
}

// ReadPage opens the segment at path and returns the page of records with Seq >= fromSeq (see Reader.ReadPage).
// Each call decrypts the segment from the start.
func ReadPage(path string, w DEKWrapper, fromSeq uint64, maxBytes int, opts ...Option) (Page, error) {
	r, err := Open(path, w, opts...)
	if err != nil {
		return Page{}, err
	}
	defer r.Close()
	return r.ReadPage(fromSeq, maxBytes)
}
