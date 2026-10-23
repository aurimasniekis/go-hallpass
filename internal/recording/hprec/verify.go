package hprec

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Status is a segment verification result (PLAN §13.7). The statuses missing and orphan are database-level and are
// assigned by the caller.
type Status string

// Verification statuses.
const (
	StatusOK          Status = "ok"          // every frame authenticated and a valid final frame ends the file
	StatusInterrupted Status = "interrupted" // every frame present authenticated, but there is no final frame
	StatusCorrupt     Status = "corrupt"     // header, key slots or a frame failed authentication or validation
)

// Report is the result of verifying one segment.
type Report struct {
	Status Status
	// Problem explains a non-ok status. It wraps ErrIncomplete, ErrCorrupt, ErrNoKey, ErrHeaderMismatch or
	// ErrUnsupportedVersion.
	Problem error
	// HeaderParsed is true when the header decoded; Header and HeaderSHA256 are valid only then.
	HeaderParsed bool
	Header       Header
	HeaderSHA256 [32]byte
	// Slots reports both key slots, each checked against this segment's AAD with the given wrapper. A slot that
	// no longer unwraps (for example a stale slot under a retired key) does not change Status while the other works.
	Slots [2]SlotCheck
	// ActiveSlot is the slot used to decrypt (0 or 1), or -1.
	ActiveSlot int
	Frames     uint64
	Records    uint64
	FirstSeq   uint64
	LastSeq    uint64
	// ValidOffset is the file offset just past the last authenticated frame. It is 0 if the header and key slots
	// were not usable.
	ValidOffset int64
	// FileSize is the size of the file (Verify) or the number of bytes consumed from the stream (VerifyReader).
	FileSize int64
	// CiphertextSHA256 covers the authenticated frames only (the valid prefix).
	CiphertextSHA256 [32]byte
	// Final is true when an authenticated final frame with a valid footer was read.
	Final     bool
	EndReason string
}

// formatError reports whether err describes the file contents rather than an I/O failure.
func formatError(err error) bool {
	return errors.Is(err, ErrCorrupt) || errors.Is(err, ErrNoKey) || errors.Is(err, ErrUnsupportedVersion) ||
		errors.Is(err, ErrIncomplete)
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// Verify checks the segment at path: header, key slots, every frame in order, the final frame and its footer. A
// non-nil error means verification could not run (for example the file could not be read); problems with the file
// contents are reported in Report.Status and Report.Problem. Callers compare Report.HeaderSHA256 and
// Report.CiphertextSHA256 with the database, or pass ExpectHeaderSHA256.
func Verify(path string, w DEKWrapper, opts ...Option) (Report, error) {
	f, err := os.Open(path) //nolint:gosec // G304: caller-chosen segment path
	if err != nil {
		return Report{ActiveSlot: -1}, err
	}
	defer f.Close()
	rep, err := VerifyReader(f, w, opts...)
	if err != nil {
		return rep, err
	}
	fi, err := f.Stat()
	if err != nil {
		return rep, err
	}
	rep.FileSize = fi.Size()
	return rep, nil
}

// VerifyReader is Verify over a stream.
func VerifyReader(src io.Reader, w DEKWrapper, opts ...Option) (Report, error) {
	cr := &countingReader{r: src}
	rep := Report{ActiveSlot: -1}
	r, err := newReader(cr, w, opts)
	if r != nil {
		rep.HeaderParsed, rep.Header, rep.HeaderSHA256 = true, r.hdr, r.h
		active := -1
		if err == nil {
			active = r.slot.Index
		}
		if !errors.Is(err, ErrHeaderMismatch) { // on a mismatch the slots were not read
			rep.Slots = checkSlots(&r.raw, r.aad, w, active)
		}
	}
	if err != nil {
		rep.FileSize = cr.n
		if !formatError(err) {
			return rep, err
		}
		rep.Status, rep.Problem = StatusCorrupt, err
		return rep, nil
	}
	rep.ActiveSlot = r.slot.Index
	for err == nil {
		_, err = r.Next()
	}
	if _, cerr := io.Copy(io.Discard, cr); cerr != nil && formatError(err) {
		err = cerr
	}
	rep.FileSize = cr.n
	rep.Frames, rep.Records, rep.FirstSeq, rep.LastSeq = r.frame, r.records, r.firstSeq, r.lastSeq
	rep.ValidOffset, rep.CiphertextSHA256 = r.offset, r.CiphertextSHA256()
	if ft, ok := r.Footer(); ok {
		rep.Final, rep.EndReason = true, ft.EndReason
	}
	switch {
	case errors.Is(err, io.EOF):
		rep.Status = StatusOK
	case errors.Is(err, ErrIncomplete):
		rep.Status, rep.Problem = StatusInterrupted, err
	case formatError(err):
		rep.Status, rep.Problem = StatusCorrupt, err
	default:
		return rep, err
	}
	return rep, nil
}

// RecoverResult is the outcome of Recover.
type RecoverResult struct {
	Manifest
	// Complete is true when the partial file already held a valid final frame (a crash between the final fsync and
	// the rename). Otherwise the recovered segment is interrupted (HP-REC-009).
	Complete bool
	// Problem is why the scan stopped before the end of the file (nil when nothing was discarded and the segment
	// is complete).
	Problem error
	// DiscardedBytes is how many trailing bytes were truncated.
	DiscardedBytes int64
	// QuarantinePath is where the original file was copied before truncation; empty if nothing was discarded.
	QuarantinePath string
}

// Recover reconciles a ".partial" segment after a crash (PLAN §13.6 step 2). It authenticates frames from the start
// and stops at the first failure or at the end. If bytes follow the valid prefix, the original file is first copied
// to quarantinePath (created exclusively, mode 0600, fsynced) and the partial file is then truncated to the valid
// prefix and fsynced. Finally the file is renamed to its final name (partialPath without ".partial") and the
// directory fsynced. The result's manifest describes the valid prefix.
//
// If the header or key slots are unusable, Recover changes nothing and returns an error wrapping the cause; the
// caller quarantines such files. Recover must not run while a Writer still has the file open.
func Recover(partialPath string, w DEKWrapper, quarantinePath string, opts ...Option) (RecoverResult, error) {
	if !strings.HasSuffix(partialPath, PartialSuffix) || len(partialPath) == len(PartialSuffix) {
		return RecoverResult{}, fmt.Errorf("hprec: recover: %q does not end in %q", partialPath, PartialSuffix)
	}
	final := strings.TrimSuffix(partialPath, PartialSuffix)
	if _, err := os.Lstat(final); err == nil {
		return RecoverResult{}, fmt.Errorf("hprec: recover: final path %s already exists", final)
	} else if !os.IsNotExist(err) {
		return RecoverResult{}, err
	}
	rep, err := Verify(partialPath, w, opts...)
	if err != nil {
		return RecoverResult{}, err
	}
	if rep.ValidOffset == 0 {
		return RecoverResult{}, fmt.Errorf("hprec: recover: %w", rep.Problem)
	}
	res := RecoverResult{
		Manifest: Manifest{
			SegmentID: rep.Header.SegmentID, Path: final, HeaderSHA256: rep.HeaderSHA256,
			CiphertextSHA256: rep.CiphertextSHA256, Frames: rep.Frames, Bytes: rep.ValidOffset,
			Records: rep.Records, FirstSeq: rep.FirstSeq, LastSeq: rep.LastSeq, EndReason: rep.EndReason,
		},
		Complete:       rep.Final,
		Problem:        rep.Problem,
		DiscardedBytes: rep.FileSize - rep.ValidOffset,
	}
	if res.DiscardedBytes > 0 {
		if quarantinePath == "" {
			return RecoverResult{}, errors.New("hprec: recover: trailing bytes to discard but no quarantine path")
		}
		if err := copyFile(partialPath, quarantinePath); err != nil {
			return RecoverResult{}, fmt.Errorf("hprec: recover: quarantine copy: %w", err)
		}
		res.QuarantinePath = quarantinePath
		if err := truncateFile(partialPath, rep.ValidOffset); err != nil {
			return res, fmt.Errorf("hprec: recover: truncate: %w", err)
		}
	}
	if err := os.Rename(partialPath, final); err != nil {
		return res, fmt.Errorf("hprec: recover: rename: %w", err)
	}
	if err := syncDir(filepath.Dir(final)); err != nil {
		return res, err
	}
	return res, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // G304: caller-chosen segment path
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: caller-chosen quarantine path
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return syncDir(filepath.Dir(dst))
}

func truncateFile(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // G304: caller-chosen segment path
	if err != nil {
		return err
	}
	err = f.Truncate(size)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
