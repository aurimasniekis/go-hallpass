package backup

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/aurimasniekis/go-hallpass/internal/recording/hprec"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// copyHashed copies the regular file src to the new file dst (mode 0600, parents 0700), fsyncs it and returns its
// size and SHA-256. extra, if non-nil, also receives every byte.
func copyHashed(src, dst string, extra io.Writer) (int64, [32]byte, error) {
	var sum [32]byte
	in, err := openRegular(src)
	if err != nil {
		return 0, sum, err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return 0, sum, err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // destination inside our own staging directory
	if err != nil {
		return 0, sum, err
	}
	h := sha256.New()
	ws := []io.Writer{out, h}
	if extra != nil {
		ws = append(ws, extra)
	}
	n, err := io.Copy(io.MultiWriter(ws...), in)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return 0, sum, fmt.Errorf("copy %s: %w", src, err)
	}
	h.Sum(sum[:0])
	return n, sum, nil
}

// hashFile returns the size and SHA-256 of a regular file. extra, if non-nil, also receives every byte.
func hashFile(p string, extra ...io.Writer) (int64, [32]byte, error) {
	var sum [32]byte
	f, err := openRegular(p)
	if err != nil {
		return 0, sum, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(append([]io.Writer{h}, extra...)...), f)
	if err != nil {
		return 0, sum, err
	}
	h.Sum(sum[:0])
	return n, sum, nil
}

// openRegular opens p for reading and refuses anything but a regular file (no symlinks, devices or FIFOs).
func openRegular(p string) (*os.File, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	f, err := os.Open(p) //nolint:gosec // paths come from the database snapshot or a validated manifest
	if err != nil {
		return nil, err
	}
	if fi2, err := f.Stat(); err != nil || !os.SameFile(fi, fi2) {
		_ = f.Close()
		return nil, fmt.Errorf("%s changed while opening", p)
	}
	return f, nil
}

func writeFileSync(p string, b []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // our own staging directory
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func fsyncPath(p string) error {
	f, err := os.Open(p) //nolint:gosec // our own file
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// fsyncTree fsyncs every directory under root so that all entries are durable (files are fsynced when written).
func fsyncTree(root string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return store.FsyncDir(p)
		}
		return nil
	})
}

// segHasher computes, without any key, the two hashes the database records for an HPREC1 segment while the file
// streams through it: H = SHA-256(bytes [0, 12+N)) and ciphertext_sha256 = SHA-256(frames region), where N is the
// header length and the frames region starts after the two key slots (docs/formats/hprec1.md §1, §8).
type segHasher struct {
	off    int64
	n      int64 // header length, -1 until known
	limit  int64 // end of the frames region recorded in the database, -1 = end of file
	prefix [12]byte
	h, f   hash.Hash
}

const prefixLen = 12 // magic + header_len

func newSegHasher(recorded sql.NullInt64) *segHasher {
	s := &segHasher{n: -1, limit: -1, h: sha256.New(), f: sha256.New()}
	if recorded.Valid {
		s.limit = recorded.Int64
	}
	return s
}

func (s *segHasher) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		var k int64
		switch {
		case s.off < prefixLen:
			k = min(prefixLen-s.off, int64(len(p)))
			copy(s.prefix[s.off:], p[:k])
			s.h.Write(p[:k])
			if s.off+k == prefixLen {
				s.n = int64(binary.BigEndian.Uint32(s.prefix[8:]))
			}
		case s.off < prefixLen+s.n:
			k = min(prefixLen+s.n-s.off, int64(len(p)))
			s.h.Write(p[:k])
		case s.off < s.framesStart():
			k = min(s.framesStart()-s.off, int64(len(p)))
		default:
			k = int64(len(p))
			if s.limit >= 0 {
				k = max(min(s.limit-s.off, k), 0)
				s.f.Write(p[:k])
				k = int64(len(p))
			} else {
				s.f.Write(p)
			}
		}
		s.off += k
		p = p[k:]
	}
	return total, nil
}

func (s *segHasher) framesStart() int64 { return prefixLen + s.n + 2*hprec.SlotSize }

// check compares the streamed file with the hashes recorded in the database and describes any mismatch.
func (s *segHasher) check(header, ciphertext []byte) string {
	switch {
	case s.off < prefixLen || string(s.prefix[:len(hprec.Magic)]) != hprec.Magic:
		return "not an HPREC1 segment file"
	case s.n <= 0 || s.n > hprec.MaxHeaderLen || s.off < s.framesStart():
		return "truncated segment header or key slots"
	case !bytes.Equal(s.h.Sum(nil), header):
		return "header hash differs from the database"
	case s.limit >= 0 && s.off < s.limit:
		return "segment file is shorter than recorded"
	case len(ciphertext) > 0 && !bytes.Equal(s.f.Sum(nil), ciphertext):
		return "ciphertext hash differs from the database"
	}
	return ""
}
