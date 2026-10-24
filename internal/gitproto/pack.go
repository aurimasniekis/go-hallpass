package gitproto

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/sha1" //nolint:gosec // git object IDs: identification, not a security boundary (SHA-1 repositories)
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"
)

// Limits for pack inspection. A pack beyond them is forwarded as usual but its ancestry is unknown, so a force-push
// check fails closed.
const (
	maxPackObjects     = 2_000_000
	maxObjectSize      = 4 << 30 // larger objects (huge blobs) make the push refused rather than inspected
	maxCommitBytes     = 1 << 20
	maxTotalCommitData = 64 << 20
)

// Pack object types.
const (
	objCommit   = 1
	objTree     = 2
	objBlob     = 3
	objTag      = 4
	objOfsDelta = 6
	objRefDelta = 7
)

// ErrPack is returned for a pack that cannot be parsed.
var ErrPack = errors.New("malformed pack")

// CommitGraph holds the parents of the commits a push sends, keyed by object ID.
type CommitGraph struct {
	parents map[string][]string
	// complete is false when some objects could not be resolved (a delta whose base is not in the pack, or limits),
	// so a commit may be missing.
	complete bool
}

// Fast-forward results.
const (
	FastForward    = "fast-forward"
	NotFastForward = "not-fast-forward"
	Unknown        = "unknown"
)

// AncestryOf reports whether old is an ancestor of new using only the pushed commits. It is FastForward when a parent
// chain inside the pack leads from new to old; NotFastForward when the pack holds the complete history of new and old
// is not in it; Unknown otherwise (the history continues on the host, or new was not pushed). Only FastForward proves
// that an update is not a force-push.
func (g *CommitGraph) AncestryOf(old, new string) string {
	if old == new {
		return FastForward
	}
	if _, ok := g.parents[new]; !ok {
		return Unknown // new already exists on the host, or was not resolvable: cannot prove anything
	}
	seen := map[string]bool{new: true}
	queue := []string{new}
	leftPack := false
	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]
		ps, inPack := g.parents[c]
		if !inPack {
			leftPack = true // the history continues on the host, where old may still be an ancestor
			continue
		}
		for _, p := range ps {
			if p == old {
				return FastForward
			}
			if !seen[p] {
				seen[p] = true
				queue = append(queue, p)
			}
		}
	}
	if leftPack || !g.complete {
		return Unknown
	}
	return NotFastForward // the whole history of new is in the pack (a new root) and old is not in it
}

// byteTee reads from a bufio.Reader, copies every byte it returns to w, and counts them. It implements io.ByteReader so
// the zlib decompressor reads exactly the compressed bytes of each object and no further.
type byteTee struct {
	r   *bufio.Reader
	w   *bufio.Writer
	off int64
	err error
}

func (t *byteTee) ReadByte() (byte, error) {
	b, err := t.r.ReadByte()
	if err != nil {
		return 0, err
	}
	t.off++
	if t.err == nil {
		t.err = t.w.WriteByte(b)
	}
	return b, nil
}

func (t *byteTee) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	t.off += int64(n)
	if n > 0 && t.err == nil {
		_, t.err = t.w.Write(p[:n])
	}
	return n, err
}

// ScanPack reads a pack from r and forwards every byte to w except the trailing checksum, which it returns: the caller
// writes it only once it has decided to let the push through. Without the checksum the host refuses the pack and
// applies no ref update. hashLen is 20 (SHA-1) or 32 (SHA-256).
func ScanPack(r *bufio.Reader, w io.Writer, hashLen int) (*CommitGraph, []byte, error) {
	bw := bufio.NewWriterSize(w, 64<<10)
	t := &byteTee{r: r, w: bw}
	g, err := scanObjects(t, hashLen)
	if ferr := bw.Flush(); err == nil {
		err = ferr
	}
	if err == nil {
		err = t.err
	}
	if err != nil {
		return nil, nil, err
	}
	trailer := make([]byte, hashLen)
	if _, err := io.ReadFull(r, trailer); err != nil {
		return nil, nil, fmt.Errorf("%w: missing checksum", ErrPack)
	}
	return g, trailer, nil
}

func newHash(hashLen int) hash.Hash {
	if hashLen == 32 {
		return sha256.New()
	}
	return sha1.New() //nolint:gosec // see import
}

type stored struct {
	typ  int
	data []byte
}

func scanObjects(t *byteTee, hashLen int) (*CommitGraph, error) {
	var hdr [12]byte
	if _, err := io.ReadFull(t, hdr[:]); err != nil {
		return nil, fmt.Errorf("%w: header", ErrPack)
	}
	if string(hdr[:4]) != "PACK" {
		return nil, fmt.Errorf("%w: signature", ErrPack)
	}
	if v := binary.BigEndian.Uint32(hdr[4:8]); v != 2 && v != 3 {
		return nil, fmt.Errorf("%w: version %d", ErrPack, v)
	}
	count := binary.BigEndian.Uint32(hdr[8:12])
	g := &CommitGraph{parents: map[string][]string{}, complete: count <= maxPackObjects}
	byOffset := map[int64]stored{} // resolved commits by pack offset, for offset deltas
	byID := map[string][]byte{}    // resolved commits by object ID, for ref deltas
	total := 0
	for i := uint32(0); i < count; i++ {
		start := t.off
		typ, size, err := readObjectHeader(t)
		if err != nil {
			return nil, err
		}
		var base []byte
		baseKnown := false
		switch typ {
		case objOfsDelta:
			rel, err := readOfsDelta(t)
			if err != nil {
				return nil, err
			}
			if b, ok := byOffset[start-rel]; ok {
				base, baseKnown = b.data, true
			}
		case objRefDelta:
			id := make([]byte, hashLen)
			if _, err := io.ReadFull(t, id); err != nil {
				return nil, fmt.Errorf("%w: delta base", ErrPack)
			}
			base, baseKnown = byID[hex.EncodeToString(id)]
		case objCommit, objTree, objBlob, objTag:
		default:
			return nil, fmt.Errorf("%w: object type %d", ErrPack, typ)
		}
		keep := typ == objCommit || baseKnown
		data, err := inflate(t, size, keep)
		if err != nil {
			return nil, err
		}
		if typ == objOfsDelta || typ == objRefDelta {
			if !baseKnown {
				// The base is not a pack commit: either not a commit at all, or a commit only the host has (thin
				// pack). In the second case a pushed commit is missing from the graph.
				if typ == objRefDelta {
					g.complete = false
				}
				continue
			}
			if data, err = applyDelta(base, data); err != nil {
				return nil, err
			}
		} else if typ != objCommit {
			continue
		}
		if total += len(data); total > maxTotalCommitData {
			g.complete = false
			continue
		}
		id := objectID(hashLen, data)
		byOffset[start] = stored{typ: objCommit, data: data}
		byID[id] = data
		g.parents[id] = commitParents(data)
	}
	return g, nil
}

func objectID(hashLen int, commit []byte) string {
	h := newHash(hashLen)
	_, _ = io.WriteString(h, "commit "+strconv.Itoa(len(commit))+"\x00")
	_, _ = h.Write(commit)
	return hex.EncodeToString(h.Sum(nil))
}

func readObjectHeader(r io.ByteReader) (typ int, size uint64, err error) {
	c, err := r.ReadByte()
	if err != nil {
		return 0, 0, fmt.Errorf("%w: object header", ErrPack)
	}
	typ = int(c>>4) & 7
	size = uint64(c & 0x0f)
	shift := 4
	for c&0x80 != 0 {
		if shift > 57 {
			return 0, 0, fmt.Errorf("%w: object size", ErrPack)
		}
		if c, err = r.ReadByte(); err != nil {
			return 0, 0, fmt.Errorf("%w: object header", ErrPack)
		}
		size |= uint64(c&0x7f) << shift
		shift += 7
	}
	return typ, size, nil
}

func readOfsDelta(r io.ByteReader) (int64, error) {
	c, err := r.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("%w: delta offset", ErrPack)
	}
	off := int64(c & 0x7f)
	for c&0x80 != 0 {
		if off > 1<<48 {
			return 0, fmt.Errorf("%w: delta offset", ErrPack)
		}
		if c, err = r.ReadByte(); err != nil {
			return 0, fmt.Errorf("%w: delta offset", ErrPack)
		}
		off = ((off + 1) << 7) | int64(c&0x7f)
	}
	if off <= 0 {
		return 0, fmt.Errorf("%w: delta offset", ErrPack)
	}
	return off, nil
}

// inflate decompresses one object's zlib stream. When keep is false the data is discarded (trees and blobs); kept
// data is bounded by maxCommitBytes.
func inflate(r io.Reader, size uint64, keep bool) ([]byte, error) {
	if size > maxObjectSize {
		return nil, fmt.Errorf("%w: object too large to inspect", ErrPack)
	}
	zr, err := zlib.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("%w: compressed data", ErrPack)
	}
	defer zr.Close()
	// Decompression is bounded by the declared size (itself bounded): a stream that inflates further is malformed.
	limited := io.LimitReader(zr, int64(size)+1) //nolint:gosec // size <= maxObjectSize
	if !keep {
		n, err := io.Copy(io.Discard, limited)
		if err != nil || n != int64(size) { //nolint:gosec // size <= maxObjectSize
			return nil, fmt.Errorf("%w: object size", ErrPack)
		}
		return nil, endOfStream(zr)
	}
	if size > maxCommitBytes {
		return nil, fmt.Errorf("%w: commit too large", ErrPack)
	}
	data, err := io.ReadAll(limited)
	if err != nil || uint64(len(data)) != size {
		return nil, fmt.Errorf("%w: object size", ErrPack)
	}
	return data, endOfStream(zr)
}

// endOfStream reads the end of a zlib stream (and its checksum) after exactly the declared bytes, so the next object
// starts where it should. Any further data means the object is malformed.
func endOfStream(zr io.Reader) error {
	var b [1]byte
	if n, err := zr.Read(b[:]); n != 0 || (err != nil && !errors.Is(err, io.EOF)) {
		return fmt.Errorf("%w: compressed data", ErrPack)
	}
	return nil
}

// applyDelta applies a git delta to base.
func applyDelta(base, delta []byte) ([]byte, error) {
	r := bytes.NewReader(delta)
	srcSize, err := deltaSize(r)
	if err != nil || srcSize != uint64(len(base)) {
		return nil, fmt.Errorf("%w: delta base size", ErrPack)
	}
	dstSize, err := deltaSize(r)
	if err != nil || dstSize > maxCommitBytes {
		return nil, fmt.Errorf("%w: delta size", ErrPack)
	}
	out := make([]byte, 0, dstSize)
	for r.Len() > 0 {
		cmd, _ := r.ReadByte()
		if cmd&0x80 != 0 {
			var off, n uint64
			for i := range 4 {
				if cmd&(1<<i) != 0 {
					b, err := r.ReadByte()
					if err != nil {
						return nil, fmt.Errorf("%w: delta copy", ErrPack)
					}
					off |= uint64(b) << (8 * i)
				}
			}
			for i := range 3 {
				if cmd&(0x10<<i) != 0 {
					b, err := r.ReadByte()
					if err != nil {
						return nil, fmt.Errorf("%w: delta copy", ErrPack)
					}
					n |= uint64(b) << (8 * i)
				}
			}
			if n == 0 {
				n = 0x10000
			}
			if off+n > uint64(len(base)) || uint64(len(out))+n > dstSize {
				return nil, fmt.Errorf("%w: delta copy out of range", ErrPack)
			}
			out = append(out, base[off:off+n]...)
		} else if cmd != 0 {
			n := int(cmd)
			if r.Len() < n || uint64(len(out))+uint64(cmd) > dstSize {
				return nil, fmt.Errorf("%w: delta insert", ErrPack)
			}
			chunk := make([]byte, n)
			_, _ = r.Read(chunk)
			out = append(out, chunk...)
		} else {
			return nil, fmt.Errorf("%w: delta opcode 0", ErrPack)
		}
	}
	if uint64(len(out)) != dstSize {
		return nil, fmt.Errorf("%w: delta result size", ErrPack)
	}
	return out, nil
}

func deltaSize(r io.ByteReader) (uint64, error) {
	var size uint64
	for shift := 0; shift < 64; shift += 7 {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		size |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return size, nil
		}
	}
	return 0, errors.New("size overflow")
}

// commitParents returns the parent IDs from a commit's header lines.
func commitParents(commit []byte) []string {
	var ps []string
	for line := range strings.SplitSeq(string(commit), "\n") {
		if line == "" {
			break // end of headers
		}
		if id, ok := strings.CutPrefix(line, "parent "); ok && validObjectID(id) {
			ps = append(ps, id)
		}
	}
	return ps
}
