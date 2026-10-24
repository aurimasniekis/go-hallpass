// Package sftpaudit follows an SFTP (version 3, as spoken by OpenSSH sftp and scp) session as it passes through the
// gateway and reports what happened to which file: reads and writes with byte counts and SHA-256 of sequential
// transfers, deletions, renames, directory changes and failures. It never changes the traffic.
package sftpaudit

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"sync"
)

// MaxPacket bounds one SFTP packet (OpenSSH uses at most 256 KiB).
const MaxPacket = 1 << 20

// MaxEvents bounds the file events reported for one session; further operations are only counted.
const MaxEvents = 5000

// SFTP packet types (draft-ietf-secsh-filexfer-02).
const (
	fxpInit     = 1
	fxpOpen     = 3
	fxpClose    = 4
	fxpRead     = 5
	fxpWrite    = 6
	fxpSetstat  = 9
	fxpOpendir  = 11
	fxpRemove   = 13
	fxpMkdir    = 14
	fxpRmdir    = 15
	fxpRename   = 18
	fxpSymlink  = 20
	fxpStatus   = 101
	fxpHandle   = 102
	fxpData     = 103
	fxpExtended = 200
)

// Open flags.
const (
	flagRead   = 0x01
	flagWrite  = 0x02
	flagAppend = 0x04
	flagCreate = 0x08
	flagTrunc  = 0x10
)

const statusOK, statusEOF = 0, 1

// Event is one completed file operation.
type Event struct {
	Op     string `json:"op"` // read, write, open, list, remove, rename, mkdir, rmdir, setstat, symlink, hardlink
	Path   string `json:"path"`
	Target string `json:"target,omitempty"` // rename, symlink and hardlink destination
	Bytes  int64  `json:"bytes,omitempty"`
	// SHA256 is the digest of the transferred content when it moved sequentially from offset 0 (scp and sftp put/get).
	SHA256 string `json:"sha256,omitempty"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

// Summary totals a session.
type Summary struct {
	BytesRead    int64 `json:"bytes_read"`
	BytesWritten int64 `json:"bytes_written"`
	Files        int   `json:"files"`
	Suppressed   int   `json:"suppressed_events"`
}

type pending struct {
	typ          byte
	path, target string
	handle       string
	flags        uint32
	offset       uint64
	length       int
	op           string
}

type stream struct {
	bytes  int64
	next   uint64
	hash   hash.Hash
	sorted bool // every chunk so far followed the previous one, starting at 0
}

func (s *stream) add(offset uint64, data []byte) {
	if s.hash == nil {
		s.hash, s.sorted = sha256.New(), true
	}
	if s.sorted && offset == s.next {
		s.hash.Write(data)
	} else {
		s.sorted = false
	}
	s.next = offset + uint64(len(data))
	s.bytes += int64(len(data))
}

func (s *stream) digest() string {
	if s.hash == nil || !s.sorted {
		return ""
	}
	return hex.EncodeToString(s.hash.Sum(nil))
}

type openFile struct {
	path        string
	dir         bool
	flags       uint32
	read, write stream
	failed      string
}

// Tracker correlates client requests with server responses. It is safe for the two directions to call it
// concurrently.
type Tracker struct {
	mu      sync.Mutex
	pending map[uint32]*pending
	files   map[string]*openFile
	emit    func(Event)
	events  int
	sum     Summary
}

// NewTracker reports completed operations to emit (called with the tracker's lock released, in operation order).
func NewTracker(emit func(Event)) *Tracker {
	return &Tracker{pending: map[uint32]*pending{}, files: map[string]*openFile{}, emit: emit}
}

// Summary returns the session totals.
func (t *Tracker) Summary() Summary {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sum
}

// Pipe copies SFTP packets from r to w unchanged, calling inspect for each. It returns when r ends or a packet
// breaks the framing limits (an error).
func Pipe(r io.Reader, w io.Writer, inspect func(pkt []byte)) error {
	br := bufio.NewReaderSize(r, 64<<10)
	var hdr [4]byte
	for {
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 || n > MaxPacket {
			return fmt.Errorf("sftp packet of %d bytes", n)
		}
		pkt := make([]byte, n)
		if _, err := io.ReadFull(br, pkt); err != nil {
			return err
		}
		inspect(pkt)
		if _, err := w.Write(hdr[:]); err != nil {
			return err
		}
		if _, err := w.Write(pkt); err != nil {
			return err
		}
	}
}

type reader struct {
	b   []byte
	bad bool
}

func (r *reader) u32() uint32 {
	if len(r.b) < 4 {
		r.bad = true
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *reader) u64() uint64 {
	if len(r.b) < 8 {
		r.bad = true
		return 0
	}
	v := binary.BigEndian.Uint64(r.b)
	r.b = r.b[8:]
	return v
}

func (r *reader) bytes() []byte {
	n := r.u32()
	if r.bad || uint64(len(r.b)) < uint64(n) {
		r.bad = true
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) str() string { return cleanPath(string(r.bytes())) }

// cleanPath keeps paths printable for the timeline: control characters become '?', and length is bounded.
func cleanPath(s string) string {
	if len(s) > 4096 {
		s = s[:4096]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

// Client inspects a packet from the SFTP client (the agent).
func (t *Tracker) Client(pkt []byte) {
	if len(pkt) < 1 || pkt[0] == fxpInit {
		return
	}
	r := &reader{b: pkt[1:]}
	id := r.u32()
	p := &pending{typ: pkt[0]}
	switch pkt[0] {
	case fxpOpen:
		p.path = r.str()
		p.flags = r.u32()
	case fxpOpendir, fxpRemove, fxpMkdir, fxpRmdir, fxpSetstat:
		p.path = r.str()
	case fxpRename, fxpSymlink:
		p.path, p.target = r.str(), r.str()
	case fxpClose:
		p.handle = string(r.bytes())
	case fxpRead:
		p.handle = string(r.bytes())
		p.offset = r.u64()
	case fxpWrite:
		p.handle = string(r.bytes())
		p.offset = r.u64()
		data := r.bytes()
		p.length = len(data)
		if !r.bad {
			t.mu.Lock()
			if f := t.files[p.handle]; f != nil {
				f.write.add(p.offset, data)
			}
			t.mu.Unlock()
		}
	case fxpExtended:
		switch string(r.bytes()) {
		case "posix-rename@openssh.com":
			p.op, p.path, p.target = "rename", r.str(), r.str()
		case "hardlink@openssh.com":
			p.op, p.path, p.target = "hardlink", r.str(), r.str()
		default:
			return
		}
	default:
		return
	}
	if r.bad {
		return
	}
	t.mu.Lock()
	if len(t.pending) < 10000 {
		t.pending[id] = p
	}
	t.mu.Unlock()
}

// Server inspects a packet from the SFTP server (the destination).
func (t *Tracker) Server(pkt []byte) {
	if len(pkt) < 5 {
		return
	}
	r := &reader{b: pkt[1:]}
	id := r.u32()
	t.mu.Lock()
	p := t.pending[id]
	delete(t.pending, id)
	var out []Event
	if p != nil {
		out = t.resolve(pkt[0], r, p)
	}
	t.mu.Unlock()
	for _, e := range out {
		t.emit(e)
	}
}

// resolve handles the server's answer to p. Called with the lock held; returns events to emit.
func (t *Tracker) resolve(typ byte, r *reader, p *pending) []Event {
	switch typ {
	case fxpHandle:
		h := string(r.bytes())
		if r.bad || len(t.files) >= 10000 {
			return nil
		}
		t.files[h] = &openFile{path: p.path, dir: p.typ == fxpOpendir, flags: p.flags}
		if p.typ == fxpOpendir {
			return t.record(Event{Op: "list", Path: p.path, OK: true})
		}
		return nil
	case fxpData:
		data := r.bytes()
		if p.typ == fxpRead && !r.bad {
			if f := t.files[p.handle]; f != nil {
				f.read.add(p.offset, data)
				t.sum.BytesRead += int64(len(data))
			}
		}
		return nil
	case fxpStatus:
		code := r.u32()
		msg := cleanPath(string(r.bytes()))
		ok := code == statusOK
		switch p.typ {
		case fxpWrite:
			if f := t.files[p.handle]; f != nil {
				if ok {
					t.sum.BytesWritten += int64(p.length)
				} else if f.failed == "" {
					f.failed = msg
				}
			}
			return nil
		case fxpRead:
			if f := t.files[p.handle]; f != nil && code != statusEOF && !ok && f.failed == "" {
				f.failed = msg
			}
			return nil
		case fxpClose:
			f := t.files[p.handle]
			delete(t.files, p.handle)
			if f == nil || f.dir {
				return nil
			}
			return t.record(closeEvent(f))
		case fxpOpen, fxpOpendir:
			if ok {
				return nil
			}
			op := "open"
			if p.typ == fxpOpendir {
				op = "list"
			}
			return t.record(Event{Op: op, Path: p.path, Error: msg})
		}
		op := map[byte]string{fxpRemove: "remove", fxpMkdir: "mkdir", fxpRmdir: "rmdir", fxpSetstat: "setstat",
			fxpRename: "rename", fxpSymlink: "symlink"}[p.typ]
		if p.op != "" {
			op = p.op
		}
		e := Event{Op: op, Path: p.path, Target: p.target, OK: ok}
		if !ok {
			e.Error = msg
		}
		return t.record(e)
	}
	return nil
}

func closeEvent(f *openFile) Event {
	e := Event{Path: f.path, OK: f.failed == ""}
	if !e.OK {
		e.Error = f.failed
	}
	switch {
	case f.flags&(flagWrite|flagAppend|flagCreate|flagTrunc) != 0 || f.write.bytes > 0:
		e.Op, e.Bytes, e.SHA256 = "write", f.write.bytes, f.write.digest()
	case f.read.bytes > 0 || f.flags&flagRead != 0:
		e.Op, e.Bytes, e.SHA256 = "read", f.read.bytes, f.read.digest()
	default:
		e.Op = "open"
	}
	return e
}

func (t *Tracker) record(e Event) []Event {
	if e.Op == "read" || e.Op == "write" {
		t.sum.Files++
	}
	if t.events >= MaxEvents {
		t.sum.Suppressed++
		return nil
	}
	t.events++
	return []Event{e}
}
