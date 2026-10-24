package sftpaudit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"strings"
	"testing"
)

type pkt struct{ b []byte }

func newPkt(typ byte, id uint32) *pkt {
	p := &pkt{b: []byte{typ}}
	return p.u32(id)
}

func (p *pkt) u32(v uint32) *pkt { p.b = binary.BigEndian.AppendUint32(p.b, v); return p }
func (p *pkt) u64(v uint64) *pkt { p.b = binary.BigEndian.AppendUint64(p.b, v); return p }
func (p *pkt) str(s string) *pkt { p.u32(uint32(len(s))); p.b = append(p.b, s...); return p }

func status(id, code uint32, msg string) []byte {
	return newPkt(fxpStatus, id).u32(code).str(msg).str("").b
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestTrackerSession(t *testing.T) {
	var got []Event
	tr := NewTracker(func(e Event) { got = append(got, e) })
	tr.Client([]byte{fxpInit, 0, 0, 0, 3})

	// Upload: open for write, two sequential writes, close.
	tr.Client(newPkt(fxpOpen, 1).str("/tmp/build.tar").u32(flagWrite | flagCreate | flagTrunc).u32(0).b)
	tr.Server(newPkt(fxpHandle, 1).str("h1").b)
	tr.Client(newPkt(fxpWrite, 2).str("h1").u64(0).str("hello ").b)
	tr.Client(newPkt(fxpWrite, 3).str("h1").u64(6).str("world").b)
	tr.Server(status(2, statusOK, ""))
	tr.Server(status(3, statusOK, ""))
	tr.Client(newPkt(fxpClose, 4).str("h1").b)
	tr.Server(status(4, statusOK, ""))

	// Download: open for read, data, EOF, close.
	tr.Client(newPkt(fxpOpen, 5).str("/etc/app.conf").u32(flagRead).u32(0).b)
	tr.Server(newPkt(fxpHandle, 5).str("h2").b)
	tr.Client(newPkt(fxpRead, 6).str("h2").u64(0).u32(32768).b)
	tr.Server(newPkt(fxpData, 6).str("key=value\n").b)
	tr.Client(newPkt(fxpRead, 7).str("h2").u64(10).u32(32768).b)
	tr.Server(status(7, statusEOF, "EOF"))
	tr.Client(newPkt(fxpClose, 8).str("h2").b)
	tr.Server(status(8, statusOK, ""))

	// Out-of-order writes: counted, but no digest.
	tr.Client(newPkt(fxpOpen, 9).str("/tmp/sparse").u32(flagWrite).u32(0).b)
	tr.Server(newPkt(fxpHandle, 9).str("h3").b)
	tr.Client(newPkt(fxpWrite, 10).str("h3").u64(100).str("x").b)
	tr.Server(status(10, statusOK, ""))
	tr.Client(newPkt(fxpClose, 11).str("h3").b)
	tr.Server(status(11, statusOK, ""))

	// Directory and path operations.
	tr.Client(newPkt(fxpOpendir, 12).str("/var/log").b)
	tr.Server(newPkt(fxpHandle, 12).str("d1").b)
	tr.Client(newPkt(fxpRemove, 13).str("/tmp/old\x1b[31m").b)
	tr.Server(status(13, statusOK, ""))
	tr.Client(newPkt(fxpRename, 14).str("/tmp/a").str("/tmp/b").b)
	tr.Server(status(14, 3, "Permission denied"))
	tr.Client(newPkt(fxpExtended, 15).str("posix-rename@openssh.com").str("/tmp/c").str("/tmp/d").b)
	tr.Server(status(15, statusOK, ""))
	tr.Client(newPkt(fxpOpen, 16).str("/root/secret").u32(flagRead).u32(0).b)
	tr.Server(status(16, 3, "Permission denied"))
	tr.Client(newPkt(fxpMkdir, 17).str("/tmp/new").u32(0).b)
	tr.Server(status(17, statusOK, ""))

	want := []Event{
		{Op: "write", Path: "/tmp/build.tar", Bytes: 11, SHA256: sum("hello world"), OK: true},
		{Op: "read", Path: "/etc/app.conf", Bytes: 10, SHA256: sum("key=value\n"), OK: true},
		{Op: "write", Path: "/tmp/sparse", Bytes: 1, OK: true},
		{Op: "list", Path: "/var/log", OK: true},
		{Op: "remove", Path: "/tmp/old?[31m", OK: true},
		{Op: "rename", Path: "/tmp/a", Target: "/tmp/b", Error: "Permission denied"},
		{Op: "rename", Path: "/tmp/c", Target: "/tmp/d", OK: true},
		{Op: "open", Path: "/root/secret", Error: "Permission denied"},
		{Op: "mkdir", Path: "/tmp/new", OK: true},
	}
	if len(got) != len(want) {
		t.Fatalf("events:\n%+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event %d:\n got %+v\nwant %+v", i, got[i], want[i])
		}
	}
	if s := tr.Summary(); s.BytesWritten != 12 || s.BytesRead != 10 || s.Files != 3 {
		t.Errorf("summary %+v", s)
	}
}

func TestFailedWriteIsReported(t *testing.T) {
	var got []Event
	tr := NewTracker(func(e Event) { got = append(got, e) })
	tr.Client(newPkt(fxpOpen, 1).str("/full/disk").u32(flagWrite).u32(0).b)
	tr.Server(newPkt(fxpHandle, 1).str("h").b)
	tr.Client(newPkt(fxpWrite, 2).str("h").u64(0).str("data").b)
	tr.Server(status(2, 4, "No space left on device"))
	tr.Client(newPkt(fxpClose, 3).str("h").b)
	tr.Server(status(3, statusOK, ""))
	if len(got) != 1 || got[0].OK || got[0].Error != "No space left on device" {
		t.Fatalf("%+v", got)
	}
}

func TestEventLimit(t *testing.T) {
	n := 0
	tr := NewTracker(func(Event) { n++ })
	for i := range uint32(MaxEvents + 10) {
		tr.Client(newPkt(fxpMkdir, i).str("/d").u32(0).b)
		tr.Server(status(i, statusOK, ""))
	}
	if n != MaxEvents || tr.Summary().Suppressed != 10 {
		t.Fatalf("emitted %d, suppressed %d", n, tr.Summary().Suppressed)
	}
}

func TestPipe(t *testing.T) {
	var in bytes.Buffer
	for _, p := range [][]byte{newPkt(fxpMkdir, 1).str("/a").u32(0).b, newPkt(fxpRemove, 2).str("/b").b} {
		in.Write(binary.BigEndian.AppendUint32(nil, uint32(len(p))))
		in.Write(p)
	}
	orig := slices.Clone(in.Bytes())
	var out bytes.Buffer
	seen := 0
	if err := Pipe(&in, &out, func([]byte) { seen++ }); err != nil || seen != 2 || !bytes.Equal(out.Bytes(), orig) {
		t.Fatalf("pipe: err=%v seen=%d equal=%v", err, seen, bytes.Equal(out.Bytes(), orig))
	}
	huge := binary.BigEndian.AppendUint32(nil, MaxPacket+1)
	if err := Pipe(bytes.NewReader(huge), &out, func([]byte) {}); err == nil {
		t.Fatal("oversized packet accepted")
	}
	if err := Pipe(bytes.NewReader([]byte{0, 0, 0, 0}), &out, func([]byte) {}); err == nil {
		t.Fatal("empty packet accepted")
	}
	if err := Pipe(strings.NewReader("\x00\x00\x00\x09abc"), &out, func([]byte) {}); err == nil {
		t.Fatal("truncated packet accepted")
	}
}

func FuzzTracker(f *testing.F) {
	f.Add(newPkt(fxpOpen, 1).str("/x").u32(flagWrite).u32(0).b, newPkt(fxpHandle, 1).str("h").b)
	f.Add(newPkt(fxpWrite, 2).str("h").u64(0).str("data").b, status(2, 0, ""))
	f.Fuzz(func(t *testing.T, client, server []byte) {
		tr := NewTracker(func(Event) {})
		tr.Client(client)
		tr.Server(server)
		tr.Client(server)
		tr.Server(client)
		_ = tr.Summary()
	})
}
