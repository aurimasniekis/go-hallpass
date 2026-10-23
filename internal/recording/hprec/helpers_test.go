package hprec

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testWrapper is an AES-256-GCM DEKWrapper with keys generated at test time.
type testWrapper struct {
	keys   map[string]cipher.AEAD
	active string
}

func newTestWrapper(t testing.TB, ids ...string) *testWrapper {
	t.Helper()
	w := &testWrapper{keys: map[string]cipher.AEAD{}, active: ids[0]}
	for _, id := range ids {
		k := make([]byte, 32)
		_, _ = rand.Read(k)
		block, err := aes.NewCipher(k)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		w.keys[id] = aead
	}
	return w
}

// union returns a wrapper that knows the keys of all given wrappers and wraps with the first one's active key.
func union(ws ...*testWrapper) *testWrapper {
	u := &testWrapper{keys: map[string]cipher.AEAD{}, active: ws[0].active}
	for _, w := range ws {
		for id, k := range w.keys {
			u.keys[id] = k
		}
	}
	return u
}

func (w *testWrapper) Wrap(dek, aad []byte) (string, []byte, error) {
	aead := w.keys[w.active]
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	return w.active, aead.Seal(nonce, nonce, dek, aad), nil
}

func (w *testWrapper) Unwrap(keyID string, wrapped, aad []byte) ([]byte, error) {
	aead, ok := w.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("unknown key %q", keyID)
	}
	if len(wrapped) < aead.NonceSize() {
		return nil, errors.New("short wrapped key")
	}
	return aead.Open(nil, wrapped[:aead.NonceSize()], wrapped[aead.NonceSize():], aad)
}

// funcWrapper adapts functions to DEKWrapper for error-path tests.
type funcWrapper struct {
	wrap   func(dek, aad []byte) (string, []byte, error)
	unwrap func(keyID string, wrapped, aad []byte) ([]byte, error)
}

func (f funcWrapper) Wrap(dek, aad []byte) (string, []byte, error) { return f.wrap(dek, aad) }
func (f funcWrapper) Unwrap(id string, w, aad []byte) ([]byte, error) {
	return f.unwrap(id, w, aad)
}

var testEpoch = time.Date(2026, 10, 23, 12, 0, 0, 123456789, time.UTC)

func testHeader(kind Kind) Header {
	return Header{
		SegmentID: "seg_01jabcdefghjkmnpqrstvwxyz0",
		SessionID: "ses_01jabcdefghjkmnpqrstvwxyz0",
		ChannelID: "chn_01jabcdefghjkmnpqrstvwxyz0",
		CreatedAt: testEpoch,
		Kind:      kind,
	}
}

// genRecords produces n records of a realistic mix for kind, with gaps in seq and occasional clock steps backwards.
func genRecords(rnd *mrand.Rand, kind Kind, n int, maxPayload int) []Record {
	recs := make([]Record, 0, n)
	seq := uint64(10)
	at := testEpoch.Add(time.Millisecond)
	mono := time.Duration(0)
	payload := func() []byte {
		b := make([]byte, rnd.IntN(maxPayload+1))
		for i := range b {
			b[i] = byte(rnd.Uint32())
		}
		return b
	}
	for i := range n {
		seq += 1 + uint64(rnd.IntN(3))
		step := time.Duration(rnd.IntN(5000)) * time.Microsecond
		if rnd.IntN(50) == 0 {
			at = at.Add(-time.Second) // wall clock stepped back
		}
		at = at.Add(step)
		mono += step + time.Duration(rnd.IntN(1000))
		r := Record{Seq: seq, Time: at, Mono: mono}
		switch {
		case i == 0 && kind == KindPTY:
			r.Type, r.Payload = RecPTYRequested, PTYRequest{Term: "xterm-256color", Cols: 80, Rows: 24, Modes: []byte{53, 0, 0, 0, 1, 0}}.Marshal()
		case i == 0:
			r.Type, r.Payload = RecExecRequested, []byte("uname -a && id")
		case i == 1:
			r.Type, r.Payload = RecEnvAccepted, Env{Name: "LANG", Value: "C.UTF-8"}.Marshal()
		case i == n-1:
			r.Type, r.Payload = RecExit, Exit{Status: uint32(rnd.IntN(256))}.Marshal()
		case i == n-2:
			r.Type = RecEOF
			if kind == KindExec {
				r.Stream = StreamStdout
			}
		default:
			switch rnd.IntN(10) {
			case 0:
				r.Type, r.Payload = RecTerminalResized, Resize{Cols: 100 + uint32(rnd.IntN(100)), Rows: 40}.Marshal()
			case 1:
				r.Type, r.Payload = RecSignal, Signal{Name: "INT"}.Marshal()
			case 2:
				r.Type, r.Payload = RecGatewayNotice, Notice{Code: "grant.expiring", Message: "grant expires in 60s"}.Marshal()
			case 3:
				if kind == KindPTY {
					r.Type = RecTerminalInput
				} else {
					r.Type = RecStderr
				}
				r.Payload = payload()
			default:
				if kind == KindPTY {
					r.Type = RecTerminalOutput
				} else {
					r.Type = RecStdout
				}
				r.Payload = payload()
			}
		}
		if r.Type != RecEOF {
			r.Stream = DefaultStream(r.Type)
		}
		recs = append(recs, r)
	}
	return recs
}

// writeSegment writes recs to dir/name, flushing every flushEvery records (0 = never), and finalizes.
func writeSegment(t testing.TB, path string, hdr Header, w DEKWrapper, recs []Record, flushEvery int) Manifest {
	t.Helper()
	sw, err := Create(path, hdr, w)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for i, r := range recs {
		if err := sw.Append(r); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		if flushEvery > 0 && (i+1)%flushEvery == 0 {
			if err := sw.Flush(); err != nil {
				t.Fatalf("Flush: %v", err)
			}
		}
	}
	m, err := sw.Finalize("channel.closed")
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("Close after Finalize: %v", err)
	}
	return m
}

func readAllFrom(src io.Reader, w DEKWrapper, opts ...Option) ([]Record, error) {
	r, err := NewReader(src, w, opts...)
	if err != nil {
		return nil, err
	}
	var out []Record
	for {
		rec, err := r.Next()
		if err != nil {
			return out, err
		}
		out = append(out, rec)
	}
}

func readFile(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sameRecord(a, b Record) bool {
	return a.Type == b.Type && a.Seq == b.Seq && a.Time.Equal(b.Time.Truncate(time.Microsecond)) &&
		a.Mono == b.Mono && a.Stream == b.Stream && bytes.Equal(a.Payload, b.Payload)
}

func requireRecords(t testing.TB, got, want []Record) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d", len(got), len(want))
	}
	for i := range got {
		if !sameRecord(got[i], want[i]) {
			t.Fatalf("record %d differs:\n got %+v\nwant %+v", i, got[i], want[i])
		}
	}
}

// isPrefix reports whether got is a prefix of want.
func isPrefix(got, want []Record) bool {
	if len(got) > len(want) {
		return false
	}
	for i := range got {
		if !sameRecord(got[i], want[i]) {
			return false
		}
	}
	return true
}

// layout locates the regions of a segment file.
type layout struct {
	headerLen int
	slotA     int
	slotB     int
	frames    []int // offset of each frame's ct_len
	end       int
}

func parseLayout(t testing.TB, data []byte) layout {
	t.Helper()
	hl := int(data[8])<<24 | int(data[9])<<16 | int(data[10])<<8 | int(data[11])
	l := layout{headerLen: hl, slotA: prefixFixed + hl, slotB: prefixFixed + hl + SlotSize, end: len(data)}
	for p := l.slotB + SlotSize; p < len(data); {
		l.frames = append(l.frames, p)
		n := int(data[p])<<24 | int(data[p+1])<<16 | int(data[p+2])<<8 | int(data[p+3])
		p += frameLenSize + n
	}
	return l
}

func (l layout) frame(data []byte, i int) []byte {
	end := l.end
	if i+1 < len(l.frames) {
		end = l.frames[i+1]
	}
	return data[l.frames[i]:end]
}

func tempPath(t testing.TB, name string) string {
	return filepath.Join(t.TempDir(), name)
}

func newRand() *mrand.Rand { return mrand.New(mrand.NewPCG(1, 2)) }
