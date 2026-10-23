package hprec

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRecordCodecRoundTrip(t *testing.T) {
	base := testEpoch.Truncate(time.Microsecond).UnixMicro()
	recs := genRecords(newRand(), KindPTY, 500, 300)
	recs = append(recs, genRecords(newRand(), KindExec, 500, 300)...)
	for i, r := range recs {
		prev := base + int64(i)*1000 - 3_000_000
		enc, err := appendRecord(nil, &r, prev)
		if err != nil {
			t.Fatal(err)
		}
		got, us, n, err := decodeRecord(enc, prev)
		if err != nil || n != len(enc) || us != r.Time.UnixMicro() {
			t.Fatalf("record %d: n=%d/%d err=%v", i, n, len(enc), err)
		}
		if !sameRecord(got, r) {
			t.Fatalf("record %d differs", i)
		}
		// Every strict prefix is rejected.
		for cut := range len(enc) {
			if _, _, _, err := decodeRecord(enc[:cut], prev); err == nil {
				t.Fatalf("record %d accepted when truncated to %d bytes", i, cut)
			}
		}
	}
}

func TestRecordDecodeRejects(t *testing.T) {
	ok := []byte{byte(RecStdout), 1, 0, 0, byte(StreamStdout), 1, 'x'}
	if _, _, _, err := decodeRecord(ok, 0); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":            {},
		"type 0":           {0, 1, 0, 0, 1, 0},
		"type unknown":     {14, 1, 0, 0, 1, 0},
		"seq non-minimal":  {byte(RecStdout), 0x81, 0x00, 0, 0, 1, 0},
		"seq overflow":     append([]byte{byte(RecStdout)}, bytes.Repeat([]byte{0xff}, 11)...),
		"t_us missing":     {byte(RecStdout), 1},
		"t_us negative":    {byte(RecStdout), 1, 1, 0, 1, 0},
		"mono missing":     {byte(RecStdout), 1, 0},
		"mono too large":   {byte(RecStdout), 1, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 1, 0},
		"stream missing":   {byte(RecStdout), 1, 0, 0},
		"stream invalid":   {byte(RecStdout), 1, 0, 0, 5, 0},
		"len missing":      {byte(RecStdout), 1, 0, 0, 1},
		"len too long":     {byte(RecStdout), 1, 0, 0, 1, 2, 'x'},
		"bad resize":       {byte(RecTerminalResized), 1, 0, 0, 4, 1, 0x80},
		"eof with payload": {byte(RecEOF), 1, 0, 0, 4, 1, 'x'},
	}
	for name, b := range cases {
		if _, _, _, err := decodeRecord(b, 0); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Times outside [1970, 9999] are rejected on both sides.
	if _, _, _, err := decodeRecord([]byte{byte(RecStdout), 1, 2, 0, 1, 0}, maxUS); !errors.Is(err, ErrCorrupt) {
		t.Errorf("time overflow accepted: %v", err)
	}
	if _, _, _, err := decodeRecord(ok, -1); !errors.Is(err, ErrCorrupt) {
		t.Errorf("negative base accepted: %v", err)
	}
}

func TestPayloadRoundTrips(t *testing.T) {
	check := func(name string, enc []byte, parse func([]byte) (any, error), want any) {
		t.Helper()
		got, err := parse(enc)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: got %+v want %+v", name, got, want)
		}
		for cut := range len(enc) {
			if _, err := parse(enc[:cut]); err == nil && name != "signal" {
				t.Fatalf("%s: prefix of %d bytes accepted", name, cut)
			}
		}
		if _, err := parse(append(bytes.Clone(enc), 0)); err == nil {
			t.Fatalf("%s: trailing byte accepted", name)
		}
	}
	pty := PTYRequest{Term: "xterm", Cols: 80, Rows: 24, WidthPx: 640, HeightPx: 480, Modes: []byte{1, 2, 3}}
	check("pty", pty.Marshal(), func(b []byte) (any, error) { return ParsePTYRequest(b) }, pty)
	ptyNoModes := PTYRequest{Term: "vt100", Cols: math.MaxUint32}
	check("pty no modes", ptyNoModes.Marshal(), func(b []byte) (any, error) { return ParsePTYRequest(b) }, ptyNoModes)
	rz := Resize{Cols: 200, Rows: 50, WidthPx: 1, HeightPx: 2}
	check("resize", rz.Marshal(), func(b []byte) (any, error) { return ParseResize(b) }, rz)
	env := Env{Name: "LC_ALL", Value: "C"}
	check("env", env.Marshal(), func(b []byte) (any, error) { return ParseEnv(b) }, env)
	sig := Signal{Name: "TERM"}
	check("signal", sig.Marshal(), func(b []byte) (any, error) { return ParseSignal(b) }, sig)
	ex := Exit{Status: 130}
	check("exit status", ex.Marshal(), func(b []byte) (any, error) { return ParseExit(b) }, ex)
	exs := Exit{Signal: "KILL", CoreDumped: true, Message: "killed"}
	check("exit signal", exs.Marshal(), func(b []byte) (any, error) { return ParseExit(b) }, exs)
	exs2 := Exit{Signal: "SEGV"}
	check("exit signal no core", exs2.Marshal(), func(b []byte) (any, error) { return ParseExit(b) }, exs2)
	nt := Notice{Code: "recording.degraded", Message: "fsync slow"}
	check("notice", nt.Marshal(), func(b []byte) (any, error) { return ParseNotice(b) }, nt)
	ft := Footer{Records: 3, FirstSeq: 10, LastSeq: 20, EndReason: "exit", PlaintextSHA256: [32]byte{9}}
	check("footer", ft.Marshal(), func(b []byte) (any, error) { return ParseFooter(b) }, ft)
	ft0 := Footer{EndReason: "empty"}
	check("footer empty", ft0.Marshal(), func(b []byte) (any, error) { return ParseFooter(b) }, ft0)
}

func TestPayloadRejects(t *testing.T) {
	type parser func([]byte) error
	pe := func(f func([]byte) (Env, error)) parser { return func(b []byte) error { _, err := f(b); return err } }
	cases := []struct {
		name string
		f    parser
		b    []byte
	}{
		{"resize overflow", func(b []byte) error { _, err := ParseResize(b); return err }, []byte{0x80, 0x80, 0x80, 0x80, 0x10, 0, 0, 0}},
		{"env empty name", pe(ParseEnv), Env{Value: "x"}.Marshal()},
		{"env long name", pe(ParseEnv), Env{Name: strings.Repeat("a", maxEnvNameLen+1)}.Marshal()},
		{"signal empty", func(b []byte) error { _, err := ParseSignal(b); return err }, nil},
		{"signal space", func(b []byte) error { _, err := ParseSignal(b); return err }, []byte("SIG INT")},
		{"signal long", func(b []byte) error { _, err := ParseSignal(b); return err }, bytes.Repeat([]byte{'A'}, maxSignalLen+1)},
		{"exit kind", func(b []byte) error { _, err := ParseExit(b); return err }, []byte{2, 0}},
		{"exit empty", func(b []byte) error { _, err := ParseExit(b); return err }, nil},
		{"exit bad signal", func(b []byte) error { _, err := ParseExit(b); return err }, []byte{1, 1, ' ', 0, 0}},
		{"exit core flag", func(b []byte) error { _, err := ParseExit(b); return err }, []byte{1, 1, 'X', 2, 0}},
		{"exit status overflow", func(b []byte) error { _, err := ParseExit(b); return err }, []byte{0, 0x80, 0x80, 0x80, 0x80, 0x10}},
		{"notice code", func(b []byte) error { _, err := ParseNotice(b); return err }, Notice{Code: "Bad"}.Marshal()},
		{"notice empty code", func(b []byte) error { _, err := ParseNotice(b); return err }, Notice{}.Marshal()},
		{"footer reason", func(b []byte) error { _, err := ParseFooter(b); return err }, Footer{EndReason: "A"}.Marshal()},
		{"footer short hash", func(b []byte) error { _, err := ParseFooter(b); return err }, Footer{EndReason: "a"}.Marshal()[:10]},
		{"footer zero records with seq", func(b []byte) error { _, err := ParseFooter(b); return err }, Footer{FirstSeq: 1, LastSeq: 1, EndReason: "a"}.Marshal()},
		{"footer records without seq", func(b []byte) error { _, err := ParseFooter(b); return err }, Footer{Records: 1, EndReason: "a"}.Marshal()},
		{"footer range too small", func(b []byte) error { _, err := ParseFooter(b); return err }, Footer{Records: 5, FirstSeq: 1, LastSeq: 3, EndReason: "a"}.Marshal()},
		{"footer reversed", func(b []byte) error { _, err := ParseFooter(b); return err }, Footer{Records: 1, FirstSeq: 3, LastSeq: 1, EndReason: "a"}.Marshal()},
		{"pty long term", func(b []byte) error { _, err := ParsePTYRequest(b); return err }, PTYRequest{Term: strings.Repeat("x", maxTermLen+1)}.Marshal()},
	}
	for _, tc := range cases {
		if err := tc.f(tc.b); !errors.Is(err, ErrInvalidRecord) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestRecordTypeNames(t *testing.T) {
	seen := map[string]bool{}
	for ty := RecExecRequested; ty <= RecSegmentFooter; ty++ {
		if !ty.Valid() || seen[ty.String()] || !strings.HasSuffix(ty.Versioned(), "@1") {
			t.Fatalf("type %d: %q", ty, ty.String())
		}
		seen[ty.String()] = true
	}
	if RecordType(0).Valid() || RecordType(14).Valid() || RecordType(200).String() != "unknown(200)" {
		t.Fatal("invalid types accepted")
	}
	if RecTerminalOutput.Versioned() != "terminal.output@1" {
		t.Fatal(RecTerminalOutput.Versioned())
	}
	want := map[RecordType]Stream{
		RecTerminalOutput: StreamPTY, RecTerminalInput: StreamStdin, RecStdout: StreamStdout,
		RecStderr: StreamStderr, RecExit: StreamMeta, RecExecRequested: StreamMeta,
	}
	for ty, s := range want {
		if DefaultStream(ty) != s {
			t.Fatalf("%v: %d", ty, DefaultStream(ty))
		}
	}
}
