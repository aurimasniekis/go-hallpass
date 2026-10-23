package hprec

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// RecordType identifies a record. Codes are part of the HPREC1 v1 format and are never reused.
type RecordType uint8

// Record types (PLAN §13.3).
const (
	RecExecRequested   RecordType = 1  // payload: raw exec command bytes
	RecPTYRequested    RecordType = 2  // payload: PTYRequest
	RecEnvAccepted     RecordType = 3  // payload: Env
	RecTerminalOutput  RecordType = 4  // payload: raw PTY output bytes
	RecTerminalInput   RecordType = 5  // payload: raw PTY input bytes
	RecTerminalResized RecordType = 6  // payload: Resize
	RecStdout          RecordType = 7  // payload: raw bytes
	RecStderr          RecordType = 8  // payload: raw bytes
	RecSignal          RecordType = 9  // payload: Signal
	RecEOF             RecordType = 10 // payload: empty; Stream tells the direction
	RecExit            RecordType = 11 // payload: Exit
	RecGatewayNotice   RecordType = 12 // payload: Notice
	RecSegmentFooter   RecordType = 13 // payload: Footer; written only by Finalize
)

var recordTypeNames = [...]string{
	RecExecRequested:   "exec.requested",
	RecPTYRequested:    "pty.requested",
	RecEnvAccepted:     "env.accepted",
	RecTerminalOutput:  "terminal.output",
	RecTerminalInput:   "terminal.input",
	RecTerminalResized: "terminal.resized",
	RecStdout:          "stdout",
	RecStderr:          "stderr",
	RecSignal:          "signal",
	RecEOF:             "eof",
	RecExit:            "exit",
	RecGatewayNotice:   "gateway.notice",
	RecSegmentFooter:   "segment.footer",
}

// Valid reports whether t is a known record type.
func (t RecordType) Valid() bool { return t >= RecExecRequested && t <= RecSegmentFooter }

// String returns the record type name, e.g. "terminal.output".
func (t RecordType) String() string {
	if !t.Valid() {
		return fmt.Sprintf("unknown(%d)", uint8(t))
	}
	return recordTypeNames[t]
}

// Versioned returns the versioned event type name (HP-REC-001), e.g. "terminal.output@1".
func (t RecordType) Versioned() string { return t.String() + "@1" }

// Stream identifies the data stream a record belongs to.
type Stream uint8

// Streams.
const (
	StreamPTY    Stream = 0
	StreamStdout Stream = 1
	StreamStderr Stream = 2
	StreamStdin  Stream = 3
	StreamMeta   Stream = 4
)

// DefaultStream returns the conventional stream for a record type.
func DefaultStream(t RecordType) Stream {
	switch t {
	case RecTerminalOutput:
		return StreamPTY
	case RecTerminalInput:
		return StreamStdin
	case RecStdout:
		return StreamStdout
	case RecStderr:
		return StreamStderr
	default:
		return StreamMeta
	}
}

// Record is one recorded event.
type Record struct {
	Type RecordType
	// Seq is the per-access-session sequence number (HP-REC-002). It must be >= 1 and strictly increase within a
	// segment.
	Seq uint64
	// Time is the UTC capture time, stored with microsecond precision.
	Time time.Time
	// Mono is the monotonic offset since the channel opened (>= 0, nanoseconds).
	Mono   time.Duration
	Stream Stream
	// Payload is the type-specific payload. Records returned by a Reader own their payload slice.
	Payload []byte
}

// appendRecord encodes r after dst with its timestamp as a delta from prevUS. It validates field ranges but not the
// payload structure.
func appendRecord(dst []byte, r *Record, prevUS int64) ([]byte, error) {
	us, err := recordMicros(r.Time)
	if err != nil {
		return dst, err
	}
	if r.Mono < 0 {
		return dst, fmt.Errorf("%w: negative monotonic offset", ErrInvalidRecord)
	}
	if r.Stream > StreamMeta {
		return dst, fmt.Errorf("%w: stream %d", ErrInvalidRecord, r.Stream)
	}
	if len(r.Payload) > MaxRecordPayload {
		return dst, fmt.Errorf("%w: %d bytes", ErrRecordTooLarge, len(r.Payload))
	}
	dst = append(dst, byte(r.Type))
	dst = binary.AppendUvarint(dst, r.Seq)
	dst = binary.AppendVarint(dst, us-prevUS) // both in [0, maxUS], cannot overflow
	dst = binary.AppendUvarint(dst, uint64(r.Mono))
	dst = append(dst, byte(r.Stream))
	dst = binary.AppendUvarint(dst, uint64(len(r.Payload)))
	return append(dst, r.Payload...), nil
}

func recordMicros(t time.Time) (int64, error) {
	if t.Before(minTime) || t.After(maxTime) {
		return 0, fmt.Errorf("%w: time out of range", ErrInvalidRecord)
	}
	return t.UnixMicro(), nil
}

// decodeRecord decodes one record from b with its timestamp relative to prevUS. It returns the record, its UTC
// microsecond timestamp and the number of bytes consumed. The payload aliases b. Decoding is strict: integers must
// use minimal varint encodings, so every accepted record has exactly one encoding.
func decodeRecord(b []byte, prevUS int64) (Record, int64, int, error) {
	var r Record
	if len(b) < 1 {
		return r, 0, 0, fmt.Errorf("%w: empty record", ErrCorrupt)
	}
	r.Type = RecordType(b[0])
	if !r.Type.Valid() {
		return r, 0, 0, fmt.Errorf("%w: unknown record type %d", ErrCorrupt, b[0])
	}
	p := 1
	seq, n := readUvarint(b[p:])
	if n <= 0 {
		return r, 0, 0, fmt.Errorf("%w: record seq", ErrCorrupt)
	}
	r.Seq, p = seq, p+n
	delta, n := readVarint(b[p:])
	if n <= 0 {
		return r, 0, 0, fmt.Errorf("%w: record t_us", ErrCorrupt)
	}
	p += n
	if prevUS < 0 || prevUS > maxUS || delta < -prevUS || delta > maxUS-prevUS {
		return r, 0, 0, fmt.Errorf("%w: record time out of range", ErrCorrupt)
	}
	us := prevUS + delta
	r.Time = time.UnixMicro(us).UTC()
	mono, n := readUvarint(b[p:])
	if n <= 0 || mono > math.MaxInt64 {
		return r, 0, 0, fmt.Errorf("%w: record mono_ns", ErrCorrupt)
	}
	r.Mono, p = time.Duration(mono), p+n
	if p >= len(b) {
		return r, 0, 0, fmt.Errorf("%w: record stream", ErrCorrupt)
	}
	r.Stream = Stream(b[p])
	p++
	if r.Stream > StreamMeta {
		return r, 0, 0, fmt.Errorf("%w: record stream %d", ErrCorrupt, r.Stream)
	}
	l, n := readUvarint(b[p:])
	if n <= 0 || l > MaxRecordPayload || l > uint64(len(b)-p-n) { //nolint:gosec // G115: p+n <= len(b), so the difference is >= 0
		return r, 0, 0, fmt.Errorf("%w: record length", ErrCorrupt)
	}
	p += n
	r.Payload = b[p : p+int(l)] //nolint:gosec // G115: l <= len(b)-p checked above
	p += int(l)                 //nolint:gosec // G115: same bound
	if err := validatePayload(r.Type, r.Payload); err != nil {
		return r, 0, 0, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	return r, us, p, nil
}

// readUvarint is binary.Uvarint restricted to minimal encodings.
func readUvarint(b []byte) (uint64, int) {
	v, n := binary.Uvarint(b)
	if n > 1 && b[n-1] == 0 {
		return 0, -1 // trailing zero group: non-minimal encoding
	}
	return v, n
}

// readVarint is binary.Varint (zigzag) restricted to minimal encodings.
func readVarint(b []byte) (int64, int) {
	ux, n := readUvarint(b)
	if n <= 0 {
		return 0, n
	}
	x := int64(ux >> 1) //nolint:gosec // G115: zigzag decoding, as in encoding/binary.Varint
	if ux&1 != 0 {
		x = ^x
	}
	return x, n
}

// validatePayload checks the structure of typed payloads.
func validatePayload(t RecordType, p []byte) error {
	var err error
	switch t {
	case RecPTYRequested:
		_, err = ParsePTYRequest(p)
	case RecEnvAccepted:
		_, err = ParseEnv(p)
	case RecTerminalResized:
		_, err = ParseResize(p)
	case RecSignal:
		_, err = ParseSignal(p)
	case RecEOF:
		if len(p) != 0 {
			err = fmt.Errorf("%w: eof payload must be empty", ErrInvalidRecord)
		}
	case RecExit:
		_, err = ParseExit(p)
	case RecGatewayNotice:
		_, err = ParseNotice(p)
	case RecSegmentFooter:
		_, err = ParseFooter(p)
	}
	return err
}
