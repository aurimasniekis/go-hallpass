package hprec

import (
	"encoding/binary"
	"fmt"
	"math"
)

// Structured payload encodings. Integers are minimal uvarints; strings and byte strings are a uvarint length followed
// by the bytes. Every parser rejects trailing bytes, so each value has exactly one encoding.

const (
	maxTermLen    = 256
	maxModesLen   = 4096
	maxEnvNameLen = 256
	maxSignalLen  = 32
	maxMessageLen = 4096
	maxCodeLen    = 64
)

// PTYRequest is the payload of RecPTYRequested.
type PTYRequest struct {
	Term     string
	Cols     uint32
	Rows     uint32
	WidthPx  uint32
	HeightPx uint32
	Modes    []byte // raw SSH encoded terminal modes
}

// Resize is the payload of RecTerminalResized.
type Resize struct {
	Cols     uint32
	Rows     uint32
	WidthPx  uint32
	HeightPx uint32
}

// Env is the payload of RecEnvAccepted.
type Env struct {
	Name  string
	Value string
}

// Signal is the payload of RecSignal (an SSH signal name without the "SIG" prefix, e.g. "INT").
type Signal struct {
	Name string
}

// Exit is the payload of RecExit. Exactly one of Status (Signal == "") or Signal applies.
type Exit struct {
	Status     uint32
	Signal     string
	CoreDumped bool
	Message    string
}

// Notice is the payload of RecGatewayNotice: a message the gateway injected or an event it observed.
type Notice struct {
	Code    string // [a-z0-9_.-], 1-64 characters
	Message string
}

// Footer is the payload of RecSegmentFooter, the last record of the final frame.
type Footer struct {
	Records   uint64 // number of records before the footer
	FirstSeq  uint64 // 0 when Records == 0
	LastSeq   uint64 // 0 when Records == 0
	EndReason string // [a-z0-9_.-], 1-64 characters
	// PlaintextSHA256 is SHA-256 over the concatenated plaintext of all frames, excluding the footer record itself.
	PlaintextSHA256 [32]byte
}

type payloadReader struct {
	b   []byte
	err error
}

func (p *payloadReader) fail(what string) {
	if p.err == nil {
		p.err = fmt.Errorf("%w: payload %s", ErrInvalidRecord, what)
	}
}

func (p *payloadReader) uvarint(what string) uint64 {
	if p.err != nil {
		return 0
	}
	v, n := readUvarint(p.b)
	if n <= 0 {
		p.fail(what)
		return 0
	}
	p.b = p.b[n:]
	return v
}

func (p *payloadReader) u32(what string) uint32 {
	v := p.uvarint(what)
	if v > math.MaxUint32 {
		p.fail(what)
		return 0
	}
	return uint32(v)
}

func (p *payloadReader) bytes(what string, maxLen int) []byte {
	l := p.uvarint(what)
	if p.err != nil {
		return nil
	}
	if l > uint64(maxLen) || l > uint64(len(p.b)) { //nolint:gosec // G115: maxLen is a positive constant
		p.fail(what)
		return nil
	}
	out := p.b[:l]
	p.b = p.b[l:]
	return out
}

func (p *payloadReader) byte(what string) byte {
	if p.err != nil {
		return 0
	}
	if len(p.b) == 0 {
		p.fail(what)
		return 0
	}
	c := p.b[0]
	p.b = p.b[1:]
	return c
}

func (p *payloadReader) done() error {
	if p.err == nil && len(p.b) != 0 {
		p.fail("trailing bytes")
	}
	return p.err
}

func appendBytes(dst, b []byte) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(b)))
	return append(dst, b...)
}

func printable(s string) bool {
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func validCode(s string) bool {
	if s == "" || len(s) > maxCodeLen {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '.' && c != '-' {
			return false
		}
	}
	return true
}

func validSignal(s string) bool { return s != "" && len(s) <= maxSignalLen && printable(s) }

// Marshal encodes the payload.
func (x PTYRequest) Marshal() []byte {
	b := binary.AppendUvarint(nil, uint64(x.Cols))
	b = binary.AppendUvarint(b, uint64(x.Rows))
	b = binary.AppendUvarint(b, uint64(x.WidthPx))
	b = binary.AppendUvarint(b, uint64(x.HeightPx))
	b = appendBytes(b, []byte(x.Term))
	return appendBytes(b, x.Modes)
}

// ParsePTYRequest decodes a RecPTYRequested payload.
func ParsePTYRequest(b []byte) (PTYRequest, error) {
	p := payloadReader{b: b}
	x := PTYRequest{Cols: p.u32("cols"), Rows: p.u32("rows"), WidthPx: p.u32("width"), HeightPx: p.u32("height")}
	x.Term = string(p.bytes("term", maxTermLen))
	if m := p.bytes("modes", maxModesLen); len(m) > 0 {
		x.Modes = append([]byte(nil), m...)
	}
	return x, p.done()
}

// Marshal encodes the payload.
func (x Resize) Marshal() []byte {
	b := binary.AppendUvarint(nil, uint64(x.Cols))
	b = binary.AppendUvarint(b, uint64(x.Rows))
	b = binary.AppendUvarint(b, uint64(x.WidthPx))
	return binary.AppendUvarint(b, uint64(x.HeightPx))
}

// ParseResize decodes a RecTerminalResized payload.
func ParseResize(b []byte) (Resize, error) {
	p := payloadReader{b: b}
	x := Resize{Cols: p.u32("cols"), Rows: p.u32("rows"), WidthPx: p.u32("width"), HeightPx: p.u32("height")}
	return x, p.done()
}

// Marshal encodes the payload.
func (x Env) Marshal() []byte {
	return appendBytes(appendBytes(nil, []byte(x.Name)), []byte(x.Value))
}

// ParseEnv decodes a RecEnvAccepted payload.
func ParseEnv(b []byte) (Env, error) {
	p := payloadReader{b: b}
	x := Env{Name: string(p.bytes("env name", maxEnvNameLen))}
	x.Value = string(p.bytes("env value", MaxRecordPayload))
	if p.err == nil && x.Name == "" {
		p.fail("empty env name")
	}
	return x, p.done()
}

// Marshal encodes the payload.
func (x Signal) Marshal() []byte { return []byte(x.Name) }

// ParseSignal decodes a RecSignal payload.
func ParseSignal(b []byte) (Signal, error) {
	if !validSignal(string(b)) {
		return Signal{}, fmt.Errorf("%w: payload signal name", ErrInvalidRecord)
	}
	return Signal{Name: string(b)}, nil
}

// Marshal encodes the payload: kind u8 (0 status, 1 signal), then uvarint status for kind 0, or signal, core u8 and
// message for kind 1.
func (x Exit) Marshal() []byte {
	if x.Signal == "" {
		return binary.AppendUvarint([]byte{0}, uint64(x.Status))
	}
	b := appendBytes([]byte{1}, []byte(x.Signal))
	core := byte(0)
	if x.CoreDumped {
		core = 1
	}
	b = append(b, core)
	return appendBytes(b, []byte(x.Message))
}

// ParseExit decodes a RecExit payload.
func ParseExit(b []byte) (Exit, error) {
	p := payloadReader{b: b}
	var x Exit
	switch p.byte("exit kind") {
	case 0:
		x.Status = p.u32("exit status")
	case 1:
		x.Signal = string(p.bytes("exit signal", maxSignalLen))
		if p.err == nil && !validSignal(x.Signal) {
			p.fail("exit signal name")
		}
		switch p.byte("core dumped") {
		case 0:
		case 1:
			x.CoreDumped = true
		default:
			p.fail("core dumped flag")
		}
		x.Message = string(p.bytes("exit message", maxMessageLen))
	default:
		p.fail("exit kind")
	}
	return x, p.done()
}

// Marshal encodes the payload.
func (x Notice) Marshal() []byte {
	return appendBytes(appendBytes(nil, []byte(x.Code)), []byte(x.Message))
}

// ParseNotice decodes a RecGatewayNotice payload.
func ParseNotice(b []byte) (Notice, error) {
	p := payloadReader{b: b}
	x := Notice{Code: string(p.bytes("notice code", maxCodeLen))}
	x.Message = string(p.bytes("notice message", MaxRecordPayload))
	if p.err == nil && !validCode(x.Code) {
		p.fail("notice code")
	}
	return x, p.done()
}

// Marshal encodes the payload.
func (x Footer) Marshal() []byte {
	b := binary.AppendUvarint(nil, x.Records)
	b = binary.AppendUvarint(b, x.FirstSeq)
	b = binary.AppendUvarint(b, x.LastSeq)
	b = appendBytes(b, []byte(x.EndReason))
	return append(b, x.PlaintextSHA256[:]...)
}

// ParseFooter decodes a RecSegmentFooter payload.
func ParseFooter(b []byte) (Footer, error) {
	p := payloadReader{b: b}
	x := Footer{Records: p.uvarint("records"), FirstSeq: p.uvarint("first_seq"), LastSeq: p.uvarint("last_seq")}
	x.EndReason = string(p.bytes("end_reason", maxCodeLen))
	if p.err == nil && !validCode(x.EndReason) {
		p.fail("end_reason")
	}
	if p.err == nil {
		if len(p.b) != len(x.PlaintextSHA256) {
			p.fail("plaintext_sha256")
		} else {
			copy(x.PlaintextSHA256[:], p.b)
			p.b = nil
		}
	}
	if p.err == nil && (x.Records == 0) != (x.FirstSeq == 0 && x.LastSeq == 0) {
		p.fail("seq range")
	}
	if p.err == nil && x.Records > 0 && (x.FirstSeq == 0 || x.LastSeq < x.FirstSeq || x.LastSeq-x.FirstSeq < x.Records-1) {
		p.fail("seq range")
	}
	return x, p.done()
}
