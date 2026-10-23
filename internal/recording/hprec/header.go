package hprec

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Kind is the channel kind recorded by a segment.
type Kind string

// Segment kinds.
const (
	KindPTY  Kind = "pty"
	KindExec Kind = "exec"
)

// TimeLayout is the canonical created_at format: UTC with exactly six fractional digits.
const TimeLayout = "2006-01-02T15:04:05.000000Z"

const maxIDLen = 128

var (
	minTime = time.Unix(0, 0).UTC()
	maxTime = time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC)
	maxUS   = maxTime.UnixMicro()
)

// Header is the authenticated segment header. The writer fills PayloadSalt; the caller sets the other fields.
type Header struct {
	SegmentID string
	SessionID string
	ChannelID string
	// Ordinal is the 0-based position of the segment within its channel.
	Ordinal uint32
	// CreatedAt is stored with microsecond precision in UTC. It is also the time base for record timestamps.
	CreatedAt time.Time
	Kind      Kind
	// PrevSegmentSHA256 links rollover segments: empty for ordinal 0, otherwise the 32-byte ciphertext_sha256 of the
	// previous segment of the same channel.
	PrevSegmentSHA256 []byte
	// PayloadSalt is the random HKDF salt chosen by the writer.
	PayloadSalt [SaltSize]byte
}

// headerJSON is the wire form. Field order is the sorted key order, so encoding/json emits canonical JSON.
type headerJSON struct {
	AEAD              string `json:"aead"`
	ChannelID         string `json:"channel_id"`
	CreatedAt         string `json:"created_at"`
	FrameMax          int    `json:"frame_max"`
	Kind              string `json:"kind"`
	Ordinal           uint32 `json:"ordinal"`
	PayloadSalt       string `json:"payload_salt"`
	PrevSegmentSHA256 string `json:"prev_segment_sha256"`
	SegmentID         string `json:"segment_id"`
	SessionID         string `json:"session_id"`
	V                 int    `json:"v"`
}

func validID(s string) bool {
	if s == "" || len(s) > maxIDLen {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-', c == '.', c == ':':
		default:
			return false
		}
	}
	return true
}

func (h *Header) validate() error {
	for _, f := range [...]struct{ name, v string }{
		{"segment_id", h.SegmentID}, {"session_id", h.SessionID}, {"channel_id", h.ChannelID},
	} {
		if !validID(f.v) {
			return fmt.Errorf("%w: %s must be 1-%d characters of [A-Za-z0-9_.:-]", ErrInvalidHeader, f.name, maxIDLen)
		}
	}
	if h.Kind != KindPTY && h.Kind != KindExec {
		return fmt.Errorf("%w: kind %q", ErrInvalidHeader, h.Kind)
	}
	if h.CreatedAt.Before(minTime) || h.CreatedAt.After(maxTime) {
		return fmt.Errorf("%w: created_at out of range", ErrInvalidHeader)
	}
	switch {
	case h.Ordinal == 0 && len(h.PrevSegmentSHA256) != 0:
		return fmt.Errorf("%w: ordinal 0 must not have prev_segment_sha256", ErrInvalidHeader)
	case h.Ordinal > 0 && len(h.PrevSegmentSHA256) != 32:
		return fmt.Errorf("%w: ordinal > 0 needs a 32-byte prev_segment_sha256", ErrInvalidHeader)
	}
	return nil
}

func (h *Header) wire() headerJSON {
	return headerJSON{
		AEAD:              AEADName,
		ChannelID:         h.ChannelID,
		CreatedAt:         h.CreatedAt.UTC().Format(TimeLayout),
		FrameMax:          FrameMax,
		Kind:              string(h.Kind),
		Ordinal:           h.Ordinal,
		PayloadSalt:       base64.StdEncoding.EncodeToString(h.PayloadSalt[:]),
		PrevSegmentSHA256: hex.EncodeToString(h.PrevSegmentSHA256),
		SegmentID:         h.SegmentID,
		SessionID:         h.SessionID,
		V:                 Version,
	}
}

func encodeJSON(v headerJSON) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// normalize truncates CreatedAt to microseconds in UTC, the precision stored in the header.
func (h *Header) normalize() {
	h.CreatedAt = h.CreatedAt.UTC().Truncate(time.Microsecond)
}

// encodeHeader returns the canonical header JSON.
func encodeHeader(h *Header) ([]byte, error) {
	if err := h.validate(); err != nil {
		return nil, err
	}
	b, err := encodeJSON(h.wire())
	if err != nil {
		return nil, err
	}
	if len(b) > MaxHeaderLen {
		return nil, fmt.Errorf("%w: header longer than %d bytes", ErrInvalidHeader, MaxHeaderLen)
	}
	return b, nil
}

// parseHeader decodes and validates header JSON, requiring the exact canonical encoding.
func parseHeader(b []byte) (Header, error) {
	var w headerJSON
	if err := json.Unmarshal(b, &w); err != nil {
		return Header{}, fmt.Errorf("%w: header: %w", ErrCorrupt, err)
	}
	if w.V != Version {
		return Header{}, fmt.Errorf("%w: header v=%d", ErrUnsupportedVersion, w.V)
	}
	if w.AEAD != AEADName || w.FrameMax != FrameMax {
		return Header{}, fmt.Errorf("%w: header aead %q frame_max %d", ErrUnsupportedVersion, w.AEAD, w.FrameMax)
	}
	h := Header{
		SegmentID: w.SegmentID,
		SessionID: w.SessionID,
		ChannelID: w.ChannelID,
		Ordinal:   w.Ordinal,
		Kind:      Kind(w.Kind),
	}
	t, err := time.Parse(TimeLayout, w.CreatedAt)
	if err != nil {
		return Header{}, fmt.Errorf("%w: header created_at: %w", ErrCorrupt, err)
	}
	h.CreatedAt = t.UTC()
	salt, err := base64.StdEncoding.Strict().DecodeString(w.PayloadSalt)
	if err != nil || len(salt) != SaltSize {
		return Header{}, fmt.Errorf("%w: header payload_salt", ErrCorrupt)
	}
	copy(h.PayloadSalt[:], salt)
	if w.PrevSegmentSHA256 != "" {
		if h.PrevSegmentSHA256, err = hex.DecodeString(w.PrevSegmentSHA256); err != nil {
			return Header{}, fmt.Errorf("%w: header prev_segment_sha256", ErrCorrupt)
		}
	}
	if err := h.validate(); err != nil {
		return Header{}, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	canon, err := encodeJSON(h.wire())
	if err != nil || !bytes.Equal(canon, b) {
		return Header{}, fmt.Errorf("%w: header is not canonical JSON", ErrCorrupt)
	}
	return h, nil
}

// readPrefixHeader reads magic, header_len and the header from r. It returns the parsed header, the raw header
// bytes and H.
func readPrefixHeader(r io.Reader) (Header, []byte, [32]byte, error) {
	var fixed [prefixFixed]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return Header{}, nil, [32]byte{}, shortRead(err, "file prefix")
	}
	if string(fixed[:len(Magic)]) != Magic {
		if bytes.HasPrefix(fixed[:], []byte("HPREC")) {
			return Header{}, nil, [32]byte{}, fmt.Errorf("%w: magic %q", ErrUnsupportedVersion, fixed[:len(Magic)])
		}
		return Header{}, nil, [32]byte{}, fmt.Errorf("%w: bad magic", ErrCorrupt)
	}
	n := binary.BigEndian.Uint32(fixed[len(Magic):])
	if n == 0 || n > MaxHeaderLen {
		return Header{}, nil, [32]byte{}, fmt.Errorf("%w: header_len %d", ErrCorrupt, n)
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(r, raw); err != nil {
		return Header{}, nil, [32]byte{}, shortRead(err, "header")
	}
	h, err := parseHeader(raw)
	if err != nil {
		return Header{}, nil, [32]byte{}, err
	}
	return h, raw, headerHash(raw), nil
}

// shortRead maps EOF while reading the fixed prefix to ErrCorrupt (a file without a complete prefix was never
// established) and passes other I/O errors through.
func shortRead(err error, what string) error {
	if err == io.EOF || err == io.ErrUnexpectedEOF { //nolint:errorlint // io.ReadFull returns these sentinels unwrapped
		return fmt.Errorf("%w: truncated %s", ErrCorrupt, what)
	}
	return err
}
