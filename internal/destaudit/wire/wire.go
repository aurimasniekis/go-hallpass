// Package wire defines the signed batch format shared by the HallPass destination-audit ingestion endpoint and the
// reference collector (WP25, HP-REC-012). It has no storage or network dependencies so the collector binary stays small.
//
// A collector posts an Envelope: the exact payload bytes (a JSON Batch) and an Ed25519 signature over
// SigningContext || payload. The receiver verifies the signature before it parses the payload, so unauthenticated
// input never reaches the JSON decoder beyond the envelope.
package wire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Version is the batch format version.
const Version = 1

// SigningContext domain-separates batch signatures from any other use of the collector key.
const SigningContext = "hallpass-destaudit-batch-v1\x00"

// SourceAuditd marks records parsed from Linux audit (auditd) EXECVE events.
const SourceAuditd = "auditd"

// Limits. The receiver enforces them; the collector truncates argv to fit and splits batches.
const (
	MaxEnvelopeBytes = 1 << 20 // HTTP body limit
	MaxRecords       = 500     // records per batch
	MaxIDLen         = 128     // record ID, login ref
	MaxUserLen       = 64
	MaxKeyIDLen      = 256
	MaxFingerprint   = 128
	MaxPathLen       = 4096 // exe, cwd
	MaxArgs          = 256
	MaxArgvBytes     = 16 << 10
)

// Envelope is the HTTP request body.
type Envelope struct {
	// Payload is the JSON-encoded Batch exactly as signed (base64 in JSON).
	Payload []byte `json:"payload"`
	// Signature is the raw 64-byte Ed25519 signature over SigningContext || Payload (base64 in JSON).
	Signature []byte `json:"signature"`
}

// Batch is the signed content.
type Batch struct {
	V           int       `json:"v"`
	CollectorID string    `json:"collector_id"`
	Seq         int64     `json:"seq"` // strictly increasing per collector (replay protection)
	SentAt      time.Time `json:"sent_at"`
	Records     []Record  `json:"records"`
}

// Record is one destination exec event.
type Record struct {
	// ID is unique per collector (the reference collector uses the audit event stamp "<sec>.<ms>:<serial>").
	ID     string    `json:"id"`
	Source string    `json:"source"`
	Time   time.Time `json:"time"` // destination clock
	Login  Login     `json:"login"`
	PID    int64     `json:"pid"`
	PPID   int64     `json:"ppid"`
	UID    int64     `json:"uid"`
	AUID   int64     `json:"auid"`
	// Success is the syscall result as reported by the kernel audit record.
	Success   bool     `json:"success"`
	Exe       string   `json:"exe"`
	Argv      []string `json:"argv"`
	Truncated bool     `json:"truncated,omitempty"` // the collector dropped argv content to fit MaxArgs/MaxArgvBytes
	CWD       string   `json:"cwd,omitempty"`
}

// Login identifies the destination login (SSH authentication + audit session) the exec belongs to. Every field is a
// destination-side claim that HallPass checks against its own state; none of it is a HallPass session ID.
type Login struct {
	// Ref is an opaque, per-collector stable reference to the audit session (the reference collector uses
	// "<login audit stamp>/<ses>").
	Ref  string `json:"ref"`
	User string `json:"user"` // destination account
	// CertKeyID is the OpenSSH certificate key ID logged by sshd ("hallpass:<role>:<grant>:<connection>").
	CertKeyID string `json:"cert_key_id,omitempty"`
	// KeyFingerprint is the SHA256 fingerprint of the authenticating public key (managed login keys).
	KeyFingerprint string    `json:"key_fingerprint,omitempty"`
	Time           time.Time `json:"time,omitzero"` // login time (destination clock)
}

// SignedMessage returns the bytes covered by the signature.
func SignedMessage(payload []byte) []byte {
	m := make([]byte, 0, len(SigningContext)+len(payload))
	m = append(m, SigningContext...)
	return append(m, payload...)
}

// Sign encodes b and signs it.
func Sign(priv ed25519.PrivateKey, b *Batch) (*Envelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("wire: invalid Ed25519 private key")
	}
	payload, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	return &Envelope{Payload: payload, Signature: ed25519.Sign(priv, SignedMessage(payload))}, nil
}

// ErrBadSignature is returned when an envelope's signature does not verify.
var ErrBadSignature = errors.New("wire: bad signature")

// Verify checks env's signature with pub.
func Verify(pub ed25519.PublicKey, env *Envelope) error {
	if len(pub) != ed25519.PublicKeySize || len(env.Signature) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	if !ed25519.Verify(pub, SignedMessage(env.Payload), env.Signature) {
		return ErrBadSignature
	}
	return nil
}

// DecodeEnvelope parses an HTTP body strictly (unknown fields are rejected).
func DecodeEnvelope(body []byte) (*Envelope, error) {
	var env Envelope
	if err := decodeStrict(body, &env); err != nil {
		return nil, fmt.Errorf("wire: envelope: %w", err)
	}
	if len(env.Payload) == 0 || len(env.Signature) == 0 {
		return nil, errors.New("wire: envelope: payload and signature are required")
	}
	return &env, nil
}

// DecodeBatch parses a verified payload strictly and checks batch-level structure.
func DecodeBatch(payload []byte) (*Batch, error) {
	var b Batch
	if err := decodeStrict(payload, &b); err != nil {
		return nil, fmt.Errorf("wire: batch: %w", err)
	}
	if b.V != Version {
		return nil, fmt.Errorf("wire: unsupported batch version %d", b.V)
	}
	if b.CollectorID == "" || b.Seq <= 0 || b.SentAt.IsZero() {
		return nil, errors.New("wire: batch: collector_id, seq and sent_at are required")
	}
	if len(b.Records) > MaxRecords {
		return nil, fmt.Errorf("wire: batch: %d records exceeds the limit of %d", len(b.Records), MaxRecords)
	}
	return &b, nil
}

func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// Validate checks one record's size limits and required fields. It returns a short reason code, or "" when valid.
func (r *Record) Validate() string {
	switch {
	case r.ID == "" || len(r.ID) > MaxIDLen || !printable(r.ID):
		return "invalid_id"
	case r.Source != SourceAuditd:
		return "invalid_source"
	case r.Time.IsZero():
		return "invalid_time"
	case r.Login.Ref == "" || len(r.Login.Ref) > MaxIDLen || !printable(r.Login.Ref):
		return "invalid_login"
	case r.Login.User == "" || len(r.Login.User) > MaxUserLen || !printable(r.Login.User):
		return "invalid_login"
	case len(r.Login.CertKeyID) > MaxKeyIDLen || len(r.Login.KeyFingerprint) > MaxFingerprint:
		return "invalid_login"
	case r.PID <= 0 || r.PPID < 0 || r.UID < 0 || r.AUID < 0:
		return "invalid_process"
	case len(r.Exe) > MaxPathLen || len(r.CWD) > MaxPathLen:
		return "too_large"
	case len(r.Argv) > MaxArgs || ArgvBytes(r.Argv) > MaxArgvBytes:
		return "too_large"
	}
	return ""
}

// ArgvBytes is the total length of argv.
func ArgvBytes(argv []string) int {
	n := 0
	for _, a := range argv {
		n += len(a)
	}
	return n
}

func printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
}

// CertKeyIDPrefix starts every certificate key ID HallPass issues.
const CertKeyIDPrefix = "hallpass:"

// CertKeyID is a parsed HallPass certificate key ID.
type CertKeyID struct {
	RoleID       string
	GrantID      string
	ConnectionID string
}

// ParseCertKeyID parses "hallpass:<role>:<grant>:<connection>" (internal/credentials issueCert). It checks only the
// shape; the receiver checks every part against its own state.
func ParseCertKeyID(s string) (CertKeyID, bool) {
	rest, ok := strings.CutPrefix(s, CertKeyIDPrefix)
	if !ok {
		return CertKeyID{}, false
	}
	parts := strings.Split(rest, ":")
	if len(parts) != 3 {
		return CertKeyID{}, false
	}
	for _, p := range parts {
		if p == "" || len(p) > 64 || !printable(p) {
			return CertKeyID{}, false
		}
	}
	return CertKeyID{RoleID: parts[0], GrantID: parts[1], ConnectionID: parts[2]}, true
}

// TruncateArgv drops trailing arguments and shortens the last kept one so argv fits the limits. It reports whether
// anything was removed.
func TruncateArgv(argv []string) ([]string, bool) {
	truncated := false
	if len(argv) > MaxArgs {
		argv, truncated = argv[:MaxArgs], true
	}
	total := 0
	for i, a := range argv {
		if total+len(a) > MaxArgvBytes {
			keep := MaxArgvBytes - total
			for keep > 0 && !utf8.RuneStart(a[keep]) {
				keep--
			}
			out := append(append([]string(nil), argv[:i]...), a[:keep])
			return out, true
		}
		total += len(a)
	}
	return argv, truncated
}
