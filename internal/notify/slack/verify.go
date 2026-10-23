package slack

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/obs/redact"
)

// Verification parameters (PLAN §10.4).
const (
	DefaultMaxBody   = 64 << 10
	DefaultTolerance = 5 * time.Minute
	ReplayTTL        = 10 * time.Minute

	HeaderTimestamp = "X-Slack-Request-Timestamp"
	HeaderSignature = "X-Slack-Signature"

	signatureVersion = "v0"
)

// VerifierConfig configures a Verifier.
type VerifierConfig struct {
	SigningSecret redact.Secret[string] // required
	Replay        chat.ReplayCache      // required
	Clock         clock.Clock           // default clock.System
	MaxBody       int64                 // default DefaultMaxBody
	Tolerance     time.Duration         // default DefaultTolerance
}

// Verifier authenticates Slack requests.
type Verifier struct {
	secret    redact.Secret[[]byte]
	replay    chat.ReplayCache
	clock     clock.Clock
	maxBody   int64
	tolerance time.Duration
}

// NewVerifier validates cfg and returns a Verifier.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if cfg.SigningSecret.Reveal() == "" {
		return nil, errors.New("slack: signing secret is required")
	}
	if cfg.Replay == nil {
		return nil, errors.New("slack: replay cache is required")
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = DefaultMaxBody
	}
	if cfg.Tolerance <= 0 {
		cfg.Tolerance = DefaultTolerance
	}
	return &Verifier{
		secret: redact.NewSecret([]byte(cfg.SigningSecret.Reveal())), replay: cfg.Replay, clock: cfg.Clock,
		maxBody: cfg.MaxBody, tolerance: cfg.Tolerance,
	}, nil
}

// Verify reads the request body (bounded) and authenticates it. It returns the raw body only if the request is
// authentic and fresh. Errors are *chat.RejectError.
func (v *Verifier) Verify(r *http.Request) ([]byte, error) {
	if r.ContentLength > v.maxBody {
		return nil, chat.Reject(chat.RejectTooLarge, "body exceeds %d bytes", v.maxBody)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, v.maxBody+1))
	if err != nil {
		return nil, chat.Reject(chat.RejectMalformed, "read body: %w", err)
	}
	if int64(len(body)) > v.maxBody {
		return nil, chat.Reject(chat.RejectTooLarge, "body exceeds %d bytes", v.maxBody)
	}
	if err := v.VerifyBody(r.Context(), r.Header, body); err != nil {
		return nil, err
	}
	return body, nil
}

// VerifyBody authenticates an already-read body. The replay cache is consulted last, so only authentic requests
// consume cache entries.
func (v *Verifier) VerifyBody(ctx context.Context, h http.Header, body []byte) error {
	if int64(len(body)) > v.maxBody {
		return chat.Reject(chat.RejectTooLarge, "body exceeds %d bytes", v.maxBody)
	}
	tsHeader := h.Values(HeaderTimestamp)
	sigHeader := h.Values(HeaderSignature)
	if len(tsHeader) != 1 || len(sigHeader) != 1 {
		return chat.Reject(chat.RejectBadSignature, "missing or repeated signature headers")
	}
	ts, err := parseTimestamp(tsHeader[0])
	if err != nil {
		return chat.Reject(chat.RejectStale, "invalid timestamp")
	}
	now := v.clock.Now()
	if d := now.Sub(time.Unix(ts, 0)); d > v.tolerance || d < -v.tolerance {
		return chat.Reject(chat.RejectStale, "timestamp outside the %s window", v.tolerance)
	}
	got, ok := parseSignature(sigHeader[0])
	if !ok {
		return chat.Reject(chat.RejectBadSignature, "malformed signature")
	}
	if !hmac.Equal(got, Sign(v.secret.Reveal(), tsHeader[0], body)) {
		return chat.Reject(chat.RejectBadSignature, "signature mismatch")
	}
	fp := sha256.Sum256(got) // decoded MAC: hex case variants cannot bypass the cache
	fresh, err := v.replay.Remember(ctx, "slack:"+hex.EncodeToString(fp[:]), now.Add(ReplayTTL))
	if err != nil {
		return chat.Reject(chat.RejectInternal, "replay cache: %w", err)
	}
	if !fresh {
		return chat.Reject(chat.RejectReplay, "request already seen")
	}
	return nil
}

// Sign returns the raw v0 MAC: HMAC-SHA256(secret, "v0:" + ts + ":" + body).
func Sign(secret []byte, ts string, body []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(signatureVersion + ":" + ts + ":"))
	m.Write(body)
	return m.Sum(nil)
}

// SignatureHeader returns the X-Slack-Signature value for ts and body ("v0=" + hex MAC).
func SignatureHeader(secret []byte, ts string, body []byte) string {
	return signatureVersion + "=" + hex.EncodeToString(Sign(secret, ts, body))
}

func parseTimestamp(s string) (int64, error) {
	if s == "" || len(s) > 12 {
		return 0, errors.New("bad timestamp")
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("bad timestamp")
		}
	}
	return strconv.ParseInt(s, 10, 64)
}

func parseSignature(s string) ([]byte, bool) {
	rest, ok := strings.CutPrefix(s, signatureVersion+"=")
	if !ok || len(rest) != 2*sha256.Size {
		return nil, false
	}
	b, err := hex.DecodeString(rest)
	if err != nil {
		return nil, false
	}
	return b, true
}
