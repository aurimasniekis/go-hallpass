package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/httpapi/gen"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// limiters are fixed-window per-key counters (per minute) for API rate limiting (HP-API-008). The table is bounded
// (maxKeys, SR-30): once full, expired windows are dropped first; a key that still finds no room is refused when the
// limit protects an unauthenticated path (failClosed) and passes otherwise, so a flood of fresh source addresses can
// neither grow memory without bound nor lock out signed-in operators.
type limiters struct {
	clk     clock.Clock
	maxKeys int
	mu      sync.Mutex
	m       map[string]*window
	swept   time.Time
}

type window struct {
	start time.Time
	n     int
}

// defaultLimiterKeys bounds the limiter table (about 100 bytes per key).
const defaultLimiterKeys = 100_000

func newLimiters(c clock.Clock) *limiters {
	return &limiters{clk: c, maxKeys: defaultLimiterKeys, m: map[string]*window{}}
}

func (l *limiters) allow(key string, perMinute int) bool { return l.allowKey(key, perMinute, false) }

func (l *limiters) allowKey(key string, perMinute int, failClosed bool) bool {
	now := l.clk.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.m[key]
	if w == nil && len(l.m) >= l.maxKeys {
		// Sweeping is O(n); do it at most once per second while the table stays full.
		if now.Sub(l.swept) >= time.Second {
			l.swept = now
			l.sweep(now)
		}
		if len(l.m) >= l.maxKeys {
			return !failClosed
		}
	}
	if w == nil || now.Sub(w.start) >= time.Minute {
		w = &window{start: now}
		l.m[key] = w
	}
	w.n++
	return w.n <= perMinute
}

// sweep drops windows that can no longer limit anything; l.mu must be held.
func (l *limiters) sweep(now time.Time) {
	for k, w := range l.m {
		if now.Sub(w.start) >= time.Minute {
			delete(l.m, k)
		}
	}
}

// sourceKey is the rate-limit identity of a client address: IPv4 addresses as they are, IPv6 by /64, the smallest
// prefix a single site is normally given (SR-30, the same rule as login throttling and SSH bans).
func sourceKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

func (l *limiters) gc(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := l.clk.Now()
		l.mu.Lock()
		l.sweep(now)
		l.mu.Unlock()
	}
}

// Idempotency (HP-API-006): a key is scoped to the operator; a replay with the same operation and body returns the
// stored response, a different request with the same key is a conflict.

const idempotencyTTL = 24 * time.Hour

// secretResponseOps return one-time secrets (invitation, reset and link tokens, recovery and link codes, TOTP
// secrets) that are otherwise stored only as MACs (HP-AUTH-018, AS-7). Their idempotency records keep the request
// hash and status but never the body (SR-11); a replay is answered 409 instead of repeating the secret.
var secretResponseOps = map[string]bool{
	"createInvitation": true, "issueResetToken": true, "issueLinkInvite": true, "createProviderLinkCode": true, "recoverLogin": true,
	"beginTOTP": true, "confirmTOTP": true, "regenerateRecoveryCodes": true, "createAPIToken": true,
}

var errSecretReplay = apperr.New(apperr.CodeConflict,
	"this request already succeeded; its one-time secret is shown only once and is not stored, so create a new one")

type idemCtxKey struct{}

type idemState struct {
	key  string
	hash []byte
}

func requestHash(c *gen.Call) ([]byte, error) {
	body, err := io.ReadAll(c.R.Body)
	if err != nil {
		return nil, err
	}
	c.R.Body = io.NopCloser(bytes.NewReader(body))
	h := sha256.New()
	h.Write([]byte(c.Op.ID + "\n" + c.R.URL.Path + "?" + c.R.URL.RawQuery + "\n"))
	h.Write(body)
	return h.Sum(nil), nil
}

// replayIdempotent writes a stored response and returns true, or remembers the key for storeIdempotent.
func (s *Server) replayIdempotent(c *gen.Call) bool {
	key := c.R.Header.Get("Idempotency-Key")
	if len(key) < 8 || len(key) > 128 || strings.ContainsFunc(key, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
		s.problem(c.W, c.R, apperr.New(apperr.CodeInvalid, "Idempotency-Key must be 8-128 printable ASCII characters"))
		return true
	}
	hash, err := requestHash(c)
	if err != nil {
		s.problem(c.W, c.R, err)
		return true
	}
	row, err := s.d.Store.R().GetIdempotency(c.R.Context(), db.GetIdempotencyParams{OperatorID: c.Principal.Operator.ID, Key: key,
		ExpiresAt: s.o.Clock.Now().UnixMicro()})
	switch {
	case errors.Is(err, sql.ErrNoRows):
		c.R = c.R.WithContext(context.WithValue(c.R.Context(), idemCtxKey{}, &idemState{key: key, hash: hash}))
		return false
	case err != nil:
		s.problem(c.W, c.R, err)
		return true
	}
	if row.Operation != c.Op.ID || !bytes.Equal(row.RequestHash, hash) {
		s.problem(c.W, c.R, apperr.New(apperr.CodeConflict, "Idempotency-Key was already used for a different request"))
		return true
	}
	if secretResponseOps[c.Op.ID] {
		s.problem(c.W, c.R, errSecretReplay)
		return true
	}
	c.W.Header().Set("Idempotent-Replayed", "true")
	if len(row.Body) > 0 {
		c.W.Header().Set("Content-Type", "application/json")
	}
	c.W.WriteHeader(int(row.Status))
	_, _ = c.W.Write(row.Body)
	return true
}

func (s *Server) storeIdempotent(c *gen.Call, status int, body []byte) {
	st, _ := c.R.Context().Value(idemCtxKey{}).(*idemState)
	if st == nil || status >= 300 || c.Principal == nil {
		return
	}
	if body == nil || secretResponseOps[c.Op.ID] {
		body = []byte{}
	}
	ctx := context.WithoutCancel(c.R.Context())
	_ = s.d.Store.W().TxNamed(ctx, "api.idempotency", func(tx *store.Tx) error {
		return tx.Q.InsertIdempotency(ctx, db.InsertIdempotencyParams{OperatorID: c.Principal.Operator.ID, Key: st.key, Operation: c.Op.ID,
			RequestHash: st.hash, Status: int64(status), Body: body, CreatedAt: tx.NowMicros(), ExpiresAt: tx.Now.Add(idempotencyTTL).UnixMicro()})
	})
}

// PurgeIdempotency removes expired idempotency records (background job).
func (s *Server) PurgeIdempotency(ctx context.Context) error {
	return s.d.Store.W().TxNamed(ctx, "api.idempotency_purge", func(tx *store.Tx) error {
		_, err := tx.Q.PurgeIdempotency(ctx, tx.NowMicros())
		return err
	})
}

// Pagination (HP-API-004): opaque cursors encode the last row's sort key.

type cursor struct {
	At  int64  `json:"t"`
	ID  string `json:"i"`
	Seq int64  `json:"s,omitempty"`
}

func encodeCursor(c cursor) *string {
	b, _ := json.Marshal(c)
	s := base64.RawURLEncoding.EncodeToString(b)
	return &s
}

func decodeCursor(raw string) (*cursor, error) {
	if raw == "" {
		return nil, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(b) > 256 {
		return nil, apperr.New(apperr.CodeInvalid, "invalid cursor")
	}
	var c cursor
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, apperr.New(apperr.CodeInvalid, "invalid cursor")
	}
	// Only cursors this server issued are accepted: decoding replaces invalid UTF-8 and re-encoding escapes <>&, so a
	// non-canonical cursor could otherwise re-encode differently (and past the size bound).
	if *encodeCursor(c) != raw {
		return nil, apperr.New(apperr.CodeInvalid, "invalid cursor")
	}
	return &c, nil
}

func pageLimit(r *http.Request) (int64, error) {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return 50, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 200 {
		return 0, apperr.New(apperr.CodeInvalid, "limit must be 1-200")
	}
	return int64(n), nil
}

func nullStr(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func queryEnum(r *http.Request, name string, allowed ...string) (string, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return "", nil
	}
	for _, a := range allowed {
		if v == a {
			return v, nil
		}
	}
	return "", apperr.New(apperr.CodeInvalid, "invalid %s", name)
}

func micros(t int64) time.Time { return time.UnixMicro(t).UTC() }

func nullTime(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := micros(v.Int64)
	return &t
}

func nullInt(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	return &v.Int64
}

// seconds renders a duration as integer seconds in API JSON.
type seconds int64

func secs(d time.Duration) seconds { return seconds(d / time.Second) }

func durPtr(s *int64) *time.Duration {
	if s == nil {
		return nil
	}
	d := time.Duration(*s) * time.Second
	return &d
}
