package opauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Authentication methods recorded on sessions.
const (
	MethodPassword   = "password"
	MethodOIDC       = "oidc"
	MethodBreakGlass = "breakglass"
)

// Principal is the authenticated operator behind a request.
type Principal struct {
	Operator  *Operator
	SessionID string // display ID (safe to show)
	Method    string
	AuthAt    time.Time
	MFAAt     *time.Time
	CSRFToken string
	ExpiresAt time.Time
	// Limited is set while MFA verification or enrollment is still required; only MFA endpoints may be used.
	Limited     bool
	NeedsEnroll bool
	tokenHash   []byte
	csrfSecret  []byte
}

// MFASatisfied reports whether this session completed MFA (or does not need it).
func (p *Principal) MFASatisfied() bool { return !p.Limited }

// HasRole reports whether the operator holds an internal role.
func (p *Principal) HasRole(r string) bool {
	for _, x := range p.Operator.Roles {
		if x == r {
			return true
		}
	}
	return false
}

func hashSessionToken(token string) []byte {
	h := sha256.Sum256([]byte("hallpass/session/v1|" + token))
	return h[:]
}

// SessionMeta describes the client.
type SessionMeta struct {
	IP        string
	UserAgent string
}

// createSession inserts a new session inside tx and returns the bearer token (cookie value).
func (svc *Service) createSession(ctx context.Context, tx *store.Tx, operatorID, method string, mfaAt *time.Time, meta SessionMeta) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	var mfa sql.NullInt64
	if mfaAt != nil {
		mfa = sql.NullInt64{Int64: mfaAt.UnixMicro(), Valid: true}
	}
	if len(meta.UserAgent) > 256 {
		meta.UserAgent = meta.UserAgent[:256]
	}
	err = tx.Q.InsertWebSession(ctx, db.InsertWebSessionParams{
		IDHash: hashSessionToken(token), OperatorID: operatorID, CsrfSecret: secret, AuthMethod: method, MfaAt: mfa,
		AuthAt: tx.NowMicros(), CreatedAt: tx.NowMicros(), LastSeenAt: tx.NowMicros(),
		AbsoluteExpiresAt: tx.Now.Add(svc.opts.SessionAbsolute).UnixMicro(), Ip: meta.IP, UserAgent: meta.UserAgent, DisplayID: ids.New(ids.WebSession),
	})
	if err != nil {
		return "", err
	}
	if err := tx.Q.TouchOperatorLogin(ctx, db.TouchOperatorLoginParams{LastLoginAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, ID: operatorID}); err != nil {
		return "", err
	}
	return token, nil
}

// ErrUnauthorized means no valid session.
var ErrUnauthorized = apperr.New(apperr.CodeUnauthorized, "authentication required")

// Authenticate resolves a session token to a principal, enforcing revocation, idle and absolute expiry (HP-AUTH-012).
func (svc *Service) Authenticate(ctx context.Context, token string) (*Principal, error) {
	if token == "" || len(token) > 128 {
		return nil, ErrUnauthorized
	}
	h := hashSessionToken(token)
	row, err := svc.s.R().GetWebSession(ctx, h)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	now := svc.opts.Clock.Now()
	if row.RevokedAt.Valid || !now.Before(time.UnixMicro(row.AbsoluteExpiresAt)) || now.Sub(time.UnixMicro(row.LastSeenAt)) > svc.opts.SessionIdle {
		return nil, ErrUnauthorized
	}
	op, err := svc.Get(ctx, row.OperatorID)
	if err != nil || !op.Enabled {
		return nil, ErrUnauthorized
	}
	p := &Principal{Operator: op, SessionID: row.DisplayID, Method: row.AuthMethod, AuthAt: time.UnixMicro(row.AuthAt).UTC(),
		ExpiresAt: time.UnixMicro(row.AbsoluteExpiresAt).UTC(), tokenHash: h, csrfSecret: row.CsrfSecret}
	if row.MfaAt.Valid {
		t := time.UnixMicro(row.MfaAt.Int64).UTC()
		p.MFAAt = &t
	}
	if row.AuthMethod == MethodPassword {
		p.NeedsEnroll = op.MFARequired && !op.MFAEnrolled
		p.Limited = p.NeedsEnroll || (op.MFAEnrolled && p.MFAAt == nil)
	}
	p.CSRFToken = csrfToken(row.CsrfSecret, row.DisplayID)
	if now.Sub(time.UnixMicro(row.LastSeenAt)) > time.Minute {
		_ = svc.s.W().TxNamed(ctx, "opauth.touch_session", func(tx *store.Tx) error {
			return tx.Q.TouchWebSession(ctx, db.TouchWebSessionParams{LastSeenAt: tx.NowMicros(), IDHash: h})
		})
	}
	return p, nil
}

func csrfToken(secret []byte, displayID string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("hallpass/csrf/v1|" + displayID))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// VerifyCSRF checks a request's CSRF token in constant time (HP-AUTH-013).
func (p *Principal) VerifyCSRF(token string) bool {
	return token != "" && hmac.Equal([]byte(token), []byte(csrfToken(p.csrfSecret, p.SessionID)))
}

// ErrReauthRequired and ErrMFARequired drive the UI's re-authentication flow (HP-AUTH-014).
var (
	ErrReauthRequired = apperr.New(apperr.CodeReauth, "recent authentication required")
	ErrMFARequired    = apperr.New(apperr.CodeMFARequired, "multi-factor authentication required")
)

// RequireRecentAuth checks that the session authenticated within the reauth window, and with MFA when the operator
// has MFA (or needMFA is set).
func (svc *Service) RequireRecentAuth(p *Principal, needMFA bool) error {
	now := svc.opts.Clock.Now()
	if now.Sub(p.AuthAt) > svc.opts.ReauthWindow {
		return ErrReauthRequired
	}
	if (needMFA || p.Operator.MFAEnrolled) && p.Method == MethodPassword {
		if p.MFAAt == nil || now.Sub(*p.MFAAt) > svc.opts.ReauthWindow {
			return ErrMFARequired
		}
	}
	return nil
}

// Rotate replaces the session token (after login completion, MFA, reauth or privilege change) and revokes the old one.
func (svc *Service) Rotate(ctx context.Context, p *Principal, meta SessionMeta) (string, error) {
	var token string
	err := svc.s.W().TxNamed(ctx, "opauth.rotate_session", func(tx *store.Tx) error {
		old, err := tx.Q.GetWebSession(ctx, p.tokenHash)
		if err != nil {
			return err
		}
		if _, err := tx.Q.RevokeWebSession(ctx, db.RevokeWebSessionParams{RevokedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
			RevokeReason: sql.NullString{String: "rotated", Valid: true}, IDHash: p.tokenHash}); err != nil {
			return err
		}
		var mfa *time.Time
		if old.MfaAt.Valid {
			t := time.UnixMicro(old.MfaAt.Int64)
			mfa = &t
		}
		token, err = svc.createSession(ctx, tx, old.OperatorID, old.AuthMethod, mfa, meta)
		if err != nil {
			return err
		}
		// Preserve the original authentication time and absolute expiry across rotation.
		return tx.Q.UpdateWebSessionAuth(ctx, db.UpdateWebSessionAuthParams{AuthAt: old.AuthAt, MfaAt: old.MfaAt, IDHash: hashSessionToken(token)})
	})
	return token, err
}

// Logout revokes the session (HP-OIDC-015: provider logout is separate and not global).
func (svc *Service) Logout(ctx context.Context, token string) error {
	return svc.s.W().TxNamed(ctx, "opauth.logout", func(tx *store.Tx) error {
		_, err := tx.Q.RevokeWebSession(ctx, db.RevokeWebSessionParams{RevokedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
			RevokeReason: sql.NullString{String: "logout", Valid: true}, IDHash: hashSessionToken(token)})
		return err
	})
}

// SessionInfo describes an active session for management views.
type SessionInfo struct {
	ID        string    `json:"id"`
	Method    string    `json:"auth_method"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Current   bool      `json:"current"`
}

// ListSessions returns an operator's active sessions.
func (svc *Service) ListSessions(ctx context.Context, operatorID, currentDisplayID string) ([]SessionInfo, error) {
	rows, err := svc.s.R().ListOperatorSessions(ctx, db.ListOperatorSessionsParams{OperatorID: operatorID, AbsoluteExpiresAt: svc.opts.Clock.Now().UnixMicro()})
	if err != nil {
		return nil, err
	}
	out := make([]SessionInfo, 0, len(rows))
	for _, r := range rows {
		out = append(out, SessionInfo{ID: r.DisplayID, Method: r.AuthMethod, CreatedAt: time.UnixMicro(r.CreatedAt).UTC(),
			LastSeen: time.UnixMicro(r.LastSeenAt).UTC(), ExpiresAt: time.UnixMicro(r.AbsoluteExpiresAt).UTC(), IP: r.Ip, UserAgent: r.UserAgent,
			Current: r.DisplayID == currentDisplayID})
	}
	return out, nil
}

// RevokeSession revokes one of an operator's sessions by display ID.
func (svc *Service) RevokeSession(ctx context.Context, operatorID, displayID, reason string) error {
	return svc.s.W().TxNamed(ctx, "opauth.revoke_session", func(tx *store.Tx) error {
		n, err := tx.Q.RevokeWebSessionByDisplayID(ctx, db.RevokeWebSessionByDisplayIDParams{RevokedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
			RevokeReason: sql.NullString{String: reason, Valid: true}, DisplayID: displayID, OperatorID: operatorID})
		if err == nil && n == 0 {
			return apperr.New(apperr.CodeNotFound, "session not found")
		}
		return err
	})
}

// RevokeAllSessions revokes every session of an operator (admin action or security event).
func (svc *Service) RevokeAllSessions(ctx context.Context, operatorID, reason string) error {
	return svc.s.W().TxNamed(ctx, "opauth.revoke_all", func(tx *store.Tx) error {
		_, err := tx.Q.RevokeOperatorSessions(ctx, db.RevokeOperatorSessionsParams{Now: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
			Reason: sql.NullString{String: reason, Valid: true}, OperatorID: operatorID, ExceptHash: []byte{}})
		return err
	})
}

// PurgeExpired deletes expired sessions and one-time tokens (periodic job).
func (svc *Service) PurgeExpired(ctx context.Context) error {
	return svc.s.W().TxNamed(ctx, "opauth.purge", func(tx *store.Tx) error {
		if _, err := tx.Q.PurgeWebSessions(ctx, tx.Now.Add(-24*time.Hour).UnixMicro()); err != nil {
			return err
		}
		_, err := tx.Q.PurgeOneTimeTokens(ctx, tx.Now.Add(-7*24*time.Hour).UnixMicro())
		return err
	})
}
