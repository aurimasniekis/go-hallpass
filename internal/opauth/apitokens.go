package opauth

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Automation (API) tokens: `hallpass_at_<43 base64url chars>` bearer tokens for Terraform and scripts. A token acts for
// the operator who created it, with one role, and only while the operator is still enabled and holds that role or is an
// administrator (administrators hold every permission of every other role, ADR-0058). Only a keyed MAC is stored.
const (
	APITokenPrefix = "hallpass_at_"
	MinAPITokenTTL = 24 * time.Hour
	MaxAPITokenTTL = 366 * 24 * time.Hour
	// apiTokenTouchEvery bounds the writes that record when a token was last used.
	apiTokenTouchEvery = time.Minute
)

// neverExpiresAt is the expires_at stored for tokens without expiry (ADR-0053), so every expiry comparison holds
// unchanged.
var neverExpiresAt = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)

// APIToken describes an automation token (never the token itself).
type APIToken struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	OperatorID string    `json:"operator_id"`
	Role       string    `json:"role"`
	Hint       string    `json:"hint"`
	CreatedAt  time.Time `json:"created_at"`
	// ExpiresAt is nil when the token never expires.
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	NeverExpires bool       `json:"never_expires"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP   string     `json:"last_used_ip,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokedBy    string     `json:"revoked_by,omitempty"`
	// ParentTokenID is the API token that issued this one, if any (ADR-0058).
	ParentTokenID string `json:"parent_token_id,omitempty"`
}

func apiTokenFromRow(r db.ApiToken) *APIToken {
	t := &APIToken{ID: r.ID, Name: r.Name, OperatorID: r.OperatorID, Role: r.Role, Hint: r.Hint,
		CreatedAt: time.UnixMicro(r.CreatedAt).UTC(), NeverExpires: r.NeverExpires == 1, LastUsedIP: r.LastUsedIp.String,
		RevokedBy: r.RevokedBy.String, ParentTokenID: r.ParentTokenID.String}
	if !t.NeverExpires {
		v := time.UnixMicro(r.ExpiresAt).UTC()
		t.ExpiresAt = &v
	}
	if r.LastUsedAt.Valid {
		v := time.UnixMicro(r.LastUsedAt.Int64).UTC()
		t.LastUsedAt = &v
	}
	if r.RevokedAt.Valid {
		v := time.UnixMicro(r.RevokedAt.Int64).UTC()
		t.RevokedAt = &v
	}
	return t
}

// CreateAPIToken issues a token for the calling operator with one of their roles, or any role for an administrator. The
// token is returned once. A token either expires after ttl or, with neverExpires (and ttl zero), never expires
// (ADR-0053). An administrator token may issue tokens, which it then parents; a token issued by a token may not
// (ADR-0058).
func (svc *Service) CreateAPIToken(ctx context.Context, p *Principal, name, role string, ttl time.Duration, neverExpires bool) (*APIToken, string, error) {
	name = strings.TrimSpace(name)
	v := &apperr.Validation{}
	if name == "" || utf8.RuneCountInString(name) > 100 {
		v.Add("name", "must be 1-100 characters")
	}
	if !slices.Contains(AllRoles, role) {
		v.Add("role", "must be administrator, approver, auditor or viewer")
	} else if !holdsTokenRole(p.Operator.Roles, role) {
		v.Add("role", "must be one of your own roles")
	}
	switch {
	case neverExpires && ttl != 0:
		v.Add("expires_in_days", "must be omitted for a token that never expires")
	case !neverExpires && (ttl < MinAPITokenTTL || ttl > MaxAPITokenTTL):
		v.Add("expires_in_days", "must be between 1 and 366 days")
	}
	if p.TokenParentID != "" {
		return nil, "", apperr.New(apperr.CodeForbidden, "a token issued by another token cannot issue tokens")
	}
	if err := v.Err(); err != nil {
		return nil, "", err
	}
	secret, err := randomToken()
	if err != nil {
		return nil, "", err
	}
	token := APITokenPrefix + secret
	mac, err := svc.tokenMAC(token)
	if err != nil {
		return nil, "", err
	}
	id := ids.New(ids.APIToken)
	err = svc.s.W().TxNamed(ctx, "opauth.create_api_token", func(tx *store.Tx) error {
		expires, details := tx.Now.Add(ttl), map[string]any{"name": name, "role": role, "expires_in": ttl.String()}
		if neverExpires {
			expires, details = neverExpiresAt, map[string]any{"name": name, "role": role, "never_expires": true}
		}
		actor := audit.Actor{Type: audit.ActorOperator, ID: p.Operator.ID}
		if p.TokenID != "" {
			actor.Via, details["parent_token_id"] = "api_token:"+p.TokenID, p.TokenID
		}
		if err := tx.Q.InsertAPIToken(ctx, db.InsertAPITokenParams{ID: id, Name: name, OperatorID: p.Operator.ID, Role: role, Mac: mac,
			Hint: token[len(token)-4:], CreatedAt: tx.NowMicros(), ExpiresAt: expires.UnixMicro(), NeverExpires: b2i(neverExpires),
			ParentTokenID: sql.NullString{String: p.TokenID, Valid: p.TokenID != ""}}); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "api_token.created",
			Target: audit.Target{Type: "api_token", ID: id}, Details: details})
		return err
	})
	if err != nil {
		return nil, "", err
	}
	t, err := svc.GetAPIToken(ctx, id)
	return t, token, err
}

// GetAPIToken returns one token's metadata.
func (svc *Service) GetAPIToken(ctx context.Context, id string) (*APIToken, error) {
	r, err := svc.s.R().GetAPIToken(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeNotFound, "API token not found")
	}
	if err != nil {
		return nil, err
	}
	return apiTokenFromRow(r), nil
}

// ListAPITokens returns every token, active first.
func (svc *Service) ListAPITokens(ctx context.Context) ([]*APIToken, error) {
	rows, err := svc.s.R().ListAPITokens(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*APIToken, len(rows))
	for i, r := range rows {
		out[i] = apiTokenFromRow(r)
	}
	return out, nil
}

// RevokeAPIToken stops a token at once, together with the tokens it issued (ADR-0058). Revoking a revoked token is a
// no-op.
func (svc *Service) RevokeAPIToken(ctx context.Context, actor audit.Actor, id string) (*APIToken, error) {
	err := svc.s.W().TxNamed(ctx, "opauth.revoke_api_token", func(tx *store.Tx) error {
		if _, err := tx.Q.GetAPIToken(ctx, id); errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeNotFound, "API token not found")
		} else if err != nil {
			return err
		}
		children, err := tx.Q.ListActiveChildAPITokens(ctx, sql.NullString{String: id, Valid: true})
		if err != nil {
			return err
		}
		for _, tid := range append([]string{id}, children...) {
			n, err := tx.Q.RevokeAPIToken(ctx, db.RevokeAPITokenParams{Now: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
				Actor: sql.NullString{String: actorRef(actor), Valid: true}, ID: tid})
			if err != nil {
				return err
			}
			if n == 0 {
				continue
			}
			var details map[string]any
			if tid != id {
				details = map[string]any{"parent_token_id": id}
			}
			if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "api_token.revoked", Target: audit.Target{Type: "api_token", ID: tid},
				Details: details}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return svc.GetAPIToken(ctx, id)
}

// AuthenticateAPIToken resolves a bearer token to a principal: the creating operator restricted to the token's role.
// Unknown, revoked and expired tokens, and tokens whose operator is disabled or no longer holds the role (nor
// administrator), all fail with the same error.
func (svc *Service) AuthenticateAPIToken(ctx context.Context, token, ip string) (*Principal, error) {
	if !strings.HasPrefix(token, APITokenPrefix) || len(token) != len(APITokenPrefix)+43 {
		return nil, ErrUnauthorized
	}
	macs, err := svc.tokenMACs(token)
	if err != nil {
		return nil, err
	}
	var row db.ApiToken
	found := false
	for _, mac := range macs {
		r, err := svc.s.R().GetAPITokenByMAC(ctx, mac)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		row, found = r, true
		break
	}
	now := svc.opts.Clock.Now()
	if !found || row.RevokedAt.Valid || !now.Before(time.UnixMicro(row.ExpiresAt)) {
		return nil, ErrUnauthorized
	}
	op, err := svc.Get(ctx, row.OperatorID)
	if err != nil || !op.Enabled || !holdsTokenRole(op.Roles, row.Role) {
		return nil, ErrUnauthorized
	}
	if !row.LastUsedAt.Valid || now.Sub(time.UnixMicro(row.LastUsedAt.Int64)) >= apiTokenTouchEvery {
		_ = svc.s.W().TxNamed(ctx, "opauth.touch_api_token", func(tx *store.Tx) error {
			return tx.Q.TouchAPIToken(ctx, db.TouchAPITokenParams{Now: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
				Ip: sql.NullString{String: ip, Valid: ip != ""}, ID: row.ID, Since: sql.NullInt64{Int64: tx.Now.Add(-apiTokenTouchEvery).UnixMicro(), Valid: true}})
		})
	}
	scoped := *op
	scoped.Roles = []string{row.Role}
	return &Principal{Operator: &scoped, SessionID: row.ID, TokenID: row.ID, TokenParentID: row.ParentTokenID.String, Method: MethodToken,
		AuthAt: now, ExpiresAt: time.UnixMicro(row.ExpiresAt)}, nil
}

// holdsTokenRole reports whether an operator with roles may hold a token with role: their own roles, and every role
// for administrators, whose permissions include those of every other role (ADR-0058).
func holdsTokenRole(roles []string, role string) bool {
	return slices.Contains(roles, role) || slices.Contains(roles, RoleAdministrator)
}
