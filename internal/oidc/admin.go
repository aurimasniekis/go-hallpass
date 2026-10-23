package oidc

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// linkInviteTTL bounds admin-issued link invitations.
const linkInviteTTL = 72 * time.Hour

// IssueLinkInvite creates a single-use invitation that links the next SSO login through providerID to operatorID
// (an audited admin action; callers require recent authentication, HP-OIDC-009). The token is shown once.
func (svc *Service) IssueLinkInvite(ctx context.Context, actor audit.Actor, operatorID, providerID string) (string, time.Time, error) {
	token, err := random32()
	if err != nil {
		return "", time.Time{}, err
	}
	exp := svc.opts.Clock.Now().Add(linkInviteTTL)
	data, _ := json.Marshal(map[string]string{"provider_id": providerID})
	err = svc.s.W().TxNamed(ctx, "oidc.link_invite", func(tx *store.Tx) error {
		if _, err := tx.Q.GetOperator(ctx, operatorID); err != nil {
			return apperr.New(apperr.CodeNotFound, "operator not found")
		}
		if _, err := tx.Q.GetOIDCProvider(ctx, providerID); err != nil {
			return apperr.New(apperr.CodeNotFound, "provider not found")
		}
		if err := tx.Q.InsertOneTimeToken(ctx, db.InsertOneTimeTokenParams{Hash: hashOf("link", token), Kind: "link_code",
			OperatorID: sql.NullString{String: operatorID, Valid: true}, DataJson: string(data), ExpiresAt: exp.UnixMicro(), CreatedAt: tx.NowMicros(),
			CreatedBy: actor.Type + ":" + actor.ID}); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "operator.identity.link_invited", Target: audit.Target{Type: "operator", ID: operatorID},
			Details: map[string]any{"provider_id": providerID, "expires_at": exp}})
		return err
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return token, exp, nil
}

// checkLinkToken consumes a link invitation (single use) and returns its operator.
func (svc *Service) checkLinkToken(ctx context.Context, token, providerID string) (string, error) {
	var opID string
	bad := apperr.New(apperr.CodeUnauthorized, "link invitation is invalid or expired")
	err := svc.s.W().TxNamed(ctx, "oidc.use_link_invite", func(tx *store.Tx) error {
		row, err := tx.Q.GetOneTimeToken(ctx, hashOf("link", token))
		if err != nil || row.Kind != "link_code" || !row.OperatorID.Valid {
			return bad
		}
		var data struct {
			ProviderID string `json:"provider_id"`
		}
		if json.Unmarshal([]byte(row.DataJson), &data) != nil || data.ProviderID != providerID {
			return bad
		}
		n, err := tx.Q.UseOneTimeToken(ctx, db.UseOneTimeTokenParams{Now: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, Hash: row.Hash})
		if err != nil {
			return err
		}
		if n == 0 {
			return bad
		}
		opID = row.OperatorID.String
		return nil
	})
	return opID, err
}

// LinkIdentity links an expected identity (issuer + subject) to an operator directly: an audited admin action that
// requires recent authentication at the API layer (HP-OIDC-009).
func (svc *Service) LinkIdentity(ctx context.Context, actor audit.Actor, operatorID, providerID, subject string) error {
	if subject == "" || len(subject) > 255 {
		return invalid("subject is required (at most 255 bytes)")
	}
	p, err := svc.GetProvider(ctx, providerID)
	if err != nil {
		return err
	}
	return svc.s.W().TxNamed(ctx, "oidc.link_admin", func(tx *store.Tx) error {
		if _, err := tx.Q.GetOperator(ctx, operatorID); err != nil {
			return apperr.New(apperr.CodeNotFound, "operator not found")
		}
		if ident, err := tx.Q.GetIdentity(ctx, db.GetIdentityParams{Issuer: p.Issuer, Subject: subject}); err == nil {
			if ident.OperatorID == operatorID {
				return nil
			}
			return apperr.New(apperr.CodeConflict, "this identity is already linked to another operator")
		}
		if err := tx.Q.InsertIdentity(ctx, db.InsertIdentityParams{Issuer: p.Issuer, Subject: subject, ProviderID: p.ID, OperatorID: operatorID,
			LinkedVia: "admin", CreatedAt: tx.NowMicros()}); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "operator.identity.linked", Target: audit.Target{Type: "operator", ID: operatorID},
			Details: map[string]any{"provider": p.Slug, "via": "admin"}})
		return err
	})
}

// UnlinkIdentity removes a linked identity and revokes the operator's SSO sessions.
func (svc *Service) UnlinkIdentity(ctx context.Context, actor audit.Actor, operatorID, issuer, subject string) error {
	err := svc.s.W().TxNamed(ctx, "oidc.unlink", func(tx *store.Tx) error {
		n, err := tx.Q.DeleteIdentity(ctx, db.DeleteIdentityParams{Issuer: issuer, Subject: subject, OperatorID: operatorID})
		if err != nil {
			return err
		}
		if n == 0 {
			return apperr.New(apperr.CodeNotFound, "identity not found")
		}
		if err := tx.Q.DeleteSSORoles(ctx, operatorID); err != nil {
			return err
		}
		if err := svc.checkSSOOnlyStillSafe(ctx, tx); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "operator.identity.unlinked", Target: audit.Target{Type: "operator", ID: operatorID},
			Details: map[string]any{"issuer": issuer}})
		return err
	})
	if err != nil {
		return err
	}
	return svc.auth.RevokeAllSessions(ctx, operatorID, "identity_unlinked")
}

// Identities lists an operator's linked identities.
func (svc *Service) Identities(ctx context.Context, operatorID string) ([]Identity, error) {
	rows, err := svc.s.R().ListIdentitiesForOperator(ctx, operatorID)
	if err != nil {
		return nil, err
	}
	out := make([]Identity, len(rows))
	for i, r := range rows {
		out[i] = Identity{Issuer: r.Issuer, Subject: r.Subject, ProviderID: r.ProviderID, OperatorID: r.OperatorID, LinkedVia: r.LinkedVia,
			CreatedAt: time.UnixMicro(r.CreatedAt).UTC()}
		if r.LastLoginAt.Valid {
			t := time.UnixMicro(r.LastLoginAt.Int64).UTC()
			out[i].LastLoginAt = &t
		}
	}
	return out, nil
}

// ErrSSOOnlyPrecondition explains why SSO-only enforcement cannot be enabled or kept (HP-AUTH-015, HP-OIDC-014).
var ErrSSOOnlyPrecondition = apperr.New(apperr.CodePrecondition,
	"password login can be disabled only after an administrator completed an SSO test login on an enabled provider, and while at least one administrator can sign in with SSO")

// ssoOnlyReady reports whether SSO-only enforcement is safe: an enabled provider with a recorded test login and at
// least one enabled administrator with a linked identity on an enabled provider.
func ssoOnlyReady(ctx context.Context, q *db.Queries) (bool, error) {
	ps, err := q.ListOIDCProviders(ctx)
	if err != nil {
		return false, err
	}
	tested := false
	for _, p := range ps {
		if p.Enabled == 1 && p.TestLoginOkAt.Valid {
			tested = true
		}
	}
	if !tested {
		return false, nil
	}
	n, err := q.CountSSOAdmins(ctx)
	return n > 0, err
}

// SetLocalLoginDisabled turns SSO-only enforcement on or off (recent authentication required at the API layer).
func (svc *Service) SetLocalLoginDisabled(ctx context.Context, actor audit.Actor, disabled bool) error {
	return svc.s.W().TxNamed(ctx, "oidc.sso_only", func(tx *store.Tx) error {
		if disabled {
			ok, err := ssoOnlyReady(ctx, tx.Q)
			if err != nil {
				return err
			}
			if !ok {
				return ErrSSOOnlyPrecondition
			}
		}
		v := "false"
		if disabled {
			v = "true"
		}
		if err := tx.Q.UpsertSetting(ctx, db.UpsertSettingParams{Key: opauth.SettingLocalLoginDisabled, Value: v, UpdatedAt: tx.NowMicros(),
			UpdatedBy: sql.NullString{String: actor.ID, Valid: actor.ID != ""}}); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "auth.local_login.changed", Details: map[string]any{"disabled": disabled}})
		return err
	})
}

// checkSSOOnlyStillSafe refuses changes (disabling or deleting providers, unlinking) that would leave SSO-only
// enforcement on without a working SSO administrator path (HP-AUTH-015).
func (svc *Service) checkSSOOnlyStillSafe(ctx context.Context, tx *store.Tx) error {
	v, err := tx.Q.GetSetting(ctx, opauth.SettingLocalLoginDisabled)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && v.Value != "true") {
		return nil
	}
	if err != nil {
		return err
	}
	ok, err := ssoOnlyReady(ctx, tx.Q)
	if err != nil {
		return err
	}
	if !ok {
		return apperr.New(apperr.CodePrecondition, "this change would leave password login disabled without an SSO administrator; re-enable password login first")
	}
	return nil
}

// LogoutURL returns the provider's RP-initiated logout URL when enabled, else "". It ends the provider session only
// at that provider; it is not a global logout (HP-OIDC-015). The ID token is not retained, so no id_token_hint is sent.
func (svc *Service) LogoutURL(ctx context.Context, providerSlug, postLogoutRedirect string) (string, error) {
	p, err := svc.providerBySlug(ctx, providerSlug)
	if err != nil || !p.EndSessionEnabled || !p.Enabled {
		return "", err
	}
	r, err := svc.discover(ctx, p)
	if err != nil || r.endSession == "" {
		return "", err
	}
	u, err := url.Parse(r.endSession)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", p.ClientID)
	if postLogoutRedirect != "" {
		q.Set("post_logout_redirect_uri", svc.opts.PublicURL+SanitizeReturnTo(postLogoutRedirect))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// PurgeStates removes expired pending authorizations (background job).
func (svc *Service) PurgeStates(ctx context.Context) (int64, error) {
	var n int64
	err := svc.s.W().TxNamed(ctx, "oidc.purge_states", func(tx *store.Tx) error {
		var err error
		n, err = tx.Q.PurgeAuthStates(ctx, tx.NowMicros())
		return err
	})
	return n, err
}
