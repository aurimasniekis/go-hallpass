package opauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Token lifetimes.
const (
	SetupTokenTTL    = 30 * time.Minute
	InviteTTL        = 72 * time.Hour
	ResetTTL         = time.Hour
	RecoveryLoginTTL = 30 * time.Minute
)

// ErrTokenInvalid is returned for unknown, expired or used tokens (one message for all, enumeration-resistant).
var ErrTokenInvalid = apperr.New(apperr.CodeUnauthorized, "this link or token is invalid or has expired")

func (svc *Service) issueToken(ctx context.Context, tx *store.Tx, kind, operatorID string, ttl time.Duration, data map[string]any, actor audit.Actor) (string, time.Time, error) {
	token, err := randomToken()
	if err != nil {
		return "", time.Time{}, err
	}
	mac, err := svc.tokenMAC(token)
	if err != nil {
		return "", time.Time{}, err
	}
	exp := tx.Now.Add(ttl)
	if data == nil {
		data = map[string]any{}
	}
	if err := tx.Q.InsertOneTimeToken(ctx, db.InsertOneTimeTokenParams{Hash: mac, Kind: kind, OperatorID: sql.NullString{String: operatorID, Valid: operatorID != ""},
		DataJson: mustJSON(data), ExpiresAt: exp.UnixMicro(), CreatedAt: tx.NowMicros(), CreatedBy: actorRef(actor)}); err != nil {
		return "", time.Time{}, err
	}
	return token, exp, nil
}

// consumeToken validates and marks a token used inside tx, returning its row.
func (svc *Service) consumeToken(ctx context.Context, tx *store.Tx, kind, token string) (db.OneTimeToken, error) {
	macs, err := svc.tokenMACs(token)
	if err != nil {
		return db.OneTimeToken{}, err
	}
	for _, mac := range macs {
		row, err := tx.Q.GetOneTimeToken(ctx, mac)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return db.OneTimeToken{}, err
		}
		if row.Kind != kind {
			return db.OneTimeToken{}, ErrTokenInvalid
		}
		n, err := tx.Q.UseOneTimeToken(ctx, db.UseOneTimeTokenParams{Now: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, Hash: mac})
		if err != nil {
			return db.OneTimeToken{}, err
		}
		if n != 1 {
			return db.OneTimeToken{}, ErrTokenInvalid
		}
		return row, nil
	}
	return db.OneTimeToken{}, ErrTokenInvalid
}

// IssueSetupToken creates the one-time bootstrap token (CLI only). It fails once any administrator exists, so there
// is never a default password or a hidden administrator (HP-AUTH-001).
func (svc *Service) IssueSetupToken(ctx context.Context) (string, time.Time, error) {
	var token string
	var exp time.Time
	err := svc.s.W().TxNamed(ctx, "opauth.setup_token", func(tx *store.Tx) error {
		n, err := tx.Q.CountEnabledAdmins(ctx)
		if err != nil {
			return err
		}
		if n > 0 {
			return apperr.New(apperr.CodePrecondition, "an administrator already exists; use `hallpass admin recover` for lost access")
		}
		token, exp, err = svc.issueToken(ctx, tx, "setup", "", SetupTokenTTL, nil, audit.Actor{Type: audit.ActorCLI, ID: "bootstrap"})
		if err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorCLI, ID: "bootstrap"}, Action: "operator.setup_token.issued"})
		return err
	})
	return token, exp, err
}

// BootstrapInput creates the first administrator.
type BootstrapInput struct {
	Token       string `json:"token"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

// Bootstrap consumes the setup token and creates the first administrator, who must enroll TOTP at first login.
func (svc *Service) Bootstrap(ctx context.Context, in BootstrapInput) (*Operator, error) {
	email, err := NormalizeEmail(in.Email)
	if err != nil {
		return nil, err
	}
	phc, err := svc.hash(ctx, in.Password)
	if err != nil {
		return nil, err
	}
	var id string
	err = svc.s.W().TxNamed(ctx, "opauth.bootstrap", func(tx *store.Tx) error {
		if _, err := svc.consumeToken(ctx, tx, "setup", in.Token); err != nil {
			return err
		}
		n, err := tx.Q.CountEnabledAdmins(ctx)
		if err != nil {
			return err
		}
		if n > 0 {
			return ErrTokenInvalid
		}
		id, err = svc.insertLocalOperator(ctx, tx, email, in.DisplayName, phc, "bootstrap", []string{RoleAdministrator}, true, audit.Actor{Type: audit.ActorCLI, ID: "bootstrap"})
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.Get(ctx, id)
}

func (svc *Service) insertLocalOperator(ctx context.Context, tx *store.Tx, email, name, phc, via string, roles []string, mfa bool, actor audit.Actor) (string, error) {
	if name == "" {
		name = email
	}
	if len(name) > 128 {
		return "", apperr.New(apperr.CodeInvalid, "display name too long")
	}
	if _, err := tx.Q.GetOperatorByEmail(ctx, sql.NullString{String: email, Valid: true}); err == nil {
		return "", apperr.New(apperr.CodeAlreadyExists, "an operator with this email already exists")
	}
	id := newOperatorID()
	if err := tx.Q.InsertOperator(ctx, db.InsertOperatorParams{ID: id, Email: sql.NullString{String: email, Valid: true}, DisplayName: name, Enabled: 1,
		ProvisionedVia: via, MfaRequired: b2i(mfa), CreatedAt: tx.NowMicros(), CreatedBy: actorRef(actor), UpdatedAt: tx.NowMicros()}); err != nil {
		return "", err
	}
	for _, r := range roles {
		if err := tx.Q.InsertOperatorRole(ctx, db.InsertOperatorRoleParams{OperatorID: id, Role: r, Source: "manual"}); err != nil {
			return "", err
		}
	}
	if err := tx.Q.UpsertLocalCredential(ctx, db.UpsertLocalCredentialParams{OperatorID: id, PasswordPhc: phc,
		ParamsVersion: int64(CurrentParams.Version), ChangedAt: tx.NowMicros()}); err != nil {
		return "", err
	}
	_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "operator.created", Target: audit.Target{Type: "operator", ID: id},
		Details: map[string]any{"email": email, "roles": roles, "via": via, "has_password": true}})
	return id, err
}

// Invite creates a single-use invitation with preset roles (HP-AUTH-011).
func (svc *Service) Invite(ctx context.Context, actor audit.Actor, email string, roles []string) (string, time.Time, error) {
	e, err := NormalizeEmail(email)
	if err != nil {
		return "", time.Time{}, err
	}
	if err := validRoles(roles); err != nil {
		return "", time.Time{}, err
	}
	var token string
	var exp time.Time
	err = svc.s.W().TxNamed(ctx, "opauth.invite", func(tx *store.Tx) error {
		if _, err := tx.Q.GetOperatorByEmail(ctx, sql.NullString{String: e, Valid: true}); err == nil {
			return apperr.New(apperr.CodeAlreadyExists, "an operator with this email already exists")
		}
		var err error
		token, exp, err = svc.issueToken(ctx, tx, "invite", "", InviteTTL, map[string]any{"email": e, "roles": roles}, actor)
		if err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "operator.invited", Details: map[string]any{"email": e, "roles": roles}})
		return err
	})
	return token, exp, err
}

// AcceptInvitation creates the invited operator with a password.
func (svc *Service) AcceptInvitation(ctx context.Context, token, displayName, password string) (*Operator, error) {
	phc, err := svc.hash(ctx, password)
	if err != nil {
		return nil, err
	}
	var id string
	err = svc.s.W().TxNamed(ctx, "opauth.accept_invite", func(tx *store.Tx) error {
		row, err := svc.consumeToken(ctx, tx, "invite", token)
		if err != nil {
			return err
		}
		var data struct {
			Email string   `json:"email"`
			Roles []string `json:"roles"`
		}
		if err := json.Unmarshal([]byte(row.DataJson), &data); err != nil {
			return err
		}
		id, err = svc.insertLocalOperator(ctx, tx, data.Email, displayName, phc, "invite", data.Roles, false, audit.Actor{Type: audit.ActorOperator})
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.Get(ctx, id)
}

// IssueResetToken creates a single-use password reset token for an operator (administrator action, HP-AUTH-009).
// Without configured email delivery the administrator hands it over out of band.
func (svc *Service) IssueResetToken(ctx context.Context, actor audit.Actor, operatorID string) (string, time.Time, error) {
	var token string
	var exp time.Time
	err := svc.s.W().TxNamed(ctx, "opauth.reset_token", func(tx *store.Tx) error {
		if _, err := tx.Q.GetOperator(ctx, operatorID); errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeNotFound, "operator not found")
		} else if err != nil {
			return err
		}
		if _, err := tx.Q.RevokeOneTimeTokens(ctx, db.RevokeOneTimeTokensParams{UsedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, Kind: "reset",
			OperatorID: sql.NullString{String: operatorID, Valid: true}}); err != nil {
			return err
		}
		var err error
		token, exp, err = svc.issueToken(ctx, tx, "reset", operatorID, ResetTTL, nil, actor)
		if err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "operator.reset_token.issued", Target: audit.Target{Type: "operator", ID: operatorID}})
		return err
	})
	return token, exp, err
}

// ResetPassword sets a new password with a reset token and revokes every session of the operator (HP-AUTH-010).
func (svc *Service) ResetPassword(ctx context.Context, token, password string) error {
	phc, err := svc.hash(ctx, password)
	if err != nil {
		return err
	}
	return svc.s.W().TxNamed(ctx, "opauth.reset_password", func(tx *store.Tx) error {
		row, err := svc.consumeToken(ctx, tx, "reset", token)
		if err != nil {
			return err
		}
		opID := row.OperatorID.String
		if err := tx.Q.UpsertLocalCredential(ctx, db.UpsertLocalCredentialParams{OperatorID: opID, PasswordPhc: phc,
			ParamsVersion: int64(CurrentParams.Version), ChangedAt: tx.NowMicros()}); err != nil {
			return err
		}
		if _, err := tx.Q.RevokeOperatorSessions(ctx, db.RevokeOperatorSessionsParams{Now: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
			Reason: sql.NullString{String: "password_reset", Valid: true}, OperatorID: opID, ExceptHash: []byte{}}); err != nil {
			return err
		}
		if r, err := tx.Q.GetOperator(ctx, opID); err == nil {
			for _, k := range []string{throttleKeyAccount(r.Email.String), "acct-op:" + opID, mfaKey(opID)} {
				if err := tx.Q.DeleteThrottle(ctx, k); err != nil {
					return err
				}
			}
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorOperator, ID: opID}, Action: "operator.password.reset",
			Target: audit.Target{Type: "operator", ID: opID}})
		return err
	})
}

// IssueRecoveryLogin is the break-glass path (HP-AUTH-016): it must only be reachable from the local CLI, which
// requires the data-directory lock and the KEK. With newAdminEmail set it creates a new administrator instead.
func (svc *Service) IssueRecoveryLogin(ctx context.Context, operatorID, newAdminEmail string) (string, time.Time, error) {
	var token string
	var exp time.Time
	actor := audit.Actor{Type: audit.ActorCLI, ID: "breakglass"}
	err := svc.s.W().TxNamed(ctx, "opauth.breakglass", func(tx *store.Tx) error {
		target := operatorID
		if newAdminEmail != "" {
			email, err := NormalizeEmail(newAdminEmail)
			if err != nil {
				return err
			}
			pw, err := randomToken()
			if err != nil {
				return err
			}
			phc, err := HashPassword([]byte(pw), CurrentParams)
			if err != nil {
				return err
			}
			if target, err = svc.insertLocalOperator(ctx, tx, email, email, phc, "recovery", []string{RoleAdministrator}, true, actor); err != nil {
				return err
			}
		} else {
			row, err := tx.Q.GetOperator(ctx, operatorID)
			if errors.Is(err, sql.ErrNoRows) {
				return apperr.New(apperr.CodeNotFound, "operator not found")
			} else if err != nil {
				return err
			}
			if row.Enabled != 1 {
				if _, err := tx.Q.SetOperatorEnabled(ctx, db.SetOperatorEnabledParams{Enabled: 1, Now: tx.NowMicros(), ID: operatorID}); err != nil {
					return err
				}
			}
		}
		var err error
		token, exp, err = svc.issueToken(ctx, tx, "recovery_login", target, RecoveryLoginTTL, nil, actor)
		if err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "breakglass.used", Outcome: audit.OutcomeSuccess,
			Target: audit.Target{Type: "operator", ID: target}, Details: map[string]any{"new_admin": newAdminEmail != ""}})
		return err
	})
	return token, exp, err
}
