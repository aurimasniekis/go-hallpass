package opauth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"strings"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// RecoveryCodeCount is how many single-use recovery codes are issued (HP-AUTH-007).
const RecoveryCodeCount = 10

func totpAAD(opID string) []byte { return keyring.FieldAAD("mfa_totp", "secret_enc", opID) }

func (svc *Service) recoveryMAC(opID, code string) ([]byte, error) {
	norm := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	return svc.kr.MAC(keyring.PurposeToken, []byte("recovery|"+opID+"|"+norm))
}

// TOTPEnrollment is returned when enrollment starts; the secret is shown once for the authenticator app.
type TOTPEnrollment struct {
	Secret string `json:"secret"`
	URI    string `json:"otpauth_uri"`
}

// BeginTOTP starts (or restarts) TOTP enrollment. Replacing an existing confirmed factor requires recent authentication.
func (svc *Service) BeginTOTP(ctx context.Context, p *Principal) (*TOTPEnrollment, error) {
	if p.Operator.MFAEnrolled {
		if err := svc.RequireRecentAuth(p, true); err != nil {
			return nil, err
		}
	}
	secret, err := NewTOTPSecret()
	if err != nil {
		return nil, err
	}
	sealed, err := svc.kr.Seal(keyring.PurposeField, totpAAD(p.Operator.ID), secret)
	if err != nil {
		return nil, err
	}
	err = svc.s.W().TxNamed(ctx, "opauth.totp_begin", func(tx *store.Tx) error {
		return tx.Q.UpsertTOTP(ctx, db.UpsertTOTPParams{OperatorID: p.Operator.ID, SecretEnc: sealed, CreatedAt: tx.NowMicros()})
	})
	if err != nil {
		return nil, err
	}
	account := p.Operator.Email
	if account == "" {
		account = p.Operator.DisplayName
	}
	return &TOTPEnrollment{Secret: EncodeTOTPSecret(secret), URI: TOTPURI(secret, svc.opts.Issuer, account)}, nil
}

// ConfirmTOTP completes enrollment with a valid code, issues fresh recovery codes (returned once) and revokes the
// operator's other sessions (MFA change, HP-AUTH-010).
func (svc *Service) ConfirmTOTP(ctx context.Context, p *Principal, code string) ([]string, error) {
	t, err := svc.s.R().GetTOTP(ctx, p.Operator.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodePrecondition, "start TOTP enrollment first")
	} else if err != nil {
		return nil, err
	}
	secret, err := svc.kr.Open(keyring.PurposeField, totpAAD(p.Operator.ID), t.SecretEnc)
	if err != nil {
		return nil, err
	}
	step, ok := VerifyTOTP(secret, code, svc.opts.Clock.Now(), 0)
	if !ok {
		return nil, apperr.New(apperr.CodeInvalid, "invalid code; check your authenticator's clock")
	}
	codes, err := svc.newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	err = svc.s.W().TxNamed(ctx, "opauth.totp_confirm", func(tx *store.Tx) error {
		if _, err := tx.Q.ConfirmTOTP(ctx, db.ConfirmTOTPParams{ConfirmedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, LastStep: step, OperatorID: p.Operator.ID}); err != nil {
			return err
		}
		if err := svc.storeRecoveryCodes(ctx, tx, p.Operator.ID, codes); err != nil {
			return err
		}
		if _, err := tx.Q.RevokeOperatorSessions(ctx, db.RevokeOperatorSessionsParams{Now: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
			Reason: sql.NullString{String: "mfa_changed", Valid: true}, OperatorID: p.Operator.ID, ExceptHash: p.tokenHash}); err != nil {
			return err
		}
		// The enrolling session has now completed MFA.
		if err := tx.Q.UpdateWebSessionAuth(ctx, db.UpdateWebSessionAuthParams{AuthAt: tx.NowMicros(), MfaAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
			IDHash: p.tokenHash}); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorOperator, ID: p.Operator.ID}, Action: "operator.mfa.enrolled",
			Target: audit.Target{Type: "operator", ID: p.Operator.ID}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return codes, nil
}

// DisableTOTP removes the second factor. It requires recent authentication with MFA and is refused when policy
// requires MFA for the operator.
func (svc *Service) DisableTOTP(ctx context.Context, p *Principal) error {
	if err := svc.RequireRecentAuth(p, true); err != nil {
		return err
	}
	if p.Operator.MFARequired {
		return apperr.New(apperr.CodeForbidden, "MFA is mandatory for this account")
	}
	return svc.s.W().TxNamed(ctx, "opauth.totp_disable", func(tx *store.Tx) error {
		if _, err := tx.Q.DeleteTOTP(ctx, p.Operator.ID); err != nil {
			return err
		}
		if err := tx.Q.DeleteRecoveryCodes(ctx, p.Operator.ID); err != nil {
			return err
		}
		if _, err := tx.Q.RevokeOperatorSessions(ctx, db.RevokeOperatorSessionsParams{Now: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
			Reason: sql.NullString{String: "mfa_changed", Valid: true}, OperatorID: p.Operator.ID, ExceptHash: p.tokenHash}); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorOperator, ID: p.Operator.ID}, Action: "operator.mfa.disabled",
			Target: audit.Target{Type: "operator", ID: p.Operator.ID}})
		return err
	})
}

// RegenerateRecoveryCodes replaces all recovery codes (recent authentication required).
func (svc *Service) RegenerateRecoveryCodes(ctx context.Context, p *Principal) ([]string, error) {
	if err := svc.RequireRecentAuth(p, true); err != nil {
		return nil, err
	}
	if !p.Operator.MFAEnrolled {
		return nil, apperr.New(apperr.CodePrecondition, "enroll TOTP first")
	}
	codes, err := svc.newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	err = svc.s.W().TxNamed(ctx, "opauth.recovery_regen", func(tx *store.Tx) error {
		if err := svc.storeRecoveryCodes(ctx, tx, p.Operator.ID, codes); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorOperator, ID: p.Operator.ID}, Action: "operator.recovery_codes.regenerated"})
		return err
	})
	return codes, err
}

const recoveryAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"

func (svc *Service) newRecoveryCodes() ([]string, error) {
	codes := make([]string, RecoveryCodeCount)
	for i := range codes {
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		var sb strings.Builder
		for j, c := range b {
			if j == 6 {
				sb.WriteByte('-')
			}
			sb.WriteByte(recoveryAlphabet[int(c)%len(recoveryAlphabet)])
		}
		codes[i] = sb.String()
	}
	return codes, nil
}

func (svc *Service) storeRecoveryCodes(ctx context.Context, tx *store.Tx, opID string, codes []string) error {
	if err := tx.Q.DeleteRecoveryCodes(ctx, opID); err != nil {
		return err
	}
	for _, c := range codes {
		mac, err := svc.recoveryMAC(opID, c)
		if err != nil {
			return err
		}
		if err := tx.Q.InsertRecoveryCode(ctx, db.InsertRecoveryCodeParams{OperatorID: opID, CodeHash: mac, CreatedAt: tx.NowMicros()}); err != nil {
			return err
		}
	}
	return nil
}
