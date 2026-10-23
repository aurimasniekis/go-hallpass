package opauth

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Throttling (HP-AUTH-004): after throttleFree failures the delay doubles per failure up to throttleMax; counters
// decay after a day without failures. There is no permanent lockout.
const (
	throttleFree  = 3
	throttleMax   = 15 * time.Minute
	throttleDecay = 24 * time.Hour
)

// ErrThrottled is returned while a login key is throttled; the message does not reveal whether the account exists.
var ErrThrottled = apperr.New(apperr.CodeRateLimited, "too many attempts; try again later")

func ipKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "ip:" + ip
	}
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return "ip:" + p.String()
	}
	return "ip:" + a.String()
}

func (svc *Service) throttled(ctx context.Context, keys ...string) (bool, error) {
	now := svc.opts.Clock.Now().UnixMicro()
	for _, k := range keys {
		t, err := svc.s.R().GetThrottle(ctx, k)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return false, err
		}
		if t.NextAllowedAt > now {
			return true, nil
		}
	}
	return false, nil
}

func (svc *Service) recordFailure(ctx context.Context, tx *store.Tx, keys ...string) error {
	for _, k := range keys {
		failures := int64(1)
		if t, err := tx.Q.GetThrottle(ctx, k); err == nil {
			if tx.Now.Sub(time.UnixMicro(t.UpdatedAt)) < throttleDecay {
				failures = t.Failures + 1
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		next := tx.Now
		if failures > throttleFree {
			d := time.Second << min(failures-throttleFree-1, 20)
			next = tx.Now.Add(min(d, throttleMax))
		}
		if err := tx.Q.UpsertThrottle(ctx, db.UpsertThrottleParams{Key: k, Failures: failures, NextAllowedAt: next.UnixMicro(), UpdatedAt: tx.NowMicros()}); err != nil {
			return err
		}
	}
	return nil
}

// LoginInput is a local login attempt.
type LoginInput struct {
	Email    string
	Password string
	Meta     SessionMeta
}

// LoginResult is a successful first factor. When MFA is pending the session is Limited until VerifyMFA succeeds.
type LoginResult struct {
	Token      string
	Principal  *Principal
	MFAPending bool
	MustEnroll bool
}

// Login verifies a password. Unknown accounts, wrong passwords and disabled accounts all return
// ErrInvalidCredentials after the same work (a dummy hash for unknown accounts, HP-AUTH-005).
func (svc *Service) Login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	acctKey, ipK := throttleKeyAccount(in.Email), ipKey(in.Meta.IP)
	if t, err := svc.throttled(ctx, acctKey, ipK); err != nil {
		return nil, err
	} else if t {
		return nil, ErrThrottled
	}
	pw, perr := NormalizePassword(in.Password, 1)
	email, eerr := NormalizeEmail(in.Email)
	var opRow db.Operator
	var cred db.OperatorLocalCredential
	found := false
	if eerr == nil {
		if r, err := svc.s.R().GetOperatorByEmail(ctx, sql.NullString{String: email, Valid: true}); err == nil {
			if c, err := svc.s.R().GetLocalCredential(ctx, r.ID); err == nil {
				opRow, cred, found = r, c, true
			}
		}
	}
	phc := dummyHash()
	if found {
		phc = cred.PasswordPhc
	}
	if perr != nil {
		pw = []byte("invalid")
	}
	if err := svc.acquire(ctx); err != nil {
		return nil, err
	}
	ok, verr := VerifyPassword(pw, phc)
	svc.release()
	success := found && ok && verr == nil && perr == nil && opRow.Enabled == 1
	if !success {
		err := svc.s.W().TxNamed(ctx, "opauth.login_failed", func(tx *store.Tx) error {
			if err := svc.recordFailure(ctx, tx, acctKey, ipK); err != nil {
				return err
			}
			_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorOperator, ID: opRow.ID}, Action: "operator.login.failed",
				Outcome: audit.OutcomeFailure, SourceIP: in.Meta.IP, Details: map[string]any{"method": MethodPassword}})
			return err
		})
		if err != nil {
			return nil, err
		}
		return nil, ErrInvalidCredentials
	}
	var token string
	err := svc.s.W().TxNamed(ctx, "opauth.login", func(tx *store.Tx) error {
		if err := tx.Q.DeleteThrottle(ctx, acctKey); err != nil {
			return err
		}
		if cred.ParamsVersion != int64(CurrentParams.Version) {
			if fresh, err := HashPassword(pw, CurrentParams); err == nil {
				if err := tx.Q.UpsertLocalCredential(ctx, db.UpsertLocalCredentialParams{OperatorID: opRow.ID, PasswordPhc: fresh,
					ParamsVersion: int64(CurrentParams.Version), ChangedAt: cred.ChangedAt, MustChange: cred.MustChange}); err != nil {
					return err
				}
			}
		}
		var err error
		if token, err = svc.createSession(ctx, tx, opRow.ID, MethodPassword, nil, in.Meta); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorOperator, ID: opRow.ID}, Action: "operator.login",
			SourceIP: in.Meta.IP, Details: map[string]any{"method": MethodPassword}})
		return err
	})
	if err != nil {
		return nil, err
	}
	p, err := svc.Authenticate(ctx, token)
	if err != nil {
		return nil, err
	}
	return &LoginResult{Token: token, Principal: p, MFAPending: p.Limited && !p.NeedsEnroll, MustEnroll: p.NeedsEnroll}, nil
}

// VerifyMFA completes the second factor with a TOTP code or a recovery code, then rotates the session.
func (svc *Service) VerifyMFA(ctx context.Context, p *Principal, code string, meta SessionMeta) (string, error) {
	code = strings.TrimSpace(code)
	opID := p.Operator.ID
	if t, err := svc.throttled(ctx, "mfa:"+opID); err != nil {
		return "", err
	} else if t {
		return "", ErrThrottled
	}
	ok, method, err := svc.checkSecondFactor(ctx, opID, code)
	if err != nil {
		return "", err
	}
	if !ok {
		_ = svc.s.W().TxNamed(ctx, "opauth.mfa_failed", func(tx *store.Tx) error {
			if err := svc.recordFailure(ctx, tx, "mfa:"+opID); err != nil {
				return err
			}
			_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorOperator, ID: opID}, Action: "operator.mfa.failed",
				Outcome: audit.OutcomeFailure, SourceIP: meta.IP})
			return err
		})
		return "", apperr.New(apperr.CodeUnauthorized, "invalid code")
	}
	var token string
	err = svc.s.W().TxNamed(ctx, "opauth.mfa_ok", func(tx *store.Tx) error {
		if err := tx.Q.DeleteThrottle(ctx, "mfa:"+opID); err != nil {
			return err
		}
		if _, err := tx.Q.RevokeWebSession(ctx, db.RevokeWebSessionParams{RevokedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
			RevokeReason: sql.NullString{String: "rotated", Valid: true}, IDHash: p.tokenHash}); err != nil {
			return err
		}
		now := tx.Now
		var err error
		if token, err = svc.createSession(ctx, tx, opID, MethodPassword, &now, meta); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorOperator, ID: opID}, Action: "operator.mfa.verified",
			SourceIP: meta.IP, Details: map[string]any{"factor": method}})
		return err
	})
	return token, err
}

// checkSecondFactor verifies a TOTP code (no step reuse) or consumes a recovery code.
func (svc *Service) checkSecondFactor(ctx context.Context, opID, code string) (bool, string, error) {
	t, err := svc.s.R().GetTOTP(ctx, opID)
	if err == nil && t.ConfirmedAt.Valid && len(code) == totpDigits {
		secret, err := svc.kr.Open(keyring.PurposeField, totpAAD(opID), t.SecretEnc)
		if err != nil {
			return false, "", err
		}
		step, ok := VerifyTOTP(secret, code, svc.opts.Clock.Now(), t.LastStep)
		if !ok {
			return false, "", nil
		}
		var advanced int64
		err = svc.s.W().TxNamed(ctx, "opauth.totp_step", func(tx *store.Tx) error {
			var err error
			advanced, err = tx.Q.AdvanceTOTPStep(ctx, db.AdvanceTOTPStepParams{Step: step, OperatorID: opID})
			return err
		})
		return err == nil && advanced == 1, "totp", err
	}
	if len(code) >= 10 {
		mac, err := svc.recoveryMAC(opID, code)
		if err != nil {
			return false, "", err
		}
		var used int64
		err = svc.s.W().TxNamed(ctx, "opauth.recovery_code", func(tx *store.Tx) error {
			var err error
			used, err = tx.Q.UseRecoveryCode(ctx, db.UseRecoveryCodeParams{UsedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, OperatorID: opID, CodeHash: mac})
			return err
		})
		return err == nil && used == 1, "recovery_code", err
	}
	return false, "", nil
}

// Reauth refreshes the authentication time with the password (and second factor when enrolled), then rotates.
func (svc *Service) Reauth(ctx context.Context, p *Principal, password, code string, meta SessionMeta) (string, error) {
	if p.Method != MethodPassword {
		return "", apperr.New(apperr.CodePrecondition, "re-authenticate with your identity provider")
	}
	cred, err := svc.s.R().GetLocalCredential(ctx, p.Operator.ID)
	if err != nil {
		return "", ErrInvalidCredentials
	}
	pw, err := NormalizePassword(password, 1)
	if err != nil {
		return "", ErrInvalidCredentials
	}
	if err := svc.acquire(ctx); err != nil {
		return "", err
	}
	ok, verr := VerifyPassword(pw, cred.PasswordPhc)
	svc.release()
	if !ok || verr != nil {
		return "", ErrInvalidCredentials
	}
	var mfaAt *time.Time
	if p.Operator.MFAEnrolled {
		ok, _, err := svc.checkSecondFactor(ctx, p.Operator.ID, strings.TrimSpace(code))
		if err != nil {
			return "", err
		}
		if !ok {
			return "", ErrMFARequired
		}
		now := svc.opts.Clock.Now()
		mfaAt = &now
	}
	var token string
	err = svc.s.W().TxNamed(ctx, "opauth.reauth", func(tx *store.Tx) error {
		if _, err := tx.Q.RevokeWebSession(ctx, db.RevokeWebSessionParams{RevokedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
			RevokeReason: sql.NullString{String: "rotated", Valid: true}, IDHash: p.tokenHash}); err != nil {
			return err
		}
		var err error
		if token, err = svc.createSession(ctx, tx, p.Operator.ID, MethodPassword, mfaAt, meta); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorOperator, ID: p.Operator.ID}, Action: "operator.reauthenticated", SourceIP: meta.IP})
		return err
	})
	return token, err
}

// ChangePassword changes the operator's own password (current password required) and revokes their other sessions.
func (svc *Service) ChangePassword(ctx context.Context, p *Principal, current, next string) error {
	cred, err := svc.s.R().GetLocalCredential(ctx, p.Operator.ID)
	if err != nil {
		return ErrInvalidCredentials
	}
	cur, err := NormalizePassword(current, 1)
	if err != nil {
		return ErrInvalidCredentials
	}
	if err := svc.acquire(ctx); err != nil {
		return err
	}
	ok, verr := VerifyPassword(cur, cred.PasswordPhc)
	svc.release()
	if !ok || verr != nil {
		return ErrInvalidCredentials
	}
	phc, err := svc.hash(ctx, next)
	if err != nil {
		return err
	}
	return svc.s.W().TxNamed(ctx, "opauth.change_password", func(tx *store.Tx) error {
		if err := tx.Q.UpsertLocalCredential(ctx, db.UpsertLocalCredentialParams{OperatorID: p.Operator.ID, PasswordPhc: phc,
			ParamsVersion: int64(CurrentParams.Version), ChangedAt: tx.NowMicros()}); err != nil {
			return err
		}
		if _, err := tx.Q.RevokeOperatorSessions(ctx, db.RevokeOperatorSessionsParams{Now: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
			Reason: sql.NullString{String: "password_changed", Valid: true}, OperatorID: p.Operator.ID, ExceptHash: p.tokenHash}); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorOperator, ID: p.Operator.ID}, Action: "operator.password.changed",
			Target: audit.Target{Type: "operator", ID: p.Operator.ID}})
		return err
	})
}

// RecoveryLogin exchanges a break-glass token (issued by the local CLI) for a session (HP-AUTH-016).
func (svc *Service) RecoveryLogin(ctx context.Context, token string, meta SessionMeta) (string, error) {
	var session string
	err := svc.s.W().TxNamed(ctx, "opauth.recovery_login", func(tx *store.Tx) error {
		row, err := svc.consumeToken(ctx, tx, "recovery_login", token)
		if err != nil {
			return err
		}
		now := tx.Now
		if session, err = svc.createSession(ctx, tx, row.OperatorID.String, MethodBreakGlass, &now, meta); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorOperator, ID: row.OperatorID.String}, Action: "breakglass.login",
			SourceIP: meta.IP})
		return err
	})
	return session, err
}

// ClearThrottle removes login throttling for an operator (administrator action).
func (svc *Service) ClearThrottle(ctx context.Context, actor audit.Actor, operatorID string) error {
	op, err := svc.Get(ctx, operatorID)
	if err != nil {
		return err
	}
	return svc.s.W().TxNamed(ctx, "opauth.clear_throttle", func(tx *store.Tx) error {
		for _, k := range []string{throttleKeyAccount(op.Email), "mfa:" + operatorID} {
			if err := tx.Q.DeleteThrottle(ctx, k); err != nil {
				return err
			}
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "operator.throttle.cleared", Target: audit.Target{Type: "operator", ID: operatorID}})
		return err
	})
}
