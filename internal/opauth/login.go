package opauth

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
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
	res, err := svc.login(ctx, in)
	svc.observeLogin(metrics.LoginPassword, err)
	return res, err
}

// observeLogin counts a login attempt; a disabled login method is not an attempt.
func (svc *Service) observeLogin(method metrics.LoginMethod, err error) {
	switch {
	case err == nil:
		svc.opts.Metrics.OperatorLogin(method, metrics.LoginSuccess)
	case errors.Is(err, ErrLocalLoginDisabled):
	case errors.Is(err, ErrThrottled):
		svc.opts.Metrics.OperatorLogin(method, metrics.LoginThrottled)
	case apperr.CodeOf(err) == apperr.CodeUnauthorized, errors.Is(err, apperr.ErrNotFound):
		svc.opts.Metrics.OperatorLogin(method, metrics.LoginFailure)
	default:
		svc.opts.Metrics.OperatorLogin(method, metrics.LoginError)
	}
}

func (svc *Service) login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	if off, err := svc.LocalLoginDisabled(ctx); err != nil {
		return nil, err
	} else if off {
		return nil, ErrLocalLoginDisabled
	}
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

// ErrNoMFAPending refuses VerifyMFA on a session that is not waiting for its second factor: it must not refresh
// the authentication time of full or SSO sessions, nor turn them into password sessions (SR-03).
var ErrNoMFAPending = apperr.New(apperr.CodePrecondition, "this session is not waiting for a second factor")

// VerifyMFA completes the second factor of a Limited password session with a TOTP code or a recovery code, then
// rotates the session.
func (svc *Service) VerifyMFA(ctx context.Context, p *Principal, code string, meta SessionMeta) (string, error) {
	if !p.Limited || p.NeedsEnroll || p.Method != MethodPassword {
		return "", ErrNoMFAPending
	}
	opID := p.Operator.ID
	ok, method, err := svc.verifySecondFactor(ctx, opID, code, meta.IP, "login")
	if err != nil {
		return "", err
	}
	if !ok {
		return "", apperr.New(apperr.CodeUnauthorized, "invalid code")
	}
	var token string
	err = svc.s.W().TxNamed(ctx, "opauth.mfa_ok", func(tx *store.Tx) error {
		if err := tx.Q.DeleteThrottle(ctx, mfaKey(opID)); err != nil {
			return err
		}
		now := tx.Now
		var err error
		if token, err = svc.rotateTx(ctx, tx, p, now, &now, meta); err != nil {
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
		// Codes issued before a token-key rotation were MACed with an older (still decrypt-only) version (SR-36).
		macs, err := svc.recoveryMACs(opID, code)
		if err != nil {
			return false, "", err
		}
		var used int64
		err = svc.s.W().TxNamed(ctx, "opauth.recovery_code", func(tx *store.Tx) error {
			for _, mac := range macs {
				n, err := tx.Q.UseRecoveryCode(ctx, db.UseRecoveryCodeParams{UsedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, OperatorID: opID, CodeHash: mac})
				if err != nil || n == 1 {
					used = n
					return err
				}
			}
			return nil
		})
		return err == nil && used == 1, "recovery_code", err
	}
	return false, "", nil
}

// accountKey is the login throttle key of an operator's local password (shared by login, reauthentication and
// password change, HP-AUTH-004).
func accountKey(op *Operator) string {
	if op.Email == "" {
		return "acct-op:" + op.ID
	}
	return throttleKeyAccount(op.Email)
}

// checkCurrentPassword verifies the signed-in operator's own password under the account throttle; a wrong password
// counts as a failure and is audited (SR-05).
func (svc *Service) checkCurrentPassword(ctx context.Context, p *Principal, password, ip, purpose string) error {
	key := accountKey(p.Operator)
	if t, err := svc.throttled(ctx, key); err != nil {
		return err
	} else if t {
		return ErrThrottled
	}
	cred, err := svc.s.R().GetLocalCredential(ctx, p.Operator.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidCredentials
	} else if err != nil {
		return err
	}
	pw, perr := NormalizePassword(password, 1)
	if perr != nil {
		pw = []byte("invalid")
	}
	if err := svc.acquire(ctx); err != nil {
		return err
	}
	ok, verr := VerifyPassword(pw, cred.PasswordPhc)
	svc.release()
	if ok && verr == nil && perr == nil {
		return nil
	}
	err = svc.s.W().TxNamed(ctx, "opauth.password_check_failed", func(tx *store.Tx) error {
		if err := svc.recordFailure(ctx, tx, key); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorOperator, ID: p.Operator.ID}, Action: "operator.password.failed",
			Outcome: audit.OutcomeFailure, SourceIP: ip, Details: map[string]any{"purpose": purpose}})
		return err
	})
	if err != nil {
		return err
	}
	return ErrInvalidCredentials
}

// Reauth refreshes the authentication time with the password (and second factor when enrolled), then rotates.
// Break-glass sessions may re-authenticate the same way when the account has a password. Wrong passwords and codes
// are throttled and audited like logins (HP-AUTH-004).
func (svc *Service) Reauth(ctx context.Context, p *Principal, password, code string, meta SessionMeta) (string, error) {
	if p.Method != MethodPassword && p.Method != MethodBreakGlass {
		return "", apperr.New(apperr.CodePrecondition, "re-authenticate with your identity provider")
	}
	if err := svc.checkCurrentPassword(ctx, p, password, meta.IP, "reauth"); err != nil {
		return "", err
	}
	var mfaAt *time.Time
	if p.Operator.MFAEnrolled {
		ok, _, err := svc.verifySecondFactor(ctx, p.Operator.ID, code, meta.IP, "reauth")
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
	err := svc.s.W().TxNamed(ctx, "opauth.reauth", func(tx *store.Tx) error {
		for _, k := range []string{accountKey(p.Operator), mfaKey(p.Operator.ID)} {
			if err := tx.Q.DeleteThrottle(ctx, k); err != nil {
				return err
			}
		}
		var err error
		if token, err = svc.rotateTx(ctx, tx, p, tx.Now, mfaAt, meta); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorOperator, ID: p.Operator.ID}, Action: "operator.reauthenticated", SourceIP: meta.IP})
		return err
	})
	return token, err
}

// ChangePassword changes the operator's own password (current password required, throttled like logins) and revokes
// their other sessions.
func (svc *Service) ChangePassword(ctx context.Context, p *Principal, current, next string) error {
	if err := svc.checkCurrentPassword(ctx, p, current, "", "change"); err != nil {
		return err
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
		if err := tx.Q.DeleteThrottle(ctx, accountKey(p.Operator)); err != nil {
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

// RecoveryResult is a redeemed break-glass recovery login (HP-AUTH-016).
type RecoveryResult struct {
	// Token is the break-glass session (cookie value).
	Token     string
	Principal *Principal
	// ResetToken is a single-use password reset token (ResetTTL), issued when the operator has a local password, so
	// that a recovered administrator (or one created with --new-admin, whose random password is never shown) sets a
	// password they know. Using it ends every session of the operator, including the break-glass one.
	ResetToken     string
	ResetExpiresAt time.Time
	// MFAReset reports that the operator's TOTP factor and recovery codes were removed (lost-factor recovery).
	MFAReset bool
}

// RecoveryLogin exchanges a break-glass token (issued by the local CLI) for a session (HP-AUTH-016). The token is
// single use and expires after RecoveryLoginTTL. Recovery assumes the account's credentials are lost or compromised:
// in the same transaction the operator's other sessions are revoked, the TOTP factor and recovery codes are removed
// and throttles cleared. The break-glass session is Limited until a new factor is enrolled when policy requires MFA,
// and a password reset token is returned for accounts with a local password. Failed redemptions are throttled per
// source and audited.
func (svc *Service) RecoveryLogin(ctx context.Context, token string, meta SessionMeta) (*RecoveryResult, error) {
	res, err := svc.recoveryLogin(ctx, token, meta)
	svc.observeLogin(metrics.LoginRecovery, err)
	return res, err
}

func (svc *Service) recoveryLogin(ctx context.Context, token string, meta SessionMeta) (*RecoveryResult, error) {
	ipK := ipKey(meta.IP)
	if t, err := svc.throttled(ctx, ipK); err != nil {
		return nil, err
	} else if t {
		return nil, ErrThrottled
	}
	res := &RecoveryResult{}
	actor := audit.Actor{Type: audit.ActorCLI, ID: "breakglass"}
	err := svc.s.W().TxNamed(ctx, "opauth.recovery_login", func(tx *store.Tx) error {
		*res = RecoveryResult{}
		if token == "" || len(token) > 128 {
			return ErrTokenInvalid
		}
		row, err := svc.consumeToken(ctx, tx, "recovery_login", token)
		if err != nil {
			return err
		}
		opID := row.OperatorID.String
		op, err := tx.Q.GetOperator(ctx, opID)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && op.Enabled != 1) {
			return ErrTokenInvalid
		} else if err != nil {
			return err
		}
		if _, err := tx.Q.RevokeOperatorSessions(ctx, db.RevokeOperatorSessionsParams{Now: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
			Reason: sql.NullString{String: "breakglass", Valid: true}, OperatorID: opID, ExceptHash: []byte{}}); err != nil {
			return err
		}
		n, err := tx.Q.DeleteTOTP(ctx, opID)
		if err != nil {
			return err
		}
		res.MFAReset = n > 0
		if err := tx.Q.DeleteTOTPPending(ctx, opID); err != nil {
			return err
		}
		if err := tx.Q.DeleteRecoveryCodes(ctx, opID); err != nil {
			return err
		}
		for _, k := range []string{throttleKeyAccount(op.Email.String), "acct-op:" + opID, mfaKey(opID)} {
			if err := tx.Q.DeleteThrottle(ctx, k); err != nil {
				return err
			}
		}
		if _, err := tx.Q.GetLocalCredential(ctx, opID); err == nil {
			if _, err := tx.Q.RevokeOneTimeTokens(ctx, db.RevokeOneTimeTokensParams{UsedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, Kind: "reset",
				OperatorID: sql.NullString{String: opID, Valid: true}}); err != nil {
				return err
			}
			if res.ResetToken, res.ResetExpiresAt, err = svc.issueToken(ctx, tx, "reset", opID, ResetTTL, nil, actor); err != nil {
				return err
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		now := tx.Now
		if res.Token, err = svc.createSession(ctx, tx, opID, MethodBreakGlass, &now, meta); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorOperator, ID: opID}, Action: "breakglass.login",
			SourceIP: meta.IP, Target: audit.Target{Type: "operator", ID: opID},
			Details: map[string]any{"mfa_reset": res.MFAReset, "password_reset_issued": res.ResetToken != ""}})
		return err
	})
	if errors.Is(err, ErrTokenInvalid) {
		ferr := svc.s.W().TxNamed(ctx, "opauth.recovery_login_failed", func(tx *store.Tx) error {
			if err := svc.recordFailure(ctx, tx, ipK); err != nil {
				return err
			}
			_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorSystem, ID: "api"}, Action: "breakglass.login.failed",
				Outcome: audit.OutcomeFailure, SourceIP: meta.IP})
			return err
		})
		if ferr != nil {
			return nil, ferr
		}
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	if res.Principal, err = svc.Authenticate(ctx, res.Token); err != nil {
		return nil, err
	}
	return res, nil
}

// ClearThrottle removes login throttling for an operator (administrator action).
func (svc *Service) ClearThrottle(ctx context.Context, actor audit.Actor, operatorID string) error {
	op, err := svc.Get(ctx, operatorID)
	if err != nil {
		return err
	}
	return svc.s.W().TxNamed(ctx, "opauth.clear_throttle", func(tx *store.Tx) error {
		for _, k := range []string{throttleKeyAccount(op.Email), "acct-op:" + operatorID, mfaKey(operatorID)} {
			if err := tx.Q.DeleteThrottle(ctx, k); err != nil {
				return err
			}
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "operator.throttle.cleared", Target: audit.Target{Type: "operator", ID: operatorID}})
		return err
	})
}
