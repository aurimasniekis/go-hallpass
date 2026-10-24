-- 0018_auth_totp_pending: a TOTP enrollment in progress is kept apart from the confirmed factor, so starting
-- (and abandoning) a re-enrollment never removes the working second factor (security review SR-04). The pending
-- secret is sealed exactly like mfa_totp.secret_enc (same AAD) and moves there only on a successful confirmation.
-- Pending rows expire after a few minutes, like OIDC PKCE verifiers, and are not resealed on key rotation.

-- +goose Up
CREATE TABLE mfa_totp_pending (
  operator_id TEXT PRIMARY KEY REFERENCES operators (id) ON DELETE CASCADE,
  secret_enc  BLOB NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

-- Unconfirmed rows were enrollments in progress under the old scheme; they never counted as a factor.
DELETE FROM mfa_totp WHERE confirmed_at IS NULL;

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
