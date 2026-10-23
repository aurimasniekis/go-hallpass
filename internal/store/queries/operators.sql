-- name: CountOperators :one
SELECT count(*) FROM operators;

-- name: CountEnabledAdmins :one
SELECT count(DISTINCT o.id) FROM operators o JOIN operator_roles r ON r.operator_id = o.id
WHERE o.enabled = 1 AND r.role = 'administrator';

-- name: InsertOperator :exec
INSERT INTO operators (id, email, display_name, enabled, provisioned_via, mfa_required, version, created_at, created_by, updated_at)
VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?);

-- name: GetOperator :one
SELECT * FROM operators WHERE id = ?;

-- name: GetOperatorByEmail :one
SELECT * FROM operators WHERE email = ?;

-- name: ListOperators :many
SELECT * FROM operators ORDER BY display_name, id;

-- name: UpdateOperatorProfile :execrows
UPDATE operators SET email = ?, display_name = ?, mfa_required = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ?;

-- name: SetOperatorEnabled :execrows
UPDATE operators SET enabled = sqlc.arg(enabled), disabled_at = CASE WHEN sqlc.arg(enabled) = 1 THEN NULL ELSE sqlc.arg(now) END,
  version = version + 1, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND enabled != sqlc.arg(enabled);

-- name: TouchOperatorLogin :exec
UPDATE operators SET last_login_at = ? WHERE id = ?;

-- name: GetLocalCredential :one
SELECT * FROM operator_local_credentials WHERE operator_id = ?;

-- name: UpsertLocalCredential :exec
INSERT INTO operator_local_credentials (operator_id, password_phc, params_version, changed_at, must_change) VALUES (?, ?, ?, ?, ?)
ON CONFLICT (operator_id) DO UPDATE SET password_phc = excluded.password_phc, params_version = excluded.params_version,
  changed_at = excluded.changed_at, must_change = excluded.must_change;

-- name: ListOperatorRoles :many
SELECT role, source, source_ref FROM operator_roles WHERE operator_id = ? ORDER BY role, source;

-- name: DeleteOperatorRolesBySource :exec
DELETE FROM operator_roles WHERE operator_id = ? AND source = ?;

-- name: InsertOperatorRole :exec
INSERT INTO operator_roles (operator_id, role, source, source_ref) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING;

-- name: ListOperatorGroupNames :many
SELECT DISTINCT g.name FROM operator_group_members m JOIN groups g ON g.id = m.group_id WHERE m.operator_id = ? ORDER BY g.name;

-- name: DeleteOperatorGroupsBySource :exec
DELETE FROM operator_group_members WHERE operator_id = ? AND source = ?;

-- name: InsertOperatorGroup :exec
INSERT INTO operator_group_members (group_id, operator_id, source) VALUES (?, ?, ?) ON CONFLICT DO NOTHING;

-- name: GetTOTP :one
SELECT * FROM mfa_totp WHERE operator_id = ?;

-- name: UpsertTOTP :exec
INSERT INTO mfa_totp (operator_id, secret_enc, confirmed_at, last_step, created_at) VALUES (?, ?, NULL, 0, ?)
ON CONFLICT (operator_id) DO UPDATE SET secret_enc = excluded.secret_enc, confirmed_at = NULL, last_step = 0, created_at = excluded.created_at;

-- name: ConfirmTOTP :execrows
UPDATE mfa_totp SET confirmed_at = ?, last_step = ? WHERE operator_id = ? AND confirmed_at IS NULL;

-- name: AdvanceTOTPStep :execrows
UPDATE mfa_totp SET last_step = sqlc.arg(step) WHERE operator_id = sqlc.arg(operator_id) AND last_step < sqlc.arg(step);

-- name: DeleteTOTP :execrows
DELETE FROM mfa_totp WHERE operator_id = ?;

-- name: DeleteRecoveryCodes :exec
DELETE FROM recovery_codes WHERE operator_id = ?;

-- name: InsertRecoveryCode :exec
INSERT INTO recovery_codes (operator_id, code_hash, created_at) VALUES (?, ?, ?);

-- name: UseRecoveryCode :execrows
UPDATE recovery_codes SET used_at = ? WHERE operator_id = ? AND code_hash = ? AND used_at IS NULL;

-- name: CountUnusedRecoveryCodes :one
SELECT count(*) FROM recovery_codes WHERE operator_id = ? AND used_at IS NULL;

-- name: InsertOneTimeToken :exec
INSERT INTO one_time_tokens (hash, kind, operator_id, data_json, expires_at, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetOneTimeToken :one
SELECT * FROM one_time_tokens WHERE hash = ?;

-- name: UseOneTimeToken :execrows
UPDATE one_time_tokens SET used_at = sqlc.arg(now) WHERE hash = sqlc.arg(hash) AND used_at IS NULL AND expires_at > sqlc.arg(now);

-- name: RevokeOneTimeTokens :execrows
UPDATE one_time_tokens SET used_at = ? WHERE kind = ? AND operator_id = ? AND used_at IS NULL;

-- name: ListOneTimeTokens :many
SELECT * FROM one_time_tokens WHERE kind = ? AND used_at IS NULL AND expires_at > ? ORDER BY created_at DESC;

-- name: PurgeOneTimeTokens :execrows
DELETE FROM one_time_tokens WHERE expires_at < ?;

-- name: InsertWebSession :exec
INSERT INTO web_sessions (id_hash, operator_id, csrf_secret, auth_method, mfa_at, auth_at, created_at, last_seen_at,
  absolute_expires_at, ip, user_agent, display_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetWebSession :one
SELECT * FROM web_sessions WHERE id_hash = ?;

-- name: TouchWebSession :exec
UPDATE web_sessions SET last_seen_at = ? WHERE id_hash = ? AND revoked_at IS NULL;

-- name: UpdateWebSessionAuth :exec
UPDATE web_sessions SET auth_at = ?, mfa_at = coalesce(?, mfa_at) WHERE id_hash = ?;

-- name: RevokeWebSession :execrows
UPDATE web_sessions SET revoked_at = ?, revoke_reason = ? WHERE id_hash = ? AND revoked_at IS NULL;

-- name: RevokeWebSessionByDisplayID :execrows
UPDATE web_sessions SET revoked_at = ?, revoke_reason = ? WHERE display_id = ? AND operator_id = ? AND revoked_at IS NULL;

-- name: RevokeOperatorSessions :execrows
UPDATE web_sessions SET revoked_at = sqlc.arg(now), revoke_reason = sqlc.arg(reason)
WHERE operator_id = sqlc.arg(operator_id) AND revoked_at IS NULL AND id_hash != sqlc.arg(except_hash);

-- name: ListOperatorSessions :many
SELECT * FROM web_sessions WHERE operator_id = ? AND revoked_at IS NULL AND absolute_expires_at > ? ORDER BY last_seen_at DESC;

-- name: PurgeWebSessions :execrows
DELETE FROM web_sessions WHERE absolute_expires_at < ?;

-- name: GetThrottle :one
SELECT * FROM login_throttle WHERE key = ?;

-- name: UpsertThrottle :exec
INSERT INTO login_throttle (key, failures, next_allowed_at, updated_at) VALUES (?, ?, ?, ?)
ON CONFLICT (key) DO UPDATE SET failures = excluded.failures, next_allowed_at = excluded.next_allowed_at, updated_at = excluded.updated_at;

-- name: DeleteThrottle :exec
DELETE FROM login_throttle WHERE key = ?;
