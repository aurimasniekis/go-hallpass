-- name: InsertLoginCredential :exec
INSERT INTO login_credentials (id, role_id, kind, algorithm, public_key, fingerprint_sha256, private_enc, state, created_at,
  created_by, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?);

-- name: GetLoginCredential :one
SELECT * FROM login_credentials WHERE id = ?;

-- name: ListLoginCredentials :many
SELECT * FROM login_credentials WHERE role_id = ? ORDER BY created_at;

-- name: ActiveLoginCredential :one
SELECT * FROM login_credentials WHERE role_id = ? AND state = 'active';

-- name: RecordProbe :exec
UPDATE login_credentials SET probe_ok_at = ?, probe_error = ?, updated_at = ? WHERE id = ?;

-- name: RevokeRoleLoginCredentials :many
UPDATE login_credentials SET state = 'revoked', revoked_at = sqlc.arg(now), updated_at = sqlc.arg(now)
WHERE role_id = sqlc.arg(role_id) AND state NOT IN ('revoked', 'retired')
RETURNING id;

-- name: SetLoginCredentialState :execrows
UPDATE login_credentials SET state = sqlc.arg(state), activated_at = coalesce(sqlc.narg(activated_at), activated_at),
  retire_after = coalesce(sqlc.narg(retire_after), retire_after), retired_at = coalesce(sqlc.narg(retired_at), retired_at),
  revoked_at = coalesce(sqlc.narg(revoked_at), revoked_at), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND state = sqlc.arg(from_state);

-- name: DueRetiringCredentials :many
SELECT * FROM login_credentials WHERE state = 'retiring' AND retire_after <= ?;

-- name: InsertUserCA :exec
INSERT INTO user_cas (id, name, algorithm, public_key, fingerprint_sha256, private_enc, signer_ref, state, created_at,
  created_by, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?);

-- name: GetUserCA :one
SELECT * FROM user_cas WHERE id = ?;

-- name: ListUserCAs :many
SELECT * FROM user_cas ORDER BY name;

-- name: UpsertRoleCertBinding :exec
INSERT INTO role_cert_bindings (role_id, user_ca_id, principals_json, ttl_s, updated_at, updated_by)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (role_id) DO UPDATE SET user_ca_id = excluded.user_ca_id, principals_json = excluded.principals_json,
  ttl_s = excluded.ttl_s, updated_at = excluded.updated_at, updated_by = excluded.updated_by;

-- name: GetRoleCertBinding :one
SELECT * FROM role_cert_bindings WHERE role_id = ?;

-- name: DeleteRoleCertBinding :execrows
DELETE FROM role_cert_bindings WHERE role_id = ?;

-- name: InsertGatewayHostKey :exec
INSERT INTO gateway_host_keys (id, algorithm, public_key, fingerprint_sha256, private_enc, state, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListGatewayHostKeys :many
SELECT * FROM gateway_host_keys WHERE state != 'retired' ORDER BY created_at;

-- name: SetGatewayHostKeyState :execrows
UPDATE gateway_host_keys SET state = sqlc.arg(state), updated_at = sqlc.arg(now) WHERE id = sqlc.arg(id) AND state = sqlc.arg(from_state);
