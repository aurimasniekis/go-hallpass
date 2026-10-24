-- name: InsertAPIToken :exec
INSERT INTO api_tokens (id, name, operator_id, role, mac, hint, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetAPITokenByMAC :one
SELECT * FROM api_tokens WHERE mac = ?;

-- name: GetAPIToken :one
SELECT * FROM api_tokens WHERE id = ?;

-- name: ListAPITokens :many
SELECT * FROM api_tokens ORDER BY revoked_at IS NOT NULL, created_at DESC;

-- name: RevokeAPIToken :execrows
UPDATE api_tokens SET revoked_at = sqlc.arg(now), revoked_by = sqlc.arg(actor) WHERE id = sqlc.arg(id) AND revoked_at IS NULL;

-- name: TouchAPIToken :exec
UPDATE api_tokens SET last_used_at = sqlc.arg(now), last_used_ip = sqlc.arg(ip)
WHERE id = sqlc.arg(id) AND (last_used_at IS NULL OR last_used_at < sqlc.arg(since));
