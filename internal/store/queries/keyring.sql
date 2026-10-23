-- name: ListKeyringKeys :many
SELECT id, purpose, version, wrapped, wrap_kek_id, state, created_at, updated_at
FROM keyring_keys ORDER BY purpose, version;

-- name: InsertKeyringKey :exec
INSERT INTO keyring_keys (id, purpose, version, wrapped, wrap_kek_id, state, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateKeyringKeyState :execrows
UPDATE keyring_keys SET state = ?, updated_at = ? WHERE id = ?;

-- name: UpdateKeyringKeyWrap :execrows
UPDATE keyring_keys SET wrapped = ?, wrap_kek_id = ?, updated_at = ? WHERE id = ?;
