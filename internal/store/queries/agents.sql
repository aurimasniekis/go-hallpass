-- name: InsertAgent :exec
INSERT INTO agents (id, name, description, enabled, source_cidrs_json, version, created_at, created_by, updated_at, updated_by)
VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?);

-- name: GetAgent :one
SELECT * FROM agents WHERE id = ?;

-- name: GetAgentByName :one
SELECT * FROM agents WHERE name = ?;

-- name: ListAgents :many
SELECT * FROM agents ORDER BY name;

-- name: UpdateAgent :execrows
UPDATE agents SET name = ?, description = ?, source_cidrs_json = ?, version = version + 1, updated_at = ?, updated_by = ?
WHERE id = ? AND version = ?;

-- name: SetAgentEnabled :execrows
UPDATE agents SET enabled = sqlc.arg(enabled), version = version + 1, updated_at = sqlc.arg(now), updated_by = sqlc.arg(actor),
  disabled_at = CASE WHEN sqlc.arg(enabled) = 1 THEN NULL ELSE sqlc.arg(now) END,
  disabled_by = CASE WHEN sqlc.arg(enabled) = 1 THEN NULL ELSE sqlc.arg(actor) END
WHERE id = sqlc.arg(id) AND enabled != sqlc.arg(enabled);

-- name: InsertAgentKey :exec
INSERT INTO agent_keys (id, agent_id, fingerprint_sha256, algorithm, bits, public_key, comment, state, created_at, created_by)
VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?);

-- name: GetAgentKey :one
SELECT * FROM agent_keys WHERE id = ?;

-- name: GetAgentKeyByFingerprint :one
SELECT * FROM agent_keys WHERE fingerprint_sha256 = ?;

-- name: ListAgentKeys :many
SELECT * FROM agent_keys WHERE agent_id = ? ORDER BY created_at;

-- name: CountActiveAgentKeys :one
SELECT count(*) FROM agent_keys WHERE agent_id = ? AND state = 'active';

-- name: RevokeAgentKey :execrows
UPDATE agent_keys SET state = 'revoked', revoked_at = ?, revoked_by = ?, revoke_reason_enc = ?
WHERE id = ? AND agent_id = ? AND state = 'active';

-- name: TouchAgentKey :exec
UPDATE agent_keys SET last_used_at = sqlc.arg(now) WHERE id = sqlc.arg(id) AND (last_used_at IS NULL OR last_used_at < sqlc.arg(threshold));

-- name: AuthLookup :one
SELECT k.id AS key_id, k.state AS key_state, k.last_used_at, a.id AS agent_id, a.name AS agent_name, a.enabled,
  a.source_cidrs_json
FROM agent_keys k JOIN agents a ON a.id = k.agent_id
WHERE k.fingerprint_sha256 = ?;

-- name: ListAgentGroupNames :many
SELECT g.name FROM agent_groups ag JOIN groups g ON g.id = ag.group_id WHERE ag.agent_id = ? ORDER BY g.name;

-- name: ListAllAgentGroups :many
SELECT ag.agent_id, g.name FROM agent_groups ag JOIN groups g ON g.id = ag.group_id ORDER BY ag.agent_id, g.name;

-- name: DeleteAgentGroups :exec
DELETE FROM agent_groups WHERE agent_id = ?;

-- name: InsertAgentGroup :exec
INSERT INTO agent_groups (agent_id, group_id) VALUES (?, ?);

-- name: CountGroupMembers :one
SELECT count(*) FROM agent_groups WHERE group_id = ?;
