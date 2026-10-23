-- name: InsertIntegration :exec
INSERT INTO integrations (id, provider, name, config_json, secrets_enc, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateIntegration :execrows
UPDATE integrations SET name = ?, config_json = ?, secrets_enc = ?, enabled = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ?;

-- name: GetIntegration :one
SELECT * FROM integrations WHERE id = ?;

-- name: ListIntegrations :many
SELECT * FROM integrations ORDER BY name;

-- name: DeleteIntegration :execrows
DELETE FROM integrations WHERE id = ?;

-- name: InsertRoute :exec
INSERT INTO notification_routes (id, integration_id, destination, targets_json, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?);

-- name: DeleteRoute :execrows
DELETE FROM notification_routes WHERE id = ?;

-- name: ListRoutes :many
SELECT r.*, i.provider FROM notification_routes r JOIN integrations i ON i.id = r.integration_id ORDER BY r.created_at;

-- name: EnabledRoutes :many
SELECT r.*, i.provider FROM notification_routes r JOIN integrations i ON i.id = r.integration_id WHERE r.enabled = 1 AND i.enabled = 1;

-- name: GetProviderLink :one
SELECT * FROM provider_links WHERE provider = ? AND workspace = ? AND provider_user_id = ?;

-- name: UpsertProviderLink :exec
INSERT INTO provider_links (provider, workspace, provider_user_id, operator_id, display, linked_at, linked_via) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (provider, workspace, provider_user_id) DO UPDATE SET operator_id = excluded.operator_id, display = excluded.display,
  linked_at = excluded.linked_at, linked_via = excluded.linked_via;

-- name: DeleteProviderLink :execrows
DELETE FROM provider_links WHERE provider = ? AND workspace = ? AND provider_user_id = ? AND operator_id = ?;

-- name: ListProviderLinks :many
SELECT * FROM provider_links WHERE operator_id = ? ORDER BY linked_at;

-- name: InsertLinkCode :exec
INSERT INTO provider_link_codes (hash, operator_id, provider, expires_at, created_at) VALUES (?, ?, ?, ?, ?);

-- name: UseLinkCode :one
UPDATE provider_link_codes SET used_at = sqlc.arg(now) WHERE hash = sqlc.arg(hash) AND used_at IS NULL AND expires_at > sqlc.arg(now)
RETURNING *;

-- name: InsertActionToken :exec
INSERT INTO action_tokens (hash, request_id, action, duration_s, provider, integration_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetActionToken :one
SELECT * FROM action_tokens WHERE hash = ?;

-- name: UseActionToken :execrows
UPDATE action_tokens SET used_at = ?, used_by_operator = ?, outcome = ? WHERE hash = ? AND used_at IS NULL;

-- name: RememberReplay :execrows
INSERT OR IGNORE INTO webhook_replay (provider, fingerprint, expires_at) VALUES (?, ?, ?);

-- name: PurgeNotify :exec
DELETE FROM webhook_replay WHERE expires_at < ?;

-- name: PurgeLinkCodes :exec
DELETE FROM provider_link_codes WHERE expires_at < ?;

-- name: PendingMessagesForRequest :many
SELECT id, provider, destination, state, provider_ref FROM outbox_messages
WHERE subject_type = 'request' AND subject_id = ? AND kind = 'request.pending' ORDER BY created_at;

-- name: GetOutboxRef :one
SELECT id, state, provider_ref FROM outbox_messages WHERE id = ?;

-- name: ListDeliveries :many
SELECT id, provider, destination, kind, subject_type, subject_id, state, attempts, max_attempts, next_at, provider_ref, last_error, created_at, updated_at
FROM outbox_messages WHERE (sqlc.narg(state) IS NULL OR state = sqlc.narg(state)) ORDER BY created_at DESC LIMIT sqlc.arg(lim);

-- name: GetRouteIntegration :one
SELECT integration_id FROM notification_routes WHERE id = ?;

-- name: GetRoute :one
SELECT r.*, i.provider FROM notification_routes r JOIN integrations i ON i.id = r.integration_id WHERE r.id = ?;
