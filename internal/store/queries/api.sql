-- Keyset-paginated listings for the REST API (HP-API-004). Cursors are (time, id) of the last row, newest first.

-- name: ListRequestsPage :many
SELECT * FROM access_requests
WHERE (sqlc.narg(state) IS NULL OR state = sqlc.narg(state))
  AND (sqlc.narg(agent_id) IS NULL OR agent_id = sqlc.narg(agent_id))
  AND (sqlc.narg(server_id) IS NULL OR server_id = sqlc.narg(server_id))
  AND (sqlc.narg(before_at) IS NULL OR created_at < sqlc.narg(before_at) OR (created_at = sqlc.narg(before_at) AND id < sqlc.narg(before_id)))
ORDER BY created_at DESC, id DESC LIMIT sqlc.arg(lim);

-- name: ListGrantsPage :many
SELECT * FROM grants
WHERE (sqlc.narg(state) IS NULL OR state = sqlc.narg(state))
  AND (sqlc.narg(agent_id) IS NULL OR agent_id = sqlc.narg(agent_id))
  AND (sqlc.narg(server_id) IS NULL OR server_id = sqlc.narg(server_id))
  AND (sqlc.narg(before_at) IS NULL OR starts_at < sqlc.narg(before_at) OR (starts_at = sqlc.narg(before_at) AND id < sqlc.narg(before_id)))
ORDER BY starts_at DESC, id DESC LIMIT sqlc.arg(lim);

-- name: ListSessionsPage :many
SELECT s.id, s.grant_id, s.state, s.opened_at, s.closed_at, s.close_reason, s.retention_class, s.delete_after,
  g.agent_id, g.server_id, g.role_id, g.remote_user, g.expires_at, g.state AS grant_state
FROM access_sessions s JOIN grants g ON g.id = s.grant_id
WHERE (sqlc.narg(state) IS NULL OR s.state = sqlc.narg(state))
  AND (sqlc.narg(agent_id) IS NULL OR g.agent_id = sqlc.narg(agent_id))
  AND (sqlc.narg(server_id) IS NULL OR g.server_id = sqlc.narg(server_id))
  AND (sqlc.narg(before_at) IS NULL OR s.opened_at < sqlc.narg(before_at) OR (s.opened_at = sqlc.narg(before_at) AND s.id < sqlc.narg(before_id)))
ORDER BY s.opened_at DESC, s.id DESC LIMIT sqlc.arg(lim);

-- name: GetSessionDetail :one
SELECT s.id, s.grant_id, s.state, s.opened_at, s.closed_at, s.close_reason, s.retention_class, s.delete_after,
  g.agent_id, g.server_id, g.role_id, g.remote_user, g.expires_at, g.state AS grant_state
FROM access_sessions s JOIN grants g ON g.id = s.grant_id WHERE s.id = ?;

-- name: ListAuditPage :many
SELECT * FROM audit_events
WHERE (sqlc.narg(action) IS NULL OR action = sqlc.narg(action))
  AND (sqlc.narg(target_id) IS NULL OR target_id = sqlc.narg(target_id))
  AND (sqlc.narg(actor_id) IS NULL OR actor_id = sqlc.narg(actor_id))
  AND (sqlc.narg(before_seq) IS NULL OR seq < sqlc.narg(before_seq))
ORDER BY seq DESC LIMIT sqlc.arg(lim);

-- name: TimelinePage :many
SELECT * FROM timeline_events WHERE access_session_id = sqlc.arg(session_id) AND seq > sqlc.arg(after_seq) ORDER BY seq LIMIT sqlc.arg(lim);

-- name: ChannelsForSessionAPI :many
SELECT * FROM ssh_channels WHERE access_session_id = ? ORDER BY opened_at, id;

-- name: GetIdempotency :one
SELECT * FROM api_idempotency WHERE operator_id = ? AND key = ? AND expires_at > ?;

-- name: InsertIdempotency :exec
INSERT OR IGNORE INTO api_idempotency (operator_id, key, operation, request_hash, status, body, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: PurgeIdempotency :execrows
DELETE FROM api_idempotency WHERE expires_at < ?;

-- name: CountRequestsByStateSince :many
SELECT state, count(*) AS n FROM access_requests WHERE created_at >= ? GROUP BY state;

-- name: RequestTimesSince :many
SELECT created_at, state FROM access_requests WHERE created_at >= ? ORDER BY created_at LIMIT 100000;

-- name: SessionTimesSince :many
SELECT opened_at FROM access_sessions WHERE opened_at >= ? ORDER BY opened_at LIMIT 100000;

-- name: CountActiveGrants :one
SELECT count(*) FROM grants WHERE state = 'active';

-- name: CountPendingAll :one
SELECT count(*) FROM access_requests WHERE state = 'pending';
