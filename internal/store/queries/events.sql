-- name: InsertEventOutbox :exec
INSERT INTO event_outbox (id, subject, type, payload_json, created_at, next_attempt_at) VALUES (?, ?, ?, ?, ?, ?);

-- name: DueEventOutbox :many
SELECT id, subject, type, payload_json, created_at, attempts
FROM event_outbox WHERE published_at IS NULL AND dead_at IS NULL AND next_attempt_at <= ?
ORDER BY next_attempt_at, id LIMIT ?;

-- name: MarkEventPublished :execrows
UPDATE event_outbox SET published_at = ?, attempts = attempts + 1, last_error = NULL WHERE id = ? AND published_at IS NULL;

-- name: MarkEventRetry :execrows
UPDATE event_outbox SET attempts = attempts + 1, next_attempt_at = ?, last_error = ? WHERE id = ? AND published_at IS NULL;

-- name: MarkEventDead :execrows
UPDATE event_outbox SET attempts = attempts + 1, dead_at = ?, last_error = ? WHERE id = ? AND published_at IS NULL;

-- name: CountEventOutbox :one
SELECT
  CAST(coalesce(sum(published_at IS NULL AND dead_at IS NULL), 0) AS INTEGER) AS pending,
  CAST(coalesce(sum(dead_at IS NOT NULL), 0) AS INTEGER) AS dead
FROM event_outbox;

-- name: PurgeEventOutbox :execrows
DELETE FROM event_outbox WHERE created_at < ?;

-- name: SessionSubjects :one
SELECT g.id AS grant_id, g.agent_id, g.server_id, g.role_id, g.operator_id
FROM access_sessions s JOIN grants g ON g.id = s.grant_id WHERE s.id = ?;
