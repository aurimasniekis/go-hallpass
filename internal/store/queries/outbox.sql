-- name: InsertOutboxMessage :exec
INSERT INTO outbox_messages (id, provider, destination, kind, subject_type, subject_id, body_enc, state, attempts,
  max_attempts, next_at, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', 0, ?, ?, ?, ?);

-- name: DueOutboxMessages :many
SELECT id, provider, destination, kind, subject_type, subject_id, body_enc, state, attempts, max_attempts, next_at,
  lease_until, provider_ref, last_error, created_at, updated_at
FROM outbox_messages
WHERE (state = 'queued' AND next_at <= sqlc.arg(now)) OR (state = 'sending' AND lease_until < sqlc.arg(now))
ORDER BY next_at LIMIT sqlc.arg(lim);

-- name: ClaimOutboxMessage :execrows
UPDATE outbox_messages SET state = 'sending', attempts = attempts + 1, lease_until = sqlc.arg(lease_until), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND (state = 'queued' OR (state = 'sending' AND lease_until < sqlc.arg(now)));

-- name: FinishOutboxMessage :exec
UPDATE outbox_messages SET state = ?, next_at = ?, lease_until = NULL, provider_ref = coalesce(?, provider_ref),
  last_error = ?, updated_at = ?
WHERE id = ?;

-- name: InsertDeliveryAttempt :exec
INSERT INTO delivery_attempts (outbox_id, at, outcome, http_status, error_code, duration_ms) VALUES (?, ?, ?, ?, ?, ?);

-- name: GetOutboxMessage :one
SELECT id, provider, destination, kind, subject_type, subject_id, body_enc, state, attempts, max_attempts, next_at,
  lease_until, provider_ref, last_error, created_at, updated_at
FROM outbox_messages WHERE id = ?;

-- name: ListDeliveryAttempts :many
SELECT id, outbox_id, at, outcome, http_status, error_code, duration_ms FROM delivery_attempts WHERE outbox_id = ? ORDER BY at, id;

-- name: OutboxBySubject :many
SELECT id, provider, destination, kind, subject_type, subject_id, body_enc, state, attempts, max_attempts, next_at,
  lease_until, provider_ref, last_error, created_at, updated_at
FROM outbox_messages WHERE subject_type = ? AND subject_id = ? ORDER BY created_at;

-- name: CountOutboxByState :many
SELECT state, count(*) AS n FROM outbox_messages GROUP BY state;
