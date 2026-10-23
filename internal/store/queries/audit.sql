-- name: LastAuditEvent :one
SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1;

-- name: InsertAuditEvent :exec
INSERT INTO audit_events (id, seq, at, actor_type, actor_id, action, target_type, target_id, outcome, source_ip,
  correlation_id, details_json, details_enc, prev_hash, hash)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: AuditEventsFrom :many
SELECT id, seq, at, actor_type, actor_id, action, target_type, target_id, outcome, source_ip, correlation_id,
  details_json, details_enc, prev_hash, hash
FROM audit_events WHERE seq > ? ORDER BY seq LIMIT ?;

-- name: CountAuditEvents :one
SELECT count(*) FROM audit_events;
