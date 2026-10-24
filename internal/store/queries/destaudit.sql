-- Destination-side audit integration (WP25, HP-REC-012).

-- name: InsertDestauditCollector :exec
INSERT INTO destaudit_collectors (id, server_id, name, public_key, fingerprint, state, created_at, created_by)
VALUES (?, ?, ?, ?, ?, 'active', ?, ?);

-- name: GetDestauditCollector :one
SELECT * FROM destaudit_collectors WHERE id = ?;

-- name: ListDestauditCollectors :many
SELECT * FROM destaudit_collectors
WHERE (sqlc.narg(server_id) IS NULL OR server_id = sqlc.narg(server_id))
ORDER BY created_at, id;

-- name: RevokeDestauditCollector :execrows
UPDATE destaudit_collectors SET state = 'revoked', revoked_at = sqlc.arg(now), revoked_by = sqlc.arg(revoked_by),
  revoke_reason = sqlc.arg(reason)
WHERE id = sqlc.arg(id) AND state = 'active';

-- name: AdvanceDestauditCollector :execrows
UPDATE destaudit_collectors SET last_seq = sqlc.arg(seq), last_batch_sha256 = sqlc.arg(payload_sha256), last_seen_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND state = 'active' AND last_seq < sqlc.arg(seq);

-- name: InsertDestauditBatch :exec
INSERT INTO destaudit_batches (collector_id, seq, payload_sha256, signature, sent_at, received_at, records, accepted, duplicates, rejected)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetDestauditBatch :one
SELECT * FROM destaudit_batches WHERE collector_id = ? AND seq = ?;

-- name: GetDestauditLogin :one
SELECT * FROM destaudit_logins WHERE collector_id = ? AND login_ref = ?;

-- name: InsertDestauditLogin :exec
INSERT INTO destaudit_logins (collector_id, login_ref, access_session_id, connection_id, correlation, bound_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (collector_id, login_ref) DO NOTHING;

-- name: InsertDestauditRecord :execrows
INSERT INTO destaudit_records (id, collector_id, record_ref, batch_seq, access_session_id, connection_id, timeline_event_id,
  correlation, confidence, after_session_end, reported_at, received_at, details_enc)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (collector_id, record_ref) DO NOTHING;

-- name: DestauditRecordExists :one
SELECT COUNT(*) FROM destaudit_records WHERE collector_id = ? AND record_ref = ?;

-- name: GetDestauditRecord :one
SELECT * FROM destaudit_records WHERE id = ?;

-- name: DestauditRecordsForSession :many
SELECT * FROM destaudit_records WHERE access_session_id = ? ORDER BY reported_at, id LIMIT ?;

-- Correlation lookups. A destination-reported identity is only a claim; these return HallPass's own state to check it.

-- name: DestauditSessionByGrant :one
SELECT s.id AS session_id, s.opened_at, s.closed_at, g.id AS grant_id, g.server_id, g.role_id, g.remote_user,
  g.starts_at, g.expires_at, g.ended_at
FROM grants g JOIN access_sessions s ON s.grant_id = g.id WHERE g.id = ?;

-- name: DestauditSessionByID :one
SELECT s.id AS session_id, s.opened_at, s.closed_at, g.id AS grant_id, g.server_id, g.role_id, g.remote_user,
  g.starts_at, g.expires_at, g.ended_at
FROM access_sessions s JOIN grants g ON g.id = s.grant_id WHERE s.id = ?;

-- name: DestauditConnectionInSession :one
SELECT COUNT(*) FROM ssh_channels WHERE connection_id = sqlc.arg(connection_id) AND access_session_id = sqlc.arg(session_id)
  AND grant_id = sqlc.arg(grant_id);

-- name: DestauditCredentialByFingerprint :one
SELECT lc.id, lc.role_id, r.server_id, r.remote_user
FROM login_credentials lc JOIN server_roles r ON r.id = lc.role_id WHERE lc.fingerprint_sha256 = ?;

-- name: DestauditSessionsForCredentialAt :many
SELECT DISTINCT access_session_id FROM ssh_channels
WHERE credential_ref = sqlc.arg(credential_ref) AND role_id = sqlc.arg(role_id)
  AND opened_at <= sqlc.arg(hi) AND (closed_at IS NULL OR closed_at >= sqlc.arg(lo))
LIMIT 2;
