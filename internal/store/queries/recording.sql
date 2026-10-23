-- name: InsertSegment :exec
INSERT INTO recording_segments (id, access_session_id, channel_id, ordinal, path, key_id, wrapped_dek, header_sha256, state, opened_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?);

-- name: GetSegment :one
SELECT * FROM recording_segments WHERE id = ?;

-- name: FinalizeSegment :execrows
UPDATE recording_segments SET state = sqlc.arg(state), first_seq = sqlc.narg(first_seq), last_seq = sqlc.narg(last_seq),
  records = sqlc.narg(records), frames = sqlc.narg(frames), bytes = sqlc.narg(bytes), ciphertext_sha256 = sqlc.narg(ciphertext_sha256),
  end_reason = sqlc.narg(end_reason), finalized_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND state = 'open';

-- name: SetSegmentState :execrows
UPDATE recording_segments SET state = sqlc.arg(state), end_reason = sqlc.narg(end_reason) WHERE id = sqlc.arg(id) AND state = sqlc.arg(from_state);

-- name: OpenSegments :many
SELECT * FROM recording_segments WHERE state = 'open' ORDER BY opened_at;

-- name: SegmentsForSession :many
SELECT * FROM recording_segments WHERE access_session_id = ? ORDER BY channel_id, ordinal;

-- name: SegmentsForChannel :many
SELECT * FROM recording_segments WHERE channel_id = ? ORDER BY ordinal;

-- name: AllSegmentPaths :many
SELECT id, path, state FROM recording_segments;

-- name: SegmentsByState :many
SELECT * FROM recording_segments WHERE state = ? ORDER BY opened_at LIMIT ?;

-- name: RecordVerification :exec
UPDATE recording_segments SET verified_at = ?, verify_result = ? WHERE id = ?;

-- name: ChainHead :one
SELECT seq, hash FROM integrity_chain ORDER BY seq DESC LIMIT 1;

-- name: InsertChainEntry :exec
INSERT INTO integrity_chain (seq, segment_id, manifest_sha256, prev_hash, hash, mac, at) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ChainFrom :many
SELECT * FROM integrity_chain WHERE seq > ? ORDER BY seq LIMIT ?;

-- name: InsertQuarantine :exec
INSERT INTO quarantine_files (original_path, quarantine_path, reason, at) VALUES (?, ?, ?, ?);

-- name: ExpiredSessions :many
SELECT id FROM access_sessions WHERE state = 'closed' AND delete_after IS NOT NULL AND delete_after < ? LIMIT ?;

-- name: SetSessionDeleteAfter :exec
UPDATE access_sessions SET delete_after = ? WHERE id = ? AND delete_after IS NULL;

-- name: ClosedSessionsWithoutRetention :many
SELECT id, closed_at, retention_class FROM access_sessions WHERE state = 'closed' AND delete_after IS NULL LIMIT ?;

-- name: MarkSegmentDeleted :execrows
UPDATE recording_segments SET state = 'deleted' WHERE id = ? AND state != 'deleted';

-- name: DeleteSessionTimelinePayloads :exec
UPDATE timeline_events SET data_json = '{}' WHERE access_session_id = ?;
