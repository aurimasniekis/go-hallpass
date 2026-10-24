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
SELECT id, access_session_id, path, state FROM recording_segments;

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

-- name: AllSegments :many
SELECT * FROM recording_segments ORDER BY opened_at, id;

-- name: ChainEntryForSegment :one
SELECT * FROM integrity_chain WHERE segment_id = ?;

-- name: GetChainHeadRecord :one
SELECT seq, hash, mac FROM recording_chain_head WHERE id = 1;

-- name: UpsertChainHeadRecord :exec
INSERT INTO recording_chain_head (id, seq, hash, mac, at) VALUES (1, sqlc.arg(seq), sqlc.arg(hash), sqlc.arg(mac), sqlc.arg(at))
ON CONFLICT (id) DO UPDATE SET seq = excluded.seq, hash = excluded.hash, mac = excluded.mac, at = excluded.at;

-- name: InsertTombstone :exec
INSERT INTO recording_tombstones (segment_id, access_session_id, prior_state, chain_seq, delete_after, deleted_at, audit_event_id, mac)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetTombstone :one
SELECT * FROM recording_tombstones WHERE segment_id = ?;

-- name: GetSessionRetention :one
SELECT state, delete_after FROM access_sessions WHERE id = ?;

-- name: SegmentsNeedingRewrap :many
SELECT * FROM recording_segments WHERE key_id != sqlc.arg(active_key_id) AND state NOT IN ('open', 'deleted') AND id > sqlc.arg(after)
ORDER BY id LIMIT sqlc.arg(lim);

-- name: UpdateSegmentKey :execrows
UPDATE recording_segments SET key_id = sqlc.arg(key_id), wrapped_dek = sqlc.arg(wrapped_dek)
WHERE id = sqlc.arg(id) AND key_id = sqlc.arg(old_key_id) AND wrapped_dek = sqlc.arg(old_wrapped_dek) AND state != 'deleted';

-- name: SegmentsWithFilesAfter :many
SELECT * FROM recording_segments WHERE state IN ('finalized', 'interrupted') AND id > sqlc.arg(after) ORDER BY id LIMIT sqlc.arg(lim);
