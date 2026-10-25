-- name: GetBackupTarget :one
SELECT * FROM backup_target WHERE id = 'default';

-- name: InsertBackupTarget :exec
INSERT INTO backup_target (id, enabled, endpoint, region, bucket, prefix, path_style, access_key_id, secret_enc, ca_bundle_pem,
  allow_private_network, interval_seconds, keep_last, keep_daily_days, generation, version, created_at, updated_at)
VALUES ('default', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?);

-- name: UpdateBackupTarget :execrows
UPDATE backup_target SET enabled = sqlc.arg(enabled), endpoint = sqlc.arg(endpoint), region = sqlc.arg(region), bucket = sqlc.arg(bucket),
  prefix = sqlc.arg(prefix), path_style = sqlc.arg(path_style), access_key_id = sqlc.arg(access_key_id), secret_enc = sqlc.arg(secret_enc),
  ca_bundle_pem = sqlc.arg(ca_bundle_pem), allow_private_network = sqlc.arg(allow_private_network), interval_seconds = sqlc.arg(interval_seconds),
  keep_last = sqlc.arg(keep_last), keep_daily_days = sqlc.arg(keep_daily_days), generation = sqlc.arg(generation),
  version = version + 1, updated_at = sqlc.arg(updated_at)
WHERE id = 'default' AND version = sqlc.arg(version);

-- name: DeleteBackupTarget :execrows
DELETE FROM backup_target WHERE id = 'default';

-- name: InsertBackupRun :exec
INSERT INTO backup_runs (id, generation, trigger, requested_by, state, started_at) VALUES (?, ?, ?, ?, 'running', ?);

-- name: FinishBackupRun :exec
UPDATE backup_runs SET state = sqlc.arg(state), finished_at = sqlc.arg(finished_at), db_bytes = sqlc.arg(db_bytes),
  segments = sqlc.arg(segments), segments_uploaded = sqlc.arg(segments_uploaded), uploaded_bytes = sqlc.arg(uploaded_bytes),
  error = sqlc.arg(error)
WHERE id = sqlc.arg(id);

-- name: InterruptRunningBackups :execrows
UPDATE backup_runs SET state = 'interrupted', finished_at = sqlc.arg(now), error = 'the server stopped during the backup'
WHERE state = 'running';

-- name: GetBackupRun :one
SELECT * FROM backup_runs WHERE id = ?;

-- name: ListBackupRuns :many
SELECT * FROM backup_runs WHERE (sqlc.arg(before) = '' OR id < sqlc.arg(before)) ORDER BY id DESC LIMIT sqlc.arg(lim);

-- name: LatestBackupRun :one
SELECT * FROM backup_runs ORDER BY id DESC LIMIT 1;

-- name: LatestSucceededBackupRun :one
SELECT * FROM backup_runs WHERE state = 'succeeded' ORDER BY id DESC LIMIT 1;

-- name: StoredBackupRuns :many
SELECT * FROM backup_runs WHERE generation = ? AND remote_state = 'stored' AND state != 'running' ORDER BY started_at DESC;

-- name: MarkBackupRunDeleted :exec
UPDATE backup_runs SET remote_state = 'deleted' WHERE id = ?;

-- name: ListRemoteSegments :many
SELECT * FROM backup_remote_segments WHERE generation = ?;

-- name: UpsertRemoteSegment :exec
INSERT INTO backup_remote_segments (segment_id, generation, object, key_id, size, first_seen_at, gone_at)
VALUES (sqlc.arg(segment_id), sqlc.arg(generation), sqlc.arg(object), sqlc.arg(key_id), sqlc.arg(size), sqlc.arg(seen_at), NULL)
ON CONFLICT (segment_id) DO UPDATE SET
  object = excluded.object, key_id = excluded.key_id, size = excluded.size, gone_at = NULL,
  first_seen_at = CASE WHEN backup_remote_segments.generation = excluded.generation THEN backup_remote_segments.first_seen_at ELSE excluded.first_seen_at END,
  generation = excluded.generation;

-- name: MarkRemoteSegmentGone :exec
UPDATE backup_remote_segments SET gone_at = sqlc.arg(gone_at) WHERE segment_id = sqlc.arg(segment_id) AND gone_at IS NULL;

-- name: DeleteRemoteSegment :exec
DELETE FROM backup_remote_segments WHERE segment_id = ?;

-- name: DeleteRemoteSegmentsOtherGenerations :exec
DELETE FROM backup_remote_segments WHERE generation != ?;
