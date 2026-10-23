-- name: InsertJob :execrows
INSERT INTO jobs (id, kind, run_at, attempts, max_attempts, state, payload_json, dedup_key, created_at, updated_at)
VALUES (?, ?, ?, 0, ?, 'queued', ?, ?, ?, ?)
ON CONFLICT DO NOTHING;

-- name: DueJobs :many
SELECT id, kind, run_at, attempts, max_attempts, lease_until, state, payload_json, last_error, dedup_key, created_at, updated_at
FROM jobs
WHERE (state = 'queued' AND run_at <= sqlc.arg(now)) OR (state = 'running' AND lease_until < sqlc.arg(now))
ORDER BY run_at LIMIT sqlc.arg(lim);

-- name: ClaimJob :execrows
UPDATE jobs SET state = 'running', attempts = attempts + 1, lease_until = sqlc.arg(lease_until), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND ((state = 'queued') OR (state = 'running' AND lease_until < sqlc.arg(now)));

-- name: FinishJob :exec
UPDATE jobs SET state = ?, run_at = ?, lease_until = NULL, last_error = ?, updated_at = ? WHERE id = ?;

-- name: GetJob :one
SELECT id, kind, run_at, attempts, max_attempts, lease_until, state, payload_json, last_error, dedup_key, created_at, updated_at
FROM jobs WHERE id = ?;

-- name: CountJobsByState :many
SELECT state, count(*) AS n FROM jobs GROUP BY state;

-- name: PurgeFinishedJobs :execrows
DELETE FROM jobs WHERE state IN ('done', 'dead') AND updated_at < ?;
