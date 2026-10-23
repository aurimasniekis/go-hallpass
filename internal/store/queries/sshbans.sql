-- name: InsertSSHBan :exec
INSERT INTO ssh_bans (id, address, failures, reason, offense, banned_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ActiveSSHBans :many
SELECT * FROM ssh_bans WHERE lifted_at IS NULL AND expires_at > sqlc.arg(now) ORDER BY banned_at DESC;

-- name: CountSSHBansSince :one
SELECT count(*) FROM ssh_bans WHERE address = sqlc.arg(address) AND banned_at >= sqlc.arg(since);

-- name: GetSSHBan :one
SELECT * FROM ssh_bans WHERE id = ?;

-- name: LiftSSHBan :execrows
UPDATE ssh_bans SET lifted_at = sqlc.arg(now), lifted_by = sqlc.arg(lifted_by)
WHERE id = sqlc.arg(id) AND lifted_at IS NULL AND expires_at > sqlc.arg(now);

-- name: PurgeSSHBans :exec
DELETE FROM ssh_bans WHERE expires_at < sqlc.arg(before);
