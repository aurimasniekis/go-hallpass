-- name: BumpPolicyVersion :one
UPDATE policy_state SET version = version + 1, updated_at = ? WHERE id = 1 RETURNING version;

-- name: SetLockdown :execrows
UPDATE policy_state SET lockdown = sqlc.arg(lockdown), lockdown_by = sqlc.narg(lockdown_by), lockdown_at = sqlc.narg(lockdown_at),
  updated_at = sqlc.arg(updated_at)
WHERE id = 1 AND lockdown != sqlc.arg(lockdown);
