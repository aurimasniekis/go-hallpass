-- name: BumpPolicyVersion :one
UPDATE policy_state SET version = version + 1, updated_at = ? WHERE id = 1 RETURNING version;

-- name: SetLockdown :execrows
UPDATE policy_state SET lockdown = ?, lockdown_by = ?, lockdown_at = ?, updated_at = ? WHERE id = 1 AND lockdown != ?;
