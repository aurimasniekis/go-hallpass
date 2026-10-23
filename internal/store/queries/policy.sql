-- name: ListPolicyRules :many
SELECT * FROM policy_rules ORDER BY name;

-- name: GetPolicyRule :one
SELECT * FROM policy_rules WHERE id = ?;

-- name: InsertPolicyRule :exec
INSERT INTO policy_rules (id, name, description, effect, level, subjects_json, targets_json, roles_json, max_duration_s,
  auto_max_duration_s, require_reason, enabled, version, created_at, updated_at, updated_by)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?);

-- name: UpdatePolicyRule :execrows
UPDATE policy_rules SET name = ?, description = ?, effect = ?, level = ?, subjects_json = ?, targets_json = ?, roles_json = ?,
  max_duration_s = ?, auto_max_duration_s = ?, require_reason = ?, enabled = ?, version = version + 1, updated_at = ?,
  updated_by = ?
WHERE id = ? AND version = ?;

-- name: DeletePolicyRule :execrows
DELETE FROM policy_rules WHERE id = ?;

-- name: ListApproverRules :many
SELECT * FROM approver_rules ORDER BY name;

-- name: GetApproverRule :one
SELECT * FROM approver_rules WHERE id = ?;

-- name: InsertApproverRule :exec
INSERT INTO approver_rules (id, name, description, operators_json, targets_json, roles_json, max_duration_s, enabled,
  version, created_at, updated_at, updated_by)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?);

-- name: UpdateApproverRule :execrows
UPDATE approver_rules SET name = ?, description = ?, operators_json = ?, targets_json = ?, roles_json = ?, max_duration_s = ?,
  enabled = ?, version = version + 1, updated_at = ?, updated_by = ?
WHERE id = ? AND version = ?;

-- name: DeleteApproverRule :execrows
DELETE FROM approver_rules WHERE id = ?;

-- name: ListAgentOwners :many
SELECT agent_id, operator_id FROM agent_owners ORDER BY agent_id, operator_id;

-- name: DeleteAgentOwners :exec
DELETE FROM agent_owners WHERE agent_id = ?;

-- name: InsertAgentOwner :exec
INSERT INTO agent_owners (agent_id, operator_id) VALUES (?, ?);
