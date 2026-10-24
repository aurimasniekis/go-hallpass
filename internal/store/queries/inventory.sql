-- name: InsertServer :exec
INSERT INTO servers (id, alias, display_name, description, environment, address, port, enabled, metadata_json, version,
  created_at, created_by, updated_at, updated_by, kind)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?);

-- name: GetServer :one
SELECT * FROM servers WHERE id = ?;

-- name: GetServerByAlias :one
SELECT * FROM servers WHERE alias = ?;

-- name: ListServers :many
SELECT * FROM servers WHERE deleted_at IS NULL ORDER BY alias;

-- name: ListServersWithDeleted :many
SELECT * FROM servers ORDER BY deleted_at IS NOT NULL, alias;

-- name: DeleteServer :execrows
UPDATE servers SET enabled = 0, deleted_alias = alias, alias = '~' || id, deleted_at = sqlc.arg(now),
  deleted_by = sqlc.arg(actor), version = version + 1, updated_at = sqlc.arg(now), updated_by = sqlc.arg(actor)
WHERE id = sqlc.arg(id) AND deleted_at IS NULL;

-- name: UpdateServer :execrows
UPDATE servers SET alias = ?, display_name = ?, description = ?, environment = ?, address = ?, port = ?, metadata_json = ?,
  version = version + 1, updated_at = ?, updated_by = ?
WHERE id = ? AND version = ?;

-- name: SetServerEnabled :execrows
UPDATE servers SET enabled = sqlc.arg(enabled), version = version + 1, updated_at = sqlc.arg(now), updated_by = sqlc.arg(actor)
WHERE id = sqlc.arg(id) AND enabled != sqlc.arg(enabled);

-- name: SetServerHostCA :exec
UPDATE servers SET host_ca_id = ?, version = version + 1, updated_at = ?, updated_by = ? WHERE id = ?;

-- name: ListServerGroupNames :many
SELECT g.name FROM server_groups sg JOIN groups g ON g.id = sg.group_id WHERE sg.server_id = ? ORDER BY g.name;

-- name: ListAllServerGroups :many
SELECT sg.server_id, g.name FROM server_groups sg JOIN groups g ON g.id = sg.group_id ORDER BY sg.server_id, g.name;

-- name: DeleteServerGroups :exec
DELETE FROM server_groups WHERE server_id = ?;

-- name: InsertServerGroup :exec
INSERT INTO server_groups (server_id, group_id) VALUES (?, ?);

-- name: ListHostCAPrincipals :many
SELECT principal FROM host_ca_principals WHERE server_id = ? ORDER BY principal;

-- name: DeleteHostCAPrincipals :exec
DELETE FROM host_ca_principals WHERE server_id = ?;

-- name: InsertHostCAPrincipal :exec
INSERT INTO host_ca_principals (server_id, principal) VALUES (?, ?);

-- name: InsertHostCA :exec
INSERT INTO host_cas (id, name, public_key, fingerprint_sha256, max_validity_s, state, created_at, created_by, updated_at)
VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?);

-- name: GetHostCA :one
SELECT * FROM host_cas WHERE id = ?;

-- name: ListHostCAs :many
SELECT * FROM host_cas ORDER BY name;

-- name: InsertHostIdentity :exec
INSERT INTO host_identities (id, server_id, algorithm, public_key, fingerprint_sha256, state, enrolled_via, created_at,
  created_by, confirmed_at, confirmed_by)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetHostIdentity :one
SELECT * FROM host_identities WHERE id = ?;

-- name: GetHostIdentityByFingerprint :one
SELECT * FROM host_identities WHERE server_id = ? AND fingerprint_sha256 = ?;

-- name: ListHostIdentities :many
SELECT * FROM host_identities WHERE server_id = ? ORDER BY created_at;

-- name: CountActiveHostIdentitiesByServer :many
SELECT server_id, count(*) AS active FROM host_identities WHERE state = 'active' GROUP BY server_id;

-- name: ActiveHostIdentitiesByFingerprint :many
SELECT * FROM host_identities WHERE fingerprint_sha256 = ? AND state = 'active';

-- name: ConfirmHostIdentity :execrows
UPDATE host_identities SET state = 'active', confirmed_at = ?, confirmed_by = ? WHERE id = ? AND state = 'pending';

-- name: ReenrollHostIdentity :execrows
UPDATE host_identities SET state = ?, enrolled_via = ?, created_at = ?, created_by = ?, confirmed_at = ?, confirmed_by = ?,
  retired_at = NULL, retired_by = NULL
WHERE id = ? AND state = 'retired';

-- name: RetireHostIdentity :execrows
UPDATE host_identities SET state = 'retired', retired_at = ?, retired_by = ? WHERE id = ? AND state != 'retired';

-- name: InsertHostDuplicateException :exec
INSERT INTO host_duplicate_exceptions (id, fingerprint_sha256, server_a, server_b, justification, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: HasHostDuplicateException :one
SELECT count(*) FROM host_duplicate_exceptions WHERE fingerprint_sha256 = ? AND server_a = ? AND server_b = ?;

-- name: InsertRole :exec
INSERT INTO server_roles (id, server_id, alias, display_name, description, remote_user, capabilities_json, default_duration_s,
  max_duration_s, max_concurrent, max_concurrent_per_agent, record_input, recording_mode, env_allow_json,
  approval_channels_json, restriction_notes, retention_class, enabled, version, created_at, updated_at, updated_by,
  git_rules_json, approvals_required)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?);

-- name: GetRole :one
SELECT * FROM server_roles WHERE id = ?;

-- name: GetRoleByAlias :one
SELECT * FROM server_roles WHERE server_id = ? AND alias = ?;

-- name: ListRoles :many
SELECT * FROM server_roles WHERE server_id = ? AND deleted_at IS NULL ORDER BY alias;

-- name: ListAllRoles :many
SELECT * FROM server_roles WHERE deleted_at IS NULL ORDER BY server_id, alias;

-- name: DeleteRole :execrows
UPDATE server_roles SET enabled = 0, deleted_alias = alias, alias = '~' || id, deleted_at = sqlc.arg(now),
  deleted_by = sqlc.arg(actor), version = version + 1, updated_at = sqlc.arg(now), updated_by = sqlc.arg(actor)
WHERE id = sqlc.arg(id) AND deleted_at IS NULL;

-- name: UpdateRole :execrows
UPDATE server_roles SET alias = ?, display_name = ?, description = ?, remote_user = ?, capabilities_json = ?,
  default_duration_s = ?, max_duration_s = ?, max_concurrent = ?, max_concurrent_per_agent = ?, record_input = ?,
  recording_mode = ?, env_allow_json = ?, approval_channels_json = ?, restriction_notes = ?, retention_class = ?,
  git_rules_json = ?, approvals_required = ?, version = version + 1, updated_at = ?, updated_by = ?
WHERE id = ? AND version = ?;

-- name: SetRoleEnabled :execrows
UPDATE server_roles SET enabled = sqlc.arg(enabled), version = version + 1, updated_at = sqlc.arg(now), updated_by = sqlc.arg(actor)
WHERE id = sqlc.arg(id) AND enabled != sqlc.arg(enabled);
