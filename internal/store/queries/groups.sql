-- name: InsertGroup :exec
INSERT INTO groups (id, kind, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?);

-- name: GetGroupByName :one
SELECT id, kind, name, description, created_at, updated_at FROM groups WHERE kind = ? AND name = ?;

-- name: GetGroup :one
SELECT id, kind, name, description, created_at, updated_at FROM groups WHERE id = ?;

-- name: ListGroups :many
SELECT id, kind, name, description, created_at, updated_at FROM groups WHERE kind = ? ORDER BY name;

-- name: UpdateGroupDescription :execrows
UPDATE groups SET description = ?, updated_at = ? WHERE id = ?;

-- name: DeleteGroup :execrows
DELETE FROM groups WHERE id = ?;

-- name: ListLabels :many
SELECT key, value FROM labels WHERE entity_type = ? AND entity_id = ? ORDER BY key;

-- name: ListAllLabels :many
SELECT entity_id, key, value FROM labels WHERE entity_type = ? ORDER BY entity_id, key;

-- name: DeleteLabels :exec
DELETE FROM labels WHERE entity_type = ? AND entity_id = ?;

-- name: InsertLabel :exec
INSERT INTO labels (entity_type, entity_id, key, value) VALUES (?, ?, ?, ?);
