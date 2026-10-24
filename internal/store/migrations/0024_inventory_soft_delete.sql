-- 0024_inventory_soft_delete: servers (including git remotes) and roles (including access profiles) can be deleted.
-- A deleted row stays so sessions, grants and the audit log keep resolving it, but it is disabled, hidden from lists
-- and policy, and its alias is freed for reuse: alias holds a tombstone ("~" + id, never a valid alias) and
-- deleted_alias the name it had.

-- +goose Up
ALTER TABLE servers ADD COLUMN deleted_at INTEGER;
ALTER TABLE servers ADD COLUMN deleted_by TEXT;
ALTER TABLE servers ADD COLUMN deleted_alias TEXT;
ALTER TABLE server_roles ADD COLUMN deleted_at INTEGER;
ALTER TABLE server_roles ADD COLUMN deleted_by TEXT;
ALTER TABLE server_roles ADD COLUMN deleted_alias TEXT;

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
