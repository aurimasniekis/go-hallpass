-- 0026_agent_soft_delete: agents can be deleted like servers and roles (0024). A deleted agent stays so sessions,
-- requests and the audit log keep naming it, but it is disabled, its keys are revoked (and stay unusable forever,
-- HP-AGT-003), it is hidden from lists and policy, and its name is freed: name holds a tombstone ("~" + id) and
-- deleted_name the name it had.

-- +goose Up
ALTER TABLE agents ADD COLUMN deleted_at INTEGER;
ALTER TABLE agents ADD COLUMN deleted_by TEXT;
ALTER TABLE agents ADD COLUMN deleted_name TEXT;

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
