-- 0015_space_probe: scratch table for the disk-full recovery probe (HP-DB-009). A degraded "database disk full"
-- state clears only after a write that allocates new pages commits; the probe inserts and deletes one row.

-- +goose Up
CREATE TABLE store_space_probe (
    id   INTEGER PRIMARY KEY CHECK (id = 1),
    data BLOB NOT NULL
) STRICT;

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
