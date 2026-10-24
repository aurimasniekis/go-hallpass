-- 0023_file_transfer: roles with the file-transfer capability accept SFTP (and scp, which uses SFTP). The channel
-- records the subsystem; file operations are recorded as timeline events (metadata and SHA-256, no file content).

-- +goose Up
ALTER TABLE ssh_channels ADD COLUMN subsystem TEXT CHECK (subsystem IS NULL OR subsystem IN ('sftp'));

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
