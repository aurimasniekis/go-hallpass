-- 0017_ssh_bans: fail2ban-style bans of agent SSH sources after repeated failed authentication (HP-SSH-026).
-- address is an IPv4 address or an IPv6 /64 prefix. Rows are kept after expiry (offense history, audit trail)
-- and purged after 30 days.

-- +goose Up
CREATE TABLE ssh_bans (
  id         TEXT PRIMARY KEY,
  address    TEXT NOT NULL,
  failures   INTEGER NOT NULL,
  reason     TEXT NOT NULL,
  offense    INTEGER NOT NULL CHECK (offense >= 1),
  banned_at  INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  lifted_at  INTEGER,
  lifted_by  TEXT
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_ssh_bans_address ON ssh_bans (address, banned_at);
CREATE INDEX ix_ssh_bans_active ON ssh_bans (expires_at) WHERE lifted_at IS NULL;

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
