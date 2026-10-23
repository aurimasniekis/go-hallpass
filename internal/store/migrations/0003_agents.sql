-- 0003_agents: groups, labels, agents and agent public keys (PLAN §6, WP06).

-- +goose Up
CREATE TABLE groups (
  id          TEXT PRIMARY KEY,
  kind        TEXT NOT NULL CHECK (kind IN ('agent', 'server', 'operator')),
  name        TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  UNIQUE (kind, name)
) STRICT, WITHOUT ROWID;

CREATE TABLE labels (
  entity_type TEXT NOT NULL CHECK (entity_type IN ('agent', 'server', 'role')),
  entity_id   TEXT NOT NULL,
  key         TEXT NOT NULL,
  value       TEXT NOT NULL,
  PRIMARY KEY (entity_type, entity_id, key)
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_labels_kv ON labels (entity_type, key, value);

CREATE TABLE agents (
  id                TEXT PRIMARY KEY,
  name              TEXT NOT NULL UNIQUE,
  description       TEXT NOT NULL DEFAULT '',
  enabled           INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  source_cidrs_json TEXT NOT NULL DEFAULT '[]',
  version           INTEGER NOT NULL DEFAULT 1,
  created_at        INTEGER NOT NULL,
  created_by        TEXT NOT NULL,
  updated_at        INTEGER NOT NULL,
  updated_by        TEXT NOT NULL,
  disabled_at       INTEGER,
  disabled_by       TEXT
) STRICT, WITHOUT ROWID;

CREATE TABLE agent_keys (
  id                 TEXT PRIMARY KEY,
  agent_id           TEXT NOT NULL REFERENCES agents (id),
  fingerprint_sha256 TEXT NOT NULL UNIQUE,
  algorithm          TEXT NOT NULL,
  bits               INTEGER NOT NULL,
  public_key         TEXT NOT NULL,
  comment            TEXT NOT NULL DEFAULT '',
  state              TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
  created_at         INTEGER NOT NULL,
  created_by         TEXT NOT NULL,
  revoked_at         INTEGER,
  revoked_by         TEXT,
  revoke_reason_enc  BLOB,
  last_used_at       INTEGER
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_agent_keys_agent ON agent_keys (agent_id, state);

CREATE TABLE agent_groups (
  agent_id TEXT NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
  group_id TEXT NOT NULL REFERENCES groups (id) ON DELETE RESTRICT,
  PRIMARY KEY (agent_id, group_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_agent_groups_group ON agent_groups (group_id);

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
