-- 0006_policy: visibility/request policy rules, approver rules and agent owners (WP08, PLAN §9).

-- +goose Up
CREATE TABLE policy_rules (
  id                  TEXT PRIMARY KEY,
  name                TEXT NOT NULL UNIQUE,
  description         TEXT NOT NULL DEFAULT '',
  effect              TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
  level               TEXT CHECK (level IN ('visible', 'requestable', 'auto_approve')),
  subjects_json       TEXT NOT NULL,
  targets_json        TEXT NOT NULL,
  roles_json          TEXT NOT NULL,
  max_duration_s      INTEGER,
  auto_max_duration_s INTEGER,
  require_reason      INTEGER NOT NULL DEFAULT 1 CHECK (require_reason IN (0, 1)),
  enabled             INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  version             INTEGER NOT NULL DEFAULT 1,
  created_at          INTEGER NOT NULL,
  updated_at          INTEGER NOT NULL,
  updated_by          TEXT NOT NULL,
  CHECK ((effect = 'deny' AND level IS NULL) OR (effect = 'allow' AND level IS NOT NULL)),
  CHECK (level IS NOT 'auto_approve' OR auto_max_duration_s > 0)
) STRICT, WITHOUT ROWID;

CREATE TABLE approver_rules (
  id             TEXT PRIMARY KEY,
  name           TEXT NOT NULL UNIQUE,
  description    TEXT NOT NULL DEFAULT '',
  operators_json TEXT NOT NULL,
  targets_json   TEXT NOT NULL,
  roles_json     TEXT NOT NULL,
  max_duration_s INTEGER,
  enabled        INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  version        INTEGER NOT NULL DEFAULT 1,
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL,
  updated_by     TEXT NOT NULL
) STRICT, WITHOUT ROWID;

-- Owners of an agent (for the self-approval prohibition, HP-POL-012). Operator IDs are validated by the service.
CREATE TABLE agent_owners (
  agent_id    TEXT NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
  operator_id TEXT NOT NULL,
  PRIMARY KEY (agent_id, operator_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_agent_owners_operator ON agent_owners (operator_id);

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
