-- 0012_notify: approval integrations, routes, provider identity links, action tokens and webhook replay cache
-- (WP16, PLAN §10).

-- +goose Up
CREATE TABLE integrations (
  id          TEXT PRIMARY KEY,
  provider    TEXT NOT NULL CHECK (provider IN ('slack', 'telegram')),
  name        TEXT NOT NULL UNIQUE,
  config_json TEXT NOT NULL,
  secrets_enc BLOB NOT NULL,
  enabled     INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  version     INTEGER NOT NULL DEFAULT 1,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE notification_routes (
  id             TEXT PRIMARY KEY,
  integration_id TEXT NOT NULL REFERENCES integrations (id) ON DELETE CASCADE,
  destination    TEXT NOT NULL,
  targets_json   TEXT NOT NULL,
  enabled        INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  created_at     INTEGER NOT NULL,
  UNIQUE (integration_id, destination)
) STRICT, WITHOUT ROWID;

CREATE TABLE provider_links (
  provider         TEXT NOT NULL,
  workspace        TEXT NOT NULL,
  provider_user_id TEXT NOT NULL,
  operator_id      TEXT NOT NULL REFERENCES operators (id) ON DELETE CASCADE,
  display          TEXT NOT NULL DEFAULT '',
  linked_at        INTEGER NOT NULL,
  linked_via       TEXT NOT NULL CHECK (linked_via IN ('link_code', 'admin')),
  PRIMARY KEY (provider, workspace, provider_user_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_provider_links_operator ON provider_links (operator_id);

CREATE TABLE provider_link_codes (
  hash        BLOB PRIMARY KEY,
  operator_id TEXT NOT NULL REFERENCES operators (id) ON DELETE CASCADE,
  provider    TEXT NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER,
  created_at  INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE action_tokens (
  hash             BLOB PRIMARY KEY,
  request_id       TEXT NOT NULL REFERENCES access_requests (id) ON DELETE CASCADE,
  action           TEXT NOT NULL CHECK (action IN ('approve', 'deny')),
  duration_s       INTEGER,
  provider         TEXT NOT NULL,
  integration_id   TEXT NOT NULL,
  expires_at       INTEGER NOT NULL,
  used_at          INTEGER,
  used_by_operator TEXT,
  outcome          TEXT,
  created_at       INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_action_tokens_request ON action_tokens (request_id);

CREATE TABLE webhook_replay (
  provider    TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  expires_at  INTEGER NOT NULL,
  PRIMARY KEY (provider, fingerprint)
) STRICT, WITHOUT ROWID;

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
