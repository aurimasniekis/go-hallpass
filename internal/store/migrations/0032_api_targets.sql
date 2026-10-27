-- 0032_api_targets: API targets are servers of kind 'api' (HTTPS APIs such as GitHub, Cloudflare or Google Cloud)
-- reached through the gateway's API proxy. A target lists its host names and holds its own interception CA (name
-- constrained to those hosts, private key sealed); its roles are access profiles whose api_rules_json says which
-- methods and paths they allow, and api_credentials holds each profile's sealed credential, which never leaves
-- HallPass. A tunnel through the proxy is an exec-kind channel that records the API host; each HTTP request is a
-- metadata-only timeline event.
--
-- servers.kind has a CHECK constraint, so the table is rebuilt (SQLite's documented procedure, with foreign keys
-- off so that dropping the old table does not cascade).

-- +goose NO TRANSACTION
-- +goose Up
PRAGMA foreign_keys = OFF;

BEGIN;

CREATE TABLE servers_new (
  id             TEXT PRIMARY KEY,
  alias          TEXT NOT NULL UNIQUE,
  display_name   TEXT NOT NULL,
  description    TEXT NOT NULL DEFAULT '',
  environment    TEXT NOT NULL DEFAULT '',
  address        TEXT NOT NULL,
  port           INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  enabled        INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  host_ca_id     TEXT REFERENCES host_cas (id),
  metadata_json  TEXT NOT NULL DEFAULT '{}',
  version        INTEGER NOT NULL DEFAULT 1,
  created_at     INTEGER NOT NULL,
  created_by     TEXT NOT NULL,
  updated_at     INTEGER NOT NULL,
  updated_by     TEXT NOT NULL,
  kind           TEXT NOT NULL DEFAULT 'ssh' CHECK (kind IN ('ssh', 'git', 'api')),
  deleted_at     INTEGER,
  deleted_by     TEXT,
  deleted_alias  TEXT,
  api_hosts_json TEXT,
  api_ca_cert    TEXT,
  api_ca_key_enc BLOB
) STRICT, WITHOUT ROWID;

INSERT INTO servers_new (id, alias, display_name, description, environment, address, port, enabled, host_ca_id,
  metadata_json, version, created_at, created_by, updated_at, updated_by, kind, deleted_at, deleted_by, deleted_alias)
SELECT id, alias, display_name, description, environment, address, port, enabled, host_ca_id, metadata_json, version,
  created_at, created_by, updated_at, updated_by, kind, deleted_at, deleted_by, deleted_alias
FROM servers;

DROP TABLE servers;

ALTER TABLE servers_new RENAME TO servers;

ALTER TABLE server_roles ADD COLUMN api_rules_json TEXT;

ALTER TABLE ssh_channels ADD COLUMN api_host TEXT;

CREATE TABLE api_credentials (
  role_id     TEXT PRIMARY KEY REFERENCES server_roles (id),
  type        TEXT NOT NULL CHECK (type IN ('bearer', 'header', 'basic', 'google_service_account')),
  header      TEXT NOT NULL DEFAULT '',
  username    TEXT NOT NULL DEFAULT '',
  scopes_json TEXT NOT NULL DEFAULT '[]',
  secret_enc  BLOB NOT NULL,
  hint        TEXT NOT NULL DEFAULT '',
  version     INTEGER NOT NULL DEFAULT 1,
  updated_at  INTEGER NOT NULL,
  updated_by  TEXT NOT NULL
) STRICT, WITHOUT ROWID;

COMMIT;

PRAGMA foreign_keys = ON;

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
