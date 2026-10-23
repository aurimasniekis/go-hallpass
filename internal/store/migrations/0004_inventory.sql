-- 0004_inventory: destination servers, host identities, host CAs, duplicate exceptions and roles (WP07).

-- +goose Up
CREATE TABLE host_cas (
  id                 TEXT PRIMARY KEY,
  name               TEXT NOT NULL UNIQUE,
  public_key         TEXT NOT NULL,
  fingerprint_sha256 TEXT NOT NULL UNIQUE,
  max_validity_s     INTEGER NOT NULL CHECK (max_validity_s > 0),
  state              TEXT NOT NULL CHECK (state IN ('active', 'retired')),
  created_at         INTEGER NOT NULL,
  created_by         TEXT NOT NULL,
  updated_at         INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE servers (
  id            TEXT PRIMARY KEY,
  alias         TEXT NOT NULL UNIQUE,
  display_name  TEXT NOT NULL,
  description   TEXT NOT NULL DEFAULT '',
  environment   TEXT NOT NULL DEFAULT '',
  address       TEXT NOT NULL,
  port          INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  enabled       INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  host_ca_id    TEXT REFERENCES host_cas (id),
  metadata_json TEXT NOT NULL DEFAULT '{}',
  version       INTEGER NOT NULL DEFAULT 1,
  created_at    INTEGER NOT NULL,
  created_by    TEXT NOT NULL,
  updated_at    INTEGER NOT NULL,
  updated_by    TEXT NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE server_groups (
  server_id TEXT NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
  group_id  TEXT NOT NULL REFERENCES groups (id) ON DELETE RESTRICT,
  PRIMARY KEY (server_id, group_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_server_groups_group ON server_groups (group_id);

CREATE TABLE host_ca_principals (
  server_id TEXT NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
  principal TEXT NOT NULL,
  PRIMARY KEY (server_id, principal)
) STRICT, WITHOUT ROWID;

CREATE TABLE host_identities (
  id                 TEXT PRIMARY KEY,
  server_id          TEXT NOT NULL REFERENCES servers (id),
  algorithm          TEXT NOT NULL,
  public_key         TEXT NOT NULL,
  fingerprint_sha256 TEXT NOT NULL,
  state              TEXT NOT NULL CHECK (state IN ('pending', 'active', 'retired')),
  enrolled_via       TEXT NOT NULL CHECK (enrolled_via IN ('paste', 'scan')),
  created_at         INTEGER NOT NULL,
  created_by         TEXT NOT NULL,
  confirmed_at       INTEGER,
  confirmed_by       TEXT,
  retired_at         INTEGER,
  retired_by         TEXT,
  UNIQUE (server_id, fingerprint_sha256)
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_host_identities_fp ON host_identities (fingerprint_sha256, state);

CREATE TABLE host_duplicate_exceptions (
  id                 TEXT PRIMARY KEY,
  fingerprint_sha256 TEXT NOT NULL,
  server_a           TEXT NOT NULL REFERENCES servers (id),
  server_b           TEXT NOT NULL REFERENCES servers (id),
  justification      TEXT NOT NULL,
  created_by         TEXT NOT NULL,
  created_at         INTEGER NOT NULL,
  CHECK (server_a < server_b),
  UNIQUE (fingerprint_sha256, server_a, server_b)
) STRICT, WITHOUT ROWID;

CREATE TABLE server_roles (
  id                       TEXT PRIMARY KEY,
  server_id                TEXT NOT NULL REFERENCES servers (id),
  alias                    TEXT NOT NULL,
  display_name             TEXT NOT NULL,
  description              TEXT NOT NULL DEFAULT '',
  remote_user              TEXT NOT NULL,
  capabilities_json        TEXT NOT NULL,
  default_duration_s       INTEGER NOT NULL CHECK (default_duration_s > 0),
  max_duration_s           INTEGER NOT NULL CHECK (max_duration_s >= default_duration_s),
  max_concurrent           INTEGER NOT NULL CHECK (max_concurrent > 0),
  max_concurrent_per_agent INTEGER NOT NULL CHECK (max_concurrent_per_agent > 0),
  record_input             INTEGER NOT NULL DEFAULT 0 CHECK (record_input IN (0, 1)),
  recording_mode           TEXT NOT NULL DEFAULT 'mandatory' CHECK (recording_mode IN ('mandatory', 'best_effort')),
  env_allow_json           TEXT NOT NULL DEFAULT '[]',
  approval_channels_json   TEXT NOT NULL DEFAULT '["web","slack","telegram"]',
  restriction_notes        TEXT NOT NULL DEFAULT '',
  retention_class          TEXT NOT NULL DEFAULT 'default',
  enabled                  INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  version                  INTEGER NOT NULL DEFAULT 1,
  created_at               INTEGER NOT NULL,
  updated_at               INTEGER NOT NULL,
  updated_by               TEXT NOT NULL,
  UNIQUE (server_id, alias)
) STRICT, WITHOUT ROWID;

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
