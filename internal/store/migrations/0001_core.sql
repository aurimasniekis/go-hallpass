-- 0001_core: settings, keyring and policy state (PLAN §6). Forward-only: rollback = restore snapshot.

-- +goose Up
CREATE TABLE settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  updated_by TEXT
) STRICT, WITHOUT ROWID;

CREATE TABLE keyring_keys (
  id          TEXT PRIMARY KEY,
  purpose     TEXT NOT NULL CHECK (purpose IN ('field', 'credential', 'recording', 'manifest', 'token')),
  version     INTEGER NOT NULL CHECK (version > 0),
  wrapped     BLOB NOT NULL,
  wrap_kek_id TEXT NOT NULL,
  state       TEXT NOT NULL CHECK (state IN ('active', 'decrypt_only', 'retired')),
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  UNIQUE (purpose, version)
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX ux_keyring_active ON keyring_keys (purpose) WHERE state = 'active';

CREATE TABLE policy_state (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  version     INTEGER NOT NULL,
  lockdown    INTEGER NOT NULL DEFAULT 0 CHECK (lockdown IN (0, 1)),
  lockdown_by TEXT,
  lockdown_at INTEGER,
  updated_at  INTEGER NOT NULL
) STRICT;

INSERT INTO policy_state (id, version, lockdown, updated_at) VALUES (1, 1, 0, 0);

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
