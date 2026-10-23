-- 0005_credentials: destination login credentials, user CAs, certificate bindings and gateway host keys (WP07).
-- Host identities, login credentials and CAs are deliberately separate tables (HP-KEY-006).

-- +goose Up
CREATE TABLE login_credentials (
  id                 TEXT PRIMARY KEY,
  role_id            TEXT NOT NULL REFERENCES server_roles (id),
  kind               TEXT NOT NULL CHECK (kind IN ('managed_key', 'imported_key')),
  algorithm          TEXT NOT NULL,
  public_key         TEXT NOT NULL,
  fingerprint_sha256 TEXT NOT NULL UNIQUE,
  private_enc        BLOB NOT NULL,
  state              TEXT NOT NULL CHECK (state IN ('pending', 'active', 'retiring', 'retired', 'revoked')),
  probe_ok_at        INTEGER,
  probe_error        TEXT,
  activated_at       INTEGER,
  retire_after       INTEGER,
  retired_at         INTEGER,
  revoked_at         INTEGER,
  created_at         INTEGER NOT NULL,
  created_by         TEXT NOT NULL,
  updated_at         INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX ux_login_cred_active ON login_credentials (role_id) WHERE state = 'active';
CREATE INDEX ix_login_cred_role ON login_credentials (role_id, state);

CREATE TABLE user_cas (
  id                 TEXT PRIMARY KEY,
  name               TEXT NOT NULL UNIQUE,
  algorithm          TEXT NOT NULL,
  public_key         TEXT NOT NULL,
  fingerprint_sha256 TEXT NOT NULL UNIQUE,
  private_enc        BLOB,
  signer_ref         TEXT,
  state              TEXT NOT NULL CHECK (state IN ('active', 'retired')),
  created_at         INTEGER NOT NULL,
  created_by         TEXT NOT NULL,
  updated_at         INTEGER NOT NULL,
  CHECK (private_enc IS NOT NULL OR signer_ref IS NOT NULL)
) STRICT, WITHOUT ROWID;

CREATE TABLE role_cert_bindings (
  role_id         TEXT PRIMARY KEY REFERENCES server_roles (id),
  user_ca_id      TEXT NOT NULL REFERENCES user_cas (id),
  principals_json TEXT NOT NULL,
  ttl_s           INTEGER NOT NULL DEFAULT 120 CHECK (ttl_s BETWEEN 30 AND 3600),
  updated_at      INTEGER NOT NULL,
  updated_by      TEXT NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE gateway_host_keys (
  id                 TEXT PRIMARY KEY,
  algorithm          TEXT NOT NULL,
  public_key         TEXT NOT NULL,
  fingerprint_sha256 TEXT NOT NULL UNIQUE,
  private_enc        BLOB NOT NULL,
  state              TEXT NOT NULL CHECK (state IN ('next', 'active', 'previous', 'retired')),
  created_at         INTEGER NOT NULL,
  updated_at         INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX ux_gateway_host_key_active ON gateway_host_keys (algorithm) WHERE state = 'active';

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
