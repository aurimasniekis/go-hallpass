-- 0008_operators: operator accounts, local credentials, MFA, one-time tokens, web sessions and login throttling (WP13).

-- +goose Up
CREATE TABLE operators (
  id              TEXT PRIMARY KEY,
  email           TEXT UNIQUE COLLATE NOCASE,
  display_name    TEXT NOT NULL,
  enabled         INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  provisioned_via TEXT NOT NULL CHECK (provisioned_via IN ('bootstrap', 'admin', 'invite', 'jit', 'recovery')),
  mfa_required    INTEGER NOT NULL DEFAULT 0 CHECK (mfa_required IN (0, 1)),
  version         INTEGER NOT NULL DEFAULT 1,
  created_at      INTEGER NOT NULL,
  created_by      TEXT NOT NULL,
  updated_at      INTEGER NOT NULL,
  disabled_at     INTEGER,
  last_login_at   INTEGER
) STRICT, WITHOUT ROWID;

CREATE TABLE operator_local_credentials (
  operator_id    TEXT PRIMARY KEY REFERENCES operators (id) ON DELETE CASCADE,
  password_phc   TEXT NOT NULL,
  params_version INTEGER NOT NULL,
  changed_at     INTEGER NOT NULL,
  must_change    INTEGER NOT NULL DEFAULT 0 CHECK (must_change IN (0, 1))
) STRICT, WITHOUT ROWID;

CREATE TABLE operator_roles (
  operator_id TEXT NOT NULL REFERENCES operators (id) ON DELETE CASCADE,
  role        TEXT NOT NULL CHECK (role IN ('administrator', 'approver', 'auditor', 'viewer')),
  source      TEXT NOT NULL CHECK (source IN ('manual', 'sso')),
  source_ref  TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (operator_id, role, source, source_ref)
) STRICT, WITHOUT ROWID;

CREATE TABLE operator_group_members (
  group_id    TEXT NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
  operator_id TEXT NOT NULL REFERENCES operators (id) ON DELETE CASCADE,
  source      TEXT NOT NULL CHECK (source IN ('manual', 'sso')),
  PRIMARY KEY (group_id, operator_id, source)
) STRICT, WITHOUT ROWID;

CREATE TABLE mfa_totp (
  operator_id  TEXT PRIMARY KEY REFERENCES operators (id) ON DELETE CASCADE,
  secret_enc   BLOB NOT NULL,
  confirmed_at INTEGER,
  last_step    INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE recovery_codes (
  operator_id TEXT NOT NULL REFERENCES operators (id) ON DELETE CASCADE,
  code_hash   BLOB NOT NULL,
  used_at     INTEGER,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (operator_id, code_hash)
) STRICT, WITHOUT ROWID;

CREATE TABLE one_time_tokens (
  hash        BLOB PRIMARY KEY,
  kind        TEXT NOT NULL CHECK (kind IN ('setup', 'invite', 'reset', 'recovery_login', 'link_code', 'oidc_test')),
  operator_id TEXT,
  data_json   TEXT NOT NULL DEFAULT '{}',
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER,
  created_at  INTEGER NOT NULL,
  created_by  TEXT NOT NULL
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_ott_kind ON one_time_tokens (kind, expires_at);

CREATE TABLE web_sessions (
  id_hash             BLOB PRIMARY KEY,
  operator_id         TEXT NOT NULL REFERENCES operators (id) ON DELETE CASCADE,
  csrf_secret         BLOB NOT NULL,
  auth_method         TEXT NOT NULL,
  mfa_at              INTEGER,
  auth_at             INTEGER NOT NULL,
  created_at          INTEGER NOT NULL,
  last_seen_at        INTEGER NOT NULL,
  absolute_expires_at INTEGER NOT NULL,
  ip                  TEXT NOT NULL DEFAULT '',
  user_agent          TEXT NOT NULL DEFAULT '',
  revoked_at          INTEGER,
  revoke_reason       TEXT,
  display_id          TEXT NOT NULL UNIQUE
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_web_sessions_operator ON web_sessions (operator_id, revoked_at);

CREATE TABLE login_throttle (
  key             TEXT PRIMARY KEY,
  failures        INTEGER NOT NULL,
  next_allowed_at INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
