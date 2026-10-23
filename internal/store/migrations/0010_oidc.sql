-- 0010_oidc: OIDC providers, group mappings, external identities and pending authorization states (WP14, PLAN §12.4).

-- +goose Up
CREATE TABLE oidc_providers (
  id                           TEXT PRIMARY KEY,
  slug                         TEXT NOT NULL UNIQUE,
  display_name                 TEXT NOT NULL,
  issuer                       TEXT NOT NULL,
  client_id                    TEXT NOT NULL,
  client_secret_enc            BLOB,
  scopes_json                  TEXT NOT NULL,
  groups_claim                 TEXT NOT NULL DEFAULT '',
  provisioning                 TEXT NOT NULL CHECK (provisioning IN ('preprovisioned', 'jit')),
  jit_json                     TEXT NOT NULL DEFAULT '{}',
  allow_private_network        INTEGER NOT NULL DEFAULT 0 CHECK (allow_private_network IN (0, 1)),
  allow_cross_origin_endpoints INTEGER NOT NULL DEFAULT 0 CHECK (allow_cross_origin_endpoints IN (0, 1)),
  ca_bundle_pem                TEXT NOT NULL DEFAULT '',
  stepup_fallback              TEXT NOT NULL DEFAULT 'none' CHECK (stepup_fallback IN ('none', 'local_totp')),
  acr_values                   TEXT NOT NULL DEFAULT '',
  end_session_enabled          INTEGER NOT NULL DEFAULT 0 CHECK (end_session_enabled IN (0, 1)),
  enabled                      INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  test_login_ok_at             INTEGER,
  test_login_by                TEXT,
  version                      INTEGER NOT NULL DEFAULT 1,
  created_at                   INTEGER NOT NULL,
  updated_at                   INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE oidc_group_mappings (
  id          TEXT PRIMARY KEY,
  provider_id TEXT NOT NULL REFERENCES oidc_providers (id) ON DELETE CASCADE,
  group_value TEXT NOT NULL,
  role        TEXT CHECK (role IN ('administrator', 'approver', 'auditor', 'viewer')),
  group_id    TEXT REFERENCES groups (id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  CHECK ((role IS NULL) != (group_id IS NULL)),
  UNIQUE (provider_id, group_value, role, group_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE operator_identities (
  issuer        TEXT NOT NULL,
  subject       TEXT NOT NULL,
  provider_id   TEXT NOT NULL REFERENCES oidc_providers (id) ON DELETE CASCADE,
  operator_id   TEXT NOT NULL REFERENCES operators (id) ON DELETE CASCADE,
  linked_via    TEXT NOT NULL CHECK (linked_via IN ('admin', 'self_link', 'jit')),
  created_at    INTEGER NOT NULL,
  last_login_at INTEGER,
  PRIMARY KEY (issuer, subject)
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_identities_operator ON operator_identities (operator_id);

CREATE TABLE oidc_auth_states (
  state_hash      BLOB PRIMARY KEY,
  provider_id     TEXT NOT NULL REFERENCES oidc_providers (id) ON DELETE CASCADE,
  purpose         TEXT NOT NULL CHECK (purpose IN ('login', 'stepup', 'test', 'link')),
  nonce_hash      BLOB NOT NULL,
  verifier_enc    BLOB NOT NULL,
  binding_hash    BLOB NOT NULL,
  return_to       TEXT NOT NULL DEFAULT '/',
  operator_id     TEXT,
  session_display TEXT,
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_oidc_states_expiry ON oidc_auth_states (expires_at);

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
