-- 0025_api_tokens: automation tokens for the REST API (Terraform, scripts). A token acts for the operator who created it,
-- with one of that operator's roles, and only while the operator is enabled and still holds the role. Only an HMAC of
-- the token is stored (keyring token key); the token itself is shown once.

-- +goose Up
CREATE TABLE api_tokens (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  operator_id  TEXT NOT NULL REFERENCES operators (id),
  role         TEXT NOT NULL CHECK (role IN ('administrator', 'approver', 'auditor', 'viewer')),
  mac          BLOB NOT NULL UNIQUE,
  hint         TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  last_used_at INTEGER,
  last_used_ip TEXT,
  revoked_at   INTEGER,
  revoked_by   TEXT
) STRICT, WITHOUT ROWID;
CREATE INDEX ix_api_tokens_operator ON api_tokens (operator_id);

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
