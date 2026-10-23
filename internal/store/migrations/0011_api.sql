-- 0011_api: idempotency records for non-idempotent API mutations (WP15, HP-API-006).

-- +goose Up
CREATE TABLE api_idempotency (
  operator_id  TEXT NOT NULL,
  key          TEXT NOT NULL,
  operation    TEXT NOT NULL,
  request_hash BLOB NOT NULL,
  status       INTEGER NOT NULL,
  body         BLOB NOT NULL,
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  PRIMARY KEY (operator_id, key)
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_api_idem_exp ON api_idempotency (expires_at);
CREATE INDEX ix_sessions_opened ON access_sessions (opened_at);
CREATE INDEX ix_grants_starts ON grants (starts_at);
CREATE INDEX ix_audit_action_at ON audit_events (action, seq);

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
