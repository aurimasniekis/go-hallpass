-- 0002_audit_jobs: hash-chained audit log, durable jobs and the notification outbox (PLAN §6, WP05).

-- +goose Up
CREATE TABLE audit_events (
  id             TEXT PRIMARY KEY,
  seq            INTEGER NOT NULL UNIQUE CHECK (seq > 0),
  at             INTEGER NOT NULL,
  actor_type     TEXT NOT NULL CHECK (actor_type IN ('operator', 'agent', 'system', 'policy', 'cli', 'provider')),
  actor_id       TEXT,
  action         TEXT NOT NULL,
  target_type    TEXT,
  target_id      TEXT,
  outcome        TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
  source_ip      TEXT,
  correlation_id TEXT,
  details_json   TEXT NOT NULL DEFAULT '{}',
  details_enc    BLOB,
  prev_hash      BLOB NOT NULL,
  hash           BLOB NOT NULL
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_audit_at ON audit_events (at);
CREATE INDEX ix_audit_target ON audit_events (target_type, target_id, at);
CREATE INDEX ix_audit_actor ON audit_events (actor_type, actor_id, at);
CREATE INDEX ix_audit_action ON audit_events (action, at);

CREATE TABLE jobs (
  id           TEXT PRIMARY KEY,
  kind         TEXT NOT NULL,
  run_at       INTEGER NOT NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
  lease_until  INTEGER,
  state        TEXT NOT NULL CHECK (state IN ('queued', 'running', 'done', 'dead')),
  payload_json TEXT NOT NULL DEFAULT '{}',
  last_error   TEXT,
  dedup_key    TEXT,
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_jobs_due ON jobs (state, run_at);
CREATE UNIQUE INDEX ux_jobs_dedup ON jobs (dedup_key) WHERE dedup_key IS NOT NULL AND state IN ('queued', 'running');

CREATE TABLE outbox_messages (
  id           TEXT PRIMARY KEY,
  provider     TEXT NOT NULL,
  destination  TEXT NOT NULL,
  kind         TEXT NOT NULL,
  subject_type TEXT,
  subject_id   TEXT,
  body_enc     BLOB NOT NULL,
  state        TEXT NOT NULL CHECK (state IN ('queued', 'sending', 'delivered', 'dead')),
  attempts     INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
  next_at      INTEGER NOT NULL,
  lease_until  INTEGER,
  provider_ref TEXT,
  last_error   TEXT,
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_outbox_due ON outbox_messages (state, next_at);
CREATE INDEX ix_outbox_subject ON outbox_messages (subject_type, subject_id);

CREATE TABLE delivery_attempts (
  id          INTEGER PRIMARY KEY,
  outbox_id   TEXT NOT NULL REFERENCES outbox_messages (id) ON DELETE CASCADE,
  at          INTEGER NOT NULL,
  outcome     TEXT NOT NULL CHECK (outcome IN ('delivered', 'retry', 'failed')),
  http_status INTEGER,
  error_code  TEXT,
  duration_ms INTEGER NOT NULL
) STRICT;

CREATE INDEX ix_delivery_outbox ON delivery_attempts (outbox_id, at);

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
