-- 0030_event_outbox: events published to Pulse (ADR-0057). Rows are written in the transaction of the change they
-- describe, only while events.pulse is enabled, and a relay publishes them after commit. id is the stable event ID
-- (the audit or timeline event ID) consumers deduplicate on. Payloads hold only what the audit log and session
-- timeline already store in plaintext.

-- +goose Up
CREATE TABLE event_outbox (
  id              TEXT PRIMARY KEY,
  subject         TEXT NOT NULL,
  type            TEXT NOT NULL,
  payload_json    TEXT NOT NULL,
  created_at      INTEGER NOT NULL,
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  published_at    INTEGER,
  dead_at         INTEGER,
  last_error      TEXT
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_event_outbox_due ON event_outbox (next_attempt_at, id) WHERE published_at IS NULL AND dead_at IS NULL;
CREATE INDEX ix_event_outbox_created ON event_outbox (created_at);

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
