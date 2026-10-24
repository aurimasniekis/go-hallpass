-- 0014_destaudit: optional destination-side audit collectors, signed batches, login bindings and ingested exec records
-- (WP25, HP-REC-012). Ingested records are destination-reported: HallPass verifies the collector signature and the
-- correlation with its own session state, never the truth of the record itself.

-- +goose Up
CREATE TABLE destaudit_collectors (
  id                TEXT PRIMARY KEY,
  server_id         TEXT NOT NULL REFERENCES servers (id),
  name              TEXT NOT NULL,
  public_key        BLOB NOT NULL CHECK (length(public_key) = 32),
  fingerprint       TEXT NOT NULL UNIQUE,
  state             TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
  last_seq          INTEGER NOT NULL DEFAULT 0 CHECK (last_seq >= 0),
  last_batch_sha256 BLOB,
  last_seen_at      INTEGER,
  created_at        INTEGER NOT NULL,
  created_by        TEXT NOT NULL,
  revoked_at        INTEGER,
  revoked_by        TEXT,
  revoke_reason     TEXT,
  UNIQUE (server_id, name)
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_dac_server ON destaudit_collectors (server_id, state);

-- One row per accepted batch: replay protection evidence (seq strictly increases per collector) and the signature.
CREATE TABLE destaudit_batches (
  collector_id   TEXT NOT NULL REFERENCES destaudit_collectors (id),
  seq            INTEGER NOT NULL CHECK (seq > 0),
  payload_sha256 BLOB NOT NULL,
  signature      BLOB NOT NULL,
  sent_at        INTEGER NOT NULL,
  received_at    INTEGER NOT NULL,
  records        INTEGER NOT NULL,
  accepted       INTEGER NOT NULL,
  duplicates     INTEGER NOT NULL,
  rejected       INTEGER NOT NULL,
  PRIMARY KEY (collector_id, seq)
) STRICT, WITHOUT ROWID;

-- A destination login (audit session) is bound to at most one access session per collector.
CREATE TABLE destaudit_logins (
  collector_id      TEXT NOT NULL REFERENCES destaudit_collectors (id),
  login_ref         TEXT NOT NULL,
  access_session_id TEXT NOT NULL REFERENCES access_sessions (id) ON DELETE CASCADE,
  connection_id     TEXT,
  correlation       TEXT NOT NULL,
  bound_at          INTEGER NOT NULL,
  PRIMARY KEY (collector_id, login_ref)
) STRICT, WITHOUT ROWID;

-- Exec records attached to an access session. details_enc (exe, argv, cwd) is sealed with the field key; the
-- timeline event carries only non-sensitive metadata.
CREATE TABLE destaudit_records (
  id                TEXT PRIMARY KEY,
  collector_id      TEXT NOT NULL REFERENCES destaudit_collectors (id),
  record_ref        TEXT NOT NULL,
  batch_seq         INTEGER NOT NULL,
  access_session_id TEXT NOT NULL REFERENCES access_sessions (id) ON DELETE CASCADE,
  connection_id     TEXT,
  timeline_event_id TEXT NOT NULL,
  correlation       TEXT NOT NULL,
  confidence        TEXT NOT NULL CHECK (confidence IN ('high', 'medium')),
  after_session_end INTEGER NOT NULL CHECK (after_session_end IN (0, 1)),
  reported_at       INTEGER NOT NULL,
  received_at       INTEGER NOT NULL,
  details_enc       BLOB,
  purged_at         INTEGER,
  UNIQUE (collector_id, record_ref)
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_dar_session ON destaudit_records (access_session_id, reported_at);

-- Retention (HP-REC-013): recording retention clears timeline payloads per session; the sealed exec details of
-- destination.exec events are purged with them, leaving a tombstone row.
-- +goose StatementBegin
CREATE TRIGGER tr_destaudit_retention AFTER UPDATE OF data_json ON timeline_events
WHEN NEW.type = 'destination.exec' AND NEW.data_json = '{}'
BEGIN
  UPDATE destaudit_records SET details_enc = NULL, purged_at = CAST(unixepoch('subsec') * 1000000 AS INTEGER)
  WHERE timeline_event_id = NEW.id AND purged_at IS NULL;
END;
-- +goose StatementEnd

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
