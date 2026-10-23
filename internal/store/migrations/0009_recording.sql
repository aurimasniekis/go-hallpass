-- 0009_recording: recording segment index, integrity chain and quarantine records (WP12, PLAN §13).

-- +goose Up
CREATE TABLE recording_segments (
  id                TEXT PRIMARY KEY,
  access_session_id TEXT NOT NULL REFERENCES access_sessions (id),
  channel_id        TEXT NOT NULL REFERENCES ssh_channels (id),
  ordinal           INTEGER NOT NULL CHECK (ordinal >= 0),
  path              TEXT NOT NULL UNIQUE,
  format            TEXT NOT NULL DEFAULT 'HPREC1',
  key_id            TEXT NOT NULL,
  wrapped_dek       BLOB NOT NULL,
  header_sha256     BLOB NOT NULL,
  state             TEXT NOT NULL CHECK (state IN ('open', 'finalized', 'interrupted', 'failed', 'missing', 'deleted')),
  first_seq         INTEGER,
  last_seq          INTEGER,
  records           INTEGER,
  frames            INTEGER,
  bytes             INTEGER,
  ciphertext_sha256 BLOB,
  end_reason        TEXT,
  opened_at         INTEGER NOT NULL,
  finalized_at      INTEGER,
  verified_at       INTEGER,
  verify_result     TEXT,
  UNIQUE (channel_id, ordinal)
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_segments_session ON recording_segments (access_session_id, opened_at);
CREATE INDEX ix_segments_state ON recording_segments (state);

CREATE TABLE integrity_chain (
  seq             INTEGER PRIMARY KEY,
  segment_id      TEXT NOT NULL UNIQUE,
  manifest_sha256 BLOB NOT NULL,
  prev_hash       BLOB NOT NULL,
  hash            BLOB NOT NULL,
  mac             BLOB NOT NULL,
  at              INTEGER NOT NULL
) STRICT;

CREATE TABLE quarantine_files (
  id              INTEGER PRIMARY KEY,
  original_path   TEXT NOT NULL,
  quarantine_path TEXT NOT NULL,
  reason          TEXT NOT NULL,
  at              INTEGER NOT NULL
) STRICT;

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
