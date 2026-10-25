-- 0028_remote_backup: scheduled backups to S3-compatible object storage (ADR-0054). One target; the secret access key
-- is sealed with the field key. generation increases when the bucket location changes, so runs and uploaded segments
-- of an earlier location are no longer managed. backup_remote_segments records which version (key ID) of each
-- segment is stored and between which backups it was present, so retention deletes a segment object only when no
-- kept backup references it.

-- +goose Up
CREATE TABLE backup_target (
  id                    TEXT PRIMARY KEY CHECK (id = 'default'),
  enabled               INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  endpoint              TEXT NOT NULL,
  region                TEXT NOT NULL,
  bucket                TEXT NOT NULL,
  prefix                TEXT NOT NULL,
  path_style            INTEGER NOT NULL CHECK (path_style IN (0, 1)),
  access_key_id         TEXT NOT NULL,
  secret_enc            BLOB NOT NULL,
  ca_bundle_pem         TEXT NOT NULL,
  allow_private_network INTEGER NOT NULL CHECK (allow_private_network IN (0, 1)),
  interval_seconds      INTEGER NOT NULL CHECK (interval_seconds BETWEEN 900 AND 604800),
  keep_last             INTEGER NOT NULL CHECK (keep_last BETWEEN 1 AND 1000),
  keep_daily_days       INTEGER NOT NULL CHECK (keep_daily_days BETWEEN 0 AND 3650),
  generation            INTEGER NOT NULL,
  version               INTEGER NOT NULL,
  created_at            INTEGER NOT NULL,
  updated_at            INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE backup_runs (
  id                TEXT PRIMARY KEY,
  generation        INTEGER NOT NULL,
  trigger           TEXT NOT NULL CHECK (trigger IN ('schedule', 'manual')),
  requested_by      TEXT,
  state             TEXT NOT NULL CHECK (state IN ('running', 'succeeded', 'failed', 'interrupted')),
  started_at        INTEGER NOT NULL,
  finished_at       INTEGER,
  db_bytes          INTEGER,
  segments          INTEGER,
  segments_uploaded INTEGER,
  uploaded_bytes    INTEGER,
  error             TEXT,
  remote_state      TEXT NOT NULL DEFAULT 'stored' CHECK (remote_state IN ('stored', 'deleted'))
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_backup_runs_started ON backup_runs (started_at);

CREATE TABLE backup_remote_segments (
  segment_id    TEXT PRIMARY KEY,
  generation    INTEGER NOT NULL,
  object        TEXT NOT NULL,
  key_id        TEXT NOT NULL,
  size          INTEGER NOT NULL,
  first_seen_at INTEGER NOT NULL,
  gone_at       INTEGER
) STRICT, WITHOUT ROWID;

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
