-- 0019_recording_integrity: authenticated retention tombstones and integrity-chain head (security review SR-02,
-- SR-17; HP-CRY-005, HP-REC-013, PLAN §13.5/§13.9).

-- +goose Up
-- One row per segment deleted by the retention job, written in the same transaction as the deletion mark and its
-- audit event. mac = HMAC(manifest key, "hallpass/rec/tombstone/v1|" || canonical JSON of the other columns), so a
-- party without the keys cannot make a removed segment look like legitimate retention. chain_seq is the segment's
-- integrity-chain entry (0 when the segment was never chained, e.g. failed or missing).
CREATE TABLE recording_tombstones (
  segment_id        TEXT PRIMARY KEY REFERENCES recording_segments (id),
  access_session_id TEXT NOT NULL,
  prior_state       TEXT NOT NULL CHECK (prior_state IN ('open', 'finalized', 'interrupted', 'failed', 'missing')),
  chain_seq         INTEGER NOT NULL CHECK (chain_seq >= 0),
  delete_after      INTEGER NOT NULL,
  deleted_at        INTEGER NOT NULL,
  audit_event_id    TEXT NOT NULL,
  mac               BLOB NOT NULL
) STRICT, WITHOUT ROWID;

-- The latest integrity-chain entry, authenticated separately: mac = HMAC(manifest key,
-- "hallpass/rec/chain-head/v1|" || seq || "|" || hex(hash)). Removing the newest chain entries is detectable because
-- this row then names an entry that no longer exists. It is written in the same transaction as each chain entry,
-- and only while it still matches the chain; a stale or missing row is left alone so verification keeps failing.
-- Chains recorded before this migration have no row until an operator adopts the current head
-- (`hallpass verify --adopt-chain-head`).
CREATE TABLE recording_chain_head (
  id   INTEGER PRIMARY KEY CHECK (id = 1),
  seq  INTEGER NOT NULL CHECK (seq >= 1),
  hash BLOB NOT NULL,
  mac  BLOB NOT NULL,
  at   INTEGER NOT NULL
) STRICT;

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
