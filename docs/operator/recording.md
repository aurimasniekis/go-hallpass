# Recording operations

Every destination channel is recorded. Recording is mandatory by default (ADR-0019): a session does not start until its
recording is established, and a session whose recording cannot be written is terminated (exit 80 to the agent). The
format is HPREC1 ([formats/hprec1.md](../formats/hprec1.md)), with one encrypted file per segment under
`<data_dir>/recordings/<shard>/<session>/<segment>.hprec` (`<shard>` is the last two characters of the session ID).
Reconciliation, verification, replay, the plaintext export, retention, key-slot maintenance, backup and restore derive
this location from the segment and session IDs and never use the `path` column for file I/O, so a modified row cannot
point them at a file outside `recordings/`. **Not yet covered:** the ciphertext bundle export
(`GET /api/v1/access-sessions/{id}/export`, default `format=bundle`) still reads the stored path (security review SR-16
follow-up).

## Configuration (`recording:`)

| Key | Default | Meaning |
|---|---|---|
| `durability` | `group` | `group`: fsync at most every `flush_interval` (≤ 250 ms of output can be lost in a crash). `strict`: fsync every record before it is forwarded (slower). |
| `flush_interval` | `250ms` | Group-commit interval (maximum 250 ms). |
| `segment_max_bytes` | 64 MiB | Roll over to a new segment at this size. |
| `segment_max_age` | `1h` | Roll over to a new segment at this age. |
| `queue_records`, `queue_bytes` | 1024, 1 MiB | Bounded queue between the session and the writer. When full, the session is slowed (SSH window backpressure), never dropped. |
| `block_timeout` | `10s` | How long a full queue may block before the recording is declared failed. |
| `retention_classes` | – | Per-class overrides, `class=duration` entries matched to the role's `retention_class`, e.g. `["sensitive=8760h"]`. |
| `default_retention` | `2160h` (90 days) | Time after a session closes before its recordings are deleted (tombstones remain). |

Terminal input is not recorded unless a role enables `record_input`.

## Verification

```
hallpass verify [--session ses_…] [--json] [--adopt-chain-head] --config /etc/hallpass/config.yaml
```

`verify` takes the data-directory lock, so stop the server first (or run it against a restored copy). It checks:

- **Every segment file against the database:** the header hash, a key slot that unwraps, every frame, the ciphertext hash
  and, for finalized segments, the final frame. Files are read only at their canonical location. A row whose stored path
  differs from that location is reported `corrupt`.
- **The integrity chain:** contiguous sequence numbers, hash links and the MAC of every entry.
- **The chain against the segment rows.** For every chain entry, the manifest is recomputed from the segment's current row:
  IDs, header and ciphertext hashes, frame, byte and record counts, sequence range and state. A row that was changed,
  relabeled (for example `finalized` to `interrupted`, `failed`, `open` or `deleted`) or removed after it was chained is
  `corrupt` (or `missing` for a removed row). Every `finalized` or `interrupted` row must have a chain entry.
- **Deletions.** A `deleted` segment must have a retention tombstone (see [Retention](#retention)) whose MAC verifies, that
  matches its chain entry, records a deletion after the session's retention time, and refers to the `recording.deleted`
  audit event. A row merely set to `deleted` is `corrupt`.
- **The chain head.** Each chain entry also updates a separately MACed head record (seq and hash of the newest entry). If the
  newest entries are removed together with their segments, the head record names an entry that no longer exists and the
  chain fails. A missing, modified or stale head record is never repaired by new recordings: it keeps failing until an
  operator adopts the current head.

Exit 0 means everything verified. Exit 3 means at least one segment is `corrupt` or `missing`, or the chain failed. The
output ends with the chain head (`seq` and hash) to compare with exported anchors (`hallpass anchors verify`).

Statuses: `ok`; `interrupted` (an authentic prefix without a final frame, from a crash or an operator abort);
`corrupt` (authentication failed, or the file, row, chain entry or tombstone disagree); `missing`; `skipped` (deleted by
retention with a valid tombstone, failed, or still being written).

**What this protects against.** A party who can write the database and the recording files but holds no keys cannot hide,
truncate, remove or relabel a finalized segment, or remove the newest chain entries, without `verify` failing. Limits:

- A key holder (KEK or the manifest purpose key) can rewrite everything consistently. Only external anchors detect that, and
  only for history up to the latest exported anchor (HP-CRY-008, `backup.md`).
- Restoring an older copy of the database together with its files (a rollback) is self-consistent. Compare the chain head
  with your newest anchor after every restore.

**Adopting the chain head.** Databases with recordings made before schema version 19 have no head record, and `verify`
reports `integrity chain head record is missing`. After you have compared the chain head printed by `verify` with your newest
exported anchor (or decided that you accept the current chain), run `hallpass verify --adopt-chain-head` once. It checks
every link and MAC, records the current newest entry as the authenticated head and writes a `recording.chain_head_adopted`
audit event. Use the same command only after investigating a reported head mismatch: adopting a truncated chain accepts the
truncation.

## Crash reconciliation

At startup, before accepting connections, HallPass:

1. Verifies final files whose row is still `open` and records them as `finalized`. This covers a crash between the
   rename and the database update. A final file that does not verify (no final frame, a failed frame, or a header that is
   not the one registered for the segment) was changed after the rename: it is moved to
   `<data_dir>/quarantine/<segment>.final.invalid`, recorded in `quarantine_files`, logged as an error, and its segment is
   marked `failed`. It is never added to the integrity chain.
2. Recovers `.partial` files to their last authentic frame and marks them `interrupted`. When trailing bytes are
   discarded, the original file is first copied to `<data_dir>/quarantine/`.
3. Moves `.partial` files whose header or key slots are unusable to quarantine and marks them `failed`.
4. Marks rows with no file on disk as `missing`.
5. Moves files under `recordings/` that are not the canonical file of any row to quarantine as orphans.
6. Repairs key slots: for every finalized or interrupted segment, if a key slot no longer unwraps but the database copy of
   the wrapped segment key does (under that segment's own associated data), the copy is written into the unusable slot
   (PLAN §13.4). This also refreshes a slot that only holds a retired recording key. Repairs and segments whose slots could
   not be checked are logged; `verify` reports any segment that still cannot be read.
7. Leaves alone, and logs, an `open` row that already has an integrity-chain entry (relabeled after finalization);
   `verify` reports it.

Quarantined files are listed in the `quarantine_files` table with a reason. Review them and delete them manually.
HallPass never deletes quarantined data.

## Export

Operators with `recording.export` (Administrator by default) can export a session's decrypted recordings as JSON
(`GET /api/v1/access-sessions/{id}/export`). This requires recent authentication and MFA, is limited to 64 MiB of payload,
and is audited (`recording.exported`). Playback in the UI uses `recording.play` and is audited per page
(`recording.played`).

## Retention

A background job runs every 10 minutes. It gives each closed session `delete_after = closed_at + default_retention`
(or the role's retention class), then, for sessions past `delete_after`, deletes the recording files at their canonical
location, marks the segments `deleted` and clears timeline payloads. Rows and integrity-chain entries are kept, so
verification still proves what existed.

Each deletion writes, in the same transaction as the `deleted` mark:

- a hash-chained audit event `recording.deleted` (actor `system`, target the segment, with the session, the prior state,
  the chain entry and `delete_after`);
- a retention tombstone in `recording_tombstones`: segment, session, prior state, chain entry, `delete_after`, deletion
  time and the audit event ID, MACed with the manifest key.

`verify` and `anchors verify` accept a `deleted` segment only with its tombstone (`verify` also checks the MAC and the audit
event). Recordings deleted before schema version 19 have no tombstone and are reported as `corrupt`; check them against
your audit log and anchors. Backups taken earlier still contain deleted recordings until they expire (`backup.md`).
