# Recording operations

Every destination channel is recorded. Recording is mandatory by default (ADR-0019): a session does not start until its
recording is established, and a session whose recording cannot be written is terminated (exit 80 to the agent). The
format is HPREC1 ([formats/hprec1.md](../formats/hprec1.md)), with one encrypted file per segment under
`<data_dir>/recordings/<shard>/<session>/<segment>.hprec`.

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
hallpass verify [--session ses_…] [--json] --config /etc/hallpass/config.yaml
```

`verify` takes the data-directory lock, so stop the server first (or run it against a restored copy). It checks each
segment against the database (header hash, ciphertext hash and a final frame for finalized segments) and walks the
integrity chain (hash links and HMACs). Exit 0 means everything verified. Exit 3 means at least one segment is
`corrupt` or `missing`, or the chain is broken. The output ends with the chain head (`seq` and hash) to compare
with exported anchors. A key holder can rewrite unanchored history (HP-CRY-008); export anchors with `hallpass anchors export`
([backup.md](backup.md)).

Statuses: `ok`; `interrupted` (an authentic prefix without a final frame, from a crash or an operator abort);
`corrupt` (authentication failed or does not match the database); `missing`; `skipped` (deleted, failed or still being
written).

## Crash reconciliation

At startup, before accepting connections, Hallpass:

1. Verifies final files whose row is still `open` and records them as `finalized`. This covers a crash between the
   rename and the database update.
2. Recovers `.partial` files to their last authentic frame and marks them `interrupted`. When trailing bytes are
   discarded, the original file is first copied to `<data_dir>/quarantine/`.
3. Moves `.partial` files whose header or key slots are unusable to quarantine and marks them `failed`.
4. Marks rows with no file on disk as `missing`.
5. Moves files under `recordings/` that no row references to quarantine as orphans.

Quarantined files are listed in the `quarantine_files` table with a reason. Review them and delete them manually.
Hallpass never deletes quarantined data.

## Export

Operators with `recording.export` (Administrator by default) can export a session's decrypted recordings as JSON
(`GET /api/v1/access-sessions/{id}/export`). This requires recent authentication and MFA, is limited to 64 MiB of payload,
and is audited (`recording.exported`). Playback in the UI uses `recording.play` and is audited per page
(`recording.played`).

## Retention

A background job runs every 10 minutes. It gives each closed session `delete_after = closed_at + default_retention`,
then deletes the recording files of expired sessions, marks their segments `deleted` and clears timeline payloads.
Rows and integrity-chain entries are kept as tombstones, so verification still proves what existed.
