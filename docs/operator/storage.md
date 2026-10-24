# Storage

HallPass stores state in a single SQLite database and session content in encrypted recording files, both inside `data_dir`.

```
<data_dir>/                 0700, owned by the hallpass service user
  hallpass.db               SQLite database (WAL mode) + hallpass.db-wal / hallpass.db-shm
  hallpass.lock             process lock (flock); contains the owner PID
  backups/                  pre-migration snapshots (pre-migrate-<from>-<to>-<UTC>.db)
  recordings/               encrypted HPREC1 segments
  quarantine/               orphaned or damaged files moved aside by reconciliation
```

## Supported topology

- **Exactly one** running HallPass per data directory. A second process (or an admin command that mutates state, such as
  `migrate`, `restore` or `admin recover`) fails immediately with `another hallpass process owns this data directory`.
- **Local storage only.** On Linux, startup refuses NFS, SMB/CIFS, FUSE, 9p, Ceph, AFS, GFS2, OCFS2, GPFS and Lustre
  filesystems. SQLite locking and durability are not reliable on them.
- **No clustering.** Independent SQLite files are not a cluster. High availability is cold standby: restore the latest backup
  on a new host (see `docs/operator/backup.md`). Live SSH sessions cannot move between processes, so agents
  reconnect after failover. Their grants remain valid until expiry.

## Durability and concurrency

- Every connection runs `journal_mode=WAL`, `synchronous=FULL`, `foreign_keys=ON`, `busy_timeout=5000`, `trusted_schema=OFF`.
  `synchronous=FULL` makes each commit durable across power loss.
- One writer connection serializes writes with `BEGIN IMMEDIATE`. Busy errors are retried up to 5 times with jittered
  backoff. A read-only pool (`query_only`) serves queries.
- Write transactions never include network I/O, SSH traffic, approval waits or file fsyncs. This is enforced by the `txscope`
  analyzer and by tests that fail any transaction slower than 100 ms.
- The database holds metadata only. Terminal content, command strings and other payloads live in encrypted recording files.

## Migrations and upgrades

- Migrations are embedded in the binary, applied in order at startup (or with `hallpass migrate`), each in its own transaction,
  and forward-only.
- Before applying migrations to an existing database, HallPass writes a `VACUUM INTO` snapshot to `backups/` and keeps the
  last `storage.pre_migration_snapshots` (default 3).
- A failing migration rolls back, leaving the database at the last successful version, and the process exits with the snapshot location.
- A database migrated by a newer HallPass is refused (`database schema is newer than this binary`). Downgrade by restoring
  a backup taken before the upgrade, together with the older binary. Data written after that backup is lost.

## Keeping the database small

The database holds metadata only; session content lives in the recordings directory. Background jobs keep it from
growing without bound:

| Job | Interval | What it does |
|---|---|---|
| `store.wal_checkpoint` | 5 minutes | Returns up to 2048 free pages (about 8 MiB) to the filesystem, then truncates the WAL. |
| `store.purge_finished` | hourly | Deletes delivered and dead notifications after 30 days and finished background jobs after 7 days. |
| `recording.retention` | 10 minutes | Deletes recordings past their retention class. |
| `auth.purge_expired` | 15 minutes | Deletes expired sessions, tokens and login state. |

`hallpass_store_db_bytes` and `hallpass_store_wal_bytes` report the file sizes; see [observability.md](observability.md).

## Failure behavior

| Condition | Behavior |
|---|---|
| Disk full | New requests and sessions are refused (fail closed), readiness reports `degraded`. Sessions that can no longer record are terminated. |
| I/O errors | `degraded`, and `failed` after repeated errors. Investigate the disk before restarting. |
| Corruption | Startup refuses with `storage corrupt`. Restore the latest verified backup. A full `integrity_check` also runs in maintenance. |
| Crash or power loss | SQLite WAL recovery at next start. Committed transactions survive. Interrupted sessions are reconciled. |
| Wrong permissions | Startup refuses data directories accessible by group or others, or owned by another user. |

## What the database reveals

Sensitive columns (reasons, secrets, private keys, TOTP seeds, provider tokens) are encrypted by HallPass, and tokens are hashed.
Inventory (aliases, addresses, usernames), policy, identities and timestamps are stored in plaintext. Anyone who can read
the database file or its backups learns your access topology and history. Use full-disk encryption for `data_dir` and protect
backups accordingly.
