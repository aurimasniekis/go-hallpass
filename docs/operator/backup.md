# Backup, restore, anchors and break-glass

This page covers backups (HP-OPS-003), restore onto a clean host (HP-OPS-004), upgrade rollback (HP-OPS-005), recovery
objectives (HP-DB-014), master-key loss (HP-CRY-007), external integrity anchors (HP-CRY-008), ciphertext-only archival
(HP-CRY-009) and break-glass administrator recovery (HP-AUTH-016). Design: PLAN §4.4, §13.8, §13.10, §18.5–18.16 and ADR-0023.

> **Losing the KEK loses the data.** Every sealed database field, every recording key and every integrity MAC depends on the
> master key (KEK). Backups never contain it. If the KEK is lost, no backup can be read, and neither HallPass nor anyone else
> can recover the data. Keep at least two offline copies of the KEK, stored separately from data backups and under stricter
> access control (see `keys.md`).

## What a backup contains

`hallpass backup create --out DIR` writes a new directory:

```
DIR/                                  0700
  manifest.json                       0600  every file with size and SHA-256, schema version, kek_id, chain head
  manifest.sha256                     0600  SHA-256 of manifest.json (sha256sum format)
  hallpass.db                         0600  consistent VACUUM INTO snapshot of the database at time T
  recordings/<shard>/<session>/*.hprec 0600  recording segments referenced by the snapshot, byte for byte
  recordings/.../*.hprec.partial      0600  segments still being written at T ("open_at_snapshot" in the manifest)
```

| Included | Not included |
|---|---|
| Database snapshot: inventory, policy, agents, grants, sessions, audit log, keyring (purpose keys **wrapped** by the KEK), gateway host key (sealed) | **The KEK** (`kek.file`, `HALLPASS_KEK`, or a development `dev-kek`) |
| Finalized and interrupted recording segments as ciphertext, including their wrapped data keys | Configuration file, TLS certificates, systemd/compose files |
| Partial files of segments open at T | `quarantine/` (orphans and pre-truncation copies kept for investigation; copy it yourself if needed) |
| Manifest with `kek_id`, schema version, binary version, chain head | `backups/` (pre-migration snapshots), `hallpass.lock`, WAL/SHM files |

Segments are copied exactly as stored. Nothing is decrypted, and restoring requires the KEK (HP-CRY-009). The manifest's
`kek_id` (a non-secret identifier derived from the KEK) lets restore check that the right key is supplied.

A backup still reveals plaintext metadata: server aliases, addresses, remote usernames, policy, identities and timestamps
(see `storage.md`). Protect backups like the live data directory: restricted access, encryption at rest, separate media.

## Creating backups

```
hallpass backup create --config /etc/hallpass/hallpass.yaml --out /backup/hallpass/$(date -u +%Y%m%dT%H%M%SZ)
```

- **Online and lock-free.** It opens the database read-only and runs `VACUUM INTO` inside a WAL read transaction. The server keeps
  running and its writer is never blocked. Run it as the HallPass service user.
- **Consistent.** The database is snapshotted first. Segment files are then copied according to the snapshot's view, so
  recordings created after T are excluded, exactly as the database excludes them. For each finalized or interrupted segment,
  the header and ciphertext hashes are checked against the snapshot while copying.
- **Atomic.** The backup is assembled in a hidden sibling directory, fsynced and renamed into place. `DIR` either holds a
  complete backup or does not exist. `DIR` must not exist yet.
- Segments open at T are copied as their current `.partial` file and flagged. After a restore, startup reconciliation keeps the
  authentic prefix and marks them `interrupted`.
- A segment file that is missing, or that does not match the database, is recorded in the manifest (`segments.missing`,
  `files[].problem`) instead of aborting the backup. The command prints it and exits with code 3. Run `hallpass verify` on the
  source to investigate.
- Segment files are read only at their canonical location `recordings/<shard>/<session>/<segment>.hprec`, derived from the
  IDs. A row whose stored path is anything else aborts the backup.
- The manifest's `kek_id` is the KEK that wraps the keys a restore loads. Retired key versions are ignored, so a retired
  key left under an older KEK does not block backups after `hallpass keys rotate-kek`.

Exit codes: `0` ok, `1` error, `2` usage, `3` written with problems (create) or verification failed (verify, restore).

### Schedule

- **Hourly** `hallpass backup create` to a separate volume, plus an **off-host copy** (rsync/object storage) after each run.
  The host-loss RPO equals this interval.
- Optionally **sync finalized segments continuously** (`rsync` of `recordings/**/*.hprec`, excluding `*.partial`). Finalized
  files never change, apart from rare key-slot rewraps after purpose-key rotation, which a later backup picks up. This keeps
  recording loss well below the backup interval. The database snapshot is still what makes a set restorable.
- Run `hallpass backup verify` on the newest backup after each run, and on the off-host copy daily.
- Expire old backups deliberately. Recordings deleted by retention (HP-REC-013) remain in older backups until those expire.
  Keep backups no longer than your recording retention requires, and keep a KEK as long as any backup made with it.
- Back up again right after `hallpass keys rotate-kek`, and before every upgrade.

## Verifying a backup

```
hallpass backup verify /backup/hallpass/20261023T120000Z
```

Verify needs no KEK and no data directory. It checks:

1. `manifest.json` against `manifest.sha256`, format and version, and that the manifest does not claim to contain a KEK.
2. Size and SHA-256 of every listed file. Missing files, unlisted files, symlinks and paths outside `recordings/` are problems.
3. `PRAGMA integrity_check` on the database copy, and that its schema version, `kek_id` and integrity-chain head match the manifest.
   A schema newer than the running binary is reported.
4. The integrity-chain hash links (`hash = SHA-256(prev_hash || manifest_sha256)`) from seq 1 to the head.
5. Every segment file against the header hash and ciphertext hash recorded in the database copy, and that every segment
   that should have a file is either present or recorded as missing at backup time.
6. Paths: every `recording_segments` row must name its canonical location under the source's `recordings/` directory, its
   IDs must be well-formed, and its file in the backup must sit at the matching `recordings/<shard>/<session>/<segment>.hprec`
   path. A database copy that points a segment anywhere else (for example at the KEK file) is refused, even when the
   manifest was recomputed to match.
7. Warnings (not restore blockers, `hallpass verify` reports them after restore): a `deleted` segment without a retention
   tombstone, and an integrity-chain head record that is missing or does not name the newest chain entry.

Limits: `manifest.sha256` detects accidental damage, not a deliberate rewrite of manifest and files together. The checks in
steps 3–5 bind files to the database copy, and **MAC verification needs the KEK**. Full authenticity is established by
`hallpass verify` after a restore, and by comparing the chain with external anchors (below).

## Restore and disaster recovery (PLAN §18.8)

On a new or clean host:

1. Install the same or a newer HallPass binary. An older binary refuses a newer schema.
2. Provide the KEK the backup was made with (`kek.file`, mode 0400, outside the data directory). Restore refuses to run without
   a configured KEK, and refuses a KEK whose ID differs from the backup's `kek_id`.
3. Restore into an empty data directory. The server must be stopped, because restore takes the data-directory lock:
   ```
   hallpass restore --config /etc/hallpass/hallpass.yaml /backup/hallpass/20261023T120000Z
   # or into another directory: --data /var/lib/hallpass
   ```
   Restore verifies the backup first, copies every file into a staging directory inside the data directory while re-hashing it
   against the manifest, rewrites every recording path to the segment's canonical location in the new data directory
   (derived from its IDs), renames everything into place, and finally checks that the KEK unlocks the restored keyring
   (canary). It needs no network access.
   A target that already holds data is refused. `--force` moves the existing database, `recordings/` and `quarantine/` to
   `backups/pre-restore-<time>/` inside the data directory. Nothing is deleted.
4. `hallpass verify --config …` authenticates every segment, including key slots, frames and integrity-chain MACs.
5. Start `hallpass serve`. Reconciliation marks segments that were open at backup time as interrupted, and marks
   connections and channels from the old process as interrupted.
6. Compare the chain head with your external anchors (`hallpass anchors verify`), then repoint DNS/VIP for SSH and HTTPS.
   Agents see the same gateway host key, because it is restored from the encrypted database.

### Recovery objectives (HP-DB-014)

| Event | RPO | RTO |
|---|---|---|
| Process crash, OS crash, power loss | 0 for committed transactions (`synchronous=FULL`). Recordings: ≤ 250 ms in `group` mode, 0 in `strict` mode | Restart time |
| Host or disk loss | Last backup (hourly recommended). Less for recordings with continuous segment sync | Target ≤ 15 min for a 10 GiB data set on the reference hardware |

The RTO target **has not yet been measured** on the reference hardware. Record your own drill timings.

### Restore drill (quarterly)

1. Take a backup on the production host, or use last night's.
2. On a scratch host or container with the same binary and a copy of the KEK, run `hallpass backup verify`, `hallpass restore`
   and `hallpass verify` against a scratch data directory. Time it.
3. Start the restored instance on non-production ports. Check `/readyz`, an operator login and replay of a recording.
4. Destroy the scratch copy (it contains production metadata) and record the drill result and duration.

## Upgrade and rollback (PLAN §18.5, HP-OPS-005)

1. Read the release notes. Take a backup (`hallpass backup create`) and verify it.
2. Stop the server and replace the binary or image.
3. Start. Pending migrations run under the lock after an automatic `VACUUM INTO` snapshot in `backups/pre-migrate-<from>-<to>-<UTC>.db`.
4. Check `/readyz` and run `hallpass verify`.

Migrations are forward-only. **Rollback** = stop, restore the pre-upgrade backup with the previous binary
(`hallpass restore --force …`). Data written after the upgrade is lost. Never run an older binary on a newer schema: it refuses to start.

## Litestream (optional, R-04)

[Litestream](https://litestream.io) can continuously replicate `hallpass.db` to object storage to shrink the database RPO.
It is **optional and not a high-availability mode**: there is still exactly one active HallPass per data directory, and failover
is a cold restore. Caveats:

- Litestream replicates only the database. Recordings still need `hallpass backup` or continuous segment sync, and a replica
  whose recordings are older than its database restores with `missing` segments.
- HallPass runs `PRAGMA wal_checkpoint(TRUNCATE)` every 5 minutes. Compatibility with Litestream's checkpoint handling has
  **not yet been tested** (R-04 open). Treat Litestream as an addition to, never a replacement for, `hallpass backup`.
- A Litestream restore must go into an empty data directory, and needs the same KEK and the recordings directory.

## External integrity anchors (HP-CRY-008)

Each finalized or reconciled segment appends an entry to the integrity chain: `hash = SHA-256(prev_hash || manifest_sha256)`,
MACed with the manifest key. Someone who holds the KEK and can write the data directory can rewrite segments, chain entries and
MACs consistently. Exported anchors stored where the gateway cannot alter them close that gap for history up to the latest anchor.

```
# Ship new chain heads, e.g. every 15 minutes (read-only, safe while the server runs):
LAST=$(tail -n1 anchors.jsonl 2>/dev/null | jq -r .seq || echo 0)
hallpass anchors export --since "${LAST:-0}" >> anchors.jsonl
aws s3 cp anchors.jsonl s3://audit-bucket-with-object-lock/hallpass/anchors-$(date -u +%Y%m%dT%H%M%SZ).jsonl

# Later, or after an incident or a restore:
hallpass anchors verify anchors.jsonl        # exit 3 on any mismatch
```

Each line is `{"seq":N,"hash":"<hex>","at":"<RFC 3339>"}`. Export refuses to anchor a chain whose links are already broken.
Verify reports:

- an anchored `seq` that is missing locally (history truncated or deleted),
- a local hash that differs from the anchor (history rewritten, even when every link was recomputed),
- broken links up to the latest anchor,
- a segment whose current metadata no longer reproduces its chain entry,
- a `deleted` segment without a matching retention tombstone (the tombstone's MAC needs the keys and is checked by
  `hallpass verify`),
- a chain-head record that does not name the newest local chain entry (newest entries removed).

It **cannot** protect entries written after the latest anchor, data written after a compromise, or deletion of not-yet-anchored
history. Ship anchors often, to storage with object lock/WORM, a transparency log, or a separate log host. A built-in scheduled push is not in v1.

## Break-glass administrator recovery (PLAN §18.16, HP-AUTH-016)

Use this when no administrator can sign in (lost MFA, disabled SSO, departed staff). It works even when password login is
disabled, and it has **no remote equivalent**: it needs shell access on the host, the KEK and the data-directory lock.

1. Stop the server (`systemctl stop hallpass` or stop the container). The command takes the lock and refuses while the server runs.
2. Issue a recovery login for an existing operator, or create a new local administrator:
   ```
   hallpass admin recover --config /etc/hallpass/hallpass.yaml --email alice@example.com
   hallpass admin recover --config /etc/hallpass/hallpass.yaml --email breakglass@example.com --new-admin
   ```
   A disabled operator is re-enabled. The command prints a single-use `<public_url>/recover?token=…` link and the token,
   valid for 30 minutes and shown only once. Its issue is audited as `breakglass.used` (actor `cli`).
3. Start the server, open the link and choose **Use recovery login**. Nothing is redeemed until you confirm, so link
   scanners cannot use up the token. The page calls `POST /api/v1/auth/recover`, which:
   - accepts the token once and only before it expires; wrong, used or expired tokens are refused with one generic error,
     audited as `breakglass.login.failed` and throttled per source address (like password logins), and the endpoint is
     under the strict per-IP limit for `/api/v1/auth` and the same-origin check of every mutation;
   - ends every other session of the account and removes its TOTP factor and recovery codes (they may be lost or
     compromised), then signs you in with a `breakglass` session (12 hours at most, idle timeout as usual). The use is
     audited as `breakglass.login`;
   - when policy requires MFA for the account (administrators and approvers with a password), keeps the session limited
     until you enroll a new authenticator on the page;
   - for accounts with a local password, returns a one-time password reset link (1 hour). A `--new-admin` account has a
     random password that is never shown, so set one with this link. Using the link ends every session of the account,
     including the break-glass one, so finish urgent work (for example re-enabling password login or fixing the identity
     provider) first. With password login disabled you can sign in again only with SSO or another break-glass login.
   - Changes that need recent authentication (provider and auth settings, operators, keys) work for 5 minutes after the
     redemption; after that the break-glass session re-authenticates with the account's password and new authenticator.
4. Review the audit log, rotate credentials as needed, acknowledge the break-glass alert (raised at every start until
   acknowledged), and disable or remove a break-glass account created with `--new-admin`.

First-time setup uses the same offline path: `hallpass admin bootstrap` prints a one-time `/setup?token=…` link (30 minutes,
single use, refused once an administrator exists).

## Related incident procedures

- **Corruption (§18.15):** stop, run `hallpass verify` and keep its report, restore the latest good backup, start (reconciliation runs).
- **Suspected gateway compromise (§18.13):** enable lockdown, isolate the host, rotate destination login credentials and
  the gateway host key, create a new KEK, restore a pre-compromise backup on a clean host, then compare chain heads with external anchors.
- **Suspected agent compromise (§18.12):** revoke the agent's keys or disable it, review its sessions and recordings, rotate
  destination credentials it could reach, and export anchors immediately.
