# Backup and restore

Reference with every detail (manifest format, verification steps, Litestream notes):
[backup.md](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/operator/backup.md).

::: danger The KEK is not in the backup
A backup contains the database (with keys **wrapped** by the KEK) and the encrypted recordings. It never contains the
KEK. Without the matching KEK a backup cannot be restored. Keep KEK copies offline, separately from backups.
:::

## Backups to object storage

HallPass can back itself up to any S3-compatible bucket (AWS S3, Cloudflare R2, MinIO, Backblaze B2, Wasabi and others)
on a schedule. Set it up under **Administration → Backups** (or with the Terraform `hallpass_backup_target` resource):

- **Endpoint, region, bucket, prefix** and an **access key** that may list, read, write and delete below the prefix. Use
  a bucket and a key for HallPass alone. The secret is stored encrypted and never shown again.
- **Schedule**, every 15 minutes to once a week (default hourly). A failed backup is retried within 15 minutes.
- **Retention**: the newest backups (default 48) plus the newest of each past day (default 30 days).

<Shot name="backups" alt="The Backups page with an S3-compatible target, its schedule and retention, and a successful backup" />

Each backup is a database snapshot plus the recordings it refers to. The snapshot and its file list are encrypted on
the server before upload, with a key protected by the KEK. Recordings are already encrypted and are uploaded once,
then shared by later backups. The bucket only ever holds ciphertext, but object names and sizes show how many
recordings there are and when they were made.

The page shows every run, its size and any error, and has **Test connection** and **Back up now**. Watch
`hallpass_backup_remote_last_success_timestamp_seconds` in your monitoring.

Turn on versioning or object lock in the bucket if you can: then a stolen access key cannot delete your backups for
good.

### Restore from object storage

On a new host with HallPass installed, its configuration and the **KEK**:

```sh
export AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=…   # a key that may read the bucket
FLAGS="--s3-endpoint https://s3.eu-central-1.amazonaws.com --s3-region eu-central-1 --s3-bucket acme-backups --s3-prefix hallpass/"
hallpass backup remote-list $FLAGS
hallpass backup remote-download --config /etc/hallpass/hallpass.yaml --out /var/tmp/hp-restore $FLAGS   # newest by default
hallpass backup verify /var/tmp/hp-restore
hallpass restore --config /etc/hallpass/hallpass.yaml /var/tmp/hp-restore
```

Add `--backup <id>` to pick an older backup, `--s3-path-style` for MinIO, and `--s3-allow-private-network` for a
bucket on your own network. The download checks every file, so a tampered or truncated object is refused.

## Create a backup on disk

```sh
hallpass backup create --config /etc/hallpass/hallpass.yaml --out /backup/hallpass/$(date -u +%Y%m%dT%H%M%SZ)
hallpass backup verify /backup/hallpass/<that directory>
```

- **Online.** It runs while the server serves, without blocking it. Run it as the service user.
- **Consistent.** The database is snapshotted first; recordings are copied according to that snapshot.
- **Atomic.** The directory either holds a complete backup or does not exist.
- Exit codes: `0` ok, `1` error, `2` usage, `3` written with problems (or verification failed).

A backup still holds plaintext metadata (aliases, addresses, policy, identities). Protect it like the live data.

## Schedule

- Backups to object storage (above) run on their own. Without them: hourly `hallpass backup create` to a separate
  volume, then an off-host copy.
- `hallpass backup verify` on the newest backup after each run, and on the off-host copy daily.
- Back up again after `hallpass keys rotate-kek` and before every upgrade.
- Expire old backups deliberately: recordings deleted by retention remain in older backups.

## Restore

On a clean host with the same or a newer binary and the KEK the backup was made with:

```sh
hallpass restore --config /etc/hallpass/hallpass.yaml /backup/hallpass/20261023T120000Z
hallpass verify --config /etc/hallpass/hallpass.yaml
```

Restore takes the data-directory lock (stop the server first), verifies the backup, refuses a mismatched KEK, and
refuses a target that already holds data unless you pass `--force` (which moves the existing data aside; nothing is
deleted). Then start the server and compare the chain head with your exported anchors.

Practice a **restore drill** every quarter on a scratch host and record how long it took.

## Integrity anchors

The integrity chain over recordings detects tampering by anyone without the keys. Someone with the KEK and write
access to the data directory could rewrite history consistently. Exported **anchors**, stored where the gateway cannot
change them, close that gap for everything up to the latest anchor.

```sh
# every 15 minutes, read-only and safe while the server runs
LAST=$(tail -n1 anchors.jsonl 2>/dev/null | jq -r .seq || echo 0)
hallpass anchors export --config /etc/hallpass/hallpass.yaml --since "${LAST:-0}" >> anchors.jsonl
# ship anchors.jsonl to storage with object lock / WORM

# after an incident or a restore
hallpass anchors verify --config /etc/hallpass/hallpass.yaml anchors.jsonl   # exit 3 on any mismatch
```

Entries written after the latest anchor are not protected, so ship anchors often.

## Recovery objectives

| Event | Data loss | Recovery time |
|---|---|---|
| Process or OS crash, power loss | None for committed transactions; recordings lose at most 250 ms in `group` mode, nothing in `strict` mode | Restart |
| Host or disk loss | Since the last backup | Restore time. The target is 15 minutes for 10 GiB on reference hardware, which **has not been measured yet**. One local drill (non-reference hardware, 349 MiB) went from restore start to ready in about 7 seconds. |
