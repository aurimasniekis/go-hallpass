# Backup and restore

Reference with every detail (manifest format, verification steps, Litestream notes):
[backup.md](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/operator/backup.md).

::: danger The KEK is not in the backup
A backup contains the database (with keys **wrapped** by the KEK) and the encrypted recordings. It never contains the
KEK. Without the matching KEK a backup cannot be restored. Keep KEK copies offline, separately from backups.
:::

## Create a backup

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

- Hourly `hallpass backup create` to a separate volume, then an off-host copy.
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
