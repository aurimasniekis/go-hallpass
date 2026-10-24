# Upgrade and rollback

HallPass upgrades are a binary or image swap. The database schema is migrated at startup (PLAN §18.5, ADR-0023,
HP-OPS-005). Versioning rules are in [../VERSIONING.md](../VERSIONING.md).

> **Status.** Forward-only migrations, the automatic pre-migration snapshot, the newer-schema refusal
> ([storage.md](storage.md)), `hallpass backup`/`restore` ([backup.md](backup.md)) and `/readyz` are implemented. No
> version has been released yet, so an upgrade from a previous release has never been exercised (release gate RG-7).

## Rules

- **Migrations are forward-only.** There are no down migrations. Each migration runs in its own transaction.
- **A pre-migration snapshot is automatic.** Before applying migrations to an existing database, HallPass writes a
  consistent `VACUUM INTO` copy to `<data_dir>/backups/pre-migrate-<from>-<to>-<UTC>.db` and keeps the newest
  `storage.pre_migration_snapshots` (default 3). A failed migration rolls back and the process exits, naming the snapshot.
- **Never run an older binary on a newer schema.** It refuses to start with `database schema is newer than this binary`.
  Do not work around this.
- **Rollback = restore a snapshot or backup taken before the upgrade, with the previous binary.** Everything written after
  that snapshot is lost: requests, grants, sessions, audit events and recording metadata. Recording files written after the
  snapshot are not referenced by the restored database.
- **The KEK does not change during an upgrade.** Keep it available; snapshots and backups are useless without it.

## Before upgrading

1. Read the release notes and the `CHANGELOG.md` entry, especially **Security** and any breaking-change notes.
2. Verify the new artifacts (checksums and `gh attestation verify`, see [install.md](install.md#release-artifacts)).
3. Take a full backup to a location outside the data directory and the host:
   - `hallpass backup create --out DIR` (online and consistent, see [backup.md](backup.md)), then
     `hallpass backup verify DIR`.
   - Alternatively, stop HallPass and copy the entire data directory (database, `-wal`/`-shm` files, `recordings/`,
     `backups/`) while it is stopped, preserving modes and ownership (`cp -a` or `tar --numeric-owner`).
     Copying a live data directory is not safe.
4. Confirm you have an offline copy of the KEK that matches `hallpass keys status` (KEK id).

## Upgrade (systemd)

```sh
systemctl stop hallpass                       # SIGTERM: drains for up to shutdown.drain_timeout
install -m 0755 -o root -g root hallpass_NEW_linux_amd64/hallpass /usr/local/bin/hallpass.new
mv /usr/local/bin/hallpass /usr/local/bin/hallpass.prev   # keep the previous binary for rollback
mv /usr/local/bin/hallpass.new /usr/local/bin/hallpass
sudo -u hallpass hallpass config check --config /etc/hallpass/hallpass.yaml
sudo -u hallpass hallpass migrate --config /etc/hallpass/hallpass.yaml   # optional: migrate now and see the result
systemctl start hallpass
journalctl -u hallpass -o cat | grep -E 'migration|serving|error'
```

Running `hallpass migrate` explicitly is optional: `serve` applies pending migrations at startup the same way. It prints
`database schema at version N (binary supports N)`.

Afterwards, check `GET /readyz`. `hallpass verify` authenticates every recording segment; it takes the data-directory
lock, so run it in a maintenance window or against a restored copy.

## Upgrade (container / Compose)

```sh
docker compose stop hallpass                  # stop_grace_period 45 s covers the 30 s drain
HP_VERSION=NEW docker compose up -d
docker compose logs -f hallpass
```

Pin images by version (or digest), never by `latest`, so a restart cannot upgrade implicitly.

## Rollback

Rollback restores state from before the upgrade. Data written after it is lost.

1. Stop HallPass.
2. Choose the restore source:
   - the full backup from "Before upgrading" (preferred), or
   - the automatic snapshot `<data_dir>/backups/pre-migrate-<from>-<to>-<UTC>.db` for this upgrade.
3. Restore:
   - **`hallpass backup` backup:** `hallpass restore --force --config … DIR` moves the current data aside and restores
     with manifest and KEK checks ([backup.md](backup.md)).
   - **Copied data directory:** move the current data directory aside and copy the backup back with its modes and ownership.
   - **Pre-migration snapshot:** move `hallpass.db`, `hallpass.db-wal` and `hallpass.db-shm` aside **together** (a stale
     WAL must never be applied to a different database file), then copy the snapshot to `hallpass.db`, owned by the
     service user with mode `0600`.
4. Reinstall the previous binary or image (`/usr/local/bin/hallpass.prev`, or the previous `HP_VERSION`).
5. Start it and check the logs. Startup reconciliation marks sessions that were open at the snapshot as interrupted.
   Recording files that the restored database does not reference are moved to `quarantine/` by reconciliation.
6. Keep the moved-aside newer database until you are sure it is not needed, then delete it securely.

## Supported upgrade paths

Upgrades are supported from the previous minor release of the same major version, in order. Skipping versions is
supported only when the release notes say so. Downgrades are only possible by restoring a pre-upgrade backup, as above.
