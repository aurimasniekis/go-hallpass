# Upgrades

An upgrade is a binary or image swap. Pending database migrations run at startup, after an automatic snapshot.
Reference: [upgrade.md](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/operator/upgrade.md) and the
[versioning policy](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/VERSIONING.md).

::: info Status
No version has been released yet, so an upgrade from a previous release has never been exercised.
:::

## Rules

- **Migrations are forward-only.** Before migrating, HallPass writes a consistent snapshot to
  `<data_dir>/backups/pre-migrate-<from>-<to>-<UTC>.db` and keeps the newest three
  (`storage.pre_migration_snapshots`).
- **Never run an older binary on a newer database.** It refuses to start; do not work around this.
- **Rollback means restoring** a backup or snapshot taken before the upgrade, with the previous binary. Anything written
  after it is lost.
- The KEK does not change during an upgrade. Keep it available.

## Before

1. Read the release notes and the [changelog](https://github.com/aurimasniekis/go-hallpass/blob/main/CHANGELOG.md).
2. Verify the new artifacts (checksums and `gh attestation verify`).
3. `hallpass backup create --out DIR` and `hallpass backup verify DIR`.
4. Check you have an offline KEK copy matching `hallpass keys status`.

## systemd

```sh
systemctl stop hallpass
install -m 0755 -o root -g root hallpass_NEW/hallpass /usr/local/bin/hallpass.new
mv /usr/local/bin/hallpass /usr/local/bin/hallpass.prev
mv /usr/local/bin/hallpass.new /usr/local/bin/hallpass
sudo -u hallpass hallpass config check --config /etc/hallpass/hallpass.yaml
systemctl start hallpass
curl -s http://127.0.0.1:8080/readyz
```

## Docker Compose

```sh
docker compose stop hallpass
HP_VERSION=NEW docker compose up -d
docker compose logs -f hallpass
```

Pin images by version or digest, never `latest`, so a restart cannot upgrade implicitly.

## Rollback

1. Stop HallPass.
2. Restore the pre-upgrade backup: `hallpass restore --force --config … DIR` (the current data is moved aside).
3. Start the **previous** binary or image.
4. Startup reconciliation marks sessions that were open at backup time as interrupted.
