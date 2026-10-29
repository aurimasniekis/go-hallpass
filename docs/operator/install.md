# Installation

This page covers the standalone (systemd) install, the container image, and Docker Compose.
Container details are in [container.md](container.md). Upgrades and rollback are in [upgrade.md](upgrade.md).

> **Releases** are listed at <https://github.com/aurimasniekis/go-hallpass/releases>. The examples use `X.Y.Z`; the
> current version is 0.7.3. Read the known limitations in [../security-guarantees.md](../security-guarantees.md) and the
> [CHANGELOG](../../CHANGELOG.md) before deploying.

## Release artifacts

Each `vX.Y.Z` release provides:

| Artifact | Content |
|---|---|
| `hallpass_X.Y.Z_linux_amd64.tar.gz`, `…_linux_arm64.tar.gz`, `…_darwin_arm64.tar.gz` | Static `hallpass` binary (`CGO_ENABLED=0`, web UI embedded), `hallpass-collector`, `hallpass-api` (agent-side wrapper for API tools), example config, systemd unit, changelog, LICENSE, NOTICE. darwin is for development only. |
| `hallpass_X.Y.Z_binaries.spdx.json` | SBOM of the shipped binaries (syft, SPDX JSON). |
| `hallpass_X.Y.Z_source.spdx.json` | SBOM of the source tree, including the web UI's locked dependencies. |
| `SHA256SUMS` | SHA-256 of every archive and SBOM. |
| `aurimasniekis/hallpass:X.Y.Z` (Docker Hub), `ghcr.io/aurimasniekis/go-hallpass:X.Y.Z` | One multi-arch image (linux/amd64, linux/arm64) in both registries, distroless, non-root. |

Every archive, SBOM and image carries a GitHub build provenance attestation. Verify before installing:

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify hallpass_X.Y.Z_linux_amd64.tar.gz --repo aurimasniekis/go-hallpass
gh attestation verify oci://docker.io/aurimasniekis/hallpass:X.Y.Z --repo aurimasniekis/go-hallpass
```

Install only artifacts whose checksum and attestation both verify.

## Requirements

- Linux (amd64 or arm64) with a **local** filesystem for the data directory. NFS, SMB/CIFS, FUSE and other network
  filesystems are refused. Use full-disk encryption: the database stores inventory and policy in plaintext
  ([storage.md](storage.md)).
- One HallPass process per data directory. There is no clustering ([storage.md](storage.md)).
- A clock synchronized by NTP with slewing (chrony or systemd-timesyncd), not stepped. Grant expiry, approval-token
  windows and webhook timestamp checks use wall-clock UTC. A backward step lengthens active grants by the size of the
  step.
- Network: agents reach the SSH port (default `2222`). HallPass reaches destination servers on port 22 from addresses you
  pin with `from=` in `authorized_keys` ([../destination/hardening.md](../destination/hardening.md)). The web console port
  (default `8080`) should only be reachable through a TLS-terminating reverse proxy.

## Standalone install (systemd)

All commands run as root unless noted.

### 1. Service user and binary

```sh
useradd --system --home-dir /var/lib/hallpass --no-create-home --shell /usr/sbin/nologin hallpass
tar -xzf hallpass_X.Y.Z_linux_amd64.tar.gz
install -m 0755 -o root -g root hallpass_X.Y.Z_linux_amd64/hallpass /usr/local/bin/hallpass
hallpass version
```

### 2. KEK (master key)

The KEK wraps every encryption key in the database. Generate it once, on the target host:

```sh
install -d -m 0750 -o root -g hallpass /etc/hallpass
hallpass keys init-kek --out /etc/hallpass/kek          # creates the file with mode 0400; refuses to overwrite
chown hallpass:hallpass /etc/hallpass/kek
```

- The KEK file must be `0400` (or `0600`), owned by the service user, and **outside the data directory**. Production mode
  refuses anything else ([keys.md](keys.md)).
- **Back it up now**, offline, in at least two places, separately from data backups. Losing the KEK makes every
  encrypted value and recording unrecoverable. Data backups never contain it.
- Never put the KEK in the configuration file, the data directory, a container image, a Compose file or version control.
  `kek.source: env` (`HALLPASS_KEK`) exists but is discouraged.

### 3. Configuration

```sh
install -m 0640 -o root -g hallpass hallpass_X.Y.Z_linux_amd64/hallpass.example.yaml /etc/hallpass/hallpass.yaml
$EDITOR /etc/hallpass/hallpass.yaml          # set public_url, egress.allow_cidrs, listeners
sudo -u hallpass hallpass config check --config /etc/hallpass/hallpass.yaml
```

The configuration is secret-free by design. Every key is documented in [configuration.md](configuration.md).

### 4. Data directory and schema

The systemd unit creates `/var/lib/hallpass` (`StateDirectory=`, mode `0700`, owned by `hallpass`). To create it and apply
the schema before the first start:

```sh
install -d -m 0700 -o hallpass -g hallpass /var/lib/hallpass
sudo -u hallpass hallpass migrate --config /etc/hallpass/hallpass.yaml
```

HallPass runs with `umask 0077`: files in the data directory are `0600` and directories `0700`. Startup refuses a data
directory or KEK that is accessible to group or others, or owned by another user.

### 5. Service

```sh
install -m 0644 hallpass_X.Y.Z_linux_amd64/hallpass.service /etc/systemd/system/hallpass.service
systemctl daemon-reload
systemctl enable --now hallpass
systemctl status hallpass
journalctl -u hallpass -o cat          # JSON logs (logging.md)
systemd-analyze security hallpass.service
```

The unit ([`deploy/systemd/hallpass.service`](../../deploy/systemd/hallpass.service)) runs as `hallpass` with
`ProtectSystem=strict`, `NoNewPrivileges`, an empty capability set, a system-call filter, private `/tmp` and devices, and
write access only to `/var/lib/hallpass`. Pending migrations run at startup after a pre-migration snapshot. `systemctl stop`
sends SIGTERM, which drains sessions for up to `shutdown.drain_timeout` (30 s) before exiting; the unit allows 45 s.

To listen on port 22 directly, prefer a firewall redirect (`22 → 2222`). Otherwise grant `CAP_NET_BIND_SERVICE` as
described in the unit's comments.

### 6. Gateway host key and first steps

```sh
systemctl stop hallpass                                   # offline commands take the data-directory lock
sudo -u hallpass hallpass hostkey show --config /etc/hallpass/hallpass.yaml --host center
systemctl start hallpass
```

Distribute the `known_hosts` line to agents ([../agent/guide.md](../agent/guide.md)). Then:

- `hallpass admin bootstrap` (offline, like `hostkey show`) prints a one-time `/setup?token=…` link for the first
  administrator (30 minutes, single use).
- Register agents and enroll servers in the web console (§18.4).
- Monitor `GET /readyz` and the Prometheus metrics ([observability.md](observability.md)).
- Schedule `hallpass backup create` to a separate volume plus an off-host copy ([backup.md](backup.md)).

## Container

```sh
docker pull aurimasniekis/hallpass:X.Y.Z
docker run --rm aurimasniekis/hallpass:X.Y.Z version
```

The image runs as UID/GID `65532`, has no shell, keeps data in the `/var/lib/hallpass` volume, reads its configuration
from `/etc/hallpass/hallpass.yaml` (`HALLPASS_CONFIG`), and needs the KEK mounted from **outside** the data volume.
See [container.md](container.md) for KEK provisioning, permissions and a hardened `docker run` command.

## Docker Compose

[`deploy/compose.yaml`](../../deploy/compose.yaml) runs one instance with a named data volume, the KEK as a Compose
secret, a read-only root filesystem, all capabilities dropped and `no-new-privileges`.

```sh
cd deploy
install -d -m 0700 secrets
docker run --rm --user 65532:65532 -v "$PWD/secrets:/out" aurimasniekis/hallpass:X.Y.Z \
  keys init-kek --out /out/hallpass.kek       # or generate it with the release binary
sudo chown 65532:65532 secrets/hallpass.kek && sudo chmod 0400 secrets/hallpass.kek
cp examples/hallpass.container.yaml hallpass.yaml && $EDITOR hallpass.yaml
HP_VERSION=X.Y.Z HP_CONFIG_FILE=./hallpass.yaml docker compose up -d
docker compose logs -f
```

The `docker run … init-kek` form needs `secrets/` to be writable by UID 65532 (`sudo chown 65532 secrets` first), or
generate the KEK with the release binary on the host. Back up `secrets/hallpass.kek` offline before continuing.
Compose variables use the `HP_` prefix because the binary rejects unknown `HALLPASS_*` variables.

## Upgrading

See [upgrade.md](upgrade.md). Never run an older binary against a database migrated by a newer one; HallPass refuses it.
