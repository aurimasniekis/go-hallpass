# Install with Docker Compose

[`deploy/compose.yaml`](https://github.com/aurimasniekis/go-hallpass/blob/main/deploy/compose.yaml) runs one
HallPass instance with a named data volume, the master key (KEK) as a Compose secret, a read-only root filesystem,
all capabilities dropped and `no-new-privileges`. Container details are in
[container.md](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/operator/container.md).

## Before you start

- A Linux host with Docker and the Compose plugin. Run **one** HallPass per data volume; there is no clustering.
- A clock synchronized by NTP (chrony or systemd-timesyncd). Grant expiry and webhook checks use wall-clock time.
- A DNS name and a TLS certificate for the web console. The console must sit behind a TLS reverse proxy (or use
  native TLS with `http.tls_cert_file` and `http.tls_key_file`). Production mode requires an `https` `public_url`.
- Network: agents reach the SSH port (`2222` by default). HallPass reaches your servers on their SSH port.

## 1. Get the image

Releases are published to Docker Hub as
[`aurimasniekis/hallpass`](https://hub.docker.com/r/aurimasniekis/hallpass) and mirrored to
`ghcr.io/aurimasniekis/go-hallpass` (same digest), for linux/amd64 and linux/arm64. Pick the latest version from the
[releases page](https://github.com/aurimasniekis/go-hallpass/releases), pull it, and verify its build provenance
before you run it:

```sh
export HP_VERSION=0.6.1
docker pull aurimasniekis/hallpass:$HP_VERSION
gh attestation verify oci://docker.io/aurimasniekis/hallpass:$HP_VERSION --repo aurimasniekis/go-hallpass
```

You also need the `deploy/` directory (Compose file and example configuration) from the same release:

```sh
git clone --depth 1 --branch v$HP_VERSION https://github.com/aurimasniekis/go-hallpass.git && cd go-hallpass
```

To build the image yourself instead: `make image IMAGE=hallpass:local VERSION=v0.0.0-local`, then use
`HP_IMAGE=hallpass HP_VERSION=local` below.

## 2. Create the master key (KEK)

The KEK wraps every encryption key in the database. It must live **outside** the data volume, be owned by the
container user (UID 65532) and be readable only by it.

```sh
cd deploy
install -d -m 0700 secrets
sudo chown 65532:65532 secrets
docker run --rm --user 65532:65532 -v "$PWD/secrets:/out" aurimasniekis/hallpass:$HP_VERSION keys init-kek --out /out/hallpass.kek
sudo chmod 0400 secrets/hallpass.kek
```

::: danger Back up the KEK now
Copy `secrets/hallpass.kek` to at least two offline places, **separately** from data backups. Without it, nothing in
the database or the recordings can ever be decrypted. Backups never contain it.
:::

## 3. Configure

```sh
cp examples/hallpass.container.yaml hallpass.yaml
$EDITOR hallpass.yaml
```

Set at least:

| Key | Value |
|---|---|
| `public_url` | The https URL of the console, for example `https://hallpass.example.com`. |
| `egress.allow_cidrs` | The networks your destination servers are in. **Empty means no destination is reachable.** |
| `egress.source_addresses` | The address(es) your servers see HallPass connect from. Used in the suggested `from="…"` restriction. |
| `http.trusted_proxies` | The CIDR your reverse proxy connects from (for a proxy on the host, the Compose network range). |

The file is secret-free. Every key is listed in the [configuration reference](/reference/configuration).

## 4. Initialize

Offline commands take the data-directory lock, so run them before the first start. `docker compose run` uses the
same volume, secret and configuration as the service:

```sh
export HP_CONFIG_FILE=./hallpass.yaml       # HP_VERSION from step 1
docker compose run --rm hallpass config check
docker compose run --rm hallpass migrate
docker compose run --rm hallpass hostkey show --host center    # known_hosts line for agents
docker compose run --rm hallpass admin bootstrap                # one-time setup link (30 minutes)
```

Keep the `known_hosts` line for [your first agent](/guide/first-agent).

## 5. Start

```sh
docker compose up -d
docker compose logs -f
curl -s http://127.0.0.1:8080/readyz
```

The console listens on `127.0.0.1:8080` on the host. Point your TLS reverse proxy at it, for example with Caddy:

```
hallpass.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Then open the setup link and continue with [First run](/guide/first-run).

## Day-2 operations

- **Stop and start:** `docker compose stop` drains sessions (45 s grace period, 30 s drain).
- **Offline commands** (`hostkey`, `keys`, `verify`, `admin recover`): `docker compose stop`, then
  `docker compose run --rm hallpass <command>`, then start again.
- **Backups:** `hallpass backup create` runs online. See [Backup and restore](/operators/backup).
- **Upgrades:** see [Upgrades](/operators/upgrades). Pin a version, never `latest`.
- **Docker Desktop:** bind-mounted data directories are FUSE-backed and refused. Keep the named volume.
