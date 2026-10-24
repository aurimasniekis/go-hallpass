# Install the binary (systemd)

This is the standalone install on a Linux host (amd64 or arm64). The full reference, with every hardening detail, is
[install.md](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/operator/install.md).

## Before you start

- A dedicated Linux host or VM, run like a bastion host: minimal access, monitoring and **full-disk encryption**.
- A **local** filesystem for the data directory. NFS, SMB/CIFS and FUSE are refused.
- A clock synchronized by NTP with slewing (chrony or systemd-timesyncd).
- A DNS name and TLS certificate for the console, served through a reverse proxy or with native TLS.

## 1. Get the binary

Download the archive for your architecture, `SHA256SUMS`, and verify both the checksum and the build provenance
before installing. The latest version is on the [releases page](https://github.com/aurimasniekis/go-hallpass/releases).

```sh
V=0.1.0 ARCH=amd64      # or arm64
base=https://github.com/aurimasniekis/go-hallpass/releases/download/v$V
curl -fLO "$base/hallpass_${V}_linux_${ARCH}.tar.gz" -fLO "$base/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify "hallpass_${V}_linux_${ARCH}.tar.gz" --repo aurimasniekis/go-hallpass
tar -xzf "hallpass_${V}_linux_${ARCH}.tar.gz" && cd "hallpass_${V}_linux_${ARCH}"
```

The archive holds the static `hallpass` binary with the web UI embedded, the optional destination-side
`hallpass-collector`, the example configuration, the systemd unit, the changelog, LICENSE and NOTICE.

To build from source instead (Go 1.27+, Node 24, pnpm):

```sh
git clone https://github.com/aurimasniekis/go-hallpass.git && cd go-hallpass
(cd web && pnpm install --frozen-lockfile && pnpm build)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags embedui -trimpath -o hallpass ./cmd/hallpass
```

## 2. Service user, binary and master key

All commands run as root unless noted.

```sh
useradd --system --home-dir /var/lib/hallpass --no-create-home --shell /usr/sbin/nologin hallpass
install -m 0755 -o root -g root hallpass /usr/local/bin/hallpass
install -d -m 0750 -o root -g hallpass /etc/hallpass
hallpass keys init-kek --out /etc/hallpass/kek      # mode 0400; refuses to overwrite
chown hallpass:hallpass /etc/hallpass/kek
```

::: danger Back up the KEK now
Copy `/etc/hallpass/kek` to at least two offline places, separately from data backups. Losing it makes every
encrypted value and recording unrecoverable. Never put it in the configuration file, the data directory or version
control.
:::

## 3. Configuration

Start from [`deploy/examples/hallpass.example.yaml`](https://github.com/aurimasniekis/go-hallpass/blob/main/deploy/examples/hallpass.example.yaml):

```sh
install -m 0640 -o root -g hallpass deploy/examples/hallpass.example.yaml /etc/hallpass/hallpass.yaml
$EDITOR /etc/hallpass/hallpass.yaml       # public_url, egress.allow_cidrs, egress.source_addresses, listeners
sudo -u hallpass hallpass config check --config /etc/hallpass/hallpass.yaml
```

The important keys are the same as for [Compose](/guide/install-docker#_3-configure). Every key is in the
[configuration reference](/reference/configuration).

## 4. Data directory, schema, host key and setup link

```sh
install -d -m 0700 -o hallpass -g hallpass /var/lib/hallpass
sudo -u hallpass hallpass migrate --config /etc/hallpass/hallpass.yaml
sudo -u hallpass hallpass hostkey show --config /etc/hallpass/hallpass.yaml --host center
sudo -u hallpass hallpass admin bootstrap --config /etc/hallpass/hallpass.yaml
```

`hostkey show` prints the fingerprint and a `known_hosts` line for agents. `admin bootstrap` prints a one-time setup
link, valid for 30 minutes. These commands take the data-directory lock, so they must run while the service is
stopped.

## 5. systemd

```sh
install -m 0644 deploy/systemd/hallpass.service /etc/systemd/system/hallpass.service
systemctl daemon-reload
systemctl enable --now hallpass
systemctl status hallpass
journalctl -u hallpass -o cat          # JSON logs
```

The [unit](https://github.com/aurimasniekis/go-hallpass/blob/main/deploy/systemd/hallpass.service) runs as
`hallpass` with `ProtectSystem=strict`, `NoNewPrivileges`, no capabilities, a system-call filter, and write access
only to `/var/lib/hallpass`. `systemctl stop` drains sessions for up to 30 seconds.

To accept agents on port 22, prefer a firewall redirect (`22 → 2222`) over granting `CAP_NET_BIND_SERVICE`.

## 6. TLS in front of the console

The console listens on `:8080` (`http.listen`). Put a TLS reverse proxy in front of it and list the proxy's address in
`http.trusted_proxies`, or set `http.tls_cert_file` and `http.tls_key_file` for native TLS. Never expose plain HTTP.

Then open the setup link and continue with [First run](/guide/first-run).
