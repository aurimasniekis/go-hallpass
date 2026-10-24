# Configuration reference

HallPass reads one YAML file (`--config PATH` or `HALLPASS_CONFIG`), then applies `HALLPASS_*` environment overrides.
An override's name is the upper-cased YAML path joined with `_`: `ssh.listen` → `HALLPASS_SSH_LISTEN`. List values
are comma-separated (`HALLPASS_EGRESS_ALLOW_CIDRS=10.0.0.0/8,192.168.0.0/16`).

Validation is strict: unknown keys, unknown `HALLPASS_*` variables and out-of-range values are errors, all reported
at once.

```sh
hallpass config check --config /etc/hallpass/hallpass.yaml    # validate
hallpass config env                                           # list every override variable
```

The configuration is secret-free by design: the KEK and all credentials live elsewhere. Examples:
[hallpass.example.yaml](https://github.com/aurimasniekis/go-hallpass/blob/main/deploy/examples/hallpass.example.yaml)
(systemd) and
[hallpass.container.yaml](https://github.com/aurimasniekis/go-hallpass/blob/main/deploy/examples/hallpass.container.yaml)
(containers). This page mirrors
[configuration.md](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/operator/configuration.md).

## Runtime modes

| Mode | Use | Restrictions |
|---|---|---|
| `production` (default) | All real deployments | `public_url` must be `https`. `kek.file` is required, absolute and outside `data_dir`. JSON logs only. All `dev.*` options, `storage.allow_network_fs` and development authentication are rejected. |
| `development` | Local experiments only | `public_url` may be `http` only for `localhost` or loopback. Without a KEK, one is generated inside the data directory (with a warning). |

## Minimal production example

```yaml
mode: production
data_dir: /var/lib/hallpass
public_url: https://hallpass.example.com
kek:
  file: /etc/hallpass/kek
ssh:
  listen: ":2222"
http:
  listen: ":8080"
  trusted_proxies: [127.0.0.1/32]
egress:
  allow_cidrs: [10.20.0.0/16]
  source_addresses: [10.20.0.5]
```

## General

| Key | Default | Description |
|---|---|---|
| `mode` | `production` | Runtime mode. |
| `data_dir` | `/var/lib/hallpass` | Absolute path on a **local** filesystem (no NFS/SMB). Created `0700`. |
| `public_url` | — (required) | Externally reachable origin of the web console, e.g. `https://hallpass.example.com`. Used for OIDC callbacks and notification links. |

## Master key (`kek`)

| Key | Default | Description |
|---|---|---|
| `kek.source` | `file` | `file`, or `env` (base64 in `HALLPASS_KEK`; discouraged because environments leak into process listings and crash reports). |
| `kek.file` | `/etc/hallpass/kek` | Master key file (`0400`, outside `data_dir`). See [Keys and the KEK](/operators/keys). |

## Agent SSH (`ssh`)

| Key | Default | Description |
|---|---|---|
| `ssh.listen` | `:2222` | Agent-facing SSH listener. |
| `ssh.max_unauthenticated` | `256` | Concurrent unauthenticated connections. |
| `ssh.max_unauthenticated_per_ip` | `16` | Concurrent unauthenticated connections per source IP. |
| `ssh.handshake_timeout` | `10s` | Deadline for handshake plus authentication. |
| `ssh.max_auth_tries` | `6` | Authentication attempts per connection. |
| `ssh.ban.enabled` | `true` | Ban sources after repeated failed authentication. Banned sources are disconnected before the SSH banner. |
| `ssh.ban.max_failures` / `ssh.ban.window` | `10` / `10m` | Failed authentications from one source (IPv4 address or IPv6 /64) within the window that trigger a ban. Plain TCP connects (health checks) never count. |
| `ssh.ban.duration` / `ssh.ban.max_duration` | `15m` / `24h` | First ban length; it doubles for each further ban of the source within 7 days, up to the maximum. |
| `ssh.ban.allow_cidrs` | `[]` | Sources never banned, for example agent subnets behind a shared NAT (one misconfigured agent would otherwise lock out the others). |
| `ssh.max_connections_per_agent` | `32` | Concurrent authenticated connections per agent. |
| `ssh.max_channels_per_connection` | `16` | Concurrent channels per connection. |
| `ssh.keepalive_interval` / `ssh.keepalive_max_missed` | `30s` / `3` | Keepalive probes on both SSH legs. |
| `ssh.idle_timeout` | `30m` | Close sessions with no traffic in either direction. |
| `ssh.dial_timeout` | `10s` | Outbound destination dial and handshake timeout. |
| `ssh.env_allow` | `TERM, LANG, LC_*` | Environment variables forwarded to destinations. Roles can extend it. |

## Web console and API (`http`)

| Key | Default | Description |
|---|---|---|
| `http.listen` | `:8080` | Web console, API and webhooks. |
| `http.tls_cert_file` / `http.tls_key_file` | — | Native TLS. Otherwise terminate TLS at a reverse proxy. |
| `http.trusted_proxies` | `[]` | CIDRs allowed to set `X-Forwarded-For`/`X-Forwarded-Proto`. |
| `http.metrics_listen` | — | Optional separate listener for `/metrics`. |

## Logging (`log`)

| Key | Default | Description |
|---|---|---|
| `log.level` / `log.format` | `info` / `json` | `debug|info|warn|error`. `text` format is development-only. |
| `log.audit_file` | — | Optional file that receives every committed audit record as one JSON line (mode `0600`, append), for SIEM ingestion. The database hash chain stays authoritative. |

## Storage (`storage`)

| Key | Default | Description |
|---|---|---|
| `storage.min_free_bytes` / `storage.min_free_percent` | `2 GiB` / `5` | Free-space reserve. Below it, new sessions are refused. |
| `storage.alert_percent` | `80, 90` | Disk-usage alert thresholds. |
| `storage.pre_migration_snapshots` | `3` | Pre-migration `VACUUM INTO` snapshots kept. |
| `storage.allow_network_fs` | `false` | Development escape hatch. Rejected in production. |

## Recording (`recording`)

| Key | Default | Description |
|---|---|---|
| `recording.durability` | `group` | `group`: fsync at most every `flush_interval`. `strict`: fsync before forwarding. |
| `recording.flush_interval` | `250ms` | Group-commit interval (max 250 ms). |
| `recording.segment_max_bytes` / `recording.segment_max_age` | `64 MiB` / `1h` | Segment rollover thresholds. |
| `recording.queue_records` / `recording.queue_bytes` | `1024` / `1 MiB` | Bounded recorder queue per channel. |
| `recording.block_timeout` | `10s` | A channel blocked on recording longer than this is terminated. |
| `recording.default_retention` | `2160h` (90 days) | Default retention class. |
| `recording.retention_classes` | `[]` | Per-class retention overrides as `class=duration` entries, e.g. `sensitive=8760h`. Roles name their retention class; classes without an entry use `default_retention`. |

## Outbound connections (`egress`)

| Key | Default | Description |
|---|---|---|
| `egress.allow_cidrs` | `[]` | Ranges destinations may resolve into. **Empty means no destination is reachable**. |
| `egress.allow_special_cidrs` | `[]` | Explicitly re-allow normally denied ranges (loopback, link-local, metadata). |
| `egress.source_addresses` | `[]` | The gateway's own egress IPs/CIDRs as destinations see them. Used for the suggested `from="…"` in login-key authorized_keys lines and firewall guidance. |

## Requests and grants (`access`)

| Key | Default | Description |
|---|---|---|
| `access.wait_timeout_default` / `access.wait_timeout_max` | `120s` / `15m` | How long `connect`/`exec` wait for approval. |
| `access.pending_expiry` | `30m` | Pending requests expire after this. |
| `access.duration_presets` | `5m,15m,30m,1h,3h,6h,24h` | Allowed grant durations (ascending). |
| `access.max_grant_duration` | `24h` | Global ceiling. |
| `access.requests_per_agent_hour` / `access.max_pending_per_agent` | `30` / `10` | Request rate limits. |
| `access.enforcement_tick` | `1s` | How often the enforcer checks for ended access (the termination bound is 5 s). |
| `access.min_remaining_to_connect` | `2s` | Grants closer to expiry than this don't start new channels. |

## Operator sessions (`auth`)

| Key | Default | Description |
|---|---|---|
| `auth.session_idle_timeout` / `auth.session_absolute_timeout` | `30m` / `12h` | Operator web sessions. |
| `auth.reauth_window` | `5m` | Recent-authentication window for sensitive actions. |
| `auth.password_min_bytes` | `12` | Minimum password length (max is fixed at 1024 bytes). |

## Telemetry (`telemetry`)

| Key | Default | Description |
|---|---|---|
| `telemetry.otlp_endpoint` | — | Optional OTLP/HTTP endpoint for traces. Metrics are exported only through Prometheus `/metrics`. |
| `telemetry.prometheus` | `true` | Expose Prometheus `/metrics`. |

## Shutdown (`shutdown`)

| Key | Default | Description |
|---|---|---|
| `shutdown.drain_timeout` | `30s` | Graceful drain before channels are closed. |

## Operator permissions (`rbac`)

| Key | Default | Description |
|---|---|---|
| `rbac.auditor_address_read` | `false` | Auditors may read destination addresses. |
| `rbac.approver_recording_play` | `false` | Approvers may replay recordings. |
| `rbac.auditor_recording_export` | `false` | Auditors may export recordings. |
| `rbac.approvers_can_lockdown` | `false` | Approvers may enable lockdown (lifting stays administrator-only). |

## Development only (`dev`)

| Key | Default | Description |
|---|---|---|
| `dev.insecure_http`, `dev.auth`, `dev.seed_file` | off | Development-only features. Production rejects them. |
