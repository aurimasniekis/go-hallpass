# Configuration

HallPass reads one YAML file (`--config PATH` or `HALLPASS_CONFIG`) and then applies `HALLPASS_*` environment overrides.
The override name is the upper-cased YAML path joined with `_`, e.g. `ssh.listen` → `HALLPASS_SSH_LISTEN`. List values
are comma-separated (`HALLPASS_EGRESS_ALLOW_CIDRS=10.0.0.0/8,192.168.0.0/16`).

Validation is strict. Unknown YAML keys, unknown `HALLPASS_*` variables and out-of-range values are errors, and every problem
is reported at once. Run `hallpass config check --config FILE` before deploying, and `hallpass config env` to list every
override variable.

Example: [`deploy/examples/hallpass.example.yaml`](../../deploy/examples/hallpass.example.yaml) (secret-free).

## Runtime modes

| Mode | Use | Restrictions |
|---|---|---|
| `production` (default) | All real deployments | `public_url` must be `https`. `kek.file` is required, absolute and outside `data_dir`. JSON logs only. All `dev.*` options, `storage.allow_network_fs` and development authentication are rejected. |
| `development` | Local development only | `public_url` may be `http` **only** for `localhost`/loopback. Without a KEK, a development KEK is generated inside the data dir (with a warning). `dev.*` features are allowed. |

## Reference

| Key | Default | Description |
|---|---|---|
| `mode` | `production` | Runtime mode. |
| `data_dir` | `/var/lib/hallpass` | Absolute path on a **local** filesystem (no NFS/SMB). Created `0700`. |
| `public_url` | — (required) | Externally reachable origin of the web console, e.g. `https://hallpass.example.com`. Used for OIDC callbacks and notification links. |
| `kek.source` | `file` | `file`, or `env` (base64 in `HALLPASS_KEK`; discouraged because environments leak into process listings and crash reports). |
| `kek.file` | `/etc/hallpass/kek` | Master key file (`0400`, outside `data_dir`). See `docs/operator/keys.md`. |
| `ssh.listen` | `:2222` | Agent-facing SSH listener. |
| `ssh.public_address` | — | Where agents connect, `host` or `host:port` (port 22 when omitted), e.g. `ssh.example.com` behind a 22 → 2222 redirect. Shown in the console's agent setup and `known_hosts` lines. Default: the `public_url` host with the `ssh.listen` port. |
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
| `http.listen` | `:8080` | Web console, API and webhooks. |
| `http.tls_cert_file` / `http.tls_key_file` | — | Native TLS. Otherwise terminate TLS at a reverse proxy. |
| `http.trusted_proxies` | `[]` | CIDRs allowed to set `X-Forwarded-For`/`X-Forwarded-Proto`. |
| `http.metrics_listen` | — | Optional separate listener for `/metrics`. |
| `log.level` / `log.format` | `info` / `json` | `debug|info|warn|error`. `text` format is development-only. |
| `log.audit_file` | — | Optional file that receives every committed audit record as one JSON line (mode `0600`, append), for SIEM ingestion. The database hash chain stays authoritative. |
| `storage.min_free_bytes` / `storage.min_free_percent` | `2 GiB` / `5` | Free-space reserve. Below it, new sessions are refused. |
| `storage.alert_percent` | `80, 90` | Disk-usage alert thresholds. |
| `storage.pre_migration_snapshots` | `3` | Pre-migration `VACUUM INTO` snapshots kept. |
| `storage.allow_network_fs` | `false` | Development escape hatch. Rejected in production. |
| `recording.durability` | `group` | `group`: fsync at most every `flush_interval`. `strict`: fsync before forwarding. |
| `recording.flush_interval` | `250ms` | Group-commit interval (max 250 ms). |
| `recording.segment_max_bytes` / `recording.segment_max_age` | `64 MiB` / `1h` | Segment rollover thresholds. |
| `recording.queue_records` / `recording.queue_bytes` | `1024` / `1 MiB` | Bounded recorder queue per channel. |
| `recording.block_timeout` | `10s` | A channel blocked on recording longer than this is terminated. |
| `recording.default_retention` | `2160h` (90 days) | Default retention class. |
| `recording.retention_classes` | `[]` | Per-class retention overrides as `class=duration` entries, e.g. `sensitive=8760h`. Roles name their retention class; classes without an entry use `default_retention`. |
| `egress.allow_cidrs` | `[]` | Ranges destinations may resolve into. **Empty means no destination is reachable**. |
| `egress.allow_special_cidrs` | `[]` | Explicitly re-allow normally denied ranges (loopback, link-local, metadata). |
| `egress.source_addresses` | `[]` | The gateway's own egress IPs/CIDRs as destinations see them. Used for the suggested `from="…"` in login-key authorized_keys lines and firewall guidance. |
| `access.wait_timeout_default` / `access.wait_timeout_max` | `120s` / `15m` | How long `connect`/`exec` wait for approval. |
| `access.pending_expiry` | `30m` | Pending requests expire after this. |
| `access.duration_presets` | `5m,15m,30m,1h,3h,6h,24h` | Allowed grant durations (ascending). |
| `access.max_grant_duration` | `24h` | Global ceiling. |
| `access.requests_per_agent_hour` / `access.max_pending_per_agent` | `30` / `10` | Request rate limits. |
| `access.enforcement_tick` | `1s` | Enforcer ticker (bound: 5 s). |
| `access.min_remaining_to_connect` | `2s` | Grants closer to expiry than this don't start new channels. |
| `auth.session_idle_timeout` / `auth.session_absolute_timeout` | `30m` / `12h` | Operator web sessions. |
| `auth.reauth_window` | `5m` | Recent-authentication window for sensitive actions. |
| `auth.password_min_bytes` | `12` | Minimum password length (max is fixed at 1024 bytes). |
| `telemetry.otlp_endpoint` | — | Optional OTLP/HTTP endpoint for traces. Metrics are exported only through Prometheus `/metrics`. |
| `telemetry.prometheus` | `true` | Expose Prometheus `/metrics`. |
| `shutdown.drain_timeout` | `30s` | Graceful drain before channels are closed. |
| `rbac.auditor_address_read` | `false` | Auditors may read destination addresses. |
| `rbac.approver_recording_play` | `false` | Approvers may replay recordings. |
| `rbac.auditor_recording_export` | `false` | Auditors may export recordings. |
| `rbac.approvers_can_lockdown` | `false` | Approvers may enable lockdown (lifting stays administrator-only). |
| `dev.insecure_http`, `dev.auth`, `dev.seed_file` | off | Development-only features. Production rejects them. |
