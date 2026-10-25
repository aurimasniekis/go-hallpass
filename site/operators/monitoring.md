# Monitoring

HallPass needs no external service to run, but it gives you everything to watch it: health endpoints, Prometheus
metrics, JSON logs and optional OpenTelemetry traces. None of them contain secrets, request reasons, commands or
terminal data. Reference:
[observability.md](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/operator/observability.md) and
[logging.md](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/operator/logging.md).

## Health

| Endpoint | Meaning |
|---|---|
| `GET /healthz` | Liveness. The process is up. It never checks dependencies, so a full disk cannot cause a restart loop. |
| `GET /readyz` | Readiness: `starting`, `ready`, `degraded`, `failed` or `stopping`. Returns 200 for ready and degraded, 503 otherwise. |

```sh
curl -s http://127.0.0.1:8080/readyz
{"status":"ready","checks":[{"name":"store","status":"ok",…},{"name":"disk.data","status":"ok",…},…]}
```

Checks cover the database, its writability, the recordings directory, the free-space reserve and the SSH listener.
Below the free-space reserve (the larger of 2 GiB and 5%), readiness is `degraded` and new sessions are refused. It
recovers on its own once space is freed.

## Metrics

Prometheus metrics are served at `/metrics`. Put them on a private listener with `http.metrics_listen` (they are
unauthenticated). Labels never contain IP addresses, agent or request IDs, paths or reasons. Useful series:

| Metric | Watch for |
|---|---|
| `hallpass_readiness_state` | Anything but `ready`. |
| `hallpass_access_requests_pending` | Requests nobody is looking at. |
| `hallpass_recording_failures_total` | Any increase: mandatory-recording sessions are being refused or ended. |
| `hallpass_enforcer_latency_seconds` | Time from access ending to the session being cut; should stay well under 5 s. |
| `hallpass_outbox_dead` | Chat notifications that could not be delivered. |
| `hallpass_backup_remote_last_success_timestamp_seconds` | Backups to object storage that stopped succeeding. |
| `hallpass_ssh_auth_failures_total` | Spikes in failed logins. |
| `hallpass_storage_filesystem_avail_bytes` | Disk running out. |

The reference has a ready-made set of Prometheus alert rules.

## Logs

One JSON object per line on stderr (journald or `docker logs`), ECS-aligned: `@timestamp`, `log.level`, `message`,
`event.action`, `event.outcome`, plus correlation fields such as `hallpass.agent_id`, `hallpass.request_id`,
`hallpass.session_id` and `trace.id`. Sensitive keys are replaced with `[REDACTED]`.

The **audit log** is separate and authoritative. To feed a SIEM, set `log.audit_file` to receive every committed audit
record as a JSON line.

## Traces

Set `telemetry.otlp_endpoint` to an OTLP/HTTP collector (for example `http://otel-collector:4318`). Spans cover HTTP
routes, SSH authentication and channels, access decisions and notification delivery. Leave it empty to disable
tracing entirely. Metrics are exported only through Prometheus.

## System status in the console

**Administration → System** shows readiness, lockdown, break-glass alerts and current **SSH bans**, which you can lift
early.

<Shot name="system" alt="System page with status and SSH bans" />
