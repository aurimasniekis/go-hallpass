# Observability

Hallpass emits three kinds of operational telemetry. None of them needs an external service to run, and all of them
leave out secrets, request reasons, exec commands, terminal data and tokens.

| Signal | Where | Requirement |
|---|---|---|
| Structured logs | JSON lines on stderr (`log/slog`, ECS-aligned) | HP-OBS-001, HP-OBS-002 |
| Correlation IDs | Log fields, span attributes | HP-OBS-003 |
| Metrics | Prometheus `/metrics` (dedicated registry) | HP-OBS-004 |
| Traces | OpenTelemetry over OTLP/HTTP (optional) | HP-OBS-004 |
| Health | `/healthz` (liveness), `/readyz` (readiness) | HP-OPS-001, HP-OPS-006 |

The **audit trail** is separate. It is hash-chained in the database, has an optional JSON sink and is the authoritative
record of security-relevant actions (HP-OBS-005). Logs and metrics are operational aids and do not replace it.

Audit events record the request or trace correlation ID in `correlation_id`. The trace and lifecycle IDs from the
request context go under `details.correlation` (`trace_id`, `http_request_id`, `agent_id`, `connection_id`, …).

## Logs

The full log schema and redaction rules are in [logging.md](logging.md). In short:

- One JSON object per line with `@timestamp` (RFC 3339 UTC), `log.level`, `message`, `service.name` = `hallpass`,
  `service.version`, `hallpass.component`, and `event.action` / `event.outcome` / `event.duration` where relevant.
- Errors go in `error.message`. Error strings never contain secrets by construction.
- Redaction: values of type `redact.Secret` always render as `[REDACTED]`, and keys on the sensitive list (`password`,
  `*_token`, `*_secret`, `reason`, `comment`, `command`, `stdin`/`stdout`/`stderr`, `terminal_data`, …) are replaced
  with `[REDACTED]` in every handler, including nested groups.

### Correlation fields (HP-OBS-003)

Records logged with a context (`logger.InfoContext(ctx, …)`) automatically carry:

| Field | Source |
|---|---|
| `trace.id`, `span.id` | Active OpenTelemetry span, when tracing is enabled |
| `http.request.id` | Random 128-bit ID generated per HTTP request. Clients cannot choose it. Returned as `X-Request-Id`. |
| `user.id` | Operator ID for web actions |
| `hallpass.agent_id`, `hallpass.key_id` | Authenticated agent and key |
| `hallpass.server_id`, `hallpass.role_id` | Target |
| `hallpass.request_id`, `hallpass.grant_id`, `hallpass.session_id` | Access lifecycle |
| `hallpass.connection_id`, `hallpass.channel_id` | Agent SSH connection and channel |

The context fields always appear at the top level, including under grouped loggers. A field set explicitly on the
record or the logger wins over the context value, and the key is never duplicated. Spans use the same attribute keys
for these IDs, so you can join logs and traces on `trace.id` or on any lifecycle ID.

## Metrics

`/metrics` serves the Prometheus text format from a dedicated registry. It is not the process-global default, so
third-party libraries cannot register metrics there. Each scrape has a 10 s timeout, and at most 4 scrapes run at
once. Serve it on the separate `http.metrics_listen` address, bound to a private interface. It is unauthenticated
infrastructure telemetry and should not face the internet. `telemetry.prometheus: false` disables it.

**Label rules.** Every label has a fixed allowlist or a hard cardinality cap, and anything else becomes `other`.
Labels never contain client or agent IP addresses, identifiers of individual agents, requests or grants, raw URL
paths, query strings, reasons, commands or error text. HTTP metrics use the route **template**
(`/api/v1/requests/{id}`) and never the request path, because paths can contain action tokens.

Besides the families below, the registry includes the standard Go runtime (`go_*`) and process (`process_*`)
collectors and `promhttp_metric_handler_*`.

### Build and readiness

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `hallpass_build_info` | gauge | `version`, `revision`, `goversion` | Always 1. One series per binary. |
| `hallpass_readiness_state` | gauge | `state` = `starting`, `ready`, `degraded`, `failed`, `stopping` | 1 for the current readiness state, 0 for the others. |
| `hallpass_readiness_check_ok` | gauge | `check` (registered check names, code-defined) | 1 if the check passed at the last evaluation, 0 if it was degraded or failed. |

### Agent SSH

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `hallpass_ssh_connections_active` | gauge | – | Authenticated agent connections open now. |
| `hallpass_ssh_connections_total` | counter | `result` = `accepted`, `auth_failed`, `handshake_failed`, `preauth_limit`, `agent_limit`, `shutting_down`, `other` | Inbound connection attempts. |
| `hallpass_ssh_auth_failures_total` | counter | `reason` = `unknown_key`, `revoked_key`, `agent_disabled`, `source_not_allowed`, `key_policy`, `method_rejected`, `other` | Failed public-key authentications. |
| `hallpass_ssh_channels_active` | gauge | `kind` = `shell`, `exec`, `other` | Open activity channels. |
| `hallpass_ssh_channels_total` | counter | `kind`; `result` = `opened`, `denied`, `limited`, `failed`, `lockdown`, `no_storage`, `other` | Channel open attempts. |
| `hallpass_ssh_refused_requests_total` | counter | `type` = `channel_type`, `port_forward`, `subsystem`, `x11`, `agent_forward`, `other` | Refused forwarding, subsystems and channel types (HP-SSH-007). |
| `hallpass_ssh_env_rejected_total` | counter | – | Environment variables dropped because they are not on the allowlist (HP-SSH-008). Variable names are not exported. |
| `hallpass_ssh_dial_duration_seconds` | histogram | `result` = `ok`, `timeout`, `egress_denied`, `host_key_mismatch`, `auth_failed`, `error`, `other` | Outbound destination dial and handshake. |

### Access lifecycle and enforcement

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `hallpass_access_requests_total` | counter | `state` = `pending` (created), `approved`, `denied`, `expired`, `canceled`, `other` | Request state transitions. |
| `hallpass_access_requests_pending` | gauge | – | Requests awaiting a decision. |
| `hallpass_access_decisions_total` | counter | `channel` = `web`, `slack`, `telegram`, `api`, `other`; `outcome` = `approved`, `denied`, `conflict`, `forbidden`, `error`, `other` | Operator decision attempts. |
| `hallpass_access_grants_active` | gauge | – | Active grants. |
| `hallpass_access_grants_ended_total` | counter | `reason` (end reasons, below) | Grants ended. |
| `hallpass_enforcer_terminations_total` | counter | `reason` (end reasons, below) | Activity terminated by the enforcer. |
| `hallpass_enforcer_latency_seconds` | histogram | – | Time from access ending (grant expiry, revocation, key or credential revocation, lockdown) until the enforcer terminates the activity. Shutdown terminations are not counted. Buckets 50 ms–60 s. |

End reasons: `expired`, `operator`, `agent`, `policy_changed`, `agent_disabled`, `key_revoked`, `target_disabled`,
`credential_revoked`, `lockdown`, `shutdown`, `recording_failed`, `idle`, `other`.

### Recording

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `hallpass_recording_records_total` | counter | – | Records written. |
| `hallpass_recording_bytes_total` | counter | – | Plaintext payload bytes recorded. |
| `hallpass_recording_queue_depth` | gauge | – | Records queued for the recording writers. |
| `hallpass_recording_failures_total` | counter | `stage` = `create`, `write`, `fsync`, `finalize`, `queue_timeout`, `other` | Recording failures. Mandatory-recording channels fail closed. |
| `hallpass_recording_segments_total` | counter | `result` = `finalized`, `interrupted`, `failed`, `other` | Closed segments. |
| `hallpass_recording_segment_finalize_seconds` | histogram | – | Segment finalize time (final frame, fsync, commit). |

### Storage

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `hallpass_store_tx_duration_seconds` | histogram | `name` (transaction name such as `access.open_connection`; at most 160 values, else `other`; `unnamed` if empty) | Write transaction time including busy retries (HP-DB-004). |
| `hallpass_store_tx_total` | counter | `name`; `result` = `ok`, `busy`, `full`, `io`, `corrupt`, `constraint`, `conflict`, `not_found`, `canceled`, `error`, `other` | Write transactions by final result. |
| `hallpass_store_tx_busy_retries_total` | counter | – | Attempts retried after `SQLITE_BUSY` (HP-DB-003). |
| `hallpass_store_writer_wait_seconds` | histogram | – | Wait for the single writer connection (HP-DB-003). |
| `hallpass_store_db_bytes`, `hallpass_store_wal_bytes` | gauge | – | SQLite database and WAL size (HP-DB-011). |
| `hallpass_storage_filesystem_size_bytes` | gauge | `volume` = `data`, `recordings`, `backups` | Filesystem size, read at scrape time. Paths are never exported. |
| `hallpass_storage_filesystem_avail_bytes` | gauge | `volume` | Space available to the process. |

### Notifications, jobs, HTTP, operators

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `hallpass_outbox_pending` | gauge | – | Outbox messages queued or awaiting retry. |
| `hallpass_outbox_dead` | gauge | – | Dead-lettered messages (exhausted 8 attempts). |
| `hallpass_notification_deliveries_total` | counter | `provider` = `slack`, `telegram`, `smtp`, `web`, `webhook`, `other`; `outcome` = `delivered`, `retry`, `dead`, `other` | Delivery attempts. |
| `hallpass_job_runs_total` | counter | `job` (code-defined job name, at most 64 values); `result` = `ok`, `error` | Background job runs (retention, checkpoints, integrity checks, …). |
| `hallpass_http_requests_total` | counter | `route` (route template, at most 128 values; `unmatched` if no route matched); `method` (standard methods, else `other`); `code` = `1xx`–`5xx` | HTTP requests. |
| `hallpass_http_request_duration_seconds` | histogram | `route`, `method` | HTTP latency. Long-lived SSE streams land in the top buckets. |
| `hallpass_http_requests_in_flight` | gauge | – | Requests being served. |
| `hallpass_sse_clients` | gauge | – | Connected live-event streams (limit 512). |
| `hallpass_oidc_logins_total` | counter | `provider` (configured provider slug, at most 32 values); `outcome` = `success`, `failure`, `denied`, `throttled`, `error`, `other` | OIDC login completions. |
| `hallpass_operator_logins_total` | counter | `method` = `password`, `oidc`, `recovery`, `other`; `outcome` | Operator login attempts. `password` counts the password step; the TOTP step is not counted separately. `recovery` is a break-glass login. |

## Health and readiness

| Endpoint | Meaning | Codes |
|---|---|---|
| `GET /healthz` | Liveness: the process is up and serving HTTP. It runs no dependency checks, so a degraded disk never causes a restart loop. Body `{"status":"ok"}`. | 200 |
| `GET /readyz` | Readiness: aggregate of the registered checks plus the process lifecycle. | 200 ready or degraded; 503 starting, failed or stopping |

Response body:

```json
{"status":"degraded","checks":[{"name":"store","status":"ok","duration_ms":0.4},
 {"name":"disk.data","status":"degraded","error":"disk_reserve","duration_ms":0.1}],"checked_at":"2026-10-23T10:00:00Z"}
```

- `status` is one of `starting` (startup not finished, PLAN §3.4), `ready`, `degraded`, `failed` or `stopping`
  (graceful shutdown has begun). `starting` and `stopping` return an empty `checks` list.
- Each check runs concurrently with its own timeout (default 2 s). A check that does not finish in time reports
  `timeout`, and one that panics reports `panic`.
- A failing **critical** check sets `failed` (503). A failing **degrading** check sets `degraded`. A degraded gateway
  still returns 200, so operators can still reach the console to fix the cause. The code can be changed to 503 for
  load balancers.
- `error` is a short public code (`storage_degraded`, `storage_failed`, `storage_busy`, `not_writable`, `disk_full`,
  `disk_reserve`, `disk_stat`, `timeout`, `check_failed`, …). Error details such as paths and byte counts are **not**
  in the public response. The detailed report is available only to authenticated admins (HP-OPS-001).
- Results are cached for 1 s, so polling `/readyz` cannot be used to load the database or filesystem. A background
  refresh every 15 s keeps `hallpass_readiness_*` current even when nothing polls the endpoint.
- Readiness recovers automatically once the failing checks pass again (PLAN §18.14). Corruption is the exception:
  the store tracker keeps it `failed` until restart and restore.

Standard checks:

| Check | Severity | Fails when |
|---|---|---|
| `store` | critical | The storage health tracker is degraded (disk full, sustained busy, I/O error) or failed (corruption, repeated I/O errors). |
| `store.writable` | critical | An empty `BEGIN IMMEDIATE` transaction cannot take the write lock. Busy or full only degrades readiness. |
| `keyring` | critical | Purpose keys are not loaded. |
| `recordings.writable` | critical | A probe file cannot be created, written, fsynced and removed in the recording directory. `ENOSPC` only degrades readiness. |
| `disk.data`, `disk.recordings` | degrading | Free space is below the reserve: the larger of `storage.min_free_bytes` (2 GiB) and `storage.min_free_percent` (5%) of the filesystem. New sessions are refused below the reserve (HP-OPS-006). |
| `ssh.listener` | critical | The agent SSH listener is not accepting connections. |

## Tracing

Set `telemetry.otlp_endpoint` to the base URL of an OTLP/HTTP collector, for example `http://otel-collector:4318`.
Hallpass appends `/v1/traces` unless the path already ends with it. `http://` sends data in plain text; use `https://`
across untrusted networks. The URL must not contain credentials, a query or a fragment. Leave the setting empty to
disable tracing. Hallpass then installs a no-op provider: no exporter, no background goroutine, no network traffic.

- Resource: `service.name=hallpass`, `service.version=<build version>`, plus the OpenTelemetry SDK defaults. The
  standard `OTEL_RESOURCE_ATTRIBUTES` and `OTEL_EXPORTER_OTLP_HEADERS` environment variables are honored.
- Sampling: parent-based with 100% root sampling.
- Spans: `HTTP <METHOD> <route template>` (server) and `ssh.auth`, `ssh.channel`, `access.authorize`, `ssh.dial`
  (client), `access.request`, `access.decide`, `notify.deliver` and `oidc.callback`. The `trace.id` of a span appears
  in every log record written inside it.
- Inbound `traceparent` headers are **ignored** by default. The API faces untrusted clients, so each request starts a
  new trace. Only a deployment behind a trusted tracing proxy should enable continuation.
- Span attributes are limited to lifecycle IDs, outcomes, HTTP method, route template and status code. Attributes
  whose keys are on the redaction list (`reason`, `command`, `*_token`, `password`, …) are dropped when they are set,
  and again before export. Raw URLs and query strings are never recorded.
- Export failures are logged at `warn` with `hallpass.component=otel` and never affect request handling.
  `Shutdown` flushes buffered spans during graceful shutdown.

## Suggested alerts

Prometheus rules. Adjust thresholds to your deployment.

```yaml
groups:
  - name: hallpass
    rules:
      - alert: HallpassNotReady
        expr: max(hallpass_readiness_state{state=~"failed|starting"}) == 1
        for: 2m
        labels: {severity: critical}
        annotations: {summary: "Hallpass readiness is failing; check the admin system status page"}
      - alert: HallpassDegraded
        expr: hallpass_readiness_state{state="degraded"} == 1
        for: 5m
        labels: {severity: warning}
        annotations: {summary: "Hallpass is degraded (storage reserve, busy writer or recording directory)"}
      - alert: HallpassRecordingFailures
        expr: increase(hallpass_recording_failures_total[10m]) > 0
        labels: {severity: critical}
        annotations: {summary: "Recording failures; mandatory-recording sessions are being refused or terminated"}
      - alert: HallpassEnforcementSlow
        expr: histogram_quantile(0.99, sum by (le) (rate(hallpass_enforcer_latency_seconds_bucket[15m]))) > 5
        for: 10m
        labels: {severity: critical}
        annotations: {summary: "p99 time to terminate ended access exceeds 5s"}
      - alert: HallpassOutboxDeadLetters
        expr: hallpass_outbox_dead > 0
        for: 5m
        labels: {severity: warning}
        annotations: {summary: "Notifications dead-lettered; approvers may not have been notified"}
      - alert: HallpassOutboxBacklog
        expr: hallpass_outbox_pending > 100
        for: 15m
        labels: {severity: warning}
      - alert: HallpassDiskUsage80
        expr: 1 - hallpass_storage_filesystem_avail_bytes / hallpass_storage_filesystem_size_bytes > 0.80
        for: 10m
        labels: {severity: warning}
      - alert: HallpassDiskUsage90
        expr: 1 - hallpass_storage_filesystem_avail_bytes / hallpass_storage_filesystem_size_bytes > 0.90
        for: 5m
        labels: {severity: critical}
      - alert: HallpassStorageBusy
        expr: sum(rate(hallpass_store_tx_total{result="busy"}[5m])) > 0
        for: 10m
        labels: {severity: warning}
      - alert: HallpassStoreTxSlow
        expr: histogram_quantile(0.99, sum by (le) (rate(hallpass_store_tx_duration_seconds_bucket[10m]))) > 0.1
        for: 15m
        labels: {severity: warning}
        annotations: {summary: "Write transactions exceed the 100 ms budget (HP-DB-004)"}
      - alert: HallpassAuthFailureSpike
        expr: sum(rate(hallpass_ssh_auth_failures_total[5m])) > 1
        for: 10m
        labels: {severity: warning}
      - alert: HallpassJobFailures
        expr: increase(hallpass_job_runs_total{result="error"}[1h]) > 3
        labels: {severity: warning}
```

The 80% and 90% disk alerts implement the HP-OPS-006 thresholds (`storage.alert_percent`). The free-space reserve
is enforced separately and does not wait for an alert to fire. Readiness degrades at once, and session admission
refuses new sessions below the reserve.

> **Status (WP22):** implemented and wired. `hallpass serve` creates the metric registry, passes it to every
> component, registers the readiness checks (store health and writability, recordings directory, data-disk reserve,
> SSH listener), serves `/healthz`, `/readyz` and (with `telemetry.prometheus`) `/metrics` on the HTTP listener or
> on `http.metrics_listen`, wraps the HTTP API in metrics and tracing middleware, marks readiness `ready` once the
> listeners are up and `stopping` at shutdown, and enforces the storage reserve at channel admission. An end-to-end
> test (`internal/app` `TestGatewayHealthAndMetrics`) checks the endpoints and metrics produced by real SSH traffic.
> OTLP metrics export is not implemented (Prometheus only).
