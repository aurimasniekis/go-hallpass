# Logging

Hallpass writes structured JSON logs (one object per line) to stderr using Go's `log/slog`. Field names follow the
[Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html) where a matching field exists, and use the
`hallpass.*` namespace otherwise (review item R-07). Logs can be ingested by OpenSearch, Elasticsearch, Loki or any JSON log
pipeline without custom parsing, and none of them is required.

Logs are operational telemetry. The **audit trail** is separate (hash-chained in the database, optional JSON audit sink) and
is the authoritative record of security-relevant actions.

## Core fields

| Field | Type | Meaning |
|---|---|---|
| `@timestamp` | string | RFC 3339 UTC with nanoseconds. |
| `log.level` | string | `debug`, `info`, `warn`, `error`. |
| `message` | string | Human-readable message. Stable per event type. |
| `service.name` / `service.version` | string | Always `hallpass` / build version. |
| `hallpass.component` | string | Emitting subsystem (`store`, `sshfront`, `access`, `recording`, …). |
| `event.action` | string | Machine-readable action (e.g. `ssh.auth`, `request.created`). |
| `event.outcome` | string | `success`, `failure` or `unknown`. |
| `event.duration` | number | Nanoseconds, where measured. |
| `error.message` | string | Error text. Errors never include secrets by construction. |
| `trace.id` / `span.id` | string | OpenTelemetry correlation (HP-OBS-003). |
| `http.request.id` | string | Per-HTTP-request correlation ID. |
| `source.ip` | string | Client IP (agent or browser), honoring `http.trusted_proxies`. |
| `user.id` | string | Operator ID for web actions. |
| `hallpass.agent_id`, `hallpass.key_id`, `hallpass.server_id`, `hallpass.role_id` | string | Inventory identifiers. |
| `hallpass.request_id`, `hallpass.grant_id`, `hallpass.session_id`, `hallpass.connection_id`, `hallpass.channel_id`, `hallpass.segment_id` | string | Access lifecycle identifiers. |

## Redaction (HP-OBS-002)

- Values of type `redact.Secret[T]` always render as `[REDACTED]` (log, `fmt`, JSON).
- Attribute keys matching the sensitive list are replaced with `[REDACTED]` in every handler, including nested groups.
  The list covers `password`, `*_secret`, `*_token`, `private_key`, `passphrase`, `kek`, `totp`, `recovery_code(s)`,
  `authorization`, `cookie`, `signature`, `reason`, `comment`, `command`, `terminal_data`, `input`, `output`, `stdin`, `stdout`, `stderr`.
- Request reasons, exec command strings and terminal content are **never** logged. They exist only in encrypted storage.
- Tests plant a secret value under each sensitive key and assert it never appears in either log format.

Redaction is defense in depth, not a guarantee for arbitrary free text. Code must not put secrets into messages or error strings.

## Audit log export

Set `log.audit_file` to append every committed audit record as one JSON line (file mode 0600) for SIEM ingestion. The
database hash chain is authoritative: verify it with `GET /api/v1/audit-events/verify` or after a restore. The file is
for forwarding only.
