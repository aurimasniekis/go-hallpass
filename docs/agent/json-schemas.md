# Agent JSON schemas

Every `--json` success document is one JSON object on stdout with a `"schema"` field. Errors are one
`hallpass.error/v1` line on stderr. The JSON Schema (draft 2020-12) files in [`api/ssh-schemas/`](../../api/ssh-schemas) are
the contract. The grammar unit tests validate every document type the gateway renders against them in strict mode.

Compatibility rules within `/v1`: fields may be added, but never removed, renamed or retyped. Timestamps are RFC 3339 UTC.
Durations are Go duration strings (`30m0s`). Optional values are `null`, never missing.

| File | Schema | Emitted by |
|---|---|---|
| [`hallpass.error.v1.json`](../../api/ssh-schemas/hallpass.error.v1.json) | `hallpass.error/v1` | any failing command (stderr) |
| [`hallpass.list.v1.json`](../../api/ssh-schemas/hallpass.list.v1.json) | `hallpass.list/v1` | `list --json` |
| [`hallpass.request.v1.json`](../../api/ssh-schemas/hallpass.request.v1.json) | `hallpass.request/v1` | `request --json` (without waiting, or when the request is already decided) |
| [`hallpass.roles.v1.json`](../../api/ssh-schemas/hallpass.roles.v1.json) | `hallpass.roles/v1` | `roles <server> --json` |
| [`hallpass.sessions.v1.json`](../../api/ssh-schemas/hallpass.sessions.v1.json) | `hallpass.sessions/v1` | `sessions [--all] --json` |
| [`hallpass.status.v1.json`](../../api/ssh-schemas/hallpass.status.v1.json) | `hallpass.status/v1` | `status --json`, `cancel --json`, `request --wait --json` |
| [`hallpass.version.v1.json`](../../api/ssh-schemas/hallpass.version.v1.json) | `hallpass.version/v1` | `version --json` |
| [`hallpass.whoami.v1.json`](../../api/ssh-schemas/hallpass.whoami.v1.json) | `hallpass.whoami/v1` | `whoami --json` |

Example error line:

```json
{"schema":"hallpass.error/v1","source":"gateway","code":"wait_timeout","exit_code":86,"message":"request still pending after 2m0s","request_id":"req_01…"}
```
