# Agent commands

What an agent can run through the gateway: `ssh <gateway> <command>`. The examples use the host alias `center`.
`ssh center help [topic]` prints the same help from the gateway itself.

| Command | Purpose |
|---|---|
| `list [--json] [--server S]` | Visible servers and roles, with your access level and active grants. The default when no command is given. |
| `roles <server> [--json]` | Roles of one server. |
| `request <server> [options]` | Request access without connecting. Returns at once unless `--wait`. |
| `status <req_id> [--json] [--wait[=bool]] [--wait-timeout d]` | State of one of your requests, and its grant when approved. |
| `cancel <req_id> [--json]` | Cancel your pending request. |
| `connect <server> [options]` | Reuse a grant, or request access and wait, then open a shell. Use `ssh -t` for an interactive shell. |
| `<server> [options]` | Same as `connect`. |
| `exec <server> [options] -- <command>` | As `connect`, but run `<command>`. stdout and stderr stay separate; the remote exit status is returned. |
| `sessions [--json] [--all]` | Your active grants (and with `--all`, recent ended ones), remaining time and connection counts. |
| `whoami [--json]` | Your agent identity and key. |
| `version [--json]` | Gateway, grammar and schema versions. |
| `help [topic]` | Topics: `cancel`, `connect`, `exec`, `exit-codes`, `json`, `list`, `quoting`, `request`, `roles`, `sessions`, `status`, `version`, `whoami`. |

## Options for `request`, `connect` and `exec`

| Option | Meaning |
|---|---|
| `--role <role>` | Role to use. Required when the server has several. |
| `--reason <text>` | Why you need access (1–1000 characters). Shown to approvers, marked untrusted. |
| `--duration <d>` | Requested duration, e.g. `30m`. Policy limits apply. |
| `--wait[=true\|false]`, `--no-wait` | Wait for a decision. Default: `false` for `request`, `true` for `connect` and `exec`. |
| `--wait-timeout <d>` | How long to wait, `0s` to `15m` (default `2m`). |
| `--idempotency-key <key>` | 8–128 characters from `A-Z a-z 0-9 . _ -`, so retries never create duplicates. |
| `--json` | Machine-readable output (one JSON document). |

Options take `--opt value` or `--opt=value`, in any order, each at most once.

## Quoting

Values with spaces must keep their quotes all the way to the gateway, so wrap the whole gateway command in single
quotes. Everything after the first unquoted `--` goes to the destination's login shell unchanged.

```sh
ssh center 'request web1 --role deploy --reason "Deploy 1.4.3" --duration 30m'
ssh center 'exec web1 --role inspect -- ls -l /var/log | head -5'
```

## JSON output

`--json` prints one document on stdout with a `schema` field: `hallpass.list/v1`, `hallpass.roles/v1`,
`hallpass.request/v1`, `hallpass.status/v1`, `hallpass.sessions/v1`, `hallpass.whoami/v1`, `hallpass.version/v1`.
Errors are one `hallpass.error/v1` line on stderr:

```json
{"schema":"hallpass.error/v1","source":"gateway","code":"wait_timeout","exit_code":86,"message":"request still pending after 2m0s","request_id":"req_01…"}
```

Within `/v1`, fields are only ever added, never removed, renamed or retyped. The JSON Schema files are in
[`api/ssh-schemas/`](https://github.com/aurimasniekis/go-hallpass/tree/main/api/ssh-schemas).
