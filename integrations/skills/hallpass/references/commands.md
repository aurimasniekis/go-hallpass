# HallPass gateway command reference

`ssh <gateway> help` prints the same grammar. `ssh <gateway> help <topic>` gives details per command (topics: cancel,
connect, exec, exit-codes, json, list, quoting, request, roles, sessions, status, version, whoami).

```
list [--json] [--server <server>]     visible servers and roles (default with no command)
roles <server> [--json]               roles of one server
request <server> [options]            request access without connecting (--wait to wait)
status <req_id> [--json] [--wait[=bool]] [--wait-timeout <d>]
cancel <req_id> [--json]              cancel your pending request
connect <server> [options]            reuse a grant or request access, wait, then open a shell
<server> [options]                    same as connect
exec <server> [options] -- <command>  as connect, but run <command> on the server
sessions [--json] [--all]             your active (and with --all, recent) grants
whoami [--json]                       your agent identity and key
version [--json]                      gateway, grammar and schema versions
help [topic]
```

Options for `request`, `connect` and `exec`:

| Option | Meaning |
|---|---|
| `--role <role>` | Role to use (required when the server has several). |
| `--reason <text>` | Why you need access, 1–1000 characters. Shown to approvers, stored encrypted. |
| `--duration <d>` | Requested duration, e.g. `30m`. Policy limits apply. |
| `--wait[=true\|false]` / `--no-wait` | Wait for a decision (default: `request` no, `connect`/`exec` yes). |
| `--wait-timeout <d>` | How long to wait, `0s`–`15m` (default `2m`). |
| `--idempotency-key <key>` | 8–128 characters `A-Z a-z 0-9 . _ -`; makes `request` retries safe. |
| `--json` | Machine-readable output: one JSON document on stdout. |

Options take `--opt value` or `--opt=value`, in any order, each at most once.

## Quoting

The gateway splits its own part of the command on spaces and tabs:
- `'…'` is literal;
- `"…"` is literal except for `\"` and `\\`;
- outside quotes, `\x` means `x`;
- there is no variable, glob, tilde or command expansion at the gateway;
- control characters other than TAB, and therefore multi-line commands, are rejected (exit 81).

Everything after the first unquoted `--` is passed unchanged to the destination, and the remote login shell
interprets it. Your local shell parses the command first, so quote the remote part once:

```sh
ssh center 'exec web1 -- ls -l /var/log | head -5'     # the pipe runs on web1
ssh center exec web1 -- 'ls -l /var/log | head -5'      # same
ssh center 'exec web1 -- echo "$HOME"'                  # $HOME expands on web1
```

For multi-line scripts, pipe them to a non-interactive shell:
`ssh center connect web1 --role inspect < script.sh`.

## JSON output

Every `--json` success is one object on stdout with a `"schema"` field. Timestamps are RFC 3339 UTC, durations are
Go duration strings (`30m0s`), and optional values are `null`. Within `/v1`, fields are only ever added.

| Schema | Emitted by |
|---|---|
| `hallpass.list/v1` | `list --json` |
| `hallpass.roles/v1` | `roles <server> --json` |
| `hallpass.request/v1` | `request --json` (no wait, or already decided) |
| `hallpass.status/v1` | `status --json`, `cancel --json`, `request --wait --json` |
| `hallpass.sessions/v1` | `sessions [--all] --json` |
| `hallpass.whoami/v1` | `whoami --json` |
| `hallpass.version/v1` | `version --json` |
| `hallpass.error/v1` | any failing command (stderr) |

Example `list --json`:

```json
{"schema":"hallpass.list/v1","servers":[{"alias":"web1","description":"Web server","roles":[
  {"alias":"inspect","description":"Read-only inspection account","level":"auto","active_grant":null},
  {"alias":"deploy","description":"Deployment account","level":"requestable","active_grant":null}]}]}
```

Example error (stderr):

```json
{"schema":"hallpass.error/v1","source":"gateway","code":"wait_timeout","exit_code":86,"message":"request pending approval; connect again when approved","request_id":"req_01…"}
```

## Client configuration (for the user)

```
Host center
  HostName hallpass.example.net
  Port 2222
  User agent                  # ignored by the gateway
  IdentityFile ~/.ssh/agent_ed25519
  IdentitiesOnly yes
  StrictHostKeyChecking yes   # pin the gateway host key from `hallpass hostkey show`
  ForwardAgent no
  ClearAllForwardings yes
  ServerAliveInterval 30
```

Forwarding (`-L`, `-R`, `-D`, `-W`), agent forwarding, X11 and subsystems such as `sftp` are refused and audited.
