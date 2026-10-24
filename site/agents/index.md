# Agent guide

For AI agents, and the people configuring them, that reach servers through a HallPass gateway. The authoritative
version is [docs/agent/guide.md](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/agent/guide.md);
`ssh center help` prints the same help as the gateway.

## How it works

You connect with an ordinary SSH client to the gateway, never to the destination, using your own key. The gateway
decides from policy which servers and roles you can see, creates access requests, waits for approval when needed, and
opens the destination session for you with credentials you never see. Every session is recorded.

<Shot name="agent-terminal" alt="An agent's terminal: list, exec, an exec waiting for approval, and a hidden server" />

## Client configuration

Pin the gateway host key; never accept it on first use. Install the line the operator gives you (from
`hallpass hostkey show`):

```
# ~/.ssh/known_hosts
[hallpass.example.com]:2222 ssh-ed25519 AAAAC3Nza…
```

```
# ~/.ssh/config
Host center
  HostName hallpass.example.com
  Port 2222
  User agent                  # ignored by the gateway; any value works
  IdentityFile ~/.ssh/agent_ed25519
  IdentitiesOnly yes
  StrictHostKeyChecking yes
  ForwardAgent no
  ClearAllForwardings yes
  ServerAliveInterval 30
```

Forwarding (`-L`, `-R`, `-D`, `-W`), agent forwarding, X11 and subsystems such as `sftp` are refused and audited.

## Commands

```sh
ssh center                                    # same as list
ssh center list --json
ssh center roles web1
ssh center 'request web1 --role deploy --reason "Deploy 1.4.3" --duration 30m'
ssh center status req_01… --wait
ssh center cancel req_01…
ssh center exec web1 --role inspect -- df -h /var
ssh -t center connect web1 --role inspect     # interactive shell: needs ssh -t
ssh -t center web1                            # shorthand for connect
ssh center sessions --all
ssh center whoami
ssh center version
ssh center help exec
```

The full list with every option is in the [agent command reference](/reference/agent-commands).

<Shot name="agent-shell" alt="An interactive shell on web1 through the gateway: uptime, ls, grep and ps" caption="ssh -t center connect web1 --role inspect" />

### Waiting for approval

- `connect` and `exec` reuse an active grant for the server and role. Otherwise they create a request (or reuse an
  identical pending one) and wait. The default wait is 2 minutes, the maximum 15 (`--wait-timeout`).
- If the wait times out, the request **stays pending**: the command exits 86 and you continue with
  `ssh center status <req_id> --wait`. Do not create a new request.
- When policy requires a reason and you gave none, the gateway prompts on a PTY; without one it exits 90.
- A grant lasts from approval for its duration. Reconnecting never extends it. When it ends, running sessions end with
  exit 87 and a notice on stderr.
- Unknown servers and servers you may not see give the same answer: exit 82, "not found or not permitted".

## Quoting

ssh joins its arguments with spaces before sending them, so quotes that your local shell removes never reach the
gateway. **Wrap the whole gateway command in single quotes** whenever a value has spaces:

```sh
ssh center 'exec web1 --role inspect --reason "Check disk usage" -- df -h /var'    # works
ssh center exec web1 --role inspect --reason "Check disk usage" -- df -h /var      # exit 81: --reason Check disk usage
```

Single-word values are fine unquoted. At the gateway, `'…'` is literal, `"…"` is literal except for `\"` and `\\`,
and there is no variable, glob or command expansion. Multi-line commands are rejected (exit 81).

Everything after the first unquoted `--` goes unchanged to the destination, where the remote user's login shell
interprets it:

```sh
ssh center 'exec web1 -- ls -l /var/log | head -5'     # the pipe runs on web1
ssh center 'exec web1 -- echo "$HOME"'                  # $HOME expands on web1
```

## Output and exit codes

- The destination's stdout and stderr pass through unchanged and separately. Gateway messages go to stderr, prefixed
  `hallpass:`.
- Gateway errors are a single JSON line (`hallpass.error/v1`) on stderr when you pass `--json` or when the gateway sees
  no terminal, which is the case for every command run without `ssh -t`.
- For `exec` and `connect`, the destination's exit status is returned as is. Gateway failures use **80–90**: see
  [exit codes](/reference/exit-codes). A destination command can also exit with a code in that range; a
  `hallpass.error/v1` line on stderr tells you it was the gateway.
- `--json` success output is one JSON document on stdout, described by the
  [JSON schemas](https://github.com/aurimasniekis/go-hallpass/tree/main/api/ssh-schemas).

## Tips for automation

- Use `exec` for non-interactive work. Use `ssh -t` only for interactive shells.
- Use `--idempotency-key` with `request` so retries never create duplicates.
- If your framework cannot hold a connection open while waiting, use `request … --no-wait --json` and then
  `status <id> --json` or `status <id> --wait`.
- Never put secrets in `--reason`. Reasons are stored and shown to approvers.
- AI coding agents: install the [HallPass skill](/agents/skill), which teaches all of this.
