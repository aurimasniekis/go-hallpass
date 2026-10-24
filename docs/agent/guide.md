# HallPass agent guide

This guide is for AI agents (and the people configuring them) that reach servers through a HallPass gateway. 
`ssh <gateway> help` prints the same command help as the gateway.

## How it works

You connect with an ordinary SSH client to the gateway, never to the destination. You authenticate with your
agent key. The gateway decides from policy which servers and roles you can see, creates access requests, waits
for approval when needed, and opens the destination session for you using credentials you never see. Every session
is recorded.

```
agent ──ssh (agent key)──▶ HallPass ──ssh (managed key or certificate)──▶ destination
```

## Client configuration

Pin the gateway host key. Do not accept it on first use. Ask the operator for the `known_hosts` line, which
`hallpass hostkey show` prints, and install it:

```
# ~/.ssh/known_hosts
[hallpass.example.net]:2222 ssh-ed25519 AAAAC3Nza…
```

```
# ~/.ssh/config
Host center
  HostName hallpass.example.net
  Port 2222
  User agent                  # any value works for commands; scp and sftp put the server here instead
  IdentityFile ~/.ssh/agent_ed25519
  IdentitiesOnly yes
  StrictHostKeyChecking yes
  ForwardAgent no
  ClearAllForwardings yes
  ServerAliveInterval 30
```

During a gateway host-key rotation, the operator stages a second key (`hallpass hostkey stage`) and the gateway serves
both. Add the new line before the promotion so you keep a pinned key throughout.

Forwarding (`-L`, `-R`, `-D`, `-W`), agent forwarding and X11 are refused and audited. `scp` and `sftp` work only
through roles with the `file-transfer` capability, with the server as the SSH user (`scp f web1@center:/tmp/`).

## Commands

```
ssh center                                 # list (default)
ssh center list --json
ssh center roles web1
ssh center 'request web1 --role inspect --reason "disk alert on /var" --duration 30m'
ssh center status req_01… --wait
ssh center cancel req_01…
ssh -t center connect web1 --role inspect  # interactive shell (needs a PTY: ssh -t)
ssh -t center web1                         # shorthand for connect
ssh center exec web1 --role inspect -- df -h /var
ssh center sessions --all
ssh center whoami
ssh center version
ssh center help exec
```

- `connect` and `exec` reuse an active grant for the server and role. Otherwise they create a request, or reuse an
  identical pending one, and wait for a decision. The default wait is 2 minutes and the maximum is 15
  (`--wait-timeout`). If the wait times out, the request stays pending: the command exits 86 and you resume with
  `status <req_id> --wait`.
- When policy requires a reason and you gave none, the gateway prompts for it on a PTY. Without a PTY the command
  exits 90. Pass `--reason`.
- A grant lasts from approval for its duration. Reconnecting never extends it. When it expires or is revoked, running
  sessions end with exit 87 and a notice on stderr.
- Unknown servers and servers you may not see give the same answer: exit 82, "not found or not permitted".

## Git and file transfer

Git and file transfer use the standard tools, not a gateway command, and wait for approval like `connect`:

```sh
git clone center:github/acme/api.git          # git remotes are marked (git) in list
scp build.tar web1@center:/tmp/               # roles with the file-transfer capability
sftp web1+deploy@center                       # "+<role>" picks the role
```

Neither git nor scp can send a reason: when one is required, `request … --reason … --wait` first, then retry.

## Quoting

The gateway splits its part of the command on spaces and tabs. `'…'` is literal, `"…"` is literal except for `\"` and
`\\`, and outside quotes `\x` means `x`. There is no variable, glob, tilde or command expansion at the gateway. Control
characters other than TAB, and therefore multi-line commands, are rejected with exit 81.

**Multi-word option values** such as `--reason` need quotes that reach the gateway. ssh joins its arguments with
spaces, so quotes your local shell removes are lost: `ssh center request web1 --reason "disk alert"` arrives as
`--reason disk alert` and fails with exit 81. Quote the whole gateway command once:
`ssh center 'request web1 --role inspect --reason "disk alert on /var"'`.

Everything after the first unquoted `--` is sent unchanged to the destination, and the remote user's login shell
interprets it. `--` does not stop remote shell expansion. Your local shell also parses the command first, so quote
the whole gateway command once for your local shell:

```
ssh center 'exec web1 -- ls -l /var/log | head -5'     # the pipe runs on web1
ssh center exec web1 -- 'ls -l /var/log | head -5'      # same: the local shell strips the outer quotes
ssh center 'exec web1 -- echo "$HOME"'                  # $HOME expands on web1
```

## Output, streams and exit codes

- The destination's stdout and stderr pass through unchanged and separately. Gateway messages go to stderr, prefixed
  `hallpass:`. Gateway errors print a single JSON line (`hallpass.error/v1`) when `--json` is given or when stderr
  is not a terminal.
- For `exec` and `connect`, the destination's exit status is returned as is. Gateway failures use exit codes 80–90.
  See [exit-codes.md](exit-codes.md). An `exec` can legitimately exit with a code in 80–90 itself. When the
  distinction matters, use `--json`: a gateway error always comes with a `hallpass.error/v1` line on stderr.
- `--json` success output is one JSON document on stdout. See [json-schemas.md](json-schemas.md).

## Automation tips

- Use `--idempotency-key` with `request` so retries never create duplicates.
- Use `request … --no-wait --json`, then poll `status <id> --json` (or block with `status <id> --wait`) when your
  framework cannot keep one SSH connection open while waiting.
- Use `exec` for non-interactive work. Allocate a PTY (`ssh -t`) only for interactive shells.
- Never put secrets in `--reason`. Reasons are stored (encrypted) and shown to approvers.
