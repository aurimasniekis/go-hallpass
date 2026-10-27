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
  User agent                  # any value works for commands; scp and sftp put the server here instead
  IdentityFile ~/.ssh/agent_ed25519
  IdentitiesOnly yes
  StrictHostKeyChecking yes
  ForwardAgent no
  ClearAllForwardings yes
  ServerAliveInterval 30
```

Forwarding (`-L`, `-R`, `-D`, `-W`), agent forwarding and X11 are refused and audited. `scp` and `sftp` work through
roles with the file-transfer capability; see [File transfer](#file-transfer).

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

## Git

Git remotes work with plain git: no wrapper, no extra configuration beyond your `Host` entry for the gateway.

<Shot name="agent-git" alt="An agent cloning through the gateway, requesting push access with a reason, pushing an agent branch and being refused on main" />

```sh
git clone center:github/acme/api.git              # <remote>/<owner>/<repository>.git
git remote set-url origin center:github/acme/api.git
git push origin agent/fix-cart-timeout
```

- `ssh center list` marks git remotes with `(git)` and lists their access profiles like roles.
- A clone or push that needs approval waits for it, printing the request ID on stderr, just like `exec`.
- Git cannot send a reason. If the profile requires one, request access first, then run git again:

  ```sh
  ssh center 'request github --role acme-push --reason "Fix cart timeout (OPS-2297)" --wait'
  git push origin agent/fix-cart-timeout
  ```

- Pushes are checked before they reach the host. Only the branches and tags the profile allows can change, protected
  branches never, and rewriting history (force-push) is refused unless the profile allows it. Push new commits on top
  of the branch instead of rewriting it. A refused push changes nothing and prints the reason, for example
  `hallpass: push refused: refs/heads/main: protected branch`.
- `repository not found or not permitted` means no profile you can use covers that repository and operation.
- `exec` and `connect` are refused on git remotes.

## APIs

API targets (marked `(api)` in `list`) are HTTPS APIs such as GitHub, Cloudflare or Google Cloud. You call them with
their usual tools through the gateway's API proxy, which adds the operator's credential. You never hold the token, and
every call is checked against your access profile and recorded.

```sh
ssh -fN -o ExitOnForwardFailure=yes -L 127.0.0.1:18080:hallpass:443 center   # the proxy tunnel; keep it running
eval "$(ssh center api env)"                     # CA bundle, HTTPS_PROXY, CA variables, placeholder tokens
gh pr list --repo acme/api                        # gh, wrangler, gcloud, curl, …
```

`api env` writes the CA bundle to `~/.hallpass/api-ca.pem` (the same as `ssh center api ca`) and exports:

| Variable | For |
|---|---|
| `HTTPS_PROXY`, `https_proxy`, `NO_PROXY` | every tool that honors a proxy |
| `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE` | Go tools (`gh`), curl, Python |
| `NODE_EXTRA_CA_CERTS`, `NODE_USE_ENV_PROXY` | Node tools (`wrangler`) |
| `CLOUDSDK_PROXY_*`, `CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE`, `CLOUDSDK_AUTH_ACCESS_TOKEN_FILE` | `gcloud` |
| `GH_TOKEN`, `CLOUDFLARE_API_TOKEN` | placeholders, so the tools do not ask you to log in; HallPass replaces them |

Use `--port <n>` with `api env` for another local port. The settings route all HTTPS of that shell through the gateway,
which refuses hosts that are not API targets, so load them only where you call the API. On macOS, Go tools such as `gh`
ignore `SSL_CERT_FILE`: add the CA to the login keychain once
(`security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db ~/.hallpass/api-ca.pem`). The CAs
can sign certificates only for the API targets' host names.

Access works like for servers: an `auto` profile is granted on your first call, a `requestable` one needs a request
with a reason first. A call HallPass refuses returns **HTTP 403** with a message starting `hallpass:`, which `gh`,
`wrangler` and `gcloud` show:

- `GET /repos/acme/api needs access to github as write: run ssh <gateway> request github --role write --reason '<why>' --wait, then retry`
- `no access profile you can use on github allows DELETE /repos/acme/api`: the call is outside what you may do.

### hallpass-api

`hallpass-api` (in the release archives, including macOS) runs one command through the proxy without any setup:

```sh
hallpass-api --gateway center --reason "Answer the customer on #42" -- gh issue comment 42 --body "Fixed in #43"
```

It uses your `ssh` (config, key and pinned host key) to fetch the CA bundle and open the tunnel, and sets the proxy,
CA and placeholder-token variables for that command only. It also reports the command line and your reason to the
gateway. When a call needs a profile that requires approval, the gateway files the request itself, and approvers see
the command next to your reason. `hallpass-api` then waits (`--wait`, default 10 minutes), and once approved runs the
command again. A refused call never reached the API, so running it again is safe for single-call commands; a command
that made other changes before the refused call repeats them (use `--retries 0` and run it again yourself).

| Option | Default | Meaning |
|---|---|---|
| `--gateway` | `$HALLPASS_GATEWAY` | ssh host of the gateway |
| `--reason` | `$HALLPASS_REASON` | why you need the access; required for profiles that require a reason |
| `--wait` | `10m` | how long to wait for approval (`0`: print the request IDs and exit) |
| `--retries` | `2` | how many times to run the command again after approvals |
| `--ssh` | `ssh` | ssh client to use |

Values of options that look like secrets (`--token x`, `--api-key=x`) are replaced by `[redacted]` in the reported
command. The command is what you report: approvers see it labeled that way, and HallPass still checks every request.
Exit codes: the command's own, or 83 denied, 84 expired, 85 canceled, 86 still pending, 80 setup failed.

`exec` and `connect` are refused on API targets.

## File transfer

Roles whose capabilities include `file-transfer` (see `ssh center roles web1`) accept `scp` and `sftp`. SFTP has no
place for a command, so the SSH user names the server, and `+role` picks a role:

```sh
scp build.tar web1@center:/tmp/                    # upload; the role is chosen for you
scp web1@center:/var/log/app.log .                 # download
scp -r dist/ web1+deploy@center:/srv/app/releases/ # name the role after "+"
sftp web1+deploy@center                            # interactive sftp
```

- Without `+role`, HallPass picks a file-transfer role you already have a grant for, then one that is approved
  automatically, then one you can request.
- A transfer that needs approval waits for it, printing the request ID on stderr, like `exec`.
- scp cannot send a reason. If the role requires one, request access first, then run scp again:

  ```sh
  ssh center 'request web1 --role deploy --reason "Upload release 1.4.3" --wait'
  scp build.tar web1+deploy@center:/srv/app/
  ```

- Every file operation is recorded: uploads and downloads with their size and SHA-256 checksum, renames, deletions,
  directory listings and failures. File contents are not stored.
- Files are read and written as the role's remote account, so its permissions decide what you can reach.
- The old scp protocol (`scp -O`) is refused; plain `scp` from OpenSSH 9 or later uses SFTP already.
- `no role you can use on web1 allows file transfer` means you need a role with the capability. Ask the user.

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
