# Troubleshooting

Start with the exit code. For `exec` and `connect`, the destination's own exit status passes through unchanged; codes
**80–90** come from the gateway and are listed in the [exit code reference](/reference/exit-codes). Exit **255** comes
from your SSH client, before the gateway ran anything.

## Agent side

### `Permission denied (publickey)` / exit 255

The gateway did not accept the key.

- Is the key registered on the agent's page, and not revoked? Is the agent enabled?
- Does `ssh -v center whoami` offer the right key? Use `IdentitiesOnly yes` and `IdentityFile` in `~/.ssh/config`.
- Is the agent restricted by **Source CIDRs**?
- Is the source banned? See [banned source](#banned-source).

### `REMOTE HOST IDENTIFICATION HAS CHANGED` (gateway host key)

Your client pinned a different gateway key. Do **not** remove the line and reconnect blindly. Ask the operator for the
current fingerprint (`hallpass hostkey show`) and compare out of band. During a planned rotation, the operator stages a
second key first; add its `known_hosts` line before the promotion.

### Banned source

After repeated failed logins from one address (10 within 10 minutes by default), Hallpass bans that source and drops
its connections before the SSH banner. Your client usually reports `Connection closed by …` or
`kex_exchange_identification`. The first ban lasts 15 minutes and doubles for each further ban within 7 days (up to 24
hours).

Operators see and lift bans under **Administration → System → SSH bans**. If many agents share one NAT address, add
it to `ssh.ban.allow_cidrs` so one misconfigured agent cannot lock out the others.

### `connect` shows nothing, no prompt

You ran `ssh center connect web1` without `-t`. Without a terminal, the shell is non-interactive: it prints no prompt
and waits for commands on stdin. The gateway says so on stderr (`no terminal requested: this is a non-interactive
shell`). Use `ssh -t center connect web1`, or `exec` for single commands.

### Exit 81 with "unexpected argument"

A value with spaces lost its quotes. ssh joins arguments with spaces, so wrap the whole gateway command once:

```sh
ssh center 'request web1 --role deploy --reason "Deploy 1.4.3" --duration 30m'
```

### Exit 82, "not found or not permitted"

Either the server or role does not exist, or policy does not let this agent see it; the gateway deliberately does not
say which. Check the alias with `ssh center list`, then ask an operator to check the agent's **effective access**. A
`deny` rule (for example "CI agents never touch production") beats every allow.

### Exit 86, still pending

Nobody decided within the wait timeout. The request is **still pending**. Keep waiting with
`ssh center status <req_id> --wait` instead of creating a new request.

### Exit 87, access ended

The grant expired or was revoked, the agent or key was disabled, or lockdown was enabled. Request again if you still
need access.

### Exit 88, destination unavailable

Hallpass could not complete the destination login. Typical causes, for the operator:

- the destination is down or unreachable, or its address is outside `egress.allow_cidrs`;
- the destination's host key changed (see [below](#destination-host-key-changed));
- the role's login key is not installed, or `from=` does not match the address the destination sees.

### Exit 89, limit exceeded

Too many requests per hour (`access.requests_per_agent_hour`, 30), too many pending requests (10), or too many
concurrent connections or channels. Wait, and reuse pending requests rather than creating new ones.

### Exit 90, input required

Policy requires a reason and there was no terminal to prompt on. Pass `--reason`.

## Operator side

### Destination host key changed

`exec` and `connect` fail with exit 88 and a host-key alert is recorded. Hallpass refuses to send credentials to a host
whose key does not match. Confirm out of band whether the change is expected. If it is, add and confirm the new key on
the server's **Host identities** tab and retire the old one. If not, keep the server disabled and investigate. See the
[runbook](/operators/incidents#destination-host-key-changed).

### Hallpass refuses to start

- `master key (KEK) does not match this data directory`: the wrong KEK file, or one rotated away.
- KEK or data directory permission errors: the KEK must be `0400`/`0600`, owned by the service user, outside
  `data_dir`; the data directory `0700` and owned by the service user.
- `another hallpass process owns this data directory`: a second process or an offline command is running.
- `database schema is newer than this binary`: you started an older binary after an upgrade. Use the newer one, or
  restore a pre-upgrade backup.
- Network filesystem refused: put `data_dir` on local storage.
- Configuration errors: run `hallpass config check`. Unknown keys and unknown `HALLPASS_*` variables are errors.

### Offline command says the data directory is locked

`hostkey`, `keys`, `verify`, `restore`, `admin` and `migrate` take the data-directory lock. Stop the server first.
`backup create` and `anchors export` run online.

### Approvers cannot approve

An operator needs the Approver or Administrator role **and** a matching approver rule. Administrators have no implicit
approval authority. Owners of the requesting agent cannot approve its requests by default.

### Readiness is `degraded`

Usually the free-space reserve (`disk_reserve`) or a busy writer. New sessions are refused until space is freed; see
[Monitoring](/operators/monitoring).
