# Destination hardening guide

HallPass controls **who** can open a session on a destination, **when**, and records **what passed through it**. It does
not control what an allowed account can do once logged in. Reliable restrictions must be enforced on the destination.
This guide lists the controls that pair with HallPass.

## 1. One account per role, least privilege

- Create a dedicated OS account for each HallPass role (e.g. `hp-inspect`, `hp-deploy`). Never reuse personal or shared
  admin accounts.
- Give each account exactly the permissions the role description promises: group membership for log access, ownership of
  one application directory, nothing else. A username such as `readonly` enforces nothing by itself.
- Lock the password (`passwd -l`); the account authenticates only with the HallPass login key or certificate.

## 2. Install the login key with restrictions

HallPass shows a ready-made line per role, for example:

```
restrict,pty,from="203.0.113.10" ssh-ed25519 AAAA… hallpass:web1/inspect
```

- `restrict` disables port, agent and X11 forwarding, `~/.ssh/rc` and PTY allocation. HallPass re-enables `pty` only when the
  role has the `pty` capability.
- `from="…"` limits the key to the gateway's egress addresses (`egress.source_addresses`). Keep it even behind a firewall.
- For single-purpose roles, add `command="/usr/local/bin/allowed-action"`. Then the destination, not HallPass, decides
  what runs, which is the only reliable command restriction.

### Certificates instead of keys

If the role uses HallPass user certificates:

```
# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/hallpass_user_ca.pub
AuthorizedPrincipalsFile /etc/ssh/principals/%u
```

and put the role's explicit principal (shown on the role page) in `/etc/ssh/principals/<account>`. Certificates are valid for
about two minutes and carry `source-address` when gateway egress addresses are configured. HallPass ends sessions
itself when access ends, because certificate expiry does not end an established session.

## 3. Firewall SSH to the gateway

Allow inbound TCP 22 only from the HallPass egress addresses. Combined with `from=`, a leaked login key is useless from
anywhere else.

## 4. Privilege escalation

- Prefer no `sudo` at all for roles whose description says read-only.
- Where needed, use narrowly scoped `sudoers` entries (full paths, no wildcards, no shells, no editors, no interpreters),
  `NOEXEC` where possible, and `Defaults use_pty, log_output` for destination-side logs.
- Remember that interpreters (`python`, `perl`, `awk`), pagers (`less`), editors and tools such as `find -exec`, `tar
  --to-command`, `git` and `rsync` can spawn shells. Command allowlists are not a sandbox.

## 5. Process lifecycle after access ends

Closing the SSH channel (expiry, revocation, lockdown) does **not** guarantee that processes started in it stop. A
`nohup`, `setsid`, `screen`/`tmux`, a cron entry or a systemd user unit survives the session. To bound this:

- systemd-logind: `KillUserProcesses=yes` (and `KillExcludeUsers=` for unrelated accounts) ends the account's processes
  when its last session closes. `loginctl disable-linger <account>` stops user services from persisting.
- Put role accounts in a dedicated cgroup/slice with limits (`systemd` `user-<uid>.slice` resource controls).
- PAM: `pam_limits` (`nproc`, `maxlogins`), and `pam_access` to allow logins only from the gateway.
- sshd: `ClientAliveInterval 30` and `ClientAliveCountMax 3` to drop dead sessions.
- Deny `crontab` and `at` for role accounts (`/etc/cron.deny`, `/etc/at.deny`).

## 6. Outbound network and file transfer

HallPass refuses SSH forwarding and serves SFTP only for roles with the `file-transfer` capability, but an
allowed shell can still open network connections
(`curl`, `nc`, `/dev/tcp`) and move data through stdout. Restrict egress from destinations (host firewall per user with
`iptables -m owner --uid-owner`, or network policy) when data exfiltration matters.

## 7. Destination-side audit (stronger command accounting)

HallPass records what crosses the gateway: exec command strings, terminal output and optionally input. It cannot reliably
reconstruct every command typed into an interactive shell, and it never labels inferred commands as verified. For
command-level accountability, enable destination auditing:

- `auditd` rules for `execve` by role accounts (`-a always,exit -F arch=b64 -S execve -S execveat -F auid>=1000 -F auid!=-1 -k hallpass`).
  Kernel exec auditing sees executed binaries and arguments, but not shell built-ins (`cd`, `echo`, `export`, …) or the
  intent behind them.
- Shell history (`HISTFILE`, `PROMPT_COMMAND` logging) is user-writable and can be disabled or forged by the session itself.
  Treat it as a hint, never as evidence.
- A root user on the destination can alter destination logs. Ship them off the host promptly.

### Shipping exec records to HallPass (optional)

The reference collector `hallpass-collector` reads the audit log and sshd's log on the destination. It signs batches
with its own Ed25519 key, enrolled in HallPass per server, and posts them to HallPass. HallPass attaches records it can
attribute to an access session as `destination.exec` timeline events, labeled `provenance: destination-audit` and
`verified: false`, with a correlation method and confidence. Setup, the correlation rules, the wire format and the
limits are in [audit-collector.md](audit-collector.md). Key points:

- **Use certificates** for roles whose sessions overlap. The certificate key ID names the grant and connection, so
  correlation is exact (`confidence: high`). A managed login key is shared by all sessions of a role, so records are
  attached only when exactly one session used it at the login time; otherwise they are refused as `ambiguous`.
- Records of processes that kept running after the session ended are still attached, up to 24 hours, flagged
  `after_session_end`. Use them to check the process-lifecycle controls in §5.
- Keep `pam_loginuid` in sshd's PAM stack and sshd at `LogLevel INFO` or higher. Correlation needs both the audit
  session (`ses`) and the `Accepted publickey … ID …` log line.
- The collector key is only as safe as root on the destination. A compromised destination can forge or suppress
  records, so revoke its collector in HallPass during incident response.

## Checklist

- [ ] Dedicated account per role, password locked, minimal groups
- [ ] Login key installed with `restrict` and `from=`, or CA trust with explicit principals
- [ ] SSH reachable only from gateway egress addresses
- [ ] No broad `sudo`; escalation paths reviewed
- [ ] `KillUserProcesses=yes`, lingering disabled, cron/at denied
- [ ] Destination egress restricted where exfiltration matters
- [ ] auditd (or equivalent) shipping to an external store
- [ ] Optional: `hallpass-collector` enrolled for the server and shipping exec records (certificate-based roles preferred)
