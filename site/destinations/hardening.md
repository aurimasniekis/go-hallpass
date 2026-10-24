# Destination setup and hardening

Hallpass controls **who** can open a session on a destination, **when**, and records **what passed through it**. It
does not control what an allowed account can do once it is logged in. That is the destination's job, and this page
lists the controls that pair with Hallpass. Reference:
[hardening.md](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/destination/hardening.md).

## 1. One account per role, least privilege

```sh
useradd --create-home --shell /bin/bash hp-inspect     # one account per Hallpass role
passwd -l hp-inspect                                    # key or certificate login only
usermod -aG adm hp-inspect                              # only the groups the role really needs (e.g. log access)
```

Give each account exactly what the role's description promises, nothing more. A username such as `readonly`
enforces nothing by itself.

## 2. Install the login key with its restrictions

Hallpass shows a ready-made line per role:

```
restrict,pty,from="203.0.113.10" ssh-ed25519 AAAA… hallpass:web1/inspect
```

- `restrict` disables forwarding, `~/.ssh/rc` and PTYs; `pty` is added back only for roles with the `pty` capability.
- `from="…"` limits the key to the gateway's egress addresses. Keep it even behind a firewall.
- For single-purpose roles, add `command="/usr/local/bin/allowed-action"`. Then the destination, not Hallpass, decides
  what runs. This is the only reliable command restriction.

With **certificates** instead of keys:

```
# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/hallpass_user_ca.pub
AuthorizedPrincipalsFile /etc/ssh/principals/%u
```

and put the role's principal (shown on the role page) into `/etc/ssh/principals/<account>`.

## 3. Firewall SSH to the gateway

Allow inbound TCP 22 only from the Hallpass egress addresses. Together with `from=`, a leaked login key is useless
from anywhere else.

## 4. Privilege escalation

- No `sudo` for read-only roles.
- Otherwise narrow `sudoers` entries: full paths, no wildcards, shells, editors or interpreters; `NOEXEC` where
  possible; `Defaults use_pty, log_output`.
- Interpreters (`python`, `perl`, `awk`), pagers, editors, `find -exec`, `tar --to-command`, `git` and `rsync` can all
  spawn shells. Command allowlists are not a sandbox.

## 5. Processes that outlive the session

Ending a channel (expiry, revocation, lockdown) does **not** stop processes started with `nohup`, `setsid`, `tmux`,
`screen`, cron or systemd user units. To bound this:

- systemd-logind `KillUserProcesses=yes` and `loginctl disable-linger <account>`;
- `pam_limits` and `pam_access` (logins only from the gateway);
- `ClientAliveInterval 30` and `ClientAliveCountMax 3` in sshd;
- deny `crontab` and `at` for role accounts.

## 6. Outbound network

Hallpass refuses SSH forwarding, SFTP and SCP, but an allowed shell can still use `curl`, `nc` or `/dev/tcp`, and
print data to stdout. Restrict egress from destinations (for example `iptables -m owner --uid-owner`) when
exfiltration matters.

## 7. Destination-side audit

Hallpass records what crosses the gateway, but cannot reliably reconstruct every command typed into a shell. For
command-level accounting, enable `auditd` on the destination and optionally ship records to Hallpass with
[`hallpass-collector`](/destinations/audit).

## Checklist

- [ ] Dedicated account per role, password locked, minimal groups
- [ ] Login key installed with `restrict` and `from=`, or CA trust with explicit principals
- [ ] SSH reachable only from gateway egress addresses
- [ ] No broad `sudo`; escalation paths reviewed
- [ ] `KillUserProcesses=yes`, lingering disabled, cron and at denied
- [ ] Destination egress restricted where exfiltration matters
- [ ] auditd (or equivalent) shipping to an external store
