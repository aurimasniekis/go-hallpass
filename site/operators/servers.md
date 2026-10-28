# Servers and roles

A **server** is a destination host. A **role** is one way to use it: a remote account plus what the role allows. The
easiest way to add a server is the guided wizard (**Servers → New server (guided)**), walked through in
[First run](/guide/first-run#enroll-your-first-server). This page covers the pieces in more depth.

<Shot name="servers" alt="Servers list with web1, db1 and ci-runner" />

<Shot name="server" alt="Server detail page with overview, host identities, roles, effective access and destination audit tabs" />

## Addresses and egress

- Agents only ever see the **alias** and description. The address and port are shown only to operators with the
  address permission (administrators, and auditors when `rbac.auditor_address_read` is set).
- HallPass dials only addresses inside `egress.allow_cidrs`. Loopback, link-local and cloud metadata ranges are denied
  unless re-allowed with `egress.allow_special_cidrs`. An empty `allow_cidrs` means nothing is reachable.
- Set `egress.source_addresses` to the address(es) your servers see HallPass connect from. The suggested
  `authorized_keys` lines and certificates use it for `from=` / `source-address`.

## Host identities

HallPass pins each server's host key, or trusts a host CA bound to the server. On the **Host identities** tab:

- **Scan host keys** fetches what the server offers; **Add key** accepts a pasted key.
- **Confirm** only after comparing the fingerprint with the server itself (`ssh-keygen -lf
  /etc/ssh/ssh_host_ed25519_key.pub` on the host, or your cloud console).
- **Retire** old keys after a planned key change.

If a server's key changes unexpectedly, connections fail with exit 88 and a host-key alert is recorded. Treat it as a
possible attack until you have confirmed the change out of band. See
[Troubleshooting](/help/troubleshooting#destination-host-key-changed).

## Roles

| Setting | Meaning |
|---|---|
| Alias, description | What agents see in `ssh center list`. Descriptions are informational. |
| Remote user | The account HallPass logs in as. Use a dedicated, least-privilege account per role. |
| Capabilities | `shell`, `exec`, `pty`: which SSH channel types are allowed. They do not restrict commands. `file-transfer` allows scp and sftp ([File transfer](/operators/file-transfer)). |
| Default / maximum duration | Grant length when the agent does not ask, and the role's ceiling. |
| Approval channels | Restrict decisions for a sensitive role to the web console only. |
| Record input | Also record what the agent types (off by default; may capture typed secrets). |
| Retention class | Which retention period applies to its recordings (`recording.retention_classes`). |

A role name such as `readonly` enforces nothing. Enforce least privilege on the destination: see
[destination hardening](/destinations/hardening).

## Login credentials

Each role needs a way for HallPass to log in.

### Managed login keys (recommended)

1. **Generate login key**. HallPass creates the key pair and keeps the private key encrypted with the KEK.
2. Install the shown line in the remote user's `~/.ssh/authorized_keys`. It already carries `restrict` and
   `from="<egress address>"`, plus `pty` only when the role has the `pty` capability.
3. **Test login**, then **Activate**.

To rotate: generate a new key, install it, test, activate, and after the overlap remove the old line and retire the
old key. Importing an existing private key is possible, but generating in HallPass is preferred.

### User certificates

Instead of installing keys, create a **user CA** in HallPass and bind the role to it. On the destination, trust the CA
and allow only the role's explicit principal:

```
# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/hallpass_user_ca.pub
AuthorizedPrincipalsFile /etc/ssh/principals/%u
```

Put the principal shown on the role page in `/etc/ssh/principals/<account>`. Certificates are valid for about two
minutes. They also make destination-side audit correlation exact; see [destination-side audit](/destinations/audit).

## Web terminal

Administrators can open a shell on a server straight from the console: **Servers → a server → Roles → Terminal**, on any
enabled role with the `shell` and `pty` capabilities. HallPass logs in with the role's credential, exactly as for an
agent, so the remote user is the role's.

- It needs a recent sign-in with two-factor authentication, and opens immediately: no request or approver.
- It is **recorded** like an agent's session (replay it under **Sessions**), audited under your name, and named in the
  session as *web terminal*.
- It lasts the role's default duration (at most its maximum), and ends when you close the window, when it expires, on
  lockdown, when the server or role is disabled, and within seconds when you are disabled or lose the administrator
  role.
- Agent policy rules do not apply to it; an administrator can already change those rules.

<Shot name="web-terminal" alt="A recorded web terminal on web1 opened from the console, running uptime and tail" />

To turn web terminals off, set `console.terminal: false` in the configuration and restart: nobody, not even an
administrator, can open one then.

## Disabling and deleting

**Disable** (on the server page, or on a role's page) when access should stop for now. Agents no longer see the
server or role, live sessions end within 5 seconds, active grants are revoked and pending requests are canceled.
**Enable** brings it back, and policy decides again who can use it.

**Delete** when it is gone for good. It does everything disabling does, and also revokes the login keys, so remove
them from the destination too. Deleting a server deletes all of its roles; you confirm by typing the server's name.
A deleted server or role disappears from the console and from agents, and its name can be used again. Past sessions,
recordings and the audit log still show it, marked as deleted. A deletion cannot be undone.

Every change to servers, roles, groups or labels bumps the policy version; grants that are no longer allowed are
revoked.
