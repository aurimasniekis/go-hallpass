# What is HallPass?

HallPass is a **terminating SSH gateway for AI agents**. Agents connect to HallPass with their own SSH key and plain
`ssh`. HallPass decides, from policy and human approvals, which servers and roles an agent may use and for how long.
It then opens the session to the destination itself, with a credential the agent never sees, and records everything
that passes through.

```
agent ──ssh (agent key)──▶ HallPass ──ssh (managed key or short-lived certificate)──▶ destination
                              │
          policy · approvals (web, Slack, Telegram) · grants · encrypted recordings · audit chain
```

## The problem with giving agents SSH keys

The quickest way to let an agent work on a server is to give it a key that is in `authorized_keys`. That key:

- **works forever**, until someone remembers to remove it from every server;
- **works everywhere** it was installed, for any task, at any hour;
- **needs nobody's approval**, so a confused or manipulated agent acts immediately;
- **leaves little trace**: shell history is optional and editable, and nothing ties a command to the task that
  caused it;
- **can leak**: anything the agent can read can end up in a prompt, a log or a tool call.

## What HallPass changes

| Without HallPass | With HallPass |
|---|---|
| The agent holds a destination key | The agent holds only its own key. HallPass keeps destination keys encrypted, or signs certificates that live about two minutes. |
| Access is permanent | Access is a **grant** with an end time. Reconnecting never extends it. |
| Nobody decides | Policy decides per agent, server and role: hidden, requestable with human approval, or approved automatically up to a limit. |
| Approval happens elsewhere, if at all | Agents ask with a reason. Approvers decide in the web console, Slack or Telegram. |
| Revocation means editing servers | Revoke a grant, disable an agent or enable lockdown: live gateway sessions end within 5 seconds. |
| History is a best effort | Every channel is recorded (encrypted, integrity-chained) and replayable, next to a timeline and a hash-chained audit log. |
| The agent knows server addresses | Agents see aliases and descriptions only. Unknown and hidden servers look the same. |
| A deploy key can push anywhere | Agents use plain git through HallPass. Access profiles limit repositories and branches, protect `main` and refuse force-pushes. |
| Files are copied without a trace | Roles with the file-transfer capability accept `scp` and `sftp`, and every file operation is recorded with its path, size and SHA-256. |

<Shot name="dashboard" themed alt="HallPass dashboard" caption="The operator dashboard" />

## What HallPass is not

HallPass controls **who** gets a session, **when**, and records **what passed through it**. It is deliberately not:

- **a sandbox.** An approved shell can do whatever its remote account can do. Restrict that on the destination with
  a dedicated account per role, `sudoers`, `ForceCommand` and firewalling. See
  [destination hardening](/destinations/hardening).
- **a port-forwarding proxy.** Forwarding (`-L`, `-R`, `-D`, `-W`), agent forwarding and X11 are refused. SFTP and
  scp work only through roles with the file-transfer capability.
- **highly available.** One active instance; recovery is restoring a backup onto a standby.
- **safe from its own host.** HallPass sees every session in plaintext and holds every destination credential. Run it
  like a bastion host. See the [security model](/security/).

## Status

The current release is **0.3.0**. Versions before 1.0 may change interfaces between minor releases
([versioning](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/VERSIONING.md)). Read the
[known limitations](/security/#release-status) before you deploy it.

Next: [Concepts](/guide/concepts).
