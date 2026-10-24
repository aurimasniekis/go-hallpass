# Concepts

A short glossary of the objects you meet in the console and in the agent's output.

## Inventory

**Agent**
: An AI agent, container or VM that uses Hallpass. It has a name, optional groups and labels, and one or more
  registered **public keys**. The SSH username an agent sends is ignored: identity comes from the key alone.

**Server**
: A destination host. Agents address it by its **alias** (`web1`). The address and port are known only to Hallpass
  and to operators allowed to see them. Servers have groups and labels for policy selectors.

**Host identity**
: The destination's SSH host key (or a host CA) that Hallpass pins. Hallpass never trusts a host key on first use: an
  operator confirms the fingerprint out of band. A changed key stops every connection until an operator acts.

**Role**
: A way to use a server, for example `inspect` or `deploy`. A role names the **remote user**, its **capabilities**
  (`shell`, `exec`, `pty`), default and maximum durations, and recording settings. Capabilities control SSH channel
  types, not commands.

**Login credential**
: How Hallpass logs in as the role's remote user: a **managed login key** that you install in that user's
  `authorized_keys`, or a short-lived **OpenSSH user certificate** signed by a Hallpass user CA. Agents never see
  either.

## Policy

**Access rule**
: Subjects (agents) × targets (servers) × roles → an effect. `deny` beats everything. Otherwise the highest matching
  level wins: `visible` (listed but not requestable), `requestable` (a human approves) or `auto_approve` (approved by
  policy up to a limit). Policy is **default deny**.

**Approver rule**
: Which operators may approve which requests. Administrators get no implicit approval authority: they need an approver
  rule too.

## Access lifecycle

**Request** → **decision** → **grant** → **access session** → **channels**

- A **request** asks for a server and role, with a reason and a duration. It expires if nobody decides
  (`access.pending_expiry`, 30 minutes by default).
- A **decision** approves (possibly for a shorter duration) or denies it. Policy can decide automatically.
- A **grant** is the approved, time-bound permission. It ends at expiry or on revocation and is never extended by
  reconnecting.
- An **access session** groups everything done under one grant: connections, channels, recordings and timeline.
- A **channel** is one `exec` command or one shell. Each channel is recorded.

## Operators

People who use the web console. Built-in roles:

| Role | Can |
|---|---|
| Administrator | Manage everything: inventory, policy, operators, integrations, settings. |
| Approver | Decide requests within their approver rules, revoke grants, terminate activities. |
| Auditor | Read requests (with reasons), replay recordings, read and verify the audit log. |
| Viewer | Read-only overview. |

Some cells are configurable (`rbac.*` in the [configuration](/reference/configuration)). Sensitive actions require
**recent authentication** (5 minutes). Operators sign in with a password and TOTP, or with SSO.

## Safety controls

**Lockdown**
: One switch that revokes every grant, cancels pending requests and refuses new ones. Agents can still `list` and
  check `status`.

**KEK (key-encryption key)**
: The master key, kept outside the data directory. It wraps every key that encrypts recordings, credentials and
  sensitive fields. **Losing it makes the data unrecoverable**, so back it up separately. See [Keys and the
  KEK](/operators/keys).

**Audit log**
: An append-only, hash-chained record of security-relevant actions. Export **integrity anchors** to storage the
  gateway cannot modify to detect later rewrites.
