# HallPass — Product Contract (GOAL)

> **Status:** canonical product contract. Established at WP00 (planning) on 2026-10-23.
> Changes to this file are contract changes: they must be recorded in `docs/DECISIONS.md` with justification,
> and security requirements may never be weakened silently (see `AGENTS.md`).
> Design reference and requirement status: `docs/PLAN.md`.

## 1. Product statement

HallPass is a **terminating SSH gateway for AI agents**:

```
Agent ──SSH (agent key)──▶ HallPass ──SSH (gateway-controlled credential)──▶ Destination server
```

An agent, container, or VM owns an SSH key pair. An operator registers the agent's public key with HallPass.
The agent uses only the gateway endpoint (examples use the SSH alias `center`) and its own private key to:

- discover the server aliases and access roles it is permitted to see, with operator-approved descriptions;
- request temporary access with a reason;
- obtain human approval through the web UI, Slack, or Telegram (or policy auto-approval within limits);
- connect, disconnect, reconnect, and execute commands during the approved interval.

HallPass authenticates agents, enforces visibility and access policy, obtains approvals, resolves destination
addresses internally, opens outbound SSH connections with credentials the agent never sees, records access
history and SSH activity into encrypted files, and terminates gateway-managed access at expiry or revocation.

HallPass is a complete product, not an MVP. Milestones are allowed, and they do not reduce the final scope (§8).

## 2. Scope

In scope for v1.0:

1. SSH front end for agents: public-key auth, the command grammar (`list`, `roles`, `request`, `status`, `cancel`,
   `connect`, `exec`, `sessions`, `help`, `version`, `whoami`, alias shorthand), shell/exec/PTY proxying.
2. Inventory: agents and keys; servers, host identities, roles; destination login credentials (managed keys and
   OpenSSH user certificates); groups and labels.
3. Policy engine: visibility, request permission, auto-approval, approver authority, effective-access preview.
4. Request → decision → grant → access session lifecycle with an enforcer that terminates activity on expiry and revocation.
5. Encrypted, append-oriented event history and terminal recording with integrity verification and replay.
6. Human operator console: local accounts (Argon2id, TOTP, recovery codes), generic OIDC SSO, RBAC, sessions.
7. Approval channels: web, Slack, Telegram, through a durable SQLite outbox.
8. REST API (OpenAPI 3.1) and SSE live events.
9. Operations: SQLite storage with migrations, backup/restore/verify, health/readiness, slog JSON logs, OpenTelemetry,
   container + Compose + standalone deployment, CI/CD with scanning, SBOM and provenance.
10. Documentation: operator, agent, destination-hardening, architecture, API, formats, security guarantees.
11. Optional destination-side audit integration (WP25) as a provenance-labeled supplementary source.

## 3. Non-goals (v1.0)

- **Not a sandbox.** HallPass does not restrict what an allowed shell can do on the destination. Command
  allowlists are not offered as a security boundary. Destination-side controls (accounts, sudoers,
  ForceCommand, MAC policies, network egress rules) are required for reliable restriction.
- **No port, agent, X11 or streamlocal forwarding, and no subsystems other than SFTP.** SFTP (and scp over SFTP) is
  served only for roles with the separately authorized `file-transfer` capability, with file operations recorded as
  metadata (ADR-0049, resolving R-06). An allowed shell can still open network connections and transfer files by
  other means. This is documented, not prevented.
- **No high availability or active-active clustering.** HallPass runs as a single active instance with cold-standby recovery.
- **No writable SQLite on network filesystems** (NFS, SMB/CIFS).
- **No agent private keys in HallPass**, and no issuing of destination keys or certificates to agents.
- **No perfect secret redaction** in recordings, and no reconstruction of "verified" commands from keystrokes.
- **No guarantee that destination processes end** when SSH closes (detached processes survive without
  destination-side controls).
- **Windows destinations** are not supported in v1 (the exec encoding assumes POSIX shells).
- **SCIM or other push provisioning** from IdPs is out of scope (group sync happens at login).
- **No license changes** without operator authorization (R-01: Apache-2.0, decided 2026-10-24).

## 4. Security boundaries and guarantees

### 4.1 What HallPass guarantees (when correctly deployed per the operator guide)

| # | Guarantee | Requirement IDs |
|---|---|---|
| G-1 | Only registered, active agent keys of enabled agents authenticate, and identity comes from the key, never the username. | HP-SSH-001..003, HP-AGT-003 |
| G-2 | An agent sees and can request only what policy allows. Hidden and nonexistent targets are indistinguishable. | HP-POL-001..005, HP-POL-010 |
| G-3 | Destination activity is possible only under an active grant, revalidated on every new channel. | HP-SSH-025, HP-GRT-006 |
| G-4 | Grants never extend implicitly. Expiry, revocation, disablement and lockdown terminate gateway-managed channels within **5 seconds**. | HP-GRT-003, HP-GRT-008, HP-GRT-011 |
| G-5 | Approval requires an authenticated, mapped operator with role and scope, checked transactionally against current state. Callback possession is never authorization. | HP-POL-011, HP-NTF-007, HP-NTF-008 |
| G-6 | Agents never receive destination addresses, credentials, gateway signing keys, or destination certificates. | HP-KEY-007, HP-SRV-010, HP-NTF-004 |
| G-7 | Outbound connections reach only enrolled destinations with verified host identity, within configured egress ranges. | HP-SSH-011, HP-SRV-004..009 |
| G-8 | With mandatory recording, no destination activity is forwarded unless recording is established, and recording failure terminates the activity. | HP-REC-007, HP-REC-011 |
| G-9 | Recording content and sensitive fields are encrypted at rest with authenticated encryption, and truncation and tampering by a party without keys are detected. | HP-CRY-002..005 |
| G-10 | Committed state survives process crashes, and interrupted sessions and recordings are reconciled and labeled accurately. | HP-DB-013, HP-REC-009 |

### 4.2 What HallPass explicitly does **not** guarantee

- **HallPass is a high-value trusted component that can access plaintext proxied session data.** Whoever controls
  the running gateway process, or holds its host plus the KEK, can read and alter sessions, recordings and credentials.
- Encrypted history is **not tamper-proof** against a compromised gateway that holds the keys. External anchoring
  (HP-CRY-008) narrows the window but does not eliminate it.
- A remote shell may reveal its machine's IP addresses, network configuration and application secrets.
  Address confidentiality covers gateway-generated output only.
- Role descriptions and usernames (e.g. `readonly`) are not enforcement.
- Source-CIDR restrictions are defense in depth, not workload attestation.
- Closing SSH or expiring a grant does not kill detached destination processes.
- Certificate expiry alone does not end established sessions. HallPass enforces deadlines itself.
- Input recording, when enabled, may capture secrets, and redaction is not guaranteed.
- Slack, Telegram and the OIDC IdP are trusted to authenticate their own users. HallPass enforces only the mapping and scope.

### 4.3 Trust boundaries (summary; full model in `docs/THREAT_MODEL.md`)

TB-1 agent ↔ gateway SSH · TB-2 gateway ↔ destination SSH · TB-3 operator browser ↔ web/API · TB-4 Slack/Telegram
↔ webhooks · TB-5 gateway ↔ OIDC IdP · TB-6 gateway ↔ local storage (SQLite, recordings) · TB-7 gateway ↔ KEK source ·
TB-8 host administrator ↔ CLI/break-glass.

## 5. Key definitions

| Term | Meaning |
|---|---|
| Agent | A registered non-human SSH client identity with one or more public keys. |
| Operator | A human web-console user (local and/or OIDC identity) with internal roles. |
| Server | A destination SSH host with a unique alias, internal address and enrolled host identity. |
| Role (server role) | A named way to log in to a server: destination username, credential, capabilities, limits. |
| Host identity | A destination's SSH host public key or host-CA binding. Used to verify the destination, never to log in. |
| Login credential | A gateway-held private key or CA signer that HallPass uses to authenticate *to* the destination. |
| Access request | An agent's request for a server+role with a reason and requested duration. |
| Approval decision | An approve/deny outcome, with actor (operator or `system:policy`) and channel. |
| Grant | Authoritative permission: agent × server × role × capabilities × [start, expiry) × policy version. |
| Access session | The user-facing activity container for one grant (1:1), spanning connections and channels. |
| Connection / channel | An inbound SSH connection, and an SSH channel (shell/exec activity) within it. |
| Recording segment | An encrypted `HPREC1` file holding event frames for one channel (rolled over by size/time). |
| Enforcement bound | Maximum delay from a grant ceasing to be valid to termination of its channels: **5 s**. |

## 6. Canonical requirements

Requirement IDs are stable: `HP-<AREA>-NNN`. IDs are never reused or renumbered. A requirement that is dropped
is marked **Withdrawn** with a DECISIONS.md reference, never deleted. Total requirements at WP00:
239.

Test layers are abbreviated in `docs/PLAN.md` §21 and in `docs/TEST_STRATEGY.md`.

### HP-SSH — SSH front end and data plane

| ID | Requirement |
|---|---|
| HP-SSH-001 | **Public-key-only agent auth.** Agents authenticate to the gateway only with SSH public keys. The `none`, `password`, `keyboard-interactive` and `hostbased` methods are never offered or accepted. |
| HP-SSH-002 | **Identity from key, not username.** Agent identity is resolved solely from the registered key that completed authentication. The SSH username supplied by the client is ignored for identity and authorization and is recorded only as untrusted `client_user` metadata. |
| HP-SSH-003 | **Uniform rejection of unknown/revoked keys.** Unknown keys, revoked keys, keys of disabled agents and keys outside an agent's source CIDRs are rejected with the same generic SSH auth failure. Each rejection produces a rate-limited `auth.failed` audit event that records the presented fingerprint and source address. |
| HP-SSH-004 | **Algorithm policy.** Accepted agent key types: Ed25519, ECDSA P-256/P-384/P-521, and RSA ≥ 3072 bits with `rsa-sha2-256`/`rsa-sha2-512` signatures. DSA, RSA < 3072 and SHA-1 `ssh-rsa` signatures are rejected. KEX, cipher and MAC sets are restricted to a documented modern allowlist on both the inbound and outbound legs. |
| HP-SSH-005 | **Gateway host key lifecycle.** The gateway's own Ed25519 host key is generated at initialization, encrypted at rest and shown as SHA-256 fingerprints in the UI and CLI. Operators get a documented procedure for agents to pin it (known_hosts line or an `@cert-authority` host certificate) and to rotate it with an announced overlap. |
| HP-SSH-006 | **Shell, exec, PTY completeness.** `shell`, `exec`, `pty-req`, `window-change`, `env`, `signal`, `eof`, `close`, `exit-status` and `exit-signal` are handled end to end between agent and destination, matching OpenSSH semantics. |
| HP-SSH-007 | **Forwarding and unknown channels denied.** Agent forwarding, `direct-tcpip`, `tcpip-forward`, `streamlocal`, X11, unknown channel types and all subsystems except `sftp` are rejected with an explicit SSH failure and an audit event. `sftp` is accepted only through a role with the `file-transfer` capability (ADR-0049, security-relevant change); the legacy scp protocol over exec is refused. |
| HP-SSH-008 | **Environment allowlist.** Only allowlisted environment variables (default `TERM`, `LANG`, `LC_*`; extendable per role) are forwarded. Rejected variables are dropped and counted in metrics. |
| HP-SSH-009 | **Stdout purity.** Destination stdout is forwarded byte-for-byte. For non-PTY sessions, gateway status and progress messages are written only to stderr. For PTY sessions, gateway messages appear only before the destination session starts or after it ends. |
| HP-SSH-010 | **Exit status and signal propagation.** The destination `exit-status` is propagated unchanged and `exit-signal` is forwarded as `exit-signal`. Gateway-originated failures use exit codes 80–90 together with a single-line JSON error object on stderr carrying `"source":"gateway"`. |
| HP-SSH-011 | **Strict destination host verification.** Every outbound connection verifies the destination host key against enrolled identities or a bound host CA. `ssh.InsecureIgnoreHostKey` and equivalent callbacks are forbidden by a CI lint rule. A mismatch fails the connection and raises an operator alert. |
| HP-SSH-012 | **Keepalive and idle timeouts.** Keepalives and idle timeouts are configurable on both legs (defaults: keepalive 30 s, 3 missed probes; idle session timeout 30 m). Dead peers are detected and their resources released. |
| HP-SSH-013 | **Pre-auth and connection limits.** Unauthenticated connections are bounded globally (default 256) and per source IP (default 16). Handshake/auth timeout defaults to 10 s, auth attempts per connection are bounded, and per-agent connections (default 32) and channels per connection (default 16) are limited. |
| HP-SSH-014 | **Bounded buffering and backpressure.** Data forwarding uses SSH channel windows and bounded buffers. A slow agent or destination applies backpressure to its peer and never causes unbounded memory growth. |
| HP-SSH-015 | **Cancellation and cleanup.** Closing either side, expiry, revocation or shutdown releases all goroutines, file descriptors and outbound connections. Release is verified with goroutine-leak checks. |
| HP-SSH-016 | **Shell-free command grammar.** Gateway commands are parsed by the documented tokenizer (whitespace, single/double quotes, backslash). It does no expansion, globbing or variable substitution and never invokes a shell. |
| HP-SSH-017 | **Reserved words.** Reserved command words (`list`, `roles`, `request`, `status`, `cancel`, `connect`, `exec`, `sessions`, `help`, `version`, `whoami`, `ls`, `ps`, `admin`, `api`, `login`, `logout`, `shell`, `ssh`, `sftp`, `scp`, `hallpass`) can never be used as server or role aliases. |
| HP-SSH-018 | **Stable JSON output.** Every `--json` output carries a `schema` field (e.g. `hallpass.list/v1`) and follows the published schema. Breaking changes require a new schema version. |
| HP-SSH-019 | **No hang without input.** When required input (reason, role choice) is missing and no PTY is allocated, the gateway exits with code 90 and an actionable message instead of prompting or hanging. |
| HP-SSH-020 | **Bounded wait with auto-connect.** `connect`/`exec`/alias invocations that create or reuse a pending request print the request ID and wait timeout on stderr and wait up to the wait timeout (default 120 s, max 15 m). They proceed automatically once approval commits. |
| HP-SSH-021 | **Disconnect does not mutate requests.** A caller disconnecting during a wait neither approves, cancels nor deletes the request. The request remains pollable with `status`. |
| HP-SSH-022 | **Unambiguous default role.** A role is selected implicitly only when exactly one role on the target is requestable or active for the agent. Otherwise the gateway asks interactively (PTY) or fails with code 81 and lists the choices. |
| HP-SSH-023 | **Remote exec encoding.** For `exec`, the raw exec-string substring after the first standalone `--` token is forwarded unchanged as the destination exec command, and the destination login shell interprets it. The docs state that `--` does not prevent remote shell interpretation and describe double-quoting rules. |
| HP-SSH-024 | **Introspection commands.** `help`, `version` and `whoami` (agent ID, name, key fingerprint) are available to every authenticated agent and never reveal hidden targets or addresses. |
| HP-SSH-025 | **Grant revalidation per channel.** Every new destination channel or activity revalidates the grant, agent, key, server, role, credential, host identity, policy and concurrency limits before the outbound channel opens. |
| HP-SSH-026 | **Source bans after failed authentication.** Sources (IPv4 address or IPv6 /64) with repeated failed agent authentication are banned for a configurable, escalating duration (fail2ban style): refused before the SSH banner, persisted across restarts, audited, listable and liftable by administrators, with an allowlist. Plain TCP connects never count. Added by ADR-0041. |

### HP-AGT — Agent registration

| ID | Requirement |
|---|---|
| HP-AGT-001 | **Agent record.** Agents have a stable prefixed ID, unique name, description, enabled flag, groups, labels, optional source CIDRs, timestamps and creator/updater identities. |
| HP-AGT-002 | **Multiple keys per agent.** An agent may have multiple keys (states `active`, `revoked`), each with fingerprint, algorithm, comment, creation and revocation actor/time, supporting overlap rotation. |
| HP-AGT-003 | **Globally unique key ownership.** A key fingerprint (SHA-256 of the wire-format public key) is unique across all agents, including revoked keys, which are tombstoned. The same key can never resolve to more than one agent. |
| HP-AGT-004 | **Validated key parsing.** Public keys are parsed from authorized_keys or OpenSSH format with strict validation and the algorithm policy of HP-SSH-004. authorized_keys options are rejected and certificates are rejected as agent keys in v1. |
| HP-AGT-005 | **Immediate key revocation.** Revoking a key blocks new authentications at once and terminates connections authenticated with that key within the enforcement bound (HP-GRT-008). |
| HP-AGT-006 | **No agent private keys.** HallPass never accepts, generates or stores agent private keys. API input containing private-key material is rejected and the material is not logged. |
| HP-AGT-007 | **Source CIDR restriction.** Optional per-agent source CIDRs are enforced at authentication and documented as defense in depth, not workload attestation. |
| HP-AGT-008 | **Agent disablement.** Disabling an agent rejects new authentication, revokes its active grants (`agent_disabled`), cancels its pending requests and terminates its activity within the enforcement bound. |
| HP-AGT-009 | **Agent audit history.** All agent and key changes emit audit events with actor, before/after (non-secret) values and timestamps, viewable per agent. |

### HP-SRV — Destination servers and roles

| ID | Requirement |
|---|---|
| HP-SRV-001 | **Server record.** Servers have a stable ID, unique alias (`^[a-z][a-z0-9-]{0,62}$`, not reserved), display name, description, environment, labels, groups, internal address and port, enabled flag, host identities, roles and operational metadata. |
| HP-SRV-002 | **Role record.** Roles have a stable ID, an alias unique per server (same alias rules), display name, description, destination OS username, credential reference, capabilities (`pty`, `exec`, `shell`, `env:<name>`), approval policy reference, maximum duration, concurrency limits (per role, per agent) and optional destination-enforced restriction notes. |
| HP-SRV-003 | **Descriptions are not enforcement.** UI and docs label descriptions and usernames as informational and point operators to destination-side enforcement. |
| HP-SRV-004 | **Explicit host identity enrollment.** Host keys are enrolled explicitly, either pasted or scanned and then confirmed by an operator who verifies the fingerprint. Unknown host keys are never trusted implicitly. |
| HP-SRV-005 | **Host key rotation.** Host identities have states (`pending`, `active`, `retired`) to allow overlap rotation. A changed or unknown host key fails the connection (agents receive exit 88 and a generic message) and raises an operator alert. |
| HP-SRV-006 | **Duplicate host identity detection.** Enrolling a host key already active on another server is rejected unless an explicit, justified, audited duplicate exception exists for that server pair. |
| HP-SRV-007 | **Host CA model.** An optional host CA is enrolled explicitly with binding rules: required principals per server, allowed validity, and certificate type `host`. Certificates that fail the binding are rejected. |
| HP-SRV-008 | **Server/role disablement.** Disabling a server, role or credential revokes affected grants (`target_disabled`), cancels pending requests and terminates activity within the enforcement bound. |
| HP-SRV-009 | **Egress validation (anti-SSRF).** Destination addresses are validated on save and again on resolution at dial time against operator-configured egress allow CIDRs. Loopback, link-local, unspecified, multicast and cloud-metadata addresses are denied unless explicitly allowlisted. Dialing uses the validated IP, which prevents DNS rebinding. |
| HP-SRV-010 | **Address confidentiality.** Destination addresses, ports, credentials and host-key details never appear in agent-facing output, notifications or gateway-generated errors, and are shown only to operators with `inventory.address.read`. |

### HP-KEY — Destination login credentials and signing keys

| ID | Requirement |
|---|---|
| HP-KEY-001 | **Managed login key default.** By default each server-role binding gets a distinct Ed25519 login key generated inside HallPass (`crypto/rand`). The private key is sealed with the credential DEK and is never exportable. |
| HP-KEY-002 | **Public key installation aid.** HallPass shows each login public key with a suggested `authorized_keys` line (`restrict,pty,from="<egress CIDRs>" ...`) and a copy action. |
| HP-KEY-003 | **Login key rotation.** Login keys move through `pending` → `active` → `retiring` → `retired`/`revoked`. A connection probe confirms a pending key before it is activated. The old key stays valid during an overlap window, and revocation takes effect immediately. |
| HP-KEY-004 | **OpenSSH user certificates.** As an alternative, a HallPass user CA signs per-connection certificates. Each has a TTL of 2 minutes by default, explicit principals mapped from the role, a key ID binding grant/connection IDs, and only the extensions the role's capabilities require. |
| HP-KEY-005 | **Signer abstraction.** Credential signing is behind a `Signer` interface. v1 ships a local encrypted-key implementation, and the docs state which external KMS/HSM algorithms can produce valid OpenSSH signatures. |
| HP-KEY-006 | **Distinct key types.** Host identities, login credentials and certificate authorities are distinct types and tables in code, distinct API resources and distinct UI pages, and are never interchangeable. |
| HP-KEY-007 | **Credential isolation.** Login private keys, CA keys and certificates are never sent to agents or exposed in API responses, logs or notifications. Imported private keys are flagged `imported` and are never re-exported. |

### HP-POL — Visibility and policy

| ID | Requirement |
|---|---|
| HP-POL-001 | **Default deny.** With no matching allow rule, an agent can neither see nor request any target. |
| HP-POL-002 | **Deny overrides.** Rules map subject × target × role selectors to `deny`, `visible`, `requestable` or `auto_approve(max_duration)`. Any matching deny overrides all allows. |
| HP-POL-003 | **Selector semantics.** A selector consists of ID, group and label clauses, and an object matches if any clause matches (union). Inside a label clause, `matchLabels` and `matchExpressions` (`In`, `NotIn`, `Exists`, `DoesNotExist`) requirements AND together, as in Kubernetes. An empty selector, or an empty label clause, matches nothing. `all: true` must be explicit and includes future objects. A rule matches only when its subject, target and role selectors all match. |
| HP-POL-004 | **Level lattice.** Effective level = max over matching allow rules (`visible` < `requestable` < `auto_approve`) when no deny matches. With several matching auto-approve rules, the smallest `max_duration` applies. Overlapping groups union. |
| HP-POL-005 | **Role and server visibility.** A role is visible when its effective level is at least `visible`, and a server is visible when any of its roles is visible. Disabled objects are invisible. |
| HP-POL-006 | **Separated permissions.** Visibility, request permission, approval authority (approver rules) and permission to establish activity (a valid grant) are separate checks with separate code paths. |
| HP-POL-007 | **Policy versioning.** Every policy or membership change increments a monotonic `policy_version` in the same transaction, and grants record the version they were issued under. |
| HP-POL-008 | **Policy change effects.** After a policy or membership change, pending requests that are no longer requestable are canceled (`policy_changed`), active grants that are no longer requestable are revoked (`policy_changed`) within the enforcement bound, and grants whose new maximum duration is shorter are clamped to start + new max. |
| HP-POL-009 | **Effective-access preview.** Operators can preview effective access per agent (targets, roles, levels, matched rules and the deciding rule) and per server (agents), including what-if evaluation of unsaved rule changes. |
| HP-POL-010 | **Hidden-target non-disclosure.** For an agent, a nonexistent target, a hidden target, a disabled target and a target with no requestable role return the byte-identical `not_found_or_forbidden` response with exit code 82, through the same code path, without target-dependent work before the decision. |
| HP-POL-011 | **Approver authority rules.** Approval authority comes from separate approver rules (operator or operator group × target × role selector). It requires the Approver or Administrator internal role plus a matching rule, and no one holds approval authority implicitly. |
| HP-POL-012 | **Self-approval prohibition.** When enabled (default: enabled; see review item R-09), an operator listed as an owner of the requesting agent cannot approve that agent's requests. |
| HP-POL-013 | **Auto-approval within limits.** Auto-approval applies only when the requested duration is at most the rule's `max_duration` (and the role maximum). Longer requests need human approval and are never silently clamped. Auto-approvals are recorded as decisions by `system:policy` with the deciding rule ID. |
| HP-POL-014 | **Command allowlists are not a sandbox.** HallPass does not present command allowlists as a security boundary. Capabilities control channel types only, and the docs point to destination-side enforcement (ForceCommand, sudoers, restricted accounts). |

### HP-REQ — Access requests

| ID | Requirement |
|---|---|
| HP-REQ-001 | **Request state machine.** Request states are `pending`, `approved`, `denied`, `expired` and `canceled`. The only transitions out of `pending` are compare-and-set to one terminal state, and terminal states are immutable. |
| HP-REQ-002 | **Request record.** Requests persist agent, key, server, role, encrypted reason, requested duration, created/expires/decided timestamps, actor identities, channel and policy version. |
| HP-REQ-003 | **Deduplication and idempotency.** At most one pending request exists per agent+server+role (partial unique index). A repeat request returns the existing one with `deduplicated: true`. An optional `--idempotency-key` makes retries return the same result. |
| HP-REQ-004 | **Pending expiry.** Pending requests expire after a configurable time (default 30 m, max 24 h) through an expiry sweep and a check at decision time. |
| HP-REQ-005 | **Wait vs expiry vs duration.** Wait timeout, pending-request expiry and grant duration are independent settings and are documented as such. |
| HP-REQ-006 | **Cancellation.** An agent can cancel its own pending requests, and an Approver in scope or an Administrator can cancel any pending request in scope. |
| HP-REQ-007 | **Request rate limits.** Requests per agent are rate limited (default 30/hour) and capped at a configurable number of pending requests per agent (default 10). |
| HP-REQ-008 | **Bounded untrusted reason.** Reasons are required by default, 1–1000 Unicode scalar values, control and bidi-override characters stripped, and labeled untrusted wherever displayed. |
| HP-REQ-009 | **Status polling.** `status <request-id>` returns current state, timestamps and grant summary to the requesting agent only. Other agents get exit 82. |

### HP-GRT — Grants and enforcement

| ID | Requirement |
|---|---|
| HP-GRT-001 | **Transactional decision and grant.** An approval decision and its grant and access session are created in one writer transaction. The grant starts at commit time and expiry = start + approved duration. |
| HP-GRT-002 | **Grant record.** Grants have states `active`, `expired` and `revoked` and record agent, server, role, remote username/credential, capabilities, start/expiry, request, decision, approver and policy version. |
| HP-GRT-003 | **No implicit extension.** Reconnecting or reusing a grant never changes its expiry. Longer access requires a new request. |
| HP-GRT-004 | **Active grant reuse.** When an active matching grant exists, connect/exec use it immediately without a new request or reason. |
| HP-GRT-005 | **Deterministic overlap selection.** With several active grants for agent+server+role, the gateway picks the one with the latest expiry and breaks ties by the lowest ID. |
| HP-GRT-006 | **Atomic concurrency limits.** Concurrency limits (per role, per agent+role) are checked and reserved atomically in the writer transaction that registers the channel. |
| HP-GRT-007 | **Race resolution.** Concurrent decisions, expiry, cancellation, revocation and channel establishment are serialized by compare-and-set transitions. The first commit wins and the others get a deterministic conflict result. |
| HP-GRT-008 | **Enforcement bound.** Expiry, revocation and disablement terminate affected gateway-managed channels within 5 seconds (in-process events plus a 1 s ticker). The bound is measured in tests. |
| HP-GRT-009 | **Operator revocation.** Administrators and in-scope Approvers can revoke grants with a reason, and revocation is audited and pushed to the UI. |
| HP-GRT-010 | **Approval after expiry.** An expired request cannot be approved. Approval after a previous grant expired creates a new grant and access session. |
| HP-GRT-011 | **Emergency lockdown.** Administrators can activate lockdown (UI or CLI), which revokes all active grants, rejects new requests and channels, and is audited, until it is explicitly lifted. |

### HP-SES — Access sessions

| ID | Requirement |
|---|---|
| HP-SES-001 | **Session per grant.** Each grant has exactly one access session, created when the grant activates. It is the container for all connections, channels and events in the approval window. |
| HP-SES-002 | **Connections and channels.** SSH connections and channels are distinct entities with IDs, timestamps, close reasons and state. One session holds many connections and concurrent channels within limits. |
| HP-SES-003 | **Session closure.** An access session closes when its grant is no longer active and all its channels are closed, and records a close reason. |
| HP-SES-004 | **Detached processes.** The docs state that closing SSH does not guarantee termination of destination processes, and list destination controls (systemd-logind `KillUserProcesses`, cgroups, sshd `ClientAlive*`, PAM limits). |
| HP-SES-005 | **Live activity view.** Operators see active connections and channels live, with agent, target, role, start time, server-derived remaining time and a terminate action. |

### HP-REC — Event history and recording

| ID | Requirement |
|---|---|
| HP-REC-001 | **Versioned event schema.** Events have a versioned type (`terminal.output@1`), a stable event ID, a per-access-session sequence number, connection/channel IDs, a UTC timestamp and a monotonic offset from session start. |
| HP-REC-002 | **Ordering and causality.** Sequence numbers are assigned in a single per-session sequencer, giving a total order consistent with per-channel causal order. Concurrent channels interleave by assignment time. |
| HP-REC-003 | **Idempotent events.** Event writers use deterministic idempotency keys, so retries after transient errors do not duplicate events. |
| HP-REC-004 | **Capture fidelity.** Recording captures exec command strings, PTY output, resize events, separate stdout/stderr for non-PTY sessions, signals, EOF and exit status. |
| HP-REC-005 | **Input recording opt-in.** Input recording is off by default, configurable per role, and both the UI and docs warn that input may contain secrets. |
| HP-REC-006 | **No false command claims.** Commands inferred from keystrokes or output are labeled `inferred`, never `verified`, and HallPass does not promise secret redaction. |
| HP-REC-007 | **Mandatory recording fail-closed.** With mandatory recording (default), forwarding starts only after the segment is created and its header is durable. Recording failure or exhausted storage terminates the affected channel and marks the recording `failed`. |
| HP-REC-008 | **Durability guarantee.** Recorded data is durable once its frame is fsynced, at most 250 ms after capture under the default `group` mode. In `strict` mode frames are fsynced before the corresponding bytes are forwarded. |
| HP-REC-009 | **Accurate incomplete marking.** After a crash, segments without a final frame are `interrupted`, and their authenticated prefix stays replayable and is labeled incomplete. |
| HP-REC-010 | **Unified timeline, distinct streams.** The UI shows one timeline per access session across connections, and replays concurrent terminals as separate streams. |
| HP-REC-011 | **No silent event drops.** Recording and event queues are bounded. When full, they apply backpressure or terminate the channel and never drop security-relevant events silently. |
| HP-REC-012 | **Destination-side audit integration.** Optional ingestion of destination-side audit data (auditd/eBPF exec records via a signed collector) is stored with provenance labels, and the docs cover the limits of shell history, kernel exec auditing and built-ins. |
| HP-REC-013 | **Retention and deletion.** Retention is configurable per server/role class (default 90 days). Deletion removes segment files and payload metadata, keeps an audited tombstone, and has a documented interaction with backups. |
| HP-REC-014 | **Restricted, audited download.** Playback and export require explicit permissions and recent authentication for export. Both are audited, and the default export is a ciphertext bundle. |

### HP-CRY — Cryptography and key management

| ID | Requirement |
|---|---|
| HP-CRY-001 | **Master KEK provisioning.** The master KEK (32 bytes) is loaded from a file (`0400`, outside the data dir), an environment variable or a secret mount. Production mode refuses to start without it, and dev mode uses an auto-generated, clearly labeled dev KEK that production config rejects. |
| HP-CRY-002 | **Purpose keys and rotation.** Purpose-specific DEKs (`field`, `credential`, `recording`, `manifest`, `token`) are wrapped by the KEK with AES-256-GCM and versioned by key ID. KEK rotation rewraps them, and purpose-key rotation re-encrypts data in the background. |
| HP-CRY-003 | **Field encryption.** Sensitive columns (reasons, TOTP secrets, OIDC client secrets, provider tokens, private keys) are AEAD-encrypted with AAD binding table, column, row ID and key ID. |
| HP-CRY-004 | **Recording file format.** Segments use the versioned `HPREC1` format: a random per-segment DEK, a STREAM construction over ChaCha20-Poly1305 with counter nonces, an authenticated header, frames of at most 64 KiB, and a final-frame flag that detects truncation. |
| HP-CRY-005 | **Integrity verification.** `hallpass verify` checks segment authentication, final-frame presence, ciphertext SHA-256 against SQLite and per-session manifest chains, and reports `ok`, `interrupted`, `corrupt`, `missing` and `orphan`. |
| HP-CRY-006 | **Vetted cryptography only.** Only Go standard library and `golang.org/x/crypto` primitives are used, with no custom ciphers or MAC constructions. The recording format gets an external review (R-02). |
| HP-CRY-007 | **Key loss and recovery.** The docs state that losing the KEK makes encrypted data unrecoverable, require backing up the KEK separately from data backups, and include tested recovery procedures. |
| HP-CRY-008 | **External integrity anchoring.** Per-session manifest hash chains can be exported (`hallpass anchors export`) to external append-only storage. The docs explain that a compromised gateway holding keys can rewrite unanchored history. |
| HP-CRY-009 | **Ciphertext-only archival.** Archival exports segments and wrapped DEKs as ciphertext, without plaintext. Restoring them requires the KEK. |

### HP-DB — SQLite storage

| ID | Requirement |
|---|---|
| HP-DB-001 | **Pure-Go driver.** SQLite access uses `modernc.org/sqlite` and builds with `CGO_ENABLED=0`. |
| HP-DB-002 | **Per-connection pragmas.** Every pooled connection has `journal_mode=WAL`, `synchronous=FULL`, `foreign_keys=ON`, `busy_timeout=5000` and `trusted_schema=OFF`. Startup and tests verify them on every pool connection. |
| HP-DB-003 | **Writer/reader split.** There is one writer connection using `BEGIN IMMEDIATE` and N read-only reader connections. Retries on `SQLITE_BUSY` are bounded (max 5, jittered backoff), and writer queue depth and wait time are exposed as metrics. |
| HP-DB-004 | **Short transactions.** No transaction is held across network I/O, approval waits, SSH traffic or file fsyncs. Transaction duration is instrumented and tests fail if it exceeds 100 ms. |
| HP-DB-005 | **Safe migrations.** Migrations are embedded, versioned (`goose`), forward-only and transactional, and run under the process lock after a `VACUUM INTO` snapshot. A migration failure leaves the DB at its prior version, and the binary refuses to open a database with a newer schema. |
| HP-DB-006 | **Single active instance.** An exclusive `flock` on `<data>/hallpass.lock` prevents a second process from opening the data directory, and it fails fast with a clear error. |
| HP-DB-007 | **Unsupported storage refusal.** On Linux, startup refuses data directories on NFS, CIFS/SMB or other network filesystems, detected via `statfs`. |
| HP-DB-008 | **Corruption checks.** Startup runs `PRAGMA quick_check`, and a scheduled maintenance task runs `integrity_check`. Corruption causes refusal to start (or degraded readiness at runtime) with restore guidance. |
| HP-DB-009 | **Disk-full and I/O failure.** On disk-full or I/O errors the gateway fails closed for new access, marks readiness degraded, alerts, and terminates mandatory-recording channels that can no longer record. |
| HP-DB-010 | **Filesystem permissions.** Data directories are created `0700` and files `0600`. Startup refuses group- or world-readable data dirs and KEK files. |
| HP-DB-011 | **Bounded growth.** SQLite holds only metadata and indexes. Retention jobs, periodic WAL `TRUNCATE` checkpoints and incremental vacuum bound growth, and DB/WAL sizes are exported as metrics. |
| HP-DB-012 | **Consistent backup primitive.** Backups use `VACUUM INTO` (online, consistent) plus a segment copy and a manifest, never a raw copy of a live DB file. |
| HP-DB-013 | **Crash reconciliation.** On startup, connections and channels left open are marked `interrupted`, sessions and grants are re-evaluated, recording segments are reconciled and the outbox resumes. |
| HP-DB-014 | **Recovery objectives.** The docs state RPO (zero for committed transactions on process crash, last backup for host loss) and RTO (target ≤ 15 min restore on the reference hardware, measured in drills). |

### HP-AUTH — Operator authentication and browser sessions

| ID | Requirement |
|---|---|
| HP-AUTH-001 | **Secure bootstrap.** The first administrator is created only with a one-time setup token from `hallpass admin bootstrap` (hashed at rest, 30-minute expiry, single use). No default password or hidden account exists. |
| HP-AUTH-002 | **Argon2id hashing.** Passwords are hashed with Argon2id using unique 16-byte salts and versioned parameters (baseline m=64 MiB, t=3, p=2, calibrated at init), stored in PHC format and rehashed on login after parameter upgrades. |
| HP-AUTH-003 | **Password policy.** Passwords are 12–1024 bytes after NFKC normalization, have no composition rules and are never truncated (over-limit input is rejected). Paste and password managers are supported. |
| HP-AUTH-004 | **Throttling without permanent lockout.** Login attempts are throttled progressively per account and per IP (exponential delay capped at 15 min). There is no permanent lockout, and an admin can clear throttles. |
| HP-AUTH-005 | **Enumeration resistance.** Login, invitation and recovery responses, and their timing (a dummy hash for unknown users), do not reveal whether an account exists. |
| HP-AUTH-006 | **TOTP MFA.** TOTP (RFC 6238, SHA-1, 6 digits, 30 s, ±1 step) is stored encrypted, confirmed at enrollment, and rejects reuse of a time step. |
| HP-AUTH-007 | **Recovery codes.** Ten single-use recovery codes are hashed (HMAC-SHA-256 with the token key), shown once and regenerable after recent authentication. |
| HP-AUTH-008 | **Mandatory MFA for privileged accounts.** Configurable mandatory MFA (default on for Administrator and Approver local accounts) forces enrollment at next login. |
| HP-AUTH-009 | **Password change and reset.** Password reset uses admin-issued single-use hashed tokens (1 h expiry), delivered by email only when SMTP is configured, and has no public reset endpoint otherwise. Password change requires the current password. |
| HP-AUTH-010 | **Session invalidation.** Password reset/change, disablement, MFA changes and role reductions invalidate the operator's other sessions. |
| HP-AUTH-011 | **Invitations.** Optional invitations use single-use hashed tokens (72 h expiry) with a preset role, and are revocable and audited. |
| HP-AUTH-012 | **Server-side sessions.** Sessions use a random 256-bit ID (stored hashed) in a `__Host-hp_session` cookie (HttpOnly, Secure in production, SameSite=Lax), with idle (30 m) and absolute (12 h) expiry, rotation on login and privilege change, logout revocation and active-session management. |
| HP-AUTH-013 | **CSRF protection.** State-changing requests require a session-bound CSRF token header plus Origin/`Sec-Fetch-Site` validation. |
| HP-AUTH-014 | **Recent authentication.** Provider changes, privilege changes, credential/key administration, account linking, MFA disablement, retention changes, recording export and lockdown require authentication within 5 minutes (configurable) plus MFA where policy requires it. API tokens (ADR-0052, security-relevant) are exempt on the configuration operations they may use, because issuing one requires both. |
| HP-AUTH-015 | **Lockout prevention.** The last enabled administrator cannot be disabled or demoted. Local login can be disabled only after an administrator completes an SSO test login, and only while at least one SSO-capable administrator exists. |
| HP-AUTH-016 | **Break-glass recovery.** `hallpass admin recover` requires local filesystem access, the KEK and the process lock (offline mode). It issues a 30-minute single-use recovery login, writes an audit event and has no remote equivalent. |
| HP-AUTH-017 | **Dev auth isolation.** Development authentication exists only behind the `devauth` build tag, is excluded from release builds and is rejected by production config. |
| HP-AUTH-018 | **Credential secrecy.** Passwords, TOTP secrets, recovery codes, tokens and cookies are never logged. Redaction tests enforce this. |

### HP-OIDC — Generic OpenID Connect SSO

| ID | Requirement |
|---|---|
| HP-OIDC-001 | **Provider configuration.** Providers are configured with display name, issuer, client ID, client secret (optional), scopes (default `openid profile email`), group claim, restrictions and an optional custom CA, using issuer discovery with an exact issuer match. |
| HP-OIDC-002 | **Code flow with PKCE.** Only Authorization Code with PKCE (S256) is used, never implicit or ROPC. State and nonce are single-use, server-side and expire after 10 minutes. |
| HP-OIDC-003 | **ID token validation.** ID tokens are checked for signature (JWKS; RS256/ES256/EdDSA, never `none` or HMAC), `iss`, `aud`, `azp` when multiple audiences are present, `exp`/`iat` with ≤ 60 s skew, and `nonce`. |
| HP-OIDC-004 | **JWKS caching and rotation.** JWKS is cached and refetched on unknown `kid` with rate limiting, and tested with key rotation. |
| HP-OIDC-005 | **TLS and redirect safety.** HTTPS is required for the issuer and HallPass base URL in production, with HTTP allowed only for `localhost` in dev mode. TLS verification is never disabled. The redirect URI is exact, and post-login return paths are relative and allowlisted. |
| HP-OIDC-006 | **Endpoint validation.** Discovery and endpoints must match the issuer origin unless explicitly allowed. Private-network IdPs require an explicit operator allowance. |
| HP-OIDC-007 | **Secret handling.** Client secrets are encrypted at rest, write-only in the API and UI, and never sent to the frontend. |
| HP-OIDC-008 | **Token minimization.** Access and refresh tokens are discarded after login (no documented need to retain them). The ID token is used only for claim extraction. |
| HP-OIDC-009 | **Identity by issuer+subject.** External identities key on `iss`+`sub`. There is no email-based auto-merge, and linking requires an authenticated session on both sides or an audited admin action with recent authentication. |
| HP-OIDC-010 | **Provisioning modes.** Provisioning is either `preprovisioned` (default) or `jit` restricted by verified domain, tenant and/or group claims. JIT users receive no privileged role unless a mapping grants it. |
| HP-OIDC-011 | **Group mapping.** Allowlisted group→role mapping rules are evaluated at each login. SSO-managed role assignments are replaced on sync, manual assignments are kept separate, and removal takes effect at next login, with sessions bounded by the absolute timeout and revocable by an admin. |
| HP-OIDC-012 | **Provider outage behavior.** When the IdP is down, SSO login fails closed with a clear message, existing sessions continue until expiry, and local or break-glass paths stay available as configured. |
| HP-OIDC-013 | **Upstream step-up.** Step-up sends `prompt=login` and `max_age` and verifies `auth_time`, plus `acr`/`amr` when mapped. Providers without `auth_time` fail step-up unless configured to require local TOTP instead. |
| HP-OIDC-014 | **Test-login before enforcement.** An admin must complete a full test login (discovery → login → claim mapping preview → role result) before SSO-only enforcement can be enabled. |
| HP-OIDC-015 | **Logout semantics.** Logout revokes the HallPass session. RP-initiated provider logout is optional and is documented as not being a global logout. |

### HP-RBAC — Operator RBAC

| ID | Requirement |
|---|---|
| HP-RBAC-001 | **Internal roles and matrix.** The Administrator, Approver, Auditor and Viewer roles follow the published permission matrix, enforced server-side on every endpoint and SSE event. |
| HP-RBAC-002 | **Address visibility permission.** Infrastructure addresses are visible only with `inventory.address.read` (Administrator by default). |
| HP-RBAC-003 | **Approval requires role and scope.** Approve and deny require the Approver or Administrator role plus a matching approver rule. SSO success alone grants nothing. |
| HP-RBAC-004 | **Recording permissions.** Playback (`recording.play`) and export (`recording.export`) are separate permissions. Auditor and Administrator hold playback by default, and only Administrator holds export by default. |
| HP-RBAC-005 | **Retention and revocation permissions.** Retention changes require Administrator plus recent authentication. Revocation requires Administrator or an in-scope Approver. |
| HP-RBAC-006 | **Auth-method-independent RBAC.** Authorization decisions are identical for local and SSO operators with the same role assignments, verified by a parameterized test suite. |
| HP-RBAC-007 | **No default privilege.** New operators (invited without a role, or JIT-provisioned) have no permissions until roles are assigned. |

### HP-API — REST API and live events

| ID | Requirement |
|---|---|
| HP-API-001 | **Spec-first OpenAPI.** An OpenAPI 3.1 spec under `/api/v1` is the source for the generated Go server interfaces and TS types. CI fails on drift. |
| HP-API-002 | **API versioning.** Changes within `/api/v1` are additive only, breaking changes require `/api/v2`, and deprecations are announced in the changelog. |
| HP-API-003 | **Problem details.** Errors use RFC 9457 `application/problem+json` with stable `code` values and never leak internals. |
| HP-API-004 | **Server-side pagination.** List endpoints support cursor pagination, filtering and sorting server-side with bounded page sizes. |
| HP-API-005 | **SSE live events.** `GET /api/v1/events` (SSE) streams authorization-filtered events with IDs, `Last-Event-ID` resume, 15 s heartbeats and bounded per-client buffers. On overflow or too-old cursors, a `reset` event tells the client to refetch. |
| HP-API-006 | **Idempotent mutations.** Approve, deny, revoke, cancel and other non-idempotent POSTs accept `Idempotency-Key`. |
| HP-API-007 | **Security headers.** Strict CSP (no inline scripts), HSTS in production, `frame-ancestors 'none'`, `nosniff` and `Referrer-Policy: same-origin` are set. CORS is disabled. |
| HP-API-008 | **API rate limiting.** Per-session and per-IP rate limits apply to the API, with stricter limits on auth endpoints. |
| HP-API-009 | **Webhook isolation.** Provider webhooks live under `/hooks/*`, use no cookie auth, are rate limited, and are verified before any parsing beyond size limits. |

### HP-UI — Web UI

| ID | Requirement |
|---|---|
| HP-UI-001 | **Frontend stack.** React + TypeScript + Vite, TanStack Router/Query/Store, Ant Design, Apache ECharts and xterm.js. TanStack Devtools appear only in dev builds. |
| HP-UI-002 | **Design system and themes.** A reusable design-system layer on Ant Design tokens (radius 4–6 px, restrained shadows, dense tables) provides complete light and dark themes. |
| HP-UI-003 | **Complete page set.** All pages listed in the brief §20 exist and are backed by real API data. |
| HP-UI-004 | **Access-session detail.** The access-session detail page includes summary, reason (untrusted), approver, scope, remaining time, connections and activities, unified timeline, per-stream replay, exec records with provenance, revocation and recording integrity. |
| HP-UI-005 | **Authentication settings.** Authentication settings cover login methods, password/MFA policy, OIDC config, a copyable callback URL, discovery checks, the test-login workflow, group mappings, provisioning, session policies and an audit trail. |
| HP-UI-006 | **Login modes.** The login UI adapts to local-only, SSO-only and combined modes. |
| HP-UI-007 | **Real UI states.** Every data view has loading, empty, error, stale, disconnected (SSE) and permission-denied states. |
| HP-UI-008 | **Tables and saved filters.** Tables use server-side pagination, filtering and sorting, with saved filters for requests, sessions and audit. |
| HP-UI-009 | **Charts with real data.** ECharts charts are theme-aware, backed only by real metrics endpoints and paired with accessible summaries or table alternatives. No fake data appears. |
| HP-UI-010 | **Destructive confirmation.** Destructive actions require explicit confirmation. High-impact ones (lockdown, delete server, revoke all) require typed confirmation. |
| HP-UI-011 | **Server-derived countdowns.** Countdowns derive from server timestamps corrected by the measured server clock offset. |
| HP-UI-012 | **No optimistic security success.** Security-sensitive mutations show success only after the server confirms. |
| HP-UI-013 | **Safe replay rendering.** Replay uses xterm.js with link activation, OSC 8/52 and title changes disabled, sanitizes output and never renders recorded content as HTML. |
| HP-UI-014 | **Accessibility.** The UI targets WCAG 2.2 AA, with zero serious/critical axe violations on all pages and full keyboard navigation and visible focus. |
| HP-UI-015 | **Visual regression.** Playwright visual snapshots cover the design-system components and key pages in both themes. |
| HP-UI-016 | **Embedded build.** The production UI is embedded in the Go binary and served with CSP-compatible assets. |

### HP-NTF — Approvals and notifications

| ID | Requirement |
|---|---|
| HP-NTF-001 | **Durable outbox.** Notifications go through the SQLite outbox with bounded retries (exponential backoff, max 8 attempts), a dead-letter state, per-attempt delivery history and UI visibility. |
| HP-NTF-002 | **Notification content.** Notifications show verified agent identity, server alias and description, role and description, capabilities, the reason (marked untrusted), request expiry, allowed durations, a deny action and a dashboard link. |
| HP-NTF-003 | **Escaping and mention suppression.** Reasons and descriptions are escaped per provider (Slack mrkdwn `&<>`, Telegram plain text), truncated, and have mentions and link unfurling suppressed. |
| HP-NTF-004 | **No infrastructure disclosure.** Notifications never include destination addresses, usernames or credentials. |
| HP-NTF-005 | **Slack verification.** Slack requests are verified with v0 HMAC-SHA256 of the signing secret, a 5-minute timestamp window, constant-time comparison and a replay cache. |
| HP-NTF-006 | **Telegram verification.** Telegram webhooks require `X-Telegram-Bot-Api-Secret-Token` and allowlisted chat and user IDs. `callback_data` carries only an opaque action-token ID of 64 bytes or less. |
| HP-NTF-007 | **Action tokens.** Action tokens are 128-bit random values, stored hashed, bound to request, action, provider and expiry, and single-use. Possession alone never authorizes. |
| HP-NTF-008 | **Unified transactional decision.** Callbacks resolve the provider user to a mapped operator and then call the same decision service as the web UI, which checks role, scope, self-approval, request state and policy in the decision transaction. |
| HP-NTF-009 | **Idempotent callbacks.** Duplicate or concurrent callbacks for the same decision return the original outcome without side effects. |
| HP-NTF-010 | **No approval on failure.** Notification failure never approves. Requests stay pending until decided, canceled or expired. |
| HP-NTF-011 | **Explicit provider identity mapping.** Slack and Telegram user IDs map to operators only through a verified link flow (a link code issued in an authenticated web session and confirmed in the provider) or an audited admin action. |
| HP-NTF-012 | **Callback rate limits.** Webhook and callback endpoints are rate limited per provider user and per source. |
| HP-NTF-013 | **Web approvals.** The web approval flow shows the full request context and duration choices limited by policy, and uses the same decision service. |

### HP-OPS — Operations and distribution

| ID | Requirement |
|---|---|
| HP-OPS-001 | **Health and readiness.** `/healthz` reports liveness. `/readyz` reports readiness (DB writable, KEK loaded, disk headroom, recording dir writable, SSH listener up), with a degraded detail visible to authenticated admins only. |
| HP-OPS-002 | **Graceful shutdown.** On shutdown the gateway stops accepting new connections, notifies agents on stderr, drains for a configurable time (default 30 s), finalizes recordings and marks the rest interrupted. |
| HP-OPS-003 | **Backup command.** `hallpass backup` writes a consistent set (DB snapshot, segments, manifest with hashes). Keys are excluded and backed up separately. |
| HP-OPS-004 | **Restore onto clean machine.** `hallpass restore` plus `hallpass verify` restores onto a clean host, and a scripted drill proves it. |
| HP-OPS-005 | **Upgrade and rollback.** Upgrades take a pre-migration snapshot, and the documented rollback restores that snapshot (forward-only migrations, data since the upgrade is lost). |
| HP-OPS-006 | **Capacity and disk alerts.** Disk usage alerts fire at 80% and 90%, and new sessions are refused below a configurable free-space reserve. The docs include a capacity planning guide. |
| HP-OPS-007 | **Container and standalone deploy.** HallPass ships a distroless non-root image, a Compose example and a documented standalone systemd deployment. |
| HP-OPS-008 | **CI pipeline.** CI runs lint, vet, unit/race tests, fuzz smoke, OpenSSH integration, frontend tests, govulncheck, Trivy and secret scanning. |
| HP-OPS-009 | **Release provenance.** Releases include an SBOM (syft), checksums and GitHub build provenance attestation. |
| HP-OPS-010 | **Project documents.** SECURITY.md, CONTRIBUTING.md, architecture and operator docs, and secret-free example configuration are provided. |
| HP-OPS-011 | **License decision.** The license is recorded only after operator authorization (R-01), and no license file is added before then. |
| HP-OPS-012 | **No secrets in repo.** The repository contains no private infrastructure, tokens, customer data or secret-bearing fixtures. Test keys are generated at test time, and gitleaks runs in CI. |
| HP-OPS-013 | **Config and runtime modes.** Config comes from a file plus env overrides, is strictly validated, and supports `production` (default) and `development` modes, with dev-only features rejected in production. |
| HP-OPS-014 | **Durable jobs.** Scheduled and background jobs (expiry, retention, outbox, reconciliation) are durable in SQLite with leases and bounded retries. |

### HP-OBS — Observability

| ID | Requirement |
|---|---|
| HP-OBS-001 | **Structured JSON logs.** `slog` JSON logs use stable ECS-aligned field names and a documented schema, and can be ingested by OpenSearch without requiring it. |
| HP-OBS-002 | **Redaction layer.** Sensitive types implement redacting `LogValue`, sensitive keys are denylisted, and tests assert that reasons, commands, terminal data and secrets never reach logs. |
| HP-OBS-003 | **Correlation IDs.** Logs, traces and audit events carry the relevant `trace.id`, `http.request.id`, `hallpass.agent_id`, `hallpass.grant_id`, `hallpass.session_id`, `hallpass.connection_id` and `hallpass.channel_id`. |
| HP-OBS-004 | **Metrics and traces.** OpenTelemetry traces cover the API, SSH auth/authorization and outbound dial. Metrics are exposed via Prometheus `/metrics` and optional OTLP, following a documented metric catalog. |
| HP-OBS-005 | **Audit log.** Security-relevant actions write append-only audit events (actor, action, target, outcome, correlation, hash-chained) separate from debug logs, with an optional JSON audit sink. |

### HP-TST — Testing and quality

| ID | Requirement |
|---|---|
| HP-TST-001 | **Race detector.** All Go tests run with `-race` in CI. |
| HP-TST-002 | **Fuzzing.** Fuzz targets cover the grammar tokenizer, key parsing, recording reader, selector parser, webhook payload parsing and the reason sanitizer. Each gets ≥ 10 min per release and a 30 s smoke run in CI. |
| HP-TST-003 | **Real OpenSSH integration.** Integration tests use real OpenSSH `ssh` clients and `sshd` destinations in containers. |
| HP-TST-004 | **Browser E2E.** Playwright E2E tests cover all operator workflows in Chromium (Firefox dropped by operator decision, ADR-0038). |
| HP-TST-005 | **Fault injection.** The fault-injection catalog in TEST_STRATEGY.md passes. |
| HP-TST-006 | **Soak.** A 24-hour soak on the reference hardware shows no goroutine or file-descriptor growth beyond 5% and stable RSS. |
| HP-TST-007 | **Measured performance.** The performance targets in TEST_STRATEGY.md are measured on the documented reference hardware, and the results are recorded in the release evidence. |
| HP-TST-008 | **Security review.** A security-focused review of the auth, policy, SSH, crypto and webhook code is completed before the RC, with findings tracked to closure. |
| HP-TST-009 | **Coverage floor.** Statement coverage is ≥ 80% for the `policy`, `access`, `keyring`, `recording`, `sshfront/grammar` and `opauth` packages. |

### HP-DOC — Documentation

| ID | Requirement |
|---|---|
| HP-DOC-001 | **Operator guide.** Operator documentation covers installation, configuration, KEK provisioning, deployment, backup/restore, upgrade, key rotation, break-glass and incident procedures. |
| HP-DOC-002 | **Agent guide.** The agent guide covers `~/.ssh/config`, `ssh -t`, the command grammar, JSON schemas, exit codes, quoting and gateway host-key pinning. |
| HP-DOC-003 | **Destination hardening guide.** The destination hardening guide covers `authorized_keys` `restrict`/`from=`, firewalling to gateway egress, sudo/ForceCommand, process-lifecycle controls and audit options. |
| HP-DOC-004 | **Guarantees and non-guarantees.** A published security guarantees page states what HallPass does and does not guarantee, consistent with THREAT_MODEL.md. |
| HP-DOC-005 | **Recording format spec.** The `HPREC1` format and the consistency protocol are specified in `docs/formats/hprec1.md`. |
| HP-DOC-006 | **Changelog and versioning.** A changelog plus versioning policy covers the binary, API, JSON schemas, recording format and DB schema. |


## 7. Definition of done

A requirement is **done** only when all of the following hold:

1. **Implemented**: code merged on `main` in a committed work package.
2. **Tested**: the test layers listed for it in `docs/TEST_STRATEGY.md` exist and pass in CI (or, for drills
   and soak, have recorded evidence under `docs/evidence/<release>/`).
3. **Documented**: operator, agent or API docs updated where the behavior is user-visible.
4. **Tracked**: its box is checked in `docs/PLAN.md` §21 with a pointer to the evidence.

Status vocabulary used in PLAN.md and release notes, which must not be conflated:

- **Implemented**: code exists.
- **Tested**: automated tests in this repo pass.
- **Externally verified**: reviewed or tested by a party outside the implementing session (crypto review,
  security review, pentest, interoperability with third-party providers).

A work package is done when all requirements it owns are done, its acceptance criteria in PLAN.md are met,
and it is committed locally (WP commit boundary).

## 8. Release gates (v1.0)

HallPass may be called **stable** or **production-ready** only when every gate passes with recorded evidence.
Features existing is not evidence.

| Gate | Criterion | Evidence |
|---|---|---|
| RG-1 Requirements | 100% of non-withdrawn requirements done (§7). | PLAN.md §21 fully checked, with links. |
| RG-2 CI health | `main` green: lint, vet, race tests, fuzz smoke, OpenSSH integration, E2E, a11y, visual, govulncheck (no reachable vulns), Trivy (no HIGH/CRITICAL unfixed without a waiver), gitleaks clean. | CI run URL/log for the release commit. |
| RG-3 Fuzzing | Every fuzz target ran ≥ 10 min with no open crashers, and the corpus is committed. | Fuzz report. |
| RG-4 Fault injection | Every scenario in the TEST_STRATEGY.md fault catalog passes. | Fault-run report. |
| RG-5 Soak | 24 h soak at the reference workload: no goroutine/FD growth > 5%, RSS within ±10% after warmup, zero lost security events, zero unrecoverable recordings. | Soak report with graphs. |
| RG-6 Performance | Targets in TEST_STRATEGY.md §5 met on the reference hardware. | Benchmark report with the hardware description. |
| RG-7 Recovery | Backup → restore onto a clean machine → verify drill passes, and measured RTO ≤ 15 min. Upgrade from the previous supported version passes. | Drill logs. |
| RG-8 Security review | Internal security review complete, with all HIGH/CRITICAL findings fixed and MEDIUM fixed or accepted in DECISIONS.md. | Review report. |
| RG-9 External crypto review | Recording format and keyring reviewed by a qualified external party (R-02), **or** the release is explicitly labeled "recording format not externally reviewed". | Review letter or label in release notes. |
| RG-10 Docs | Operator, agent, destination-hardening, API and format docs complete. Security guarantees page is consistent with THREAT_MODEL.md. | Docs review checklist. |
| RG-11 Open decisions | All review items blocking release (R-01 license at minimum before public release) resolved. | DECISIONS.md. |

Pre-1.0 release candidates may ship with explicit known-gaps notes, but must never claim the gates above.
