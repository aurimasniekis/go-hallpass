# HallPass — Security guarantees and non-guarantees

> Status words on this page: **implemented** means the code exists, **tested** means automated tests in this
> repository pass, **externally verified** means someone outside the project reviewed or tested it. No guarantee below
> is externally verified yet.

## Read this first

**HallPass is a high-value trusted component that can access plaintext proxied session data.** It terminates agent SSH
and originates destination SSH, so every session passes through its memory in plaintext. It holds the credentials for
every enrolled destination and the keys that decrypt every recording. Whoever controls the running process, or holds
the host together with the KEK, can read and alter sessions, impersonate HallPass toward destinations, and read
recordings. Run it like a bastion or a CA:
- a dedicated host or VM with a hardened OS, minimal access and monitoring;
- full-disk encryption;
- the KEK and backups protected separately from each other.

## What HallPass guarantees

These hold only when HallPass is deployed per the operator guide (`docs/operator/`) and the assumptions below hold.

| # | Guarantee | Status |
|---|---|---|
| G-1 | Only registered, active keys of enabled agents authenticate. Identity comes from the key, never from the SSH username. | tested |
| G-2 | An agent sees and can request only what policy allows. A hidden target and a nonexistent target give identical responses. | tested |
| G-3 | Destination activity is possible only under an active grant, which is revalidated on every new channel. | per-channel revalidation tested; concurrency-limit stress evidence pending |
| G-4 | Grants never extend implicitly. Expiry, revocation, agent disablement and lockdown terminate gateway-managed channels within **5 seconds**. | no-extension tested; the 5-second bound tested against real OpenSSH; no 24-hour soak yet |
| G-5 | Approval requires an authenticated, mapped operator whose role and scope are checked in the same transaction that creates the decision. Holding a chat button or callback is never authorization. | tested (Slack/Telegram against recorded provider behavior, not live workspaces) |
| G-6 | Agents never receive destination addresses, login credentials, gateway signing keys or destination certificates. | tested |
| G-7 | Outbound connections reach only enrolled destinations with a verified host identity, inside the configured egress ranges. | tested; host-CA and server-disablement paths partially tested |
| G-8 | With mandatory recording (the default), nothing is forwarded until recording is established, and a recording failure terminates the activity. | tested (fault injection) |
| G-9 | Recordings and sensitive fields are encrypted at rest with authenticated encryption. Truncation and tampering by a party without the keys are detected. | tested; **recording format not externally reviewed** |
| G-10 | Committed state survives process crashes, and interrupted sessions and recordings are reconciled and labeled accurately at startup. | recording reconciliation tested; full crash catalog pending |

## What HallPass does not guarantee

- **Protection against a compromised gateway.** A party controlling the process, or the host plus the KEK, has full
  plaintext access.
- **Tamper-proof history against a key holder.** Encrypted history and the audit chain detect tampering by parties
  without keys. A key holder can rewrite history after the last external anchor. Exporting anchors
  (`hallpass anchors export`) narrows that window but does not close it.
- **Least privilege inside an approved shell.** An approved role gives the agent whatever its OS account can do on the
  destination. Role names and descriptions such as `readonly` are labels, not enforcement. Enforce least
  privilege on the destination (`docs/destination/`).
- **Address confidentiality for destination output.** HallPass keeps addresses out of its own output, API responses for
  roles without `inventory.address.read`, and notifications. A remote shell can still print its IPs, network
  configuration and application secrets.
- **Termination of detached destination processes.** Closing SSH or expiring a grant ends gateway-managed channels.
  `nohup`, `setsid`, tmux, screen and similar processes keep running unless the destination enforces session-lifecycle
  controls.
- **Session end at certificate expiry.** OpenSSH does not end established sessions when a user certificate expires.
  HallPass enforces grant deadlines itself.
- **Workload attestation.** Agent source-CIDR restrictions are defense in depth. Anyone holding an agent's private
  key acts as that agent.
- **Byte-level recording of git and file transfers.** Git operations and SFTP/scp transfers are recorded as
  metadata (repository, ref updates and bytes; file paths, operations, sizes and SHA-256 of sequential transfers), not
  as byte streams, so G-8 applies to shell and exec channels only. HallPass does not restrict which paths a
  file-transfer role reaches: the destination account's permissions do.
- **Secret redaction.** Recordings capture what the session showed. Input recording, when enabled, may capture typed
  secrets. Authorized auditors can see both.
- **Zero-delay revocation or zero loss of recording.** Up to 5 seconds of activity may continue after revocation. With `recording.durability: group` (the default), up to `flush_interval` (250 ms) of output can be
  forwarded but not yet durable on disk when the host crashes. Use `strict` if that matters more than throughput.
- **Correct identity from third parties.** Slack, Telegram and the OIDC IdP are trusted to authenticate their own
  users. HallPass enforces only the mapping to operators and the operator's scope. A compromised IdP can log in as any
  identity mapped for its issuer.
- **Availability under volumetric attack.** Pre-authentication, request, API, SSE and webhook rate limits are built
  in. Network-level DoS needs upstream protection.
- **High availability.** One active instance only. Established SSH sessions cannot fail over. Recovery means restoring
  from backup onto a cold standby.
- **Recovery without the KEK.** Losing the KEK makes encrypted data unrecoverable, by design. Back it up separately
  from the data (`docs/operator/keys.md`).

## Assumptions

The guarantees depend on these assumptions:
1. The host OS, the Go runtime and the vetted crypto libraries behave correctly.
2. Only the HallPass service account and recovery operators can read the KEK.
3. Operators verify host-key fingerprints out of band.
4. Destinations restrict SSH to gateway egress addresses and give each role's account least privilege.
5. Slack, Telegram and the IdP authenticate their own users.
6. Clocks are NTP-synchronized.
7. TLS and `trusted_proxies` are configured correctly.
8. Agents protect their private keys.

## Where to go next

- Destination hardening: `docs/destination/`.
- Key management and rotation: `docs/operator/keys.md`.
- Backup, restore and anchoring: `docs/operator/backup.md`.
- Recording format and its review status: `docs/formats/hprec1.md`.
