# Security model and guarantees

This page summarizes what HallPass does and does not guarantee. The canonical text is
[security-guarantees.md](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/security-guarantees.md). If the
two disagree, that page wins.

## Read this first

**HallPass is a high-value component that sees proxied sessions in plaintext.** It terminates the agent's SSH and
originates the destination's, so every session passes through its memory unencrypted. It holds the credentials for
every enrolled destination and the keys that decrypt every recording. Whoever controls the running process, or holds
the host together with the KEK, can read and alter sessions, impersonate HallPass toward destinations and read
recordings.

Run it like a bastion host or a CA:

- a dedicated host or VM with a hardened OS, minimal access and monitoring;
- full-disk encryption;
- the KEK and the backups protected separately from each other.

## What HallPass guarantees

These hold only when HallPass is deployed as the operator guides describe and the assumptions below hold. Status words
are strict: **implemented** means the code exists, **tested** means automated tests in the repository pass,
**externally verified** means someone outside the implementing work checked it. **No guarantee is externally verified
yet.**

| # | Guarantee | Status |
|---|---|---|
| G-1 | Only registered, active keys of enabled agents authenticate. Identity comes from the key, never from the SSH username. | tested |
| G-2 | An agent sees and can request only what policy allows. A hidden server and a nonexistent server give identical responses. | tested |
| G-3 | Destination activity is possible only under an active grant, revalidated on every new channel. | per-channel revalidation tested; concurrency stress evidence pending |
| G-4 | Grants never extend implicitly. Expiry, revocation, agent disablement and lockdown end gateway-managed channels within **5 seconds**. | no-extension tested; bound tested against real OpenSSH; soak-level evidence pending |
| G-5 | Approval requires an authenticated, mapped operator whose role and scope are checked in the same transaction that creates the decision. A chat button is never authorization by itself. | tested (Slack and Telegram against recorded provider behavior, not live workspaces) |
| G-6 | Agents never receive destination addresses, login credentials, gateway signing keys or destination certificates. | tested |
| G-7 | Outbound connections reach only enrolled destinations with a verified host identity, inside the configured egress ranges. | tested; host-CA and disablement paths partially |
| G-8 | With mandatory recording (the default), nothing is forwarded until recording is established, and a recording failure ends the activity. | tested (fault injection) |
| G-9 | Recordings and sensitive fields are encrypted at rest with authenticated encryption; truncation and tampering by a party without the keys are detected. | tested; **recording format not externally reviewed** |
| G-10 | Committed state survives process crashes; interrupted sessions and recordings are reconciled and labeled at startup. | recording reconciliation tested; full crash catalog pending |

## What HallPass does not guarantee

- **Protection against a compromised gateway.** Process control, or the host plus the KEK, means full plaintext access.
- **Tamper-proof history against a key holder.** A key holder can rewrite history after the last exported
  [anchor](/operators/backup#integrity-anchors). Anchors narrow that window but do not close it.
- **Least privilege inside an approved shell.** An approved role gives the agent whatever its OS account can do. Role
  names such as `readonly` are labels. Enforce least privilege [on the destination](/destinations/hardening).
- **Address confidentiality for destination output.** HallPass keeps addresses out of its own output and
  notifications, but a remote shell can print its own IPs and configuration.
- **Termination of detached processes.** `nohup`, `setsid`, tmux and screen survive the SSH channel unless the
  destination enforces session-lifecycle controls.
- **Session end at certificate expiry.** OpenSSH does not end sessions when a certificate expires; HallPass ends them
  itself when the grant ends.
- **Workload attestation.** Anyone holding an agent's private key acts as that agent. Source-CIDR restrictions are
  defense in depth.
- **Byte-level recording of git and file transfers.** Git pushes and fetches, and scp/sftp transfers, are recorded
  as metadata: repository, ref updates and bytes; file paths, operations, sizes and SHA-256 checksums. The contents
  are not stored, so the recording guarantee above covers shell and exec channels. HallPass does not limit which paths
  a file-transfer role can reach: the role's remote account decides.
- **Secret redaction.** Recordings capture what the session showed. Input recording, when enabled, may capture typed
  secrets.
- **Zero-delay revocation or zero recording loss.** Up to 5 seconds of activity may continue after revocation. In the
  default `group` durability mode, up to 250 ms of forwarded output may not be on disk when the host crashes; use
  `recording.durability: strict` if that matters more than throughput.
- **Correct identity from third parties.** Slack, Telegram and your IdP are trusted to authenticate their own users. A
  compromised IdP can sign in as any identity mapped for its issuer.
- **Availability under volumetric attack.** Rate limits are built in; network-level DoS needs upstream protection.
- **High availability.** One active instance. Recovery is a restore onto a cold standby.
- **Recovery without the KEK.** Losing it makes encrypted data unrecoverable, by design.

- **API tokens skip step-up.** A configuration change that needs recent sign-in in the console does not with an
  [API token](/operators/api-tokens). A leaked token can change configuration until it expires or is revoked, but it can
  never approve requests, read recordings or manage operators.

## Assumptions

1. The host OS, the Go runtime and the vetted crypto libraries behave correctly.
2. Only the HallPass service account and recovery operators can read the KEK.
3. Operators verify host-key fingerprints out of band.
4. Destinations restrict SSH to gateway egress addresses and give each role's account least privilege.
5. Slack, Telegram and the IdP authenticate their own users.
6. Clocks are NTP-synchronized.
7. TLS and `http.trusted_proxies` are configured correctly.
8. Agents protect their private keys.

## Cryptography

HallPass uses only the Go standard library and `golang.org/x/crypto`. Secrets at rest use AES-256-GCM under purpose
keys wrapped by the KEK ([Keys and the KEK](/operators/keys)). Operator passwords use Argon2id. Recordings use the
HPREC1 segment format ([format description](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/formats/hprec1.md)),
which **has not been externally reviewed**.

## Release status

The current release is 0.2.0, a pre-1.0 version. Its known limitations:

- The HPREC1 recording format, the keyring and field encryption have had internal review only, no external
  cryptographic review.
- No 24-hour soak test and no benchmarks on the reference hardware. Short soak runs and smoke benchmarks passed.
- Slack and Telegram approvals are tested against recorded and fake provider APIs, not live workspaces.
- Browser end-to-end tests cover the main workflows in Chromium only. There are no visual regression snapshots.

## Reporting vulnerabilities

Report vulnerabilities privately. See
[SECURITY.md](https://github.com/aurimasniekis/go-hallpass/blob/main/SECURITY.md).
