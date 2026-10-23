# Hallpass — Threat Model

> Maintained alongside `docs/GOAL.md` (§4 guarantees) and `docs/PLAN.md` (§3 trust boundaries). Update when a WP changes a
> boundary, adds an asset or alters a mitigation. Mitigations reference requirement IDs, so a mitigation is only as real as the status
> of its requirement in PLAN.md §21.

## 1. Fundamental statement

**Hallpass is a high-value trusted component that can access plaintext proxied session data.** It terminates agent SSH and
originates destination SSH, so every byte of every session passes through its memory in plaintext. It holds (encrypted at rest,
decrypted in memory) the credentials that log in to every enrolled destination, plus the keys that decrypt all recordings. A party that
controls the running process, or the host together with the KEK, can impersonate Hallpass toward every destination, read and alter
live sessions, and read recordings. Deployments must treat the Hallpass host like a bastion or a CA: minimal access, dedicated host or VM,
hardened OS, full-disk encryption, monitored, and with its KEK and backups protected separately.

## 2. Assets

| ID | Asset | Where | Protection |
|---|---|---|---|
| AS-1 | Destination login private keys, user CA keys | SQLite (sealed, `credential` key) / memory | AEAD, never exported, RBAC + reauth to manage |
| AS-2 | Gateway SSH host private key | SQLite (sealed) / memory | AEAD, fingerprint published |
| AS-3 | Master KEK | File/env/secret mount outside data dir | OS perms 0400, separate backup, never in backups |
| AS-4 | Purpose keys, segment DEKs | SQLite / segment key slots (wrapped) | Wrapped by KEK / recording key |
| AS-5 | Recording content (terminal I/O, exec strings) | Segment files | HPREC1 AEAD, RBAC for playback/export, audit |
| AS-6 | Request reasons, comments | SQLite (sealed) | AEAD, `requests.reason.read` |
| AS-7 | Operator credentials (password hashes, TOTP secrets, recovery codes, sessions) | SQLite | Argon2id / AEAD / HMAC |
| AS-8 | OIDC client secrets, Slack/Telegram tokens and secrets, SMTP password | SQLite (sealed) | AEAD, write-only API |
| AS-9 | Inventory topology (addresses, ports, usernames) | SQLite (plaintext) | RBAC (`inventory.address.read`), disk encryption |
| AS-10 | Policy, grants, audit trail, integrity chain | SQLite | RBAC, hash chain, external anchoring |
| AS-11 | Availability of the approval and access path | Process | Limits, fail-closed semantics, backups |

## 3. Trust boundaries

| TB | Boundary | Who is on the other side | Trust level |
|---|---|---|---|
| TB-1 | Agent → gateway SSH | Agents (automated, possibly compromised or prompt-injected) | Untrusted beyond key identity |
| TB-2 | Gateway → destination SSH | Destination hosts (may be compromised) | Untrusted output; identity verified by host key |
| TB-3 | Browser → web/API | Operators (authenticated), the internet | Authenticated and authorized per request |
| TB-4 | Slack/Telegram → webhooks | Provider platforms and their users | Provider authenticity verified; user mapped and authorized |
| TB-5 | Gateway → OIDC IdP | Identity provider | Trusted for authentication of mapped identities only |
| TB-6 | Gateway → local storage | Filesystem, disk | Trusted for availability, not confidentiality (AEAD) |
| TB-7 | Gateway → KEK source | Host secret store | Trusted |
| TB-8 | Host admin → CLI/break-glass | Host root/service account | Fully trusted (equivalent to gateway control) |

## 4. Adversaries

| ID | Adversary | Capabilities assumed |
|---|---|---|
| AD-1 | Compromised or misbehaving agent (incl. prompt-injected LLM) | Holds its private key; can send arbitrary SSH requests, reasons and commands within its grants |
| AD-2 | External network attacker | Reaches SSH and HTTPS listeners; no credentials |
| AD-3 | Thief of an agent private key | Same as AD-1 for that key, from a different network location |
| AD-4 | Malicious or compromised destination | Controls its sshd and the output of sessions |
| AD-5 | Malicious insider operator (any internal role) | Valid web session within their role |
| AD-6 | Attacker controlling a Slack/Telegram account or chat member | Can click buttons, send messages, observe notification content |
| AD-7 | Misconfigured or compromised IdP / IdP admin | Can mint ID tokens for arbitrary subjects for that issuer |
| AD-8 | Attacker with read access to disk or backups (no KEK) | Reads SQLite, segments, backups |
| AD-9 | Attacker with host root or the KEK | Full control (see §1) |
| AD-10 | Browser-side attacker | XSS attempts via rendered data, CSRF from other origins, stolen cookies |

## 5. Threats and mitigations

STRIDE: **S**poofing, **T**ampering, **R**epudiation, **I**nformation disclosure, **D**enial of service, **E**levation of privilege.

| ID | Brief scenario | STRIDE | Threat | Mitigations (requirement IDs) | Residual risk |
|---|---|---|---|---|---|
| T-01 | Compromised agent | E, I, T | An agent abuses its grants, enumerates targets, issues destructive commands, exfiltrates data through the shell, attempts forwarding or subsystem access, sends huge inputs. | Default deny and least visibility (HP-POL-001..005); human approval for non-auto roles (HP-POL-013); short durations (HP-REQ-005, HP-GRT-003); forwarding and subsystems denied (HP-SSH-007); env allowlist (HP-SSH-008); grammar without shell (HP-SSH-016); limits (HP-SSH-013, HP-REQ-007); full recording (HP-REC-004, HP-REC-007); revocation and lockdown (HP-GRT-009, HP-GRT-011); destination-side restrictions documented (HP-POL-014, HP-DOC-003). | **Within an approved shell the agent can do anything the destination account permits**, including network access and file transfer by other means. Hallpass records but cannot prevent it. Destination-side least privilege is mandatory. |
| T-02 | Stolen SSH key | S | An attacker uses a stolen agent key from elsewhere. | Source CIDR restriction (HP-AGT-007, defense in depth only); immediate revocation and termination ≤ 5 s (HP-AGT-005, HP-GRT-008); per-key audit and last-used (HP-AGT-009, HP-SSH-003); approvals show key fingerprint (HP-NTF-002); multiple keys for rotation (HP-AGT-002). | Until revoked, the thief has the agent's capabilities, including reuse of active grants. Hardware-backed agent keys are recommended where available. |
| T-03 | Malicious destination | T, I, S, E | A destination returns terminal escape sequences that target the operator replay UI (OSC 52 clipboard, OSC 8 links, title injection); a destination impersonates another host; a destination tries to use gateway credentials elsewhere or attack the gateway through the SSH client. | Strict host verification and duplicate detection (HP-SSH-011, HP-SRV-004..007); per-binding credentials limit reuse (HP-KEY-001), and certificate principals and TTL (HP-KEY-004); safe replay rendering (HP-UI-013); no HTML rendering of recorded content; bounded buffers (HP-SSH-014); agent forwarding never offered to destinations (HP-SSH-007); fuzzed recorder input path (HP-TST-002). | A compromised destination can lie in its output and capture what the agent types into it. A login public key is useless elsewhere unless the same key is authorized on other hosts, which per-binding keys prevent. |
| T-04 | Malicious request reason | T, E, I | Reason text carries markup, mentions (`<!channel>`), links, bidi tricks or social engineering aimed at approvers, or injection into logs and UI. | Bounded, sanitized reason (HP-REQ-008); provider escaping and mention/unfurl suppression (HP-NTF-003); "untrusted" labeling (HP-NTF-002, HP-UI-004); plain-text rendering (`UntrustedText`); reasons excluded from logs (HP-OBS-002) and encrypted at rest (HP-CRY-003). | Persuasive social engineering in plain text remains possible. Approvers are trained via the UI label and docs. |
| T-05 | Approval forgery or replay | S, T | Forged Slack/Telegram callbacks, replayed signed requests, guessed or reused action tokens, CSRF on web approve. | Slack v0 HMAC + timestamp + replay cache (HP-NTF-005); Telegram secret token + allowlists (HP-NTF-006); hashed single-use bound tokens that are never sufficient alone (HP-NTF-007); idempotent callbacks (HP-NTF-009); CSRF + Origin (HP-AUTH-013); webhook isolation (HP-API-009). | Compromise of the Slack signing secret or Telegram bot token enables forged callbacks, but the clicking identity must still map to an authorized operator. Rotation of these secrets is documented. |
| T-06 | Unauthorized approver | E | An operator without scope, an agent owner approving their own agent, an unlinked chat user, or a demoted operator approves. | Approver rules + role check in the decision tx (HP-POL-011, HP-RBAC-003, HP-NTF-008); self-approval prohibition (HP-POL-012); explicit provider linking (HP-NTF-011); session invalidation on role reduction (HP-AUTH-010); SSO group removal at next login (HP-OIDC-011); audit of every decision (HP-OBS-005). | An SSO-mapped role removed at the IdP persists until next login or absolute session expiry (≤ 12 h default) unless an admin revokes sessions. |
| T-07 | Credential stuffing | S, D | Password spraying or stuffing against local login, and lockout-based DoS. | Argon2id (HP-AUTH-002); progressive per-account/IP throttling without permanent lockout (HP-AUTH-004); enumeration resistance (HP-AUTH-005); MFA, mandatory for privileged accounts (HP-AUTH-006, HP-AUTH-008); API rate limits (HP-API-008); hash-concurrency semaphore. | Distributed low-rate guessing against weak passwords without MFA. Mitigated by the 12-byte minimum and MFA policy (R-12 breached list deferred). |
| T-08 | Password-reset abuse | S, E | Public reset endpoints abused, reset tokens intercepted or replayed, reset without MFA. | No public reset without configured email (HP-AUTH-009); hashed single-use 1 h tokens; reset invalidates sessions (HP-AUTH-010); MFA re-verification after reset; audited admin recovery (HP-AUTH-016). | Email account compromise enables reset where SMTP delivery is enabled. MFA still required for privileged accounts. |
| T-09 | SSO misconfiguration | S, E | Wrong issuer or audience accepted, `alg=none`/HMAC confusion, missing nonce/state, open redirect, implicit flow, TLS disabled, JIT admitting any tenant user, overbroad group mapping. | Discovery with exact issuer (HP-OIDC-001); PKCE/state/nonce (HP-OIDC-002); strict token validation (HP-OIDC-003); JWKS handling (HP-OIDC-004); TLS and redirect rules (HP-OIDC-005); endpoint validation (HP-OIDC-006); restricted JIT with no default privilege (HP-OIDC-010, HP-RBAC-007); allowlisted group mapping (HP-OIDC-011); test login before enforcement (HP-OIDC-014). | A compromised or malicious IdP (AD-7) can authenticate as any mapped subject. Hallpass trusts the configured issuer by design. Keep privileged mappings narrow and require local TOTP step-up fallback where `auth_time` is absent. |
| T-10 | Identity-linking attack | S, E | An attacker registers an IdP account with a victim's email to take over a local account, or links a chat account to someone else's operator. | Identity is `iss`+`sub` (HP-OIDC-009); no email auto-merge; linking requires both authentications or an audited admin action; provider link codes are single-use and bound to the issuer (HP-NTF-011). | Admin error during manual linking. Audited, and requires reauth. |
| T-11 | Compromised browser session | S, E, I | Stolen cookie, XSS, CSRF, session fixation, long-lived sessions, privilege escalation through a hijacked session. | HttpOnly/Secure/`__Host-` cookie, rotation, idle/absolute expiry, revocation (HP-AUTH-012); CSRF (HP-AUTH-013); strict CSP and headers (HP-API-007); recent auth + MFA for sensitive actions (HP-AUTH-014); no secrets in frontend (HP-OIDC-007); safe rendering (HP-UI-013); active-session management. | A stolen live session can act within the role until expiry or revocation, except for reauth-gated actions. |
| T-12 | Gateway compromise | All | RCE in Hallpass or host compromise exposes credentials, plaintext sessions and recordings, and allows forging approvals or audit. | Memory-safe language, minimal dependencies, fuzzing (HP-TST-002), security review (HP-TST-008), distroless non-root container and systemd sandboxing (HP-OPS-007), vulnerability scanning (HP-OPS-008), per-binding credentials and CA TTLs to limit later use, destination `from=` restrictions to gateway egress (HP-KEY-002), external anchoring (HP-CRY-008), incident procedure (PLAN §18.13). | **Total compromise of brokered access during the compromise window** (§1). Recordings and audit written after compromise cannot be trusted. Credential rotation on all destinations is required after an incident. |
| T-13 | Signing, credential or encryption-key compromise | S, I | KEK, purpose keys, login keys or CA keys leak (backup theft plus KEK, memory dump, operator export). | KEK stored separately from data and backups (HP-CRY-001, HP-CRY-007); purpose separation and rotation (HP-CRY-002); per-segment DEKs (HP-CRY-004); non-exportable managed keys (HP-KEY-001, HP-KEY-007); per-binding rotation and revocation (HP-KEY-003); short-lived certs (HP-KEY-004); `KeyWrapper`/`Signer` for KMS/HSM later (R-03). | Without an HSM, keys exist in process memory. A leaked KEK plus a DB copy exposes all sealed data in that copy until rotated. Recordings encrypted under the old keys remain exposed. |
| T-14 | Recording disclosure | I | Unauthorized playback or export, recordings in logs, backup theft, input recording capturing secrets. | AEAD at rest (HP-CRY-004); playback and export permissions plus reauth and audit (HP-REC-014, HP-RBAC-004); ciphertext-only export by default; no content in logs or SQLite (HP-OBS-002, PLAN §4.8); input recording off by default with warnings (HP-REC-005); retention (HP-REC-013). | Authorized auditors can view secrets that appear on screen. Redaction is not guaranteed (HP-REC-006). |
| T-15 | Recording alteration | T, R | An attacker edits, truncates, reorders, swaps or deletes segments, or rewrites DB metadata to hide activity. | STREAM framing with final flag and header binding (HP-CRY-004); ciphertext hashes and MAC'd hash chain (HP-CRY-005); verification jobs and CLI; hash-chained audit (HP-OBS-005); external anchors (HP-CRY-008). | An AD-9 attacker with keys can forge consistent history after the last exported anchor. Deletion of unanchored history cannot be prevented. |
| T-16 | SQLite or storage failure | D, T | Disk full, I/O errors, corruption, NFS misuse, two processes on one DB, lost writes on power failure. | Fail closed and readiness (HP-DB-009); `synchronous=FULL` (HP-DB-002); flock (HP-DB-006); network FS refusal (HP-DB-007); integrity checks (HP-DB-008); backups and restore drills (HP-DB-012, HP-OPS-003, HP-OPS-004); disk alerts and reserve (HP-OPS-006). | Hardware that lies about fsync can lose committed data. Documented; enterprise SSDs with power-loss protection recommended. |
| T-17 | Crash during authorization or recording | T, R | A crash leaves half-created grants, channels without recordings, segments without metadata, or forwarding that happened unrecorded. | Single-transaction decision + grant + session (HP-GRT-001); recording established before forwarding (HP-REC-007); defined write protocol and reconciliation (PLAN §13.5–13.6, HP-DB-013, HP-REC-009); outbox resume (HP-NTF-001). | Up to 250 ms of output per channel can be lost in `group` mode (HP-REC-008). `strict` mode removes this at a latency cost. |
| T-18 | Policy, expiry or revocation races | E | Approval racing expiry, cancel or policy change; channel open racing revocation; concurrency limit overshoot; reconnect extending access. | CAS state transitions (HP-REQ-001, HP-GRT-007); decision-time rechecks (HP-NTF-008); revalidation per channel (HP-SSH-025); atomic concurrency (HP-GRT-006); enforcer with DB reconciliation (HP-GRT-008); no extension on reconnect (HP-GRT-003); policy change effects (HP-POL-008). | Up to 5 s of activity after revocation (documented bound). |
| T-19 | Inventory-based SSRF | E, I | A malicious or careless admin, or a compromised admin session, adds a server pointing at internal services, metadata endpoints or loopback, then uses scan, probe or agent sessions to reach them. | Egress guard on save and at dial time with IP pinning (HP-SRV-009, ADR-0021); scans and probes through the same guard; address changes require `inventory.write` and are audited; addresses hidden from agents (HP-SRV-010). | Destinations inside allowed egress ranges are reachable by design. Network segmentation should complement this. |
| T-20 | Administrator lockout | D | The last admin is disabled, SSO-only enforcement breaks login, MFA device lost, IdP outage. | Last-admin protection and SSO test-login gate (HP-AUTH-015, HP-OIDC-014); recovery codes (HP-AUTH-007); provider-outage behavior (HP-OIDC-012); break-glass CLI requiring host control and KEK, audited (HP-AUTH-016). | Losing both host access and the KEK leaves no recovery path, by design. |
| T-21 | Target enumeration (agent) | I | An agent probes aliases to discover hidden servers through error differences, timing, `status` on others' requests, or search. | Single resolution path with identical responses (HP-POL-010); no target-dependent work before the decision; own-requests-only status (HP-REQ-009). | Aggregate timing noise from host load. The in-memory evaluation keeps differences negligible, and tests compare outputs. |
| T-22 | Denial of service | D | Pre-auth connection floods, request storms, SSE connection exhaustion, slow-read clients, notification floods, Argon2id CPU exhaustion. | Pre-auth limits (HP-SSH-013); request rate limits (HP-REQ-007); bounded buffers and backpressure (HP-SSH-014); SSE limits (HP-API-005); webhook rate limits (HP-NTF-012); API rate limits (HP-API-008); hash semaphore. | Volumetric network DoS needs upstream protection. |

## 6. Assumptions

1. The host OS, kernel, Go runtime and the vetted crypto libraries behave correctly.
2. The KEK source is accessible only to the Hallpass service account and to recovery operators.
3. Operators verify host-key fingerprints out of band when confirming scans.
4. Destinations enforce least privilege for each role's OS account and restrict SSH to gateway egress addresses.
5. Slack, Telegram and the OIDC IdP authenticate their own users correctly. Hallpass relies on them only for identity, never for authorization.
6. Clocks are NTP-synchronized (expiry and token windows depend on wall-clock UTC).
7. TLS for the web UI is configured correctly (native or reverse proxy), and `trusted_proxies` is accurate.
8. Agents protect their private keys. Hallpass cannot attest workloads.

## 7. Residual risks (summary)

- Plaintext access by the gateway itself (T-12, §1).
- Unrestricted capability inside approved shells (T-01), mitigated only by destination-side controls.
- Up to 5 s post-revocation activity (T-18) and up to 250 ms of unrecorded-durable output in `group` mode (T-17).
- History forgery by a key-holding attacker after the last external anchor (T-15).
- IdP compromise maps to Hallpass operator compromise for mapped identities (T-09).
- Detached destination processes surviving session termination (HP-SES-004).
- Secrets visible in recordings to authorized auditors (T-14).

## 8. Review cadence

Revisit this model at WP10 (SSH front end live), WP15 (API surface complete), WP16–WP18 (approval channels), WP26 (pre-RC review),
and on any change to a trust boundary. Record findings as ADRs or tracked issues.
