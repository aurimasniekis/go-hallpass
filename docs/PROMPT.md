Act as a staff software engineer, security architect, and product engineering lead.

You are operating in PLAN MODE. Produce and persist an implementation-ready plan for Hallpass: a complete, stable, security-sensitive SSH access gateway for AI agents.

Do not implement application code during this planning phase. Inspect the existing repository when available, identify constraints, make justified decisions, and save a durable project goal and execution plan for future implementation sessions.

Do not ask clarifying questions. Make reasonable assumptions, document them, and identify decisions requiring operator review.

PROJECT IDENTITY

Name: Hallpass
Repository: aurimasniekis/go-hallpass
Current visibility: private
Future intent: open source
Default SSH alias in examples: center

Hallpass is the selected project name. Do not claim trademark or domain availability has been verified.

1. WORKFLOW, PERSISTENCE, AND COMMITS

Create these files, respecting existing repository conventions and preserving unrelated content:

- docs/GOAL.md
  Canonical product requirements, security boundaries, and definition of done.

- docs/PLAN.md
  Implementation-ready architecture and execution plan with dependencies, milestones, acceptance criteria, and progress tracking.

- docs/DECISIONS.md
  Architectural decisions, alternatives, rationale, consequences, and unresolved review items.

- docs/THREAT_MODEL.md
  Trust boundaries, threats, mitigations, assumptions, and residual risks.

- docs/TEST_STRATEGY.md
  Functional, integration, security, performance, recovery, and release-validation strategy.

- docs/PROMPT.md
  A faithful copy of this complete project brief.

Update the root AGENTS.md, preserving existing instructions, to require future agents to:
- Read docs/GOAL.md and docs/PLAN.md before working.
- Treat GOAL.md as the canonical product contract.
- Keep PLAN.md progress and DECISIONS.md current.
- Never silently weaken security requirements.
- Never redefine unfinished features as complete.
- Record deviations and their justification.
- Distinguish implemented, tested, and externally verified behavior.
- Follow the commit and no-push rules below.

Git workflow:
- Work on the main branch.
- Commit completed, coherent changes using the environment’s /cc command or skill.
- Commit planning/documentation changes at the end of this planning phase.
- During later implementation, commit meaningful completed work packages rather than leaving all work uncommitted until the end.
- Inspect the working tree before committing.
- Include only relevant changes; do not accidentally commit unrelated user work.
- Never commit secrets, credentials, private production data, or secret-bearing fixtures.
- Do not discard existing changes, force-switch branches, rewrite history, or amend unrelated commits.
- If safely working on main is blocked by existing work, preserve that work and report the blocker instead of forcing a destructive operation.
- If /cc is unavailable, do not invent its behavior or claim it ran. Leave changes intact and report that the required commit workflow is unavailable.
- Do not run git push or otherwise publish repository changes automatically.
- Pushing requires a separate, explicit user instruction.
- Check that /cc itself does not push; do not invoke a workflow that would violate the no-push requirement.
- Report local commit hashes when commits are actually created.

If filesystem access is unavailable, provide the intended document contents without claiming they were saved or committed.

This plan is a durable engineering contract, not a disposable brainstorming document.

2. PRODUCT QUALITY STANDARD

Hallpass is not an MVP, prototype, demo-only tool, or UI sketch.

Plan a complete, maintainable product suitable for real operational use:
- Secure defaults.
- Reliable upgrades and recovery.
- Comprehensive testing.
- Strong observability.
- Polished operator workflows.
- Complete documentation.
- Explicit failure behavior.
- Production-quality UI.
- Clearly bounded security guarantees.

Development may use incremental milestones, but those milestones must not reduce the final product scope.

Define measurable release gates and required evidence. Do not claim stability or production readiness merely because features exist.

3. PRODUCT CONCEPT

Hallpass is a terminating SSH gateway:

Agent → Hallpass → Destination server

An agent, container, or VM owns an SSH key pair. An operator registers its public key with Hallpass.

Agents can:
- Discover permitted server aliases and access roles.
- Read descriptions explaining what each server and role provides.
- Request temporary access with a reason.
- Receive approval through the web UI, Slack, or Telegram.
- Connect, disconnect, reconnect, and execute commands during the approved interval.
- Use only the gateway endpoint and their own private key.

Hallpass:
- Authenticates agents.
- Enforces visibility and access policies.
- Obtains human approval where required.
- Resolves destination addresses internally.
- Establishes outgoing SSH connections with gateway-controlled credentials.
- Records access-session history and SSH activity.
- Terminates gateway-managed access at expiry or revocation.

Never provide destination private keys, gateway signing keys, or destination login certificates to agents.

Confidentiality boundaries:
- Agent-facing discovery, APIs, notifications, and gateway-generated errors must not disclose destination routing addresses or credentials.
- Authorized aliases and approved descriptions are intentionally visible.
- A remote shell may reveal its machine’s IP, network configuration, or application secrets. An SSH proxy cannot prevent this universally.
- Destination permissions and network controls must complement gateway policy.

4. REQUIRED STACK

Backend:
- Go.
- golang.org/x/crypto/ssh.
- SQLite.
- Versioned SQL migrations.
- Typed database access, preferably sqlc where appropriate.
- slog structured logging.
- OpenTelemetry.
- REST API with OpenAPI.
- Durable jobs/outbox using SQLite.
- Encrypted file-based history and recording storage.

Frontend:
- React and TypeScript.
- Vite.
- TanStack Router.
- TanStack Query.
- TanStack Store for appropriate client-only state.
- TanStack Devtools in development only.
- A mature professional component library.
- Light and dark themes.
- Professional charts and operational tables.
- Live updates through SSE or WebSockets, with a justified choice.

Operations:
- Container image and Docker Compose.
- Documented standalone deployment.
- Logs suitable for OpenSearch ingestion without requiring OpenSearch.
- CI, testing, security scanning, and release workflows.

Prefer a modular monolith with clear interfaces and minimal unnecessary infrastructure.

5. SQLITE ARCHITECTURE

SQLite is a requirement, not a temporary substitute for PostgreSQL.

Specify:
- Driver choice and CGO implications.
- WAL mode where appropriate.
- Foreign-key enforcement on every connection.
- Busy timeouts and bounded retries.
- Read/write connection configuration.
- Short transactions and writer-contention management.
- Durability and synchronous settings.
- Migration locking and failure recovery.
- SQLite-safe backup and restore.
- Disk-full, I/O failure, corruption, and abrupt-shutdown behavior.
- Database/filesystem permissions.
- Supported deployment topology.

Do not:
- Put a writable SQLite database on unsupported shared network storage.
- Pretend independent SQLite files form a shared cluster.
- Hold transactions open during approval waits, external API calls, or SSH traffic.

Prefer a clearly supported single-active-instance architecture unless a more complex topology is fully justified.

Document:
- Failover/recovery model.
- Recovery objectives and expected downtime.
- Prevention of unintended concurrent active process owners.
- State surviving restart.
- Reconciliation of sessions interrupted by crashes.
- Why established SSH sessions cannot migrate seamlessly.

Bound database growth. High-volume recording payloads belong in encrypted files; SQLite stores necessary state and indexes.

Explain which metadata remains in SQLite and its confidentiality implications. If database encryption is proposed, specify the actual technology and key-management requirements; stock SQLite does not automatically encrypt data.

6. AGENT REGISTRATION

Agent records include:
- Stable ID.
- Name and description.
- Public keys and fingerprints.
- Enabled/disabled state.
- Groups and labels.
- Visibility/access assignments.
- Creation and rotation history.
- Optional source CIDR restrictions.
- Audit history.

Requirements:
- Public-key-only SSH authentication for agents.
- Multiple keys per agent for rotation.
- No ambiguous key ownership across agents.
- Validated key parsing and supported algorithm policy.
- Immediate key revocation.
- Identity derived from registered keys, not supplied SSH usernames.
- No storage of agent private keys.
- Source-network restrictions are defense in depth, not workload attestation.

7. DESTINATION SERVERS AND ROLES

Server records include:
- Stable ID.
- Unique alias.
- Display name.
- Description/definition.
- Environment.
- Labels and groups.
- Internal connection address and port.
- Enabled/disabled state.
- Explicit SSH host identity.
- One or more access roles.
- Operational metadata.

Each role includes:
- Stable ID.
- Alias and display name.
- Description of what access it provides and its limitations.
- Actual destination OS username.
- Authentication/credential reference.
- Capabilities.
- Approval policy.
- Maximum duration.
- Concurrency limits.
- Optional destination-enforced restrictions.

Examples:
- inspect: inspect service health and logs.
- deploy: manage a specific application’s deployments.
- database-maintenance: perform controlled maintenance.
- administrator: privileged access requiring stricter approval.

Descriptions are not enforcement. A username such as “readonly” does not make an account read-only.

Distinguish these key concepts explicitly:

A. Server host identity:
- Enroll and verify the server’s SSH host public key/fingerprint.
- Require explicit enrollment and rotation.
- Detect duplicate enrolled host identities by default.
- Allow exceptions only through an explicit, justified, audited mechanism.
- Never silently trust unknown hosts or changed keys.
- An optional host-CA model requires explicit enrollment and identity-binding rules.

B. Destination login identity:
- A host public key does not grant login access.
- Hallpass needs a private login credential or signer.
- Prefer distinct gateway-controlled authentication identities for each server-role binding.
- For managed keys, generate the key pair within Hallpass’s trust boundary.
- Expose the public key for installation in the role’s authorized_keys.
- Keep its private key encrypted and unavailable to agents.
- Support safe rotation with overlap and revocation.
- Support short-lived OpenSSH user certificates with explicit principal mapping and protected signing.
- Abstract signing for compatible external signers or KMS/HSM implementations; do not assume every KMS supports OpenSSH signing directly.

Choose and justify a secure default authentication approach.

Keep host keys, user login keys, and certificate authorities distinct in code, UI, APIs, and documentation.

8. VISIBILITY AND POLICY

Agent assignments may permit:
- All eligible servers explicitly.
- Specific servers.
- Server groups.
- Label selectors.
- Particular roles or role classes.

Separate:
- Visibility.
- Permission to request access.
- Approval authority.
- Permission to establish destination activity.

Default deny. Explicit denies override allows.

Define:
- Selector semantics.
- Rule precedence.
- Empty-selector behavior.
- Overlapping groups.
- Role visibility.
- Whether “all servers” includes future servers.
- Effects of policy/membership changes on pending requests and active access.

Policy outcomes:
- Deny.
- Auto-approve within policy limits.
- Require human approval.

Provide an effective-access preview for operators.

Prevent hidden-target disclosure through inconsistent lookup errors or unrestricted search.

Command allowlists are not a general sandbox for shells, interpreters, or tools with escape mechanisms. Reliable restrictions require destination-side enforcement.

9. SSH USER EXPERIENCE

Support:

ssh center
ssh center foo-server
ssh -t center foo-server

The first command shows authorized aliases, descriptions, and roles.

Target connection behavior:
- Use a default role only when unambiguous.
- Otherwise require selection or an explicit role.
- Reuse an active matching grant immediately.
- Otherwise collect a reason and create or reuse a pending request.
- Display request ID and wait timeout.
- Wait for a configurable bounded interval.
- Connect automatically if approved while the caller is waiting.

OpenSSH nuance:
- Remote-command invocations do not normally allocate a PTY automatically.
- Document `ssh -t` for interactive terminal workflows.
- Support useful non-PTY operation.
- Missing required input without interactive input must return an actionable error, not hang.

Automation commands:

ssh center list --json
ssh center roles foo-server --json
ssh center request foo-server --role inspect --reason "Investigate elevated errors" --wait=false --json
ssh center status REQUEST_ID --json
ssh center connect foo-server --role inspect --wait-timeout 120s
ssh -t center connect foo-server --role inspect
ssh center exec foo-server --role inspect --reason "Check disk usage" -- df -h
ssh center sessions --json

Specify:
- Exact command grammar.
- Reserved names and alias collision handling.
- Parsing without a local shell.
- Remote exec encoding and supported shell/platform assumptions.
- Stable JSON schemas and exit codes.
- Gateway status on stderr, preserving destination stdout.
- Destination exit status and signal propagation.
- Request deduplication and idempotency.
- Wait timeout versus request expiry versus grant duration.

SSH exec carries a command string, not native argv. Do not claim `--` alone eliminates remote-shell interpretation.

A disconnected caller can poll and reconnect. Disconnection must not accidentally approve or delete a request.

10. REQUESTS AND APPROVALS

Request states:
- pending
- approved
- denied
- expired
- canceled

Grant states:
- active
- expired
- revoked

Persist timestamps and actor identities.

Approval channels:
- Web UI.
- Slack.
- Telegram.

Configurable duration presets:
- 5m
- 15m
- 30m
- 1h
- 3h
- 6h
- 24h

Policies constrain available durations and maximum access.

Notifications show:
- Verified agent identity.
- Server alias and description.
- Role and description.
- Capabilities.
- Agent-provided reason, clearly marked as untrusted.
- Request expiry.
- Allowed approval durations.
- Deny action.
- Dashboard details link.

Security:
- Explicit mapping of provider identities to internal approvers.
- Approver scope enforcement.
- Optional self-approval prohibition.
- Slack signature and timestamp validation.
- Telegram webhook secret validation and authorized user/chat checks.
- Replay protection.
- Action tokens bound to the request/action and expiry.
- Idempotent callbacks.
- Transactional decision and grant creation.
- Current policy/state checks at decision time.
- Rate limiting.
- Escaped, bounded reasons.
- No unwanted mentions or infrastructure-secret disclosure.
- Durable outbox and bounded retries.
- Delivery history.
- No approval on notification failure.
- Callback possession alone is not authorization.

Handle races between concurrent decisions, request expiry, revocation, and connection establishment explicitly.

11. ACCESS SESSION DOMAIN MODEL

An “access session” is the approved access window, not a single SSH connection.

One access session may contain:
- Multiple connections.
- Multiple shell/exec/channel activities.
- Repeated connect/disconnect cycles.
- Concurrent activities within limits.
- A unified chronological history.

Use distinct entities:
- Access request.
- Approval decision.
- Grant: authoritative permission scope and time interval.
- Access session: user-facing activity container associated with a grant.
- SSH connection.
- SSH channel/activity.
- Recording segment.
- Audit/history event.

A one-to-one grant/access-session relationship is a reasonable default; document the decision.

Grant scope includes:
- Agent.
- Server.
- Role and remote identity.
- Capabilities.
- Start and expiry.
- Approver and request.
- Relevant policy version.

Rules:
- Duration begins when approval is committed.
- Reconnection never extends expiry.
- Matching authorized activity reuses the active access session.
- Approval after expiry creates a new access session.
- Define overlapping-grant selection deterministically.
- No implicit extensions.
- Revalidate every new destination channel/activity.
- A long-lived inbound SSH connection cannot bypass expiry.
- Enforce concurrency limits atomically.
- Expiry/revocation terminates affected gateway-managed activity within a documented bound.
- Agent/server/role disablement invalidates affected access.
- Policy changes have explicit safe effects.

Closing SSH does not guarantee detached destination processes terminate. Document destination-side controls required for stronger process-lifecycle enforcement.

12. EVENT HISTORY AND REPLAY

Represent access activity as an ordered, append-oriented event timeline.

Example events:
- request.created
- request.approved
- grant.activated
- connection.opened
- channel.opened
- exec.requested
- terminal.output
- terminal.input, when enabled
- terminal.resized
- channel.exited
- connection.closed
- recording.failed
- grant.revoked
- grant.expired
- access_session.closed

Define:
- Versioned schemas.
- Stable event IDs.
- Per-access-session sequence assignment.
- Connection/channel IDs.
- UTC timestamps and suitable monotonic offsets.
- Ordering and causality across concurrent activities.
- Idempotency.
- Recovery and incomplete-segment semantics.

Show repeated activity across the approval window in one timeline.

Replay concurrent terminals as distinct streams. Do not combine unrelated output into a misleading single terminal.

Recording accuracy:
- Capture exec request strings.
- Capture output and terminal resize events.
- Preserve separate stdout/stderr for non-PTY exec.
- Make input recording configurable with a privacy-conscious default.
- Explain that input may include secrets.
- Do not promise perfect secret redaction.
- A gateway cannot reliably reconstruct every interactive command from keystrokes/output.
- Never label inferred commands as verified commands.

Plan optional destination-side audit integration for stronger command accounting. Explain provenance and the limitations of shell history, kernel exec auditing, and shell built-ins.

13. ENCRYPTED HISTORY FILES

Store history and recording content in encrypted files.

Specify:
- Versioned format and headers.
- Authenticated encryption using vetted libraries.
- Per-file/segment data encryption keys.
- Key wrapping under a managed master key.
- Unique nonces and authenticated metadata.
- Bounded streaming/replay chunks.
- Truncation and corruption detection.
- Atomic finalization and manifests.
- Crash recovery.
- Integrity verification.
- Key rotation and rewrapping.
- Retention and deletion.
- Backup/restore.

Do not invent cryptography or use unauthenticated encryption.

Keep plaintext reasons, command strings, and terminal contents out of ordinary logs and unprotected SQLite indexes. SQLite should contain minimal operational metadata; sensitive history payloads belong in encrypted files.

Define:
- Master-key provisioning.
- Key storage separate from history.
- Production/development key handling.
- Startup when keys are missing.
- Key-loss consequences.
- Recovery procedures.
- Ciphertext-only archival if archival is supported.

Database/file consistency:
- SQLite cannot atomically commit arbitrary filesystem writes.
- Specify the write, commit, indexing, and reconciliation protocol.
- Detect orphan files and dangling metadata.
- State when a recording is durable.
- Define consistent backup across SQLite, history files, and key material.

Queues must be bounded and must not silently drop security-relevant events.

For mandatory recording:
- Satisfy recording prerequisites before forwarding activity.
- Define durable-write guarantees.
- Apply bounded backpressure.
- Fail closed on unrecoverable recording failure or exhausted storage.
- Mark interrupted/incomplete recordings accurately.

Encrypted history is not inherently tamper-proof against a compromised gateway with keys. Explain optional immutable archival/external integrity anchoring and its limits.

14. SSH DATA PLANE

Plan complete handling of:
- Public-key authentication.
- Shell and exec.
- PTY allocation and resizing.
- stdin/stdout/stderr.
- EOF and half-close.
- Exit status and signals.
- Cancellation and cleanup.
- Keepalive and idle timeout.
- Slow clients and backpressure.
- Resource limits.
- Authorization races.

Deny by default:
- Agent forwarding.
- TCP forwarding.
- X11 forwarding.
- Unknown channels.
- SFTP/SCP subsystems unless explicitly supported and separately authorized.

Disabling forwarding does not stop an allowed shell from opening network connections or transferring files.

Allowlist environment variables.

Validate inventory destinations to prevent unintended outbound access and inventory-based SSRF.

Use strict destination host verification. Never use InsecureIgnoreHostKey in production paths.

Document destination firewall restrictions to gateway egress addresses.

Certificate expiry alone does not terminate existing sessions; enforce deadlines in Hallpass.

Document gateway host-key enrollment and rotation for agents.

Bound buffers, goroutines, sessions, channels, pending requests, and unauthenticated connections.

15. HUMAN OPERATOR AUTHENTICATION

Support production-grade:
- Local username/email and password.
- Generic OpenID Connect SSO.
- Both together when explicitly configured.

This applies only to human web operators. Agents continue using registered SSH public keys.

Allow disabling local login after SSO is verified. Prevent accidental administrator lockout.

No default password, hidden administrator, or universal authentication bypass.

16. LOCAL PASSWORD AUTHENTICATION

Provide:
- Secure initial administrator bootstrap.
- Administrator-managed accounts.
- Optional invitation-based enrollment.
- Account disablement.
- Password change/reset.
- Optional TOTP MFA.
- Hashed single-use recovery codes.
- Configurable mandatory MFA for privileged local accounts.
- Session management and revocation.

Security:
- Argon2id with unique salts and versioned, calibrated parameters.
- Long passwords and password-manager compatibility.
- No silent truncation.
- Rate limits and progressive throttling.
- Enumeration-resistant login/recovery responses.
- Avoid trivial permanent-lockout denial of service.
- Recent authentication for sensitive changes.
- Session invalidation after resets, disablement, and relevant credential changes.
- Never log credentials or recovery secrets.
- Encrypt TOTP secrets.
- Hash reset/recovery tokens where verification permits.

Password-reset delivery must be explicitly configured. Without email delivery, provide an audited administrative recovery procedure rather than an insecure public reset mechanism.

17. GENERIC OIDC SSO

Use standards-based OpenID Connect, not plain OAuth treated as authentication.

Configuration:
- Provider display name.
- Issuer/server URL.
- Client ID.
- Client secret where required.
- Public Hallpass base URL.
- Exact callback URL.
- Scopes, defaulting to openid, profile, email.
- Optional group-claim mapping.
- Tenant/group/verified-domain restrictions.
- Optional explicit custom CA trust for private providers.

Use issuer discovery and a mature implementation.

Support common standards-compliant providers without hardcoding provider APIs.

Protocol security:
- Authorization Code flow with PKCE.
- State and nonce validation.
- Exact redirect URI validation.
- Signature, issuer, audience, expiration, and applicable authorized-party checks.
- Safe JWKS caching and rotation.
- HTTPS in production.
- Narrow localhost-only development exceptions.
- No implicit flow.
- No resource-owner password grant.
- No disabled TLS verification.
- Login-CSRF, replay, and open-redirect protection.

Provider configuration is privileged. Validate discovery/endpoints while permitting explicitly authorized private-network identity providers.

Encrypt client secrets or use secret references. Never expose secrets to frontend code or redisplay them after creation.

Do not retain access/refresh tokens without a documented need. Encrypt retained tokens and minimize scopes.

18. PROVISIONING, LINKING, AND OPERATOR RBAC

Provisioning modes:
- Pre-provisioned operators only.
- Restricted just-in-time provisioning.

Identify external users by issuer plus subject, not email alone.

Never automatically merge local and SSO identities because emails match. Require explicit authenticated linking or a privileged audited administrative action.

Map external groups to internal roles through explicit allowlisted rules. Default new users to no privileged access.

Define:
- Claim validation.
- Mapping precedence.
- Synchronization timing.
- Effects of removed group membership.
- Existing-session effects.
- Account disablement.
- Provider outage behavior.

Internal roles:
- Administrator.
- Approver.
- Auditor.
- Viewer.

Specify permissions for:
- Infrastructure address visibility.
- Key/credential administration.
- Target/role approvals.
- Recording playback/export.
- Retention changes.
- Access revocation.

SSO success does not itself grant approval authority. All authorization remains server-enforced by Hallpass.

19. BROWSER SESSIONS AND REAUTHENTICATION

Use secure server-managed sessions for local and SSO login:
- HttpOnly cookies.
- Secure cookies in production.
- Appropriate SameSite behavior for the OIDC callback flow.
- CSRF protection.
- Session rotation after login/privilege changes.
- Configurable idle and absolute expiry.
- Logout and server-side revocation.
- Active-session management.

Require recent authentication, and MFA where policy requires it, for:
- Provider changes.
- Privilege escalation.
- Credential/encryption-key administration.
- Account linking.
- MFA disablement.
- Other high-risk changes.

Define how upstream reauthentication/MFA assurance is requested and verified. Do not assume all providers expose equivalent assurance claims.

Logout must invalidate Hallpass’s session. Provider logout may be supported but is not guaranteed global logout.

Development authentication, if provided, must be isolated and rejected in production configuration.

20. PROFESSIONAL WEB UI

Build a complete professional infrastructure/security console, not a small sketch.

Choose and justify a mature component library. Ant Design is a suitable default unless repository constraints favor an equally capable alternative.

Design:
- Restrained corner radii.
- Clean typography.
- Strong visual hierarchy.
- Dense, readable tables.
- Consistent spacing.
- Subtle borders and shadows.
- No excessive pill shapes or decorative gradients.
- Full light/dark themes.
- Accessible contrast, focus, and keyboard behavior.
- Responsive operator-focused layouts.

Use a capable chart library such as Apache ECharts, with theme-aware styling and accessible summaries.

Pages:
- Dashboard.
- Requests.
- Access sessions.
- Active connections/activities.
- Replay and timeline.
- Agents and key management.
- Servers and host identities.
- Server roles and descriptions.
- Groups, labels, assignments.
- Policies and effective-access preview.
- Operators and approvers.
- Authentication settings.
- Slack/Telegram integrations.
- Audit history.
- Storage, retention, key-management status.
- System health/settings.

Access-session detail:
- Agent/server/role summary.
- Reason and approver.
- Scope and remaining duration.
- Connections/activities.
- Unified timeline.
- Per-stream replay.
- Exec records with provenance.
- Revocation.
- Recording integrity/completeness.

Authentication settings:
- Enabled login methods.
- Password/MFA policies.
- OIDC configuration.
- Copyable callback URL.
- Discovery/connectivity checks.
- Complete test-login workflow before SSO-only enforcement.
- Group mappings.
- Provisioning restrictions.
- Session policies.
- Audited changes.

A successful discovery check does not prove an administrator can complete login and retain access.

Login UI must adapt cleanly to local-only, SSO-only, and combined modes.

UX:
- Real loading, empty, error, stale, disconnected, and denied states.
- Server-side pagination/filtering/sorting.
- Saved filters where useful.
- Charts backed by real data.
- No fake metrics.
- Clear destructive-action confirmation.
- Accurate server-derived countdowns.
- No optimistic success for security-sensitive operations.
- Restricted/audited recording download.
- Safe handling of malicious terminal escapes and rendered links.

Plan a reusable design system and visual regression tests.

21. THREAT MODEL

Cover:
- Compromised agent.
- Stolen SSH key.
- Malicious destination.
- Malicious request reason.
- Approval forgery/replay.
- Unauthorized approver.
- Credential stuffing and password-reset abuse.
- SSO misconfiguration and identity-linking attacks.
- Compromised browser session.
- Gateway compromise.
- Signing/credential/encryption-key compromise.
- Recording disclosure or alteration.
- SQLite/storage failure.
- Crash during authorization or recording.
- Policy/expiry/revocation races.
- Inventory-based SSRF.
- Administrator lockout.

Explicitly acknowledge that Hallpass is a high-value trusted component that can access plaintext proxied session data.

22. OPERATIONS AND OPEN-SOURCE READINESS

Plan:
- Health/readiness.
- Redacted structured logs.
- Metrics/traces.
- Correlation IDs.
- Graceful shutdown and draining.
- Backup/restore drills.
- Upgrade/migration procedures.
- Rollback limitations.
- Capacity planning and disk alerts.
- Dependency/container scanning.
- SBOM and release provenance where practical.
- Versioned APIs and recording formats.
- Security reporting policy.
- CONTRIBUTING.md.
- Architecture and operator documentation.
- Secret-free example configuration.
- A recorded license decision; do not choose a license without authorization.
- A separately controlled, audited human break-glass path.

Lost-admin recovery must require deployment-environment control and produce an audit record. It must not be a remote authentication bypass.

Do not embed private infrastructure details, tokens, customer data, or secret-bearing fixtures in a repository intended for future publication.

23. TESTING AND RELEASE GATES

Define measurable tests for:
- Registered/unknown/revoked SSH keys.
- SSH username spoofing.
- Visibility and hidden-target non-disclosure.
- Policy precedence and role restrictions.
- Request waiting/polling/deduplication.
- Approval authorization, forgery, replay, and concurrent decisions.
- Grant reuse and expiry boundaries.
- Revalidation for every channel.
- Revocation and disablement.
- Host verification and rotation.
- Credential isolation.
- Shell/exec/PTY stream semantics.
- EOF, resize, exit status, and disconnect cleanup.
- Denied forwarding/subsystems.
- Event ordering.
- Durable recording and mandatory-recording failure.
- Encryption, integrity, key rotation, recovery.
- SQLite concurrency and crash consistency.
- Disk exhaustion and storage/database failure.
- Restart reconciliation.
- Restore onto a clean machine.
- Long-running/concurrent-session load.
- Resource leaks and bounded memory.
- Accessibility and visual consistency.
- Replay safety and recording permissions.
- Supported-version upgrades.

Authentication tests:
- Secure bootstrap.
- Password hashing/verification.
- Throttling and enumeration resistance.
- Password reset/session invalidation.
- MFA enrollment/recovery/disablement.
- OIDC state/nonce/PKCE/token/issuer checks.
- JWKS rotation.
- Provisioning restrictions.
- Account-linking safety.
- Group-role mapping/removal.
- All login modes.
- Provider outages.
- Administrator lockout prevention.
- Secret redaction/encryption.
- Identical RBAC across authentication methods.

Use:
- Go race detector.
- Fuzzing.
- Real OpenSSH integration tests.
- Browser E2E tests.
- Fault injection.
- Soak tests.
- Visual regression.
- Security-focused review.

Performance targets must include test hardware/workload assumptions. Do not invent scalability claims.

24. REQUIRED PLAN OUTPUT

Persist an actionable plan containing:

1. Summary and assumptions.
2. Canonical requirements with stable requirement IDs.
3. Architecture/trust boundaries.
4. SQLite deployment/recovery design.
5. Domain model and state machines.
6. Schema, constraints, indexes, migrations.
7. SSH grammar.
8. API and live-event contracts.
9. Visibility, policy, and role semantics.
10. Approval-provider design.
11. Agent/server key and credential lifecycle.
12. Local/OIDC authentication and RBAC.
13. Encrypted event/history format and consistency protocol.
14. UI architecture/design system.
15. Repository/module layout.
16. Threat model.
17. Test matrix and release gates.
18. Operational procedures.
19. Dependency-ordered implementation packages.
20. Risks/trade-offs/review decisions.
21. Acceptance checklist mapped to requirement IDs.
22. Documentation and commit workflow.

Each work package includes:
- Goal.
- Dependencies.
- Files/modules.
- Design decisions.
- Tests.
- Acceptance criteria.
- Documentation updates.
- Appropriate local /cc commit boundary.

Resolve the engineering design sufficiently for implementation rather than merely repeating this prompt. Separate firm decisions from proposals requiring review.

End the planning response with:
- Files actually created/updated.
- Major architectural decisions.
- Remaining review decisions.
- First implementation work package.
- Local commit hashes, if created.
- Confirmation that nothing was pushed.

Do not push anything without a separate explicit user instruction.
