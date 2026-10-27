# HallPass — Architectural Decisions

> ADR log plus unresolved review items. Format per ADR: **Status · Context · Decision · Alternatives · Consequences**.
> Statuses: `accepted`, `proposed`, `superseded by ADR-NNNN`, `withdrawn`. ADR numbers are never reused.
> A decision that weakens a GOAL.md security requirement must be labeled **security-relevant change** and needs operator review.

## 1. Decision log

### ADR-0001 — Modular monolith, single active instance
- **Status:** accepted (WP00, 2026-10-23)
- **Context:** The brief requires SQLite, prefers minimal infrastructure, and requires a clearly supported topology. SSH sessions are
  stateful inside the process.
- **Decision:** One Go binary `hallpass` (`serve` plus admin subcommands) structured as internal packages with explicit interfaces.
  Exactly one active process per data directory, enforced by an exclusive `flock` on `<data>/hallpass.lock`. Recovery is cold standby:
  restore a backup on a new host. Writable SQLite on NFS/SMB is refused.
- **Alternatives:** microservices (operational overhead, distributed state for no benefit at A-7 scale); active-active with
  PostgreSQL (contradicts the SQLite requirement); active-passive with replicated SQLite (Litestream/LiteFS: adds failure modes,
  LiteFS needs FUSE and a lease service; Litestream is kept as optional backup, R-04).
- **Consequences:** Simple deployment and reasoning. Host loss → downtime ≈ RTO (target ≤ 15 min). Established SSH sessions cannot
  migrate, because transport keys, sequence numbers and channel windows live in process memory. Agents must reconnect after failover.

### ADR-0002 — SQLite via `modernc.org/sqlite`, WAL, `synchronous=FULL`, split pools
- **Status:** accepted
- **Context:** Need a durable, embedded, CGO-free database with predictable concurrency.
- **Decision:** `modernc.org/sqlite` (pure Go). Pragmas on every connection through the DSN: WAL, `synchronous=FULL`, `foreign_keys=ON`,
  `busy_timeout=5000`, `trusted_schema=OFF`. One writer connection using `BEGIN IMMEDIATE`, plus N `query_only` readers. Bounded jittered
  retries. No transaction spans network I/O, waits or SSH traffic, which an analyzer and tx-duration tests enforce. Queries are generated with `sqlc`,
  migrations use `pressly/goose` (embedded, forward-only, under the flock, after a `VACUUM INTO` snapshot). `quick_check` runs at startup and
  `integrity_check` in maintenance. Disk-full and I/O errors fail closed. File modes `0700`/`0600`.
- **Alternatives:** `mattn/go-sqlite3` (CGO: faster, but complicates static, multi-arch and distroless builds); `ncruces/go-sqlite3`
  (wasm, CGO-free, a viable fallback if modernc benchmarks disappoint, K-1); `synchronous=NORMAL` (can lose recent commits on
  power loss, unacceptable for audit).
- **Consequences:** Static binaries and simple cross-compiles. Some write throughput is lost, which is acceptable because payloads live in files.

### ADR-0003 — Application-level encryption of sensitive SQLite columns (no SQLCipher)
- **Status:** accepted
- **Context:** Stock SQLite doesn't encrypt. SQLCipher requires CGO, which conflicts with ADR-0002.
- **Decision:** AEAD-encrypt sensitive columns with keyring purpose keys (AAD binds table, column, row ID and key version): reasons, comments,
  TOTP secrets, OIDC client secrets, provider tokens and secrets, private keys, SMTP password. Hash high-entropy tokens. Document the plaintext
  metadata (topology, timestamps, identities, policy) in PLAN §4.8. Recommend full-disk encryption as the baseline.
- **Alternatives:** SQLCipher (CGO, single key, all-or-nothing); a SQLite VFS encryption layer in pure Go (immature, and harder to review).
- **Consequences:** DB-file readers learn topology and access metadata but not secrets or content. Some columns can't be
  queried or indexed, which is acceptable.

### ADR-0004 — Keyring: KEK → purpose DEKs, `KeyWrapper` abstraction
- **Status:** accepted
- **Decision:** A 32-byte master KEK from a file (`0400`, outside the data dir), an env var, or a secret mount. Purpose keys (`field`, `credential`,
  `recording`, `manifest`, `token`) are wrapped with AES-256-GCM and versioned. Each recording segment gets a random DEK wrapped by the recording key.
  `KeyWrapper` interface for future KMS/Vault transit (R-03). Production refuses to start without the KEK, and a canary detects a wrong KEK.
  KEK rotation is offline (rewrap purpose keys), and purpose-key rotation is online with background re-encryption.
- **Alternatives:** a single key for everything (no rotation granularity); keys stored in the DB unwrapped (useless); OS keychains
  (not portable to containers).
- **Consequences:** Losing the KEK makes encrypted data unrecoverable, so the KEK must be backed up separately (operator guide).
  Backups exclude the KEK by design.

### ADR-0005 — HPREC1 recording format (STREAM over ChaCha20-Poly1305)
- **Status:** accepted; **external review required (R-02)**
- **Context:** Need streaming, bounded, authenticated, truncation-detecting encrypted files with crash-tolerant appends and
  rewrappable keys, built only from vetted primitives.
- **Decision:** PLAN §13.3. Versioned plaintext header (authenticated as frame AAD via its SHA-256). Two fixed-size key slots for
  crash-safe rewrap. Random per-segment DEK, HKDF-derived payload key. Frames ≤ 64 KiB sealed with `x/crypto/chacha20poly1305`
  using nonce = 88-bit big-endian counter ‖ final flag (the STREAM construction, as in age). A footer record in the final frame.
  Ciphertext SHA-256 and a hash-chained, MAC'd manifest entry in SQLite at finalization. Group-commit fsync ≤ 250 ms by default, strict
  per-frame mode optional.
- **Alternatives:** the age library directly (recipient model, and no control of frame flushing or slot rewrap); AES-GCM with random
  per-frame nonces (no structural truncation detection); per-record DB storage (unbounded DB growth, violates the brief); Tink
  streaming AEAD (adds a large dependency and key-management model mismatch).
- **Consequences:** Small custom format to specify, fuzz and review. Format version bump path defined (`HPREC2`).

### ADR-0006 — Destination login: managed Ed25519 key per server-role binding (default), OpenSSH user certificates (alternative)
- **Status:** accepted
- **Context:** HallPass needs gateway-controlled login credentials that agents never see, with safe rotation.
- **Decision:** Default: a distinct Ed25519 key per server-role binding, generated in HallPass, sealed at rest, with the public key shown as a
  `restrict,from="<egress>"` authorized_keys line. Rotation `pending → probe → active → retiring → retired`, with immediate revocation.
  Alternative: a HallPass user CA signing per-connection certificates (TTL 120 s, explicit principals, minimal extensions) behind a `Signer`
  interface. Host keys, login credentials and CAs are separate types, tables, APIs and UI pages. Strict host verification, with
  `InsecureIgnoreHostKey` banned by lint.
- **Why the per-binding key is the default:** it works with any stock sshd without configuration beyond authorized_keys, gives
  per-binding revocation and blast-radius isolation, and needs no CA trust distribution. Certificates suit fleets that already
  manage `TrustedUserCAKeys`.
- **Alternatives:** one shared gateway key (large blast radius, no per-role revocation); passwords (weak, not supported);
  agent forwarding of the agent's own key (violates the credential boundary).
- **Consequences:** Operators install one public key per binding. The UI provides copyable lines and probe verification.

### ADR-0007 — Domain: request → decision → grant ↔ access session (1:1)
- **Status:** accepted
- **Decision:** Separate entities for request, decision, grant, access session, connection, channel, segment and timeline/audit events. Grant to
  access session is 1:1, created in the approval transaction. The grant duration starts at commit. Reconnecting never extends it, and there are
  no implicit extensions. Overlapping grants are selected by the latest expiry, then the lowest ID. Every channel revalidates the grant, and concurrency is reserved
  atomically in the writer transaction.
- **Alternatives:** session = SSH connection (breaks reconnect semantics and the unified timeline); many sessions per grant (no benefit,
  more complex UI).
- **Consequences:** A single, clear unit for UI, retention and audit. Approval after expiry creates a new session.

### ADR-0008 — Policy model: default deny, deny overrides, level lattice, separate approver rules
- **Status:** accepted
- **Decision:** PLAN §9. Rules map subject × target × role selectors to `deny` or an allow level (`visible` < `requestable` <
  `auto_approve(max)`). Selector clauses union, label requirements AND, and an empty selector matches nothing. `all: true` is explicit and includes future
  objects. Approval authority comes from separate approver rules, and **administrators also need an approver rule** so authority is
  always explicit and reviewable. The policy version is stored on grants. Policy changes cancel pending requests or revoke grants that are no longer
  permitted, and clamp durations.
- **Alternatives:** first-match ordered rules (fragile under edits); OPA/Rego (powerful, but adds a language and runtime to audit);
  implicit admin approval (surprising authority).
- **Consequences:** Order-independent, explainable evaluation, and a straightforward effective-access preview.

### ADR-0009 — SSH command grammar, exit codes 80–90, JSON schemas
- **Status:** accepted
- **Decision:** PLAN §7. A gateway-side tokenizer (quotes and backslash only, no expansion, no shell). Reserved words. Raw-substring
  forwarding after `--`, interpreted by the destination shell (documented). Gateway messages go to stderr and stdout passes through untouched.
  Exit codes 80–90 with a single-line `hallpass.error/v1` JSON on stderr. A missing reason without a PTY → exit 90. Wait timeout
  (120 s default, 15 m max), pending expiry (30 m) and grant duration are independent. Requests are deduplicated per agent+server+role.
- **Alternatives:** a subsystem-based protocol (incompatible with plain `ssh center …` UX); exit codes in the 1–3 range
  (collide with common destination codes more often); interpreting commands through `sh -c` on the gateway (unsafe).
- **Consequences:** Agents can script reliably. Remote quoting requires care, which the agent guide explains.

### ADR-0010 — Identifiers and time
- **Status:** accepted
- **Decision:** Type-prefixed, lowercase Crockford base32 UUIDv7 IDs (`req_…`), sortable and non-guessable enough for display (never
  used as secrets). Persisted times are INTEGER µs UTC. In-process deadlines use monotonic timers. API/JSON times are RFC 3339 UTC.
- **Alternatives:** integer autoincrement (leaks volume, merges badly across restores); ULID (equivalent; UUIDv7 is standardized in RFC 9562).
- **Consequences:** IDs are readable in logs and Slack and safe to expose to agents.

### ADR-0011 — Approvals through one decision service; action tokens; Slack and Telegram verification
- **Status:** accepted
- **Decision:** PLAN §10. Web, Slack, Telegram and policy auto-approval call one transactional `Decide`. Action tokens are 128-bit, hashed,
  bound to request/action/duration/provider/expiry and single-use, and never authorize alone. Slack: v0 HMAC, ±300 s window, replay
  cache. Telegram: `secret_token` header, chat/user allowlists, opaque ≤ 64-byte `callback_data`. Provider identities link to operators only
  through a verified link-code flow or an audited admin action. Durable outbox with bounded retries and delivery history. Failure never approves.
- **Alternatives:** callback URLs carrying signed approve links (possession becomes authorization); per-provider decision logic (divergence).
- **Consequences:** Uniform guarantees across channels, and chat approvers must link accounts first.

### ADR-0012 — Live updates via Server-Sent Events
- **Status:** accepted
- **Context:** The brief requires SSE or WebSockets with a justified choice.
- **Decision:** SSE (`GET /api/v1/events`). Traffic is server-to-client only. SSE works over plain HTTP/1.1 and HTTP/2 through standard
  reverse proxies, uses the same cookie auth and CSRF-free GET semantics, and has built-in reconnect with `Last-Event-ID`. Mutations
  stay on REST. Events carry only invalidation hints, and clients refetch via authorized REST. Replay data is fetched in REST chunks.
- **Alternatives:** WebSockets (bidirectional not needed, separate auth and origin handling, proxy configuration burden); polling (latency
  and load).
- **Consequences:** A per-browser connection limit (HTTP/1.1, 6 per origin) is mitigated by a single shared stream per tab and recommending HTTP/2.

### ADR-0013 — Frontend: React + TS + Vite, TanStack, Ant Design, ECharts, xterm.js, Playwright
- **Status:** accepted
- **Decision:** PLAN §14. **Ant Design v5** with theme tokens (radius 4–6, dense tables, light and dark). It is mature, has a comprehensive
  table/form set suited to operator consoles, an algorithmic dark theme, and good keyboard support. **Apache ECharts** for charts,
  **xterm.js** for replay with link handlers, OSC 8/52 and title changes disabled. Playwright for E2E and visual regression, axe for accessibility.
  The UI is embedded in the binary.
- **Alternatives:** MUI (strong, but Material styling needs heavier restyling for a dense console); Mantine (smaller enterprise table
  ecosystem); Chakra (less suited to dense data). Recharts (less capable for time-series density).
- **Consequences:** CSS-in-JS needs `style-src 'unsafe-inline'` unless a nonce or static extraction works (R-11).

### ADR-0014 — Operator authentication: local + OIDC, server-side sessions
- **Status:** accepted
- **Decision:** PLAN §12. Local accounts with Argon2id (versioned, calibrated), 12–1024-byte passwords without truncation,
  progressive throttling without permanent lockout, TOTP with encrypted secret, and hashed recovery codes. OIDC via `coreos/go-oidc/v3` +
  `x/oauth2`: code + PKCE, state/nonce, exact redirect, identity `iss`+`sub`, no email auto-merge, preprovisioned or restricted JIT,
  allowlisted group mapping synced at login. Sessions are server-side, in a `__Host-` cookie with SameSite=Lax (needed for the top-level callback
  redirect carrying the state-binding cookie), CSRF token + Origin checks, rotation, and idle/absolute expiry. Recent-auth gates. Break-glass only via the
  local CLI with the lock and KEK.
- **Alternatives:** JWT sessions (hard to revoke); SameSite=Strict (breaks the OIDC callback cookie binding); email-based account linking
  (account takeover risk).
- **Consequences:** Session revocation is immediate, and group removals take effect at next login (bounded by the absolute expiry).

### ADR-0015 — Operator RBAC: four internal roles plus scoped approver rules
- **Status:** accepted
- **Decision:** Administrator, Approver, Auditor, Viewer with the matrix in PLAN §12.5. Permission checks are generated from OpenAPI
  `x-permission`. Address visibility is Administrator-only by default. Recording export is Administrator plus reauth. New users get no privilege.
- **Consequences:** Identical enforcement regardless of auth method, verified by a parameterized suite.

### ADR-0016 — Spec-first OpenAPI 3.1 with generated server and client types
- **Status:** accepted
- **Decision:** `api/openapi.yaml` is authoritative. `oapi-codegen` (strict `net/http` server) and `openapi-typescript`. CI fails on drift.
  `/api/v1` is additive-only, RFC 9457 errors, cursor pagination.
- **Alternatives:** code-first annotations (spec drifts from behavior); gRPC + gateway (unnecessary for a browser console).

### ADR-0017 — Observability: slog JSON (ECS-aligned) + OpenTelemetry + Prometheus
- **Status:** accepted (log schema naming pending R-07)
- **Decision:** `log/slog` JSON with stable ECS-aligned field names and a redaction layer (`LogValuer` types plus a key denylist). OTel
  traces and metrics, an OTLP exporter optional, Prometheus `/metrics`. Audit events are separate from debug logs (DB hash chain plus an optional JSON
  sink). `/healthz` and `/readyz`.
- **Consequences:** Logs ingest into OpenSearch/Elastic without custom parsing, and OpenSearch is not required.

### ADR-0018 — Enforcement bound of 5 seconds
- **Status:** accepted
- **Decision:** The enforcer reacts to in-process events, runs a 1 s expiry ticker, and runs a 1 s DB reconciliation of changed grants. The documented
  and tested bound from a grant becoming invalid to channel termination is ≤ 5 s. Channel registration requires ≥ 2 s of remaining validity.
- **Alternatives:** per-channel timers only (miss revocations); a tighter bound (marginal value, more load).
- **Consequences:** Up to 5 s of residual activity after revocation, which is documented in the guarantees.

### ADR-0019 — Mandatory recording by default; input recording off; group-commit durability
- **Status:** accepted
- **Decision:** Roles default to `recording_mode=mandatory`. Forwarding starts only after a durable segment header, write failures
  terminate the channel, and full queues apply backpressure instead of dropping. Input recording defaults off (privacy: input can contain secrets).
  Durability: `group` (fsync ≤ 250 ms) by default, `strict` optional. `best_effort` is a per-role opt-in, prominently flagged.
- **Consequences:** Interactive latency depends on the disk, which the performance suite measures. A storage outage blocks access (fail closed).

### ADR-0020 — Host identity verification and gateway host-key rotation
- **Status:** accepted
- **Decision:** Destinations: explicit enrollment (paste or scan-plus-operator-confirm), states `pending/active/retired`, duplicate detection
  with audited exceptions, optional host CA with principal bindings, `HostKeyAlgorithms` restricted to enrolled types. Gateway: Ed25519 host
  key sealed in the DB. Rotation by second-algorithm overlap or a gateway host certificate (`@cert-authority`), because `x/crypto/ssh` lacks
  `hostkeys-00@openssh.com`.
- **Consequences:** Agents must update known_hosts during rotation unless they use a host CA. Documented.

### ADR-0021 — Egress guard against inventory-based SSRF
- **Status:** accepted
- **Decision:** Destinations must resolve into operator-configured egress allow CIDRs. Loopback, link-local, unspecified, multicast and
  cloud-metadata ranges (including IPv4-mapped IPv6) are denied unless explicitly allowlisted. Resolution happens at dial time and the connection
  goes to the validated IP (no second resolution). Host-key scans and probes use the same guard.
- **Consequences:** Operators must configure egress ranges before adding servers, and the UI explains the error.

### ADR-0022 — Distribution and supply chain
- **Status:** accepted
- **Decision:** `CGO_ENABLED=0` static binaries (linux amd64/arm64, darwin for dev). A distroless `static-debian12:nonroot` image, a Compose
  example, and a systemd unit with sandboxing. GitHub Actions CI: golangci-lint, race tests, fuzz smoke, OpenSSH integration, frontend
  tests, govulncheck, Trivy, gitleaks. Release: SBOM (syft), checksums, `actions/attest-build-provenance`. Actions are pinned by SHA.
- **Consequences:** Reproducible, scannable artifacts. Cosign keyless signing can be added later.

### ADR-0023 — Backup model: `VACUUM INTO` + segment copy + manifest; KEK separate
- **Status:** accepted
- **Decision:** PLAN §13.10. Online consistent snapshot, segments copied according to the snapshot's view, a manifest with hashes and the KEK ID. The KEK is never
  in backups. Restore only into an empty directory, followed by verification and reconciliation. Forward-only migrations, so rollback = restore the pre-upgrade backup.
- **Alternatives:** filesystem snapshots only (good complement but not portable); copying the live DB file (unsafe).
- **Consequences:** Host-loss RPO equals the backup interval unless continuous segment sync and Litestream (R-04) are used.

### ADR-0024 — Local commits per work package; never push
- **Status:** accepted
- **Context:** The brief requires `/cc`-based commits and forbids pushing without explicit instruction. On 2026-10-23 the user explicitly
  authorized agents to create local commits on their own, but not to push.
- **Decision:** At each completed WP: inspect the tree, stage explicit paths, generate the message with the `/cc` skill (verified to only print
  a message, never commit or push), run `git commit`, and report the hash. Never `git push`. No history rewriting.
- **Consequences:** Work is preserved incrementally, and publishing stays a human decision.
- **Recorded deviation (WP00):** `/cc` could not run for the root commit because its `git log` step fails when a repository
  has no commits. With the user's explicit approval, the WP00 commit used a hand-written Conventional Commits message.
  Later commits use `/cc` as normal.

### ADR-0025 — Configuration loader: YAML + reflective HALLPASS_* overrides, no framework
- **Status:** accepted (WP02)
- **Context:** PLAN WP02 left the choice between `knadh/koanf` and a minimal loader open.
- **Decision:** `go.yaml.in/yaml/v3` with `KnownFields(true)` into one typed `Config` struct, plus a small reflective walker that maps
  each YAML path to `HALLPASS_<PATH>` and rejects unknown `HALLPASS_*` variables (except `HALLPASS_KEK`, `HALLPASS_CONFIG`). Validation
  collects all problems. Production mode is the default.
- **Alternatives:** koanf/viper (more dependencies and looser unknown-key handling).
- **Consequences:** One small dependency, strict typo detection, and override names derived mechanically (`hallpass config env`).

### ADR-0026 — HPREC1 format refinements
- **Status:** accepted (WP12). Not security-relevant: no requirement is relaxed.
- **Context:** PLAN §13.3 sketched the segment format. An independent implementation needed exact encodings.
- **Decision:** Adopt the refinements listed in `docs/formats/hprec1.md` §12:
  - binary `HPK1` key slots with a SHA-256 checksum instead of zero-padded JSON;
  - `prev_segment_sha256` = the previous segment's `ciphertext_sha256` (required for ordinal > 0);
  - per-frame timestamp bases;
  - records never span frames, and the maximum payload is 65 472 bytes (the recorder splits larger writes);
  - `ciphertext_sha256` covers the frame region only;
  - a fixed binary footer, in its own final frame when it does not fit;
  - canonical decoding everywhere;
  - recovery copies the original to quarantine only when bytes are actually discarded.
- **Consequences:** Every accepted file has exactly one encoding. The construction still needs external review (R-02).

### ADR-0027 — SSH grammar interpretations
- **Status:** accepted (WP10). Not security-relevant: each item is stricter than, or equal to, PLAN §7.
- **Decision:**
  1. The NUL/C0 control-character and UTF-8 checks apply to the whole input, including the remote command after
     `--`. Multi-line remote commands (LF inside quotes or heredocs) are therefore rejected with exit 81. Allowing LF
     after `--` would need a new ADR.
  2. The alias or request ID must directly follow the command word, as in the EBNF. Options may then come in any
     order, each at most once.
  3. `status` rejects `--no-wait` (`--wait=false` works). `--wait=` accepts `true/false/yes/no/1/0`.
  4. Option words are recognized quoted or unquoted, but a quoted `--` never acts as the separator. In
     `--opt value` form, an unquoted value starting with `-` counts as a missing value; use `--opt=value`.
  5. `cancel --json` emits `hallpass.status/v1` because §7.7 defines no cancel schema.
  6. Agents see the level `auto`, which the gateway maps from the policy level `auto_approve`.
  7. Wait-timeout and shorthand hints never echo reasons. Echoed words are quoted and capped at 64 bytes.
  8. The parser accepts any positive `--duration`. Presets and maximums are enforced by policy at request time.
  9. `ps` is reserved, per GOAL HP-SSH-017 (PLAN §7.4 omitted it). The alias rules live in the leaf package
     `internal/inventory/alias`, so the grammar has no storage or I/O dependency. A depguard rule enforces this.
     No server can already use the alias `ps`, because no release predates this rule.
- **Consequences:** The agent guide (`docs/agent/guide.md`) documents these behaviors.

### ADR-0028 — Recorder pipeline and recording consistency details
- **Status:** accepted (WP11/WP12). Not security-relevant: consistent with ADR-0019.
- **Decision:**
  - Each channel gets a recorder that inserts the segment row, then creates and fsyncs the file before the
    destination session starts (HP-REC-007).
  - Records go through a bounded queue. Producers block when the queue is full (SSH window backpressure). After
    `recording.block_timeout` the recording fails, and mandatory-recording channels are terminated (exit 80).
    Nothing is dropped silently.
  - Sequence assignment and hand-off to the writer are one critical section per recorder, so concurrently recorded
    streams (stdout, stderr, stdin) reach the file in sequence order. A regression test covers this. An OpenSSH test
    found the race: out-of-order appends failed the recording.
  - Segments roll over by size (pending bytes included) and by age. Each new segment chains to its predecessor's
    ciphertext hash.
  - Finalization appends the manifest to the HMAC'd integrity chain in the same transaction as the row update.
  - The exit status is delivered to the agent before the final frame is committed. A crash in that window leaves an
    `interrupted` segment holding everything up to the last group commit (≤ 250 ms), the same bound as ADR-0019.
  - Startup reconciliation:
    - verifies final files whose row is still `open` and finalizes them;
    - recovers `.partial` files to their authentic prefix, quarantining the original when bytes are discarded;
    - quarantines unrecoverable partial files and marks them `failed`;
    - marks rows with no file as `missing`;
    - moves unreferenced files to quarantine.
  - Retention schedules `delete_after = closed_at + recording.default_retention` for closed sessions, deletes segment
    files and keeps tombstone rows.
- **Consequences:** `hallpass verify` checks segment headers and ciphertext hashes against the database, final
  frames, and the integrity chain's hash links and MACs. External anchoring (HP-CRY-008) remains WP23 work.

### ADR-0029 — Frontend toolchain versions (WP19 foundation)
- **Status:** accepted (WP19, partial). Not security-relevant.
- **Context:** ADR-0013 and PLAN §14.1 name Ant Design v5. The latest stable majors were chosen at implementation time.
- **Decision:**
  - Ant Design **6** (6.6.7) instead of v5.
  - React 19.3, Vite 8, TanStack Router/Query/Store, ECharts 6, xterm.js 6.
  - TypeScript **6.0** rather than 7, because typescript-eslint 8.72 supports TypeScript below 6.1.
  - ESLint 10, with a `peerDependencyRules` override for `eslint-plugin-jsx-a11y@6.10.2`, which declares ESLint ≤ 9. Its
    rules were verified to load and fire under ESLint 10.
  - Exact versions are pinned (`save-exact`) through pnpm with a frozen lockfile.
- **R-11 remains open:** antd's CSS-in-JS still needs `style-src 'unsafe-inline'`. `script-src 'self'` stays strict, and
  the build check (`scripts/check-dist.mjs`) fails on inline scripts, dev-only modules or non-image `data:` URIs.
- **Consequences:** The xterm.js wrapper disables link handling and swallows OSC 0/1/2/8/52, with a test against a
  real terminal instance. ESLint forbids `dangerouslySetInnerHTML` and other HTML sinks, as well as static devtools
  imports.

### ADR-0030 — OIDC implementation details
- **Status:** accepted (WP14). Not security-relevant: each item is stricter than, or equal to, PLAN §12.4.
- **Decision:**
  - **Library pieces:** `coreos/go-oidc/v3` for discovery and claim verification, `x/oauth2` for the code exchange with
    PKCE, and a HallPass key set built on `go-jose/v4`. go-oidc's remote key set refetches on every unknown `kid`; HP-OIDC-004
    requires rate limiting (one refetch per 10 s, cached keys stay usable during outages). The key set accepts only RSA
    ≥ 2048 bits, ECDSA P-256 and Ed25519 keys.
  - **Clock skew:** go-oidc checks `exp` without leeway. HallPass verifies with the clock shifted back 60 s, which gives
    60 s skew on `exp`, and checks `iat` and `nbf` itself with ±60 s, tighter than go-oidc's 5-minute `nbf` leeway.
  - **IdP requests:**
    - no HTTP proxy and no redirect following;
    - private, loopback, link-local and CGNAT addresses are refused at connect time unless `allow_private_network` is set;
    - endpoint origin is checked by registrable domain (public suffix list), or by exact host for IP literals.
  - **Fresh IdP login:** test-login and self-link flows also send `prompt=login&max_age=0`.
  - **Link invitations:** single-use, consumed when the flow starts. An abandoned flow requires a new invitation.
  - **Session MFA:** SSO sessions are never "MFA-limited"; MFA is delegated to the IdP and is observable through `acr`
    and `amr`. Local TOTP is used only as the configured step-up fallback.
  - **Last-admin guard:** SSO role sync keeps the administrator role, and audits `operator.role_sync.blocked`, when
    removing it would leave no enabled administrator (HP-AUTH-015).
  - **JIT email conflicts:** a JIT login whose verified email belongs to another operator is refused with a conflict,
    never merged.
  - **Interop tests:** smoke tests against real Keycloak and Dex containers (`test/oidcinterop`, nightly CI) pass
    locally. They found and fixed one bug: logout offered the first provider's end-session URL instead of the
    session's provider (migration 0013 records `web_sessions.auth_provider`).

### ADR-0031 — REST API implementation: in-repo generator, conventions and UI embedding
- **Status:** accepted (WP15). Not security-relevant: no requirement is relaxed.
- **Context:** PLAN §8.1 names `oapi-codegen` for the strict server. Its OpenAPI 3.1 support is incomplete (it is built
  on kin-openapi, which targets 3.0), and HP-API-001 requires a 3.1 spec.
- **Decision:**
  1. **Spec and code generation:**
     - `api/openapi.yaml` (3.1) is the source.
     - `internal/tools/apigen` generates `internal/httpapi/gen/operations.gen.go`: the operation table (method, path,
       `x-permission`, `x-reauth`, `x-mfa`, `x-idempotency-key`, `x-stream`, `x-redirect`) and a `Server` interface
       with one method per operation, so a missing handler fails compilation.
     - `openapi-typescript` generates `web/src/api/schema.gen.ts`.
     - `make api-check` fails CI on drift.
  2. **Conformance:** the API tests validate response bodies against the spec's JSON Schemas
     (`santhosh-tekuri/jsonschema/v6`, draft 2020-12). A negative test proves the validator rejects drift.
  3. **Single authorization point:** every operation goes through one middleware in this order:
     1. rate limits (per IP, per session, stricter on auth endpoints);
     2. Origin/`Sec-Fetch-Site` check for mutations;
     3. session cookie;
     4. RBAC `Authorize(x-permission)`;
     5. CSRF token for authenticated mutations;
     6. recent auth / MFA gates;
     7. idempotency replay;
     8. the handler;
     9. RFC 9457 problem details.
     A parameterized test runs the whole matrix (every operation × four roles plus no role × password and SSO
     principals) and proves local and SSO decisions are identical (HP-RBAC-006).
  4. **API conventions:**
     - Durations are integer **seconds** in the API. Domain JSON uses nanoseconds; DTOs shadow those fields.
     - `PATCH` takes the version from `If-Match` (or the body); with neither, it returns 428.
     - `validation_failed` → 422; `conflict` and `precondition_failed` → 409; `unauthorized`, `reauth_required` and
       `mfa_required` → 401.
     - Mutations without a same-origin `Origin` (or `Sec-Fetch-Site: same-origin`) are refused.
  5. **Redaction:**
     - Addresses and ports are redacted without `inventory.address.read`, and host identities need that permission.
     - Request reasons are returned only with `requests.reason.read`.
     - SSE events carry only type, resource and ID.
  6. **SSE:**
     - in-process hub with a 4096-event ring per boot, 256-event per-client buffer and `reset` on overflow, unknown ID
       or another boot;
     - at most 4 streams per web session and 512 in total;
     - 15 s heartbeat;
     - the session is re-validated every 30 s (revocation closes the stream) and role changes apply to later events.
  7. **UI embedding (HP-UI-016):** release and container builds compile with `-tags embedui` and embed `web/dist`.
     Other builds serve a "UI not included" notice, so Go builds and tests do not depend on a frontend build. The
     handler serves index.html for client routes (no-cache) and immutable hashed assets, and returns 404 for missing
     assets.
  8. **Test-login preview:** the preview is kept in memory per operator and provider for 10 minutes (`GET
     /oidc-providers/{id}/test-login`), so claims never travel in redirect URLs.
- **Consequences:** routes, permissions and security flags cannot drift from the spec. Webhook endpoints
  (`/hooks/*`) and the remaining PLAN §8.2 resources (integrations, notification routes, retention, recording export,
  system keys and backup) are added with WP16–WP18 and WP23.

### ADR-0032 — Backup, restore, anchors and break-glass CLI details
- **Status:** accepted (WP23). Item 2 is a **security-relevant change** and is flagged for operator review.
- **Decision:**
  1. **CLI syntax:**
     - `hallpass backup create --out DIR`, `backup verify DIR`, `restore DIR [--data D] [--force]`;
     - `anchors export [--since N]`, `anchors verify FILE`;
     - `admin bootstrap`, `admin recover --email E [--new-admin]`.
     These replace PLAN's `backup --out` and `admin recover --operator`.
  2. **`restore --force`** (*security-relevant*). ADR-0023 says restore only into an empty directory. `--force` instead
     moves the existing data aside to `backups/pre-restore-<ts>/` and deletes nothing. It needs an explicit flag, the
     process lock and the matching KEK. Without `--force`, a non-empty target is still refused.
  3. **Path rewrite:** restore rewrites `recording_segments.path`, because paths are stored as absolute paths.
     Storing them relative to the data directory is a follow-up.
  4. **Live segments:**
     - A segment whose file is missing or does not match during an online backup is recorded in the manifest and
       makes the CLI exit 3; the backup is not aborted.
     - Segments still open at snapshot time are copied as `.partial`, and after restore they reconcile as `interrupted`.
  5. **Online snapshot:** online backups snapshot through a read-only connection (`backup.OpenReadOnly`, `VACUUM INTO`
     on `mode=ro`). They neither hold the store writer nor take the process lock.
  6. **Integrity checks:**
     - `backup verify` checks file hashes, `integrity_check`, schema version, KEK ID, chain links and segment hashes
       against the DB copy. It does not check chain MACs, which need the KEK; run `hallpass verify` after restore.
     - `manifest.sha256` detects accidental damage only. Malicious rewrites are caught by the DB cross-checks and by
       external anchors.
  7. **Not backed up:** `quarantine/` and the KEK. Both exclusions are documented.
  8. **Admin commands:** `admin bootstrap` is offline only.
- **Open follow-ups:**
  - the PLAN §18.16 "raise alert on next start after break-glass";
  - the scripted clean-container restore drill (HP-OPS-004);
  - the upgrade test from a previous-release fixture (HP-OPS-005);
  - RTO measurement (HP-DB-014);
  - Litestream compatibility (R-04, untested).

### ADR-0033 — Packaging and release pipeline details
- **Status:** accepted (WP24). Item 3 is a **security-relevant change** and is flagged for operator review.
- **Decision:**
  1. **Dockerfile location:** at the repository root, not `deploy/Dockerfile`.
  2. **Build:** scripted release (`scripts/release-build.sh`) instead of goreleaser. Archives are reproducible (byte-identical
     on rebuild of a frozen tree). The container image builds its own binary from source and has its own provenance
     attestation.
  3. **Trivy gate** (*security-relevant*): the release fails on **fixable** HIGH/CRITICAL findings. Unfixed
     HIGH/CRITICAL findings are reported by a non-blocking step. GOAL RG-2 requires "no HIGH/CRITICAL unfixed without a
     waiver", but the waiver mechanism (`.trivyignore` with justification and expiry) does not exist yet. Until it
     does, RG-2 evidence must be reviewed manually from the report.
  4. **Trivy scope:** Trivy runs in `release.yaml` only. Per-push and nightly scans in `ci.yaml` (HP-OPS-008) are a
     follow-up.
  5. **Publishing:** a pushed `v*` tag publishes the image to GHCR with SBOM and provenance, attests the binaries and
     creates a **draft** GitHub release that a human publishes. A tag push counts as an explicit human publishing
     action, consistent with ADR-0024. Agents never push tags.
  6. **Compose:**
     - interpolation uses `HP_*` variables, because the binary rejects unknown `HALLPASS_*` variables;
     - the KEK is a Compose secret at `/run/secrets/hallpass_kek`;
     - HTTP is published on loopback only.
  7. **Kubernetes:** Secret volumes cannot meet the KEK owner and mode checks. This is documented; Kubernetes is not a
     v1 target.
  8. **Release targets:** a `darwin/arm64` binary ships for development use (ADR-0022).
  9. **`docs/VERSIONING.md`** adds policy commitments that need operator sign-off:
     - an API v1/v2 overlap of at least one minor release;
     - a one-minor deprecation window for config keys;
     - upgrades supported only from the previous minor release;
     - security fixes for the latest minor release line only.
- **Not verified:** the release workflow has only been exercised locally (actionlint, docker build, smoke tests,
  Trivy, syft) and has not run on GitHub. `docker/login-action` v4.6.0 resolves to `dbcb8138…`.

### ADR-0034 — Observability implementation details
- **Status:** accepted (WP22). Not security-relevant.
- **Decision:**
  1. **Package naming:** tracing lives in `internal/obs/tracing` (PLAN named it `internal/obs/otel`). Metrics use a
     dedicated Prometheus registry in `internal/obs/metrics`, with typed, allowlisted label values: unknown values
     become `other`, and cardinality caps cover transaction names, routes, jobs and OIDC slugs. A nil `*Metrics`
     disables metrics everywhere.
  2. **Readiness semantics:** a `degraded` gateway answers `/readyz` with **200** by default, so operators can still
     reach it; `health.Options.DegradedStatusCode` can make it 503. `starting`, `failed` and `stopping` return 503.
     Public `/readyz` responses carry only short codes; error details appear only in development mode.
  3. **Storage reserve:** the reserve is the **larger** of `storage.min_free_bytes` and `storage.min_free_percent`.
     Below it, readiness degrades and new channels are refused at admission (HP-OPS-006).
  4. **Tracing:**
     - OTLP over HTTP only when `telemetry.otlp_endpoint` is set;
     - an exporter wrapper strips sensitive attributes;
     - inbound `traceparent` is ignored by default;
     - request IDs are always generated server-side.
  5. **Metrics endpoint:** with `telemetry.prometheus` and no `http.metrics_listen`, `/metrics` is served on the main
     HTTP listener. A separate `metrics_listen` (for example on loopback) is recommended in production.
  6. **Not implemented:** OTLP *metrics* export (Prometheus only), and copying the trace ID into audit-event
     correlation for SSH-originated events beyond the audit hook.

### ADR-0035 — Approval notifications: core design and chat-adapter details
- **Status:** accepted (WP16–WP18). Item 1 is a **security-relevant correction** of the threat model and is flagged
  for operator review.
- **Decision:**
  1. **Threat-model correction** (*security-relevant*). THREAT_MODEL T-05 claimed that forged callbacks still need
     "an authorized operator identity". That does not hold. With the Slack signing secret or the Telegram webhook
     secret, an attacker can claim any provider user ID, including a linked approver's. The remaining barriers are:
     - a valid, unused action token (Telegram shows button data to every chat member);
     - the decision checks for the claimed operator.
     The real mitigations are per-role `approval_channels` (web-only for sensitive roles) and the chat MFA requirement
     (R-10). T-05 has been updated to say this.
  2. **Single decision path:** web, Slack and Telegram decisions all call `access.Decide`, which checks role, approver
     scope, self-approval, request state, lockdown and duration bounds in the decision transaction (HP-NTF-008).
     Chat callbacks additionally require:
     - a linked operator (`provider_links`);
     - the chat MFA condition, which defaults on: local TOTP enrolled or a linked SSO identity;
     - a per-operator rate limit of 30 decisions/min.
  3. **Message rendering:** the request hook issues one hashed, single-use token per button (up to 5 approve
     durations + deny) and enqueues an outbox row that carries only token IDs and request IDs. The text is rendered
     at delivery time from the current request, so a request decided before delivery is not announced and reasons are
     not copied into extra storage. Updates edit delivered messages; an update waits for its original message and gives
     up if the original is dead.
  4. **Webhook paths and verification:**
     - webhooks are per integration: `/hooks/{slack|telegram}/{integration_id}` (PLAN named `/hooks/slack/interactions`);
     - no cookies; 20 requests/s per integration;
     - provider verification happens inside the adapters before parsing;
     - replay caches are durable (`webhook_replay`).
  5. **Adapter details:**
     - Button payload is `hp1:<a|d>:<token>`.
     - Telegram:
       - private chats are accepted for `/link`;
       - group chats must be route destinations or configured;
       - link codes posted in groups are burned;
       - rendering uses explicit entities and defangs `@` and `/` instead of a parse mode.
     - Chat text collapses newlines.
     - Status updates do not re-render the original message context.
  6. **Not externally verified:** the adapters are tested against fake Slack and Telegram API servers only. Verification
     against a real workspace and bot is pending and will be recorded as *externally verified* evidence when done.

### ADR-0036 — Retention, export and break-glass alert details
- **Status:** accepted. Not security-relevant: no requirement is relaxed.
- **Decision:**
  1. **Retention is configured, not managed through the API.** It is set by `recording.default_retention` plus
     `recording.retention_classes` entries (`class=duration`) that match a role's `retention_class`. Changes need host
     access and a restart, which is stricter than "administrator with recent authentication" (HP-RBAC-005). A retention
     API can be added later behind `retention.manage` with recent authentication.
  2. *(Export format superseded by ADR-0040.)* **Recording export:** `GET /access-sessions/{id}/export` (`recording.export`, recent authentication and MFA)
     returns every segment's decrypted records as JSON, limited to 64 MiB of payload (marked `truncated` beyond that),
     and is audited as `recording.exported`. Playback paging is a separate permission (`recording.play`) and is audited
     as `recording.played` (HP-REC-014, HP-RBAC-004).
  3. **Break-glass alert:** a `breakglass.used` audit event newer than the acknowledged sequence is logged as an error
     at every start and shown in the system status (`breakglass_alert`) until an administrator acknowledges it (`POST
     /system/breakglass-ack`, recent authentication and MFA; audited) (PLAN §18.16, HP-AUTH-016).
  4. **Audit sink:** `log.audit_file` appends every committed audit record as one JSON line (0600) for SIEM
     ingestion. The database hash chain stays authoritative (HP-OBS-005).

### ADR-0037 — Destination-side audit integration details (WP25)
- **Status:** accepted. **Security-relevant change** (operator review): it adds an ingest route that operator sessions
  do not protect, and narrows PLAN's correlation design.
- **Context:** PLAN WP25 proposed a `hallpass collector` subcommand that posts to `/api/v1/destaudit/ingest` and
  correlates through a `HALLPASS_SESSION` environment marker.
- **Decision:**
  1. **Ingest route.** Collectors post to `POST /hooks/destaudit/{collector_id}`, not under `/api/v1`. The route needs
     no operator session, CSRF token or idempotency key; the batch signature authenticates it.
     - Signature: Ed25519 over `"hallpass-destaudit-batch-v1\x00" || payload`, with the collector's enrolled key,
       verified before the payload is parsed.
     - Unknown collector, revoked collector and bad signature all return the same 401. Signature failures are logged
       but not audited, so unauthenticated traffic cannot grow the audit log.
     - Limits: 1 MiB bodies, strictly increasing per-collector sequence numbers (exact resends return the stored
       result; anything else gets 409), ±2 minute clock skew, records at most 24 h old, 500 records per batch.
     - Rate limit: 10 requests/s per collector ID, with a bounded key table.
  2. **Separate binary.** The collector ships as `cmd/hallpass-collector` (`keygen`, `pubkey`, `run`), not as a
     `hallpass` subcommand, so the gateway binary and its credentials never need to be installed on destinations.
  3. **No `HALLPASS_SESSION` marker.** The agent controls the environment it sends, so the marker would be forgeable.
     Correlation never uses collector-supplied session IDs:
     - *certificate logins (high confidence):* the certificate key ID `hallpass:<role>:<grant>:<conn>` is checked
       against the grant's server, role and remote user, the connection, and the session time window;
     - *managed-key logins (medium confidence):* fingerprint plus server and user, and exactly one session must have
       a channel using that credential at login time;
     - ambiguous matches are refused, and a destination login is bound to one session.
  4. **Sealed details.** Exec details (exe, argv, cwd) are sealed with the field key and kept out of timeline data.
     The timeline holds only metadata labeled `provenance: destination-audit`, `verified: false`, with correlation
     and confidence. Retention purges the sealed details through a trigger and leaves a tombstone.
  5. **Late records.** Records up to 24 h after the session ended are attached with `after_session_end` set: the
     signal for detached processes (HP-SES-004).
  6. **API.**
     - Registering a collector needs `credentials.manage` with recent authentication and MFA, because a collector
       can attach records to every session on its server. Revoking it needs recent authentication.
     - Listing collectors needs `inventory.read`, and record metadata needs `sessions.read`.
     - Decrypted record details need `recording.play` and are audited as `destaudit.record.read`, like playback
       (HP-REC-014).
- **Bug fixed alongside:** the Slack/Telegram webhook rate limiter kept one entry per path ID without bound, and
  unauthenticated requests choose that ID. Both webhook routes now use `internal/ratelimit.Window`, which prunes expired
  windows and sends unseen keys to a shared overflow window once its table is full.
- **Consequences:** HP-REC-012 is implemented and covered by unit and integration tests. The OpenSSH + auditd
  container test from PLAN WP25 does not exist yet, so the requirement stays partial.

### ADR-0038 — Browser E2E runs in Chromium only
- **Status:** accepted (operator decision, 2026-10-23). Changes HP-TST-004; not security-relevant (no security
  control, guarantee or default changes; only cross-browser test coverage is reduced).
- **Context:** HP-TST-004 required the Playwright E2E suite in Chromium and Firefox. The operator asked to use
  Chromium only and not install Playwright's Firefox build.
- **Decision:** the E2E suite (including axe accessibility checks) runs in Playwright's Chromium only, on every push.
  The `firefox` Playwright project and the nightly Firefox run are removed.
- **Consequences:** Firefox-specific rendering or behavior regressions in the operator UI are not caught by
  automated tests. The UI uses standard React, Ant Design and xterm.js, which support Firefox, but Firefox support is
  no longer verified. Reverting is adding the project back to `web/playwright.config.ts` and the nightly job.

### ADR-0039 — Wall-clock steps and enforcement
- **Status:** accepted. Not a weakening: it documents existing behavior under THREAT_MODEL assumption 6 (clocks are
  NTP-synchronized) and fixes a lost-revocation gap. Flagged for operator review because it states a limit of G-4.
- **Context:** WP26 fault test FI-21 showed that after a backward wall-clock step the enforcer's database safety
  net skipped grant, key and credential changes stamped earlier than rows it had already seen, so a revocation
  whose in-process event was lost was never enforced.
- **Decision:**
  1. Reconciliation cursors never exceed the current time. After a backward step, rows written since the step fall
     inside the 5 s overlap window. Until the clock catches up, changes from before the step are re-read on every
     pass; handling them is idempotent.
  2. Grant start, expiry and token windows stay wall-clock UTC, as specified. A backward step of N lengthens the real
     duration of active grants by N, and a forward step shortens them. HallPass does not use the monotonic clock for
     expiry, because grants must survive restarts and be comparable across components.
  3. Operators must run NTP with slewing (no large steps); `docs/operator/install.md` states the requirement.
- **Consequences:** G-4 holds with the documented clock assumption; under a backward step, the 5 s revocation
  bound holds even when the in-process event is lost (TestFI21).

### ADR-0040 — Recording export defaults to a ciphertext bundle (corrects ADR-0036 item 2)
- **Status:** accepted. **Security-relevant:** it restores a requirement. ADR-0036 item 2 made the only export a
  decrypted JSON download, which contradicted HP-REC-014 ("the default export is a ciphertext bundle") and was not
  flagged as a weakening. The WP20 frontend review found the contradiction.
- **Decision:** `GET /access-sessions/{id}/export` defaults to `format=bundle`: a tar with `manifest.json` (segment
  states, file SHA-256, header hash, frames digest, key ID) and the stored HPREC1 files, never decrypted. Reading
  them needs a HallPass keyring. `format=plaintext` keeps the decrypted JSON. Both formats need `recording.export`,
  recent authentication and MFA, and are audited as `recording.exported` with the format. The UI offers the bundle
  first and the decrypted export as a separate, warned action.
- **Consequences:** HP-REC-014 matches GOAL. ADR-0036 item 2 is superseded where it describes the export format.

### ADR-0041 — fail2ban-style SSH source bans (HP-SSH-026)
- **Status:** accepted (operator request, 2026-10-24). Adds a requirement and a protection; nothing is relaxed.
- **Context:** the agent SSH port is internet-facing in many deployments. Per-IP pre-auth limits (HP-SSH-013) bound
  concurrency, but a source can keep guessing keys indefinitely. The operator asked for fail2ban-style protection.
- **Decision:**
  1. A source is an IPv4 address or an IPv6 /64.
  2. Only connections whose authentication was attempted and failed count. Plain TCP connects and handshake errors
     don't, so load-balancer health checks can't be banned.
  3. `max_failures` within `window` bans the source for `duration`, doubled per prior ban in 7 days, capped at
     `max_duration`.
  4. Banned sources are closed right after accept, before the SSH banner (metric result `banned`).
  5. Bans are stored in `ssh_bans`, loaded at startup, audited as `ssh.source.banned` / `ssh.source.unbanned`, and
     listed and lifted through the API (`system.read` / `system.settings` + recent auth).
  6. `allow_cidrs` exempts sources. The failure table is bounded (65,536 sources), and rows are purged 30 days after
     expiry.
- **Consequences:**
  - Agents behind one NAT share a source, so a misconfigured agent can ban the others until the ban expires or an
    administrator lifts it. Operators should list such networks in `allow_cidrs`.
  - An attacker spoofing a victim's address cannot trigger a ban, because a TCP handshake is required.
  - Web login keeps its own per-account and per-IP progressive throttling (HP-AUTH-004).

### ADR-0042 — Operator authentication hardening from the internal review (SR-01, SR-03..07, SR-10, SR-11, SR-24..27, SR-30, SR-48)
- **Status:** accepted. **Security-relevant change:** it tightens defaults and changes some flows; one item (5) deviates
  from HP-API-006 replay semantics.
- **Decision:**
  1. **TOTP enrollment lifecycle (SR-01/03/04/27).**
     - The secret being enrolled lives in `mfa_totp_pending` (15 min TTL), separate from the confirmed factor. It is
       consumed exactly once and replaces the factor only on a successful confirm.
     - Enrollment never refreshes `auth_at`. A Limited session that had to enroll stays Limited and must verify a
       later code (`/auth/mfa`).
     - On a full session, adding a factor needs recent authentication; replacing one also needs MFA. The session
       rotates.
     - `VerifyMFA` is only for Limited password sessions. `ReauthTOTP` is only for SSO sessions whose provider allows
       `local_totp` step-up.
     - Second-factor checks share one throttle and are audited.
  2. **Break-glass redemption (SR-07, HP-AUTH-016).**
     - `POST /api/v1/auth/recover` plus the `/recover` page redeem the token from `hallpass admin recover`. The token
       is single use, expires after 30 min, is per-IP throttled, refused for disabled operators, and audited.
     - Redeeming revokes the account's other sessions and removes its second factor and recovery codes.
     - It issues a password-reset link when the account has a password. MFA must be re-enrolled when policy
       requires it.
  3. **SSO roles apply only to SSO sessions; deleting a provider strips its roles (SR-26).**
     - Operators with both a password and IdP-mapped roles get only their local roles on password sessions.
     - Provider deletion refuses to remove the last administrator.
  4. **SSO-only lockout guard (SR-06).** While SSO-only is on, role edits, disables and IdP group sync that would leave
     no SSO-capable administrator are refused or kept.
  5. **Secret-bearing idempotent responses (SR-11).** Operations that return one-time secrets (invitations, reset and link
     tokens, link codes, recovery, TOTP and recovery codes) store only the request hash. A replay with the same key
     gets 409 instead of the stored body, so secrets never sit in `api_idempotency`. The operation still never runs
     twice. *Deviation from HP-API-006 replay semantics, recorded for operator review.*
  6. **Role changes revoke sessions (SR-27)**, elevation included. An administrator who edits their own roles is
     signed out.
  7. **API limiter (SR-30).** IPv6 is keyed by /64 and the table is capped at 100k keys. When full, new
     unauthenticated keys fail closed; session and flood-guard keys fail open so signed-in operators keep working.
  8. **Self-service links need recent authentication (SR-10).** Chat link codes require recent auth plus MFA, and OIDC
     self-link requires recent auth. A password-only operator must enroll TOTP (or use SSO) before linking a chat
     account.
  9. **Redirects (SR-24, SR-48).** `return_to` values that path cleaning would change, including those with
     fragments, are refused. SSO test-login needs `auth.settings` and a full session.

### ADR-0043 — Recording integrity, confinement and key maintenance from the internal review (SR-02, SR-16..18, SR-36..39)
- **Status:** accepted. **Security-relevant change:** it strengthens verification; operators of databases created
  before migration 0019 must act once (item 1).
- **Decision:**
  1. **Verify binds the chain to the rows (SR-02).**
     - `hallpass verify` rebuilds every chain entry's manifest from the segment's current row and requires an entry
       for every finalized, interrupted or deleted row.
     - A separately MACed head record (`recording_chain_head`) catches removal of the newest entries. MACs are
       domain-separated HMAC-SHA-256 under the manifest key: `hallpass/rec/chain-head/v1|…`.
     - Databases from before 0019 report "head record missing" until an operator runs
       `hallpass verify --adopt-chain-head` (offline, audited). That command checks every link and MAC first;
       compare with exported anchors before adopting.
     - A key holder can still rewrite history after the last external anchor (unchanged, T-15).
  2. **Retention tombstones (SR-17).**
     - Deleting a segment writes an audited `recording.deleted` event and a MACed tombstone
       (`hallpass/rec/tombstone/v1|…`) in the same transaction.
     - Verify and anchors verify accept a deleted segment only with a matching tombstone.
     - Deletions from before 0019 show as `corrupt` once.
  3. **Confined segment paths (SR-16).**
     - Segment file locations are derived from validated IDs everywhere: reconcile, verify, replay, export,
       retention, rewrap, backup and restore.
     - The stored path is only compared, never opened. Backup refuses rows whose path is not their own location.
  4. **Tampered final files are quarantined (SR-38).** A final file that fails verification at startup is moved to
     `quarantine/`, its segment is marked `failed`, and it is never chained (refines PLAN §13.6).
  5. **Recording-key rewrap and slot repair are wired (SR-39).**
     - A 6-hourly `recording.rewrap` job moves segment keys to the active recording key.
     - Startup repairs damaged key slots after checking the header.
  6. **KEK rotation covers retired keys (SR-18).** The backup `kek_id` check ignores retired rows.
  7. **Token-key retirement is guarded (SR-36).** Lookups try every non-retired version. Retiring a version is
     refused while codes or tokens created before its successor are still usable.
  8. **Destination-audit details are re-sealed and covered by the retire guard (SR-37).**
- **Consequences:**
  - G-9 and HP-CRY-005 hold against keyless deletion, relabeling and truncation of finalized recordings.
  - The new MAC message formats are flagged for the R-02 external review.

### ADR-0044 — Access, policy, SSH and notification hardening from the internal review (SR-08..10, SR-12..15, SR-19..23, SR-28..34, SR-36, SR-40..45)
- **Status:** accepted. **Security-relevant change.** Most items tighten; items 6, 9, 10 and 13 record explicit
  acceptances.
- **Decision:**
  1. **Policy reconciliation (SR-12).** Every transaction that bumps the policy version publishes `policy.changed`, so
     group, label and limit changes reach the enforcer at once.
  2. **Revoked keys and disabled agents close SSH connections (SR-15).** The connection closes at once on the event, and
     a 2 s database re-check covers lost events. Creating a request re-checks the authenticating key.
  3. **Refusal audit limits (SR-20).** Refusal audits are limited per connection (10/min) and per agent (30/min), the
     excess is counted as `suppressed`, and a connection is closed after 64 refusals. This trades individual refusal
     rows for protection against audit flooding (T-22).
  4. **Source keying (SR-22, SR-44).**
     - Pre-auth limits and the auth-failure audit limit key by IPv4 address or IPv6 /64, with a /48 cap of 4× the
       per-IP limit.
     - Hosts sharing one /64 share one limit.
  5. **Chat links are removed on operator disable and on password set or reset (SR-10)**, by database triggers.
     Operators re-link afterwards.
  6. **Self-approval (SR-14, SR-32).**
     - Agent owners are set through `PUT /agents/{id}/owners` (`policy.write`, recent auth and MFA) and must be
       existing operators.
     - The ban (`/policy/self-approval`, default on) applies to approving only. Owners may still deny, cancel, revoke
       and terminate, which only withdraws access.
  7. **Reasons (SR-33, SR-29).** An omitted `require_reason` means true. Approvers read reasons only within their
     approver scope.
  8. **Decisions re-read the operator (SR-23).** Decide refuses missing or disabled operators and narrows roles and
     groups to those still assigned. Cancel and revoke narrow too, but internal non-operator actors keep their stated
     authority, because withdrawal cannot widen access.
  9. **Webhook and collector limits (SR-19, SR-40).**
     - Unknown IDs are excluded from per-ID budgets.
     - Limits: 40/s per source (IPv4 or /64), 5/s per provider user, and a shared 20/s for unknown collector IDs.
     - Residual, accepted: an attacker who knows an integration ID and controls several sources can exhaust its
       budget. This is denial of service only, and notification failure never changes a request (HP-NTF-010).
     - Behind a reverse proxy without `trusted_proxies`, the per-source limit becomes one global budget.
  10. **Telegram allowlist semantics (SR-42).**
      - Button presses are accepted only from route chats or configured extra chats.
      - Users are not filtered by a separate allowlist: every decision requires an explicit provider link to an
        enabled operator plus all decision checks.
      - Recorded against HP-NTF-006 as written.
  11. **Destination algorithm floor (SR-45).**
      - Newly enrolled host keys and CAs need RSA ≥ 3072. SHA-1 CA signatures are refused. RSA login keys sign with
        SHA-2 only.
      - Destinations with only RSA-2048 host keys or OpenSSH before 7.2 can no longer be enrolled.
  12. **Address confidentiality in the audit API (SR-08, SR-28).**
      - Audit details redact addresses, ports, host-CA principals and raw dial errors for callers without
        `inventory.address.read`.
      - Host-key alerts audit the address-free classification.
      - `remote_user` stays visible (operator review: THREAT_MODEL AS-9 and ADR-0031 differ).
  13. **Accepted (SR-34).** Policy rules may name groups not in use yet: write-policy-first and lazily created IdP
      groups need this, and group assignment is itself privileged and audited. The UI should warn on unknown group
      names.
  14. **Live-event streams (SR-09, SR-31).** Streams re-validate without refreshing the session's idle timer, close at
      idle or absolute expiry, and are capped at 16 per operator.

### ADR-0045 — Apache-2.0 license, backdated to the first commit
- **Status:** accepted (operator decision, 2026-10-24). Resolves R-01. Not security-relevant.
- **Decision:**
  - HallPass is licensed under Apache-2.0. `LICENSE` holds the canonical text, unmodified. `NOTICE` holds the
    copyright line.
  - At the operator's request, history was rewritten (`git filter-branch --index-filter`) so that `LICENSE` exists
    in every commit from the first one. Trees, authors, author and committer dates and messages are otherwise
    unchanged.
  - Docs that cite commit hashes were updated to the new hashes. The full old→new map was kept in
    `docs/evidence/history-rewrite-2026-10-24.txt` until ADR-0050 removed it; it remains in git history
    (`git show b298d76:docs/evidence/history-rewrite-2026-10-24.txt`).
  - The pre-rewrite history is kept locally as the branch `backup/pre-license-rewrite`.
- **Deviation:** HP-OPS-011 says no license file is added before the decision. Backdating deliberately puts `LICENSE`
  into commits that predate the decision; the operator requested exactly that.
- **Consequences:**
  - The rewritten `main` must be force-pushed (operator action).
  - Clones made before the rewrite must re-clone or reset.
  - AGENTS.md's "no license" rule is replaced by "do not change the license without an operator decision".

### ADR-0046 — Release 0.1.0 with known limitations; publish images to Docker Hub

- **Status:** accepted (operator decision, 2026-10-24). Not a requirement change; flagged for operator review because
  it removes the "pre-release, not production-ready" wording from user-facing docs.
- **Context:** the operator asked to drop the pre-release notices, prepare release docs and publish container images
  to Docker Hub as `aurimasniekis/hallpass`. RG-1, RG-5 and RG-6 do not pass (docs/evidence/v0.1.0/release-gates.md).
- **Decision:**
  - The first release is **0.1.0**, a pre-1.0 version under GOAL.md §8 ("pre-1.0 release candidates may ship with
    explicit known-gaps notes"). It is not called stable or production-ready anywhere.
  - The "pre-release" banners in README, site and install docs are replaced by a version note plus a short, factual
    known-limitations list: no external crypto review (R-02 label, unchanged), no 24 h soak or reference-hardware
    benchmarks, Slack/Telegram tested against recorded APIs only, Chromium-only E2E without visual snapshots.
  - The release workflow pushes one multi-arch manifest to `docker.io/aurimasniekis/hallpass` (primary in docs) and
    `ghcr.io/aurimasniekis/go-hallpass` (mirror), with a build provenance attestation in each registry. Docker Hub
    needs the `DOCKERHUB_TOKEN` secret; without it the publish job fails before pushing.
  - A tag without a matching CHANGELOG section fails the release; the draft release notes are that section.
  - The release procedure is docs/RELEASING.md. Release evidence lives in `docs/evidence/vX.Y.Z/`.
- **Open before tagging (operator):** R-08 (name/trademark check) and R-15 (versioning commitments) are marked as
  blocking a public release and are not resolved by this ADR. Both were resolved by operator decision on 2026-10-25,
  before the v0.1.0 tag.

### ADR-0047 — Git remotes: plain git through the gateway, repository and ref rules, metadata-only recording

- **Status:** accepted (operator decision, 2026-10-24). **Security-relevant change** (git operations are not recorded
  as byte streams); flagged for operator review.
- **Context:** the operator asked for agents to push and pull with git through HallPass, with request/approval,
  limits on which repositories (patterns such as `acme/{api,web}`) and which refs, on a page separate from servers.
- **Decision:**
  - A git remote is a server with `kind = git` (fixed at creation). Its roles are access profiles with the
    capabilities `git-read` and/or `git-write` (never shell/exec/pty) and `git` rules: repository patterns and push
    rules (allowed branches, protected branches, tag patterns, branch deletion). Policy rules, requests, approvals
    and grants work unchanged.
  - Agents use plain git with the gateway as the SSH host (`git clone center:github/acme/api.git`). The gateway
    recognizes `git-upload-pack`, `git-receive-pack` and `git-upload-archive` before its own grammar, validates the
    path (safe segments only, no `..`), chooses the profile covering the repository and operation (active grant, then
    auto-approve, then requestable), requests access and waits like `connect`, and runs the service on the git host
    with the profile's credential. A hidden remote, an unknown repository and a forbidden operation give one answer.
  - For a push, the ref-update commands are read and checked before anything is sent to the host; any refused ref
    ends the session, so the host never sees the push. Signed pushes are refused.
  - **Recording:** git channels record metadata only (service, repository, every ref update with old and new object
    IDs, refusals, bytes transferred) in the session timeline and the channel row. Pack data is not recorded: it is the
    repository content, which the host keeps. This deviates from mandatory byte-stream recording for this channel type.
  - Only `GIT_PROTOCOL` is forwarded from the agent's environment.
- **Force-push:** unless a profile sets `allow_force_push`, every update of an existing branch must be proven a
  fast-forward. HallPass reads the pushed pack as it streams to the host (commits, including commits deltified against
  pack objects), computes their object IDs and follows parent links from the new tip to the old one. The pack's final
  checksum is withheld until the proof succeeds; otherwise the session ends, the host rejects the truncated pack and
  no ref changes. An update it cannot prove from the pushed commits (for example moving a branch to a commit the host
  already has) is refused rather than guessed.
- **Limits:** multi-approver requests are a separate follow-up. Host-side branch protection remains a good second
  layer.

### ADR-0048 — Requests that need several approvers

- **Status:** accepted (operator request, 2026-10-24). Not security-relevant in the weakening sense: it only adds a
  stricter option.
- **Decision:** a role (SSH role or git access profile) has `approvals_required` (1–5, default 1). Each approval is
  checked exactly like a single approval (approver rule, self-approval, channel, policy, duration) and recorded in
  `request_approvals`; one operator approves at most once. The request stays pending until the required number of
  distinct approvers is reached; the last approval writes the decision and creates the grant with the shortest
  duration any approver chose. Any one authorized denial ends the request. Policy auto-approval never applies to a
  role that needs more than one approver. The web API answers a partial approval with 202 and the pending request;
  chat buttons stay usable for the other approvers.

### ADR-0049 — File transfer (SFTP and scp) as a separately authorized capability

- **Status:** accepted (operator request, 2026-10-24). **Security-relevant change:** it relaxes HP-SSH-007 ("all
  subsystems are rejected") and the v1 non-goal "no SFTP/SCP subsystems" for roles that opt in, and file contents
  are not recorded as byte streams. Flagged for operator review. Resolves R-06.
- **Context:** agents need to copy build artifacts and configuration to and from servers. Through a shell they can
  already do so (`cat > file`), but without any record of which files moved. The operator asked for a separate
  capability that records file operations.
- **Decision:**
  - A new role capability `file-transfer`, for SSH roles only (never for git remotes), not in the default set. A
    role may have it alone, so it can transfer files without shell or exec.
  - The gateway serves the `sftp` subsystem and nothing else; every other subsystem is still refused and audited.
    The legacy scp protocol (`scp -O`, an exec of `scp -t`/`scp -f`) is refused with a hint, because its stream
    cannot be followed per file. Current OpenSSH scp uses SFTP by default.
  - SFTP carries no target, so the SSH user name selects it: `web1@gateway` or `web1+deploy@gateway`. The user name
    is used only for routing, like the command text; the agent's identity is still only its key (HP-SSH-002).
  - Role choice: the named role, else the roles with `file-transfer` the agent may use, ranked active grant,
    auto-approve, requestable, then by alias. Access is reused or requested and awaited like `connect`. A role that
    requires a reason fails with a message telling the agent to `request … --reason … --wait` first.
  - The destination channel is an exec-kind channel without PTY or forwarded environment; grant expiry, revocation,
    concurrency limits, idle timeout and lockdown apply unchanged.
- **Recording:** the gateway follows the SFTP v3 packets in both directions without changing them and records one
  timeline event per completed operation (`file.operation`: read or write with bytes and SHA-256 when the transfer
  was sequential from offset 0, list, remove, rename, mkdir, rmdir, setstat, symlink, hardlink, failures with the
  server's message) and a summary (`file.summary`). Paths have control characters replaced and are bounded to 4096
  bytes; at most 5000 operations per session are listed, the rest are counted. A packet over 1 MiB ends the channel.
  File contents are not stored.
- **Not provided:** HallPass does not restrict paths. The destination account decides what can be read or written;
  the docs recommend a dedicated account, optionally with `ForceCommand internal-sftp` and `ChrootDirectory`. No
  digest is recorded for non-sequential transfers (resumed or parallel).

### ADR-0050 — Planning documents trimmed after delivery

- **Status:** accepted (operator request, 2026-10-24). Not security-relevant: no requirement, guarantee or default
  changes.
- **Decision:** with all work packages delivered, the build-time material is removed from the working tree:
  `docs/PROMPT.md` (the verbatim original brief), PLAN.md §19.1 (per-package plans) and §19.3 (progress log), the
  stale review-item summary in PLAN.md §20.2 (DECISIONS.md §2 is the list) and the duplicated commit workflow in PLAN.md
  §22.2 (AGENTS.md is the source), and the history-rewrite hash map. The status table is now PLAN.md §19.1. GOAL.md,
  DECISIONS.md, THREAT_MODEL.md, TEST_STRATEGY.md, the acceptance checklist (PLAN.md §21) and the release evidence stay.
- **Consequences:** the removed text is in git history (`git show b298d76:<path>`). GOAL.md no longer names a source
  brief.

### ADR-0051 — Disabling and soft-deleting servers and roles

- **Status:** accepted (operator request, 2026-10-24). Not security-relevant: nothing is relaxed. Deleting ends access
  like disabling (HP-SRV-008) and additionally revokes login keys.
- **Context:** servers, git remotes, roles and access profiles could not be deleted, and disabling them was implemented
  in the service but not reachable: `enabled` in a `PATCH` was ignored and the console had no control.
- **Decision:** `POST /servers/{id}/disable|enable` and `POST /roles/{id}/disable|enable`, and `PATCH` applies
  `enabled`. `DELETE /servers/{id}` and `DELETE /roles/{id}` (recent authentication) soft-delete: the row is disabled,
  marked `deleted_at`/`deleted_by`, grants are revoked and pending requests canceled through the disable hook, login
  keys are revoked, and the alias is replaced by a tombstone (`~<id>`, never a valid alias) with the former name in
  `deleted_alias`, so the name can be reused. Deleting a server deletes its roles. Deleted rows are left out of lists
  and the policy snapshot, refuse every change, and remain readable by ID (and `GET /servers?include_deleted=true`) so
  sessions, recordings and the audit log keep naming them. Deleting a server needs typed confirmation (HP-UI-010).
- **Alternatives:** hard delete (breaks the foreign keys from grants, sessions and recordings, and loses names in
  history); a rebuilt table with a partial unique index instead of the alias tombstone (a risky rebuild of tables many
  others reference).
- **Consequences:** policy rules that select roles by name match a new role with a reused name; rules that select by ID
  keep pointing at the deleted one and match nothing. A deletion cannot be undone.
- **Agents (added 2026-10-24, migration 0026):** `DELETE /agents/{id}` (recent authentication; the console needs the
  name typed) works the same way: the agent is disabled through its disable hooks, every key is revoked, the name
  becomes a tombstone with the former name in `deleted_name`, and `GET /agents?include_deleted=true` names it in
  history. Revoked keys stay globally unique tombstones (HP-AGT-003), so a recreated agent needs a new key.

### ADR-0052 — API tokens for automation (security-relevant change)

- **Status:** accepted (operator request, 2026-10-24). **Security-relevant change, flagged for operator review.**
- **Context:** a Terraform provider and scripts need non-interactive access to the API. Until now the API accepted only
  browser sessions, with CSRF, Origin checks and step-up (HP-AUTH-013, HP-AUTH-014).
- **Decision:**
  - `hallpass_at_<43 base64url chars>` bearer tokens (32 random bytes), stored only as an HMAC under the keyring token
    key, shown once, with a mandatory expiry of 1–366 days, last-used time and address, and revocation. Issuing and
    revoking need `operators.manage`; issuing also needs recent authentication and MFA (`createAPIToken` is `x-reauth`
    and `x-mfa`, and its idempotent replay never repeats the token).
  - A token acts for its creator with one role the creator held when issuing it, and only while the creator is enabled
    and still holds that role. Tokens cannot issue tokens.
  - Tokens work only on operations marked `x-token` in the API document: reads within the role (including the
    operator list, so approver rules can name operators), and configuration changes (agents, inventory, credentials,
    policy, SSO, integrations). Decisions, cancellations, grant revocation, activity termination, recording content and
    export, changes to operators, tokens, `/me`, `auth`, the event stream and lockdown stay browser-only.
  - **Relaxations:** token requests skip the Origin and CSRF checks (no ambient credential) and **skip recent
    authentication and MFA** on the `x-token` operations that normally require them (HP-AUTH-014), because issuing the
    token required both.
  - Audit events of token requests are attributed to the creating operator with `via: api_token:<id>` in the details,
    so the existing actor types and the hash-chained audit table are unchanged.
- **Alternatives:** per-operation step-up for tokens (unusable for automation); a separate service-account principal
  (decouples tokens from an accountable person and needs its own role assignment).
- **Consequences:** a leaked token can change configuration until it expires or is revoked (THREAT_MODEL T-23), for
  example add an agent key or widen a rule, but cannot approve the resulting requests.

### ADR-0053 — API tokens without expiry (security-relevant change)

- **Status:** accepted (operator request, 2026-10-25). **Security-relevant change, flagged for operator review.**
- **Context:** ADR-0052 requires every API token to expire within 366 days. For the operator's own Terraform and
  break-glass automation that is a recurring outage: when the token lapses, automation stops, usually when nobody is
  watching the date. Porch made the same exception for its installation owners (its ADR-0046).
- **Decision:**
  - `createAPIToken` accepts `never_expires: true` instead of `expires_in_days` (sending both is invalid). The console
    offers it as a **Never expires** switch with a warning.
  - Such a token stores a far-future `expires_at` (9999-12-31), so every expiry comparison is unchanged, and
    `never_expires = 1`. The API omits `expires_at` and returns `never_expires: true`; the token list shows "Never".
  - Everything else from ADR-0052 holds: issuing needs `operators.manage` (administrators), recent authentication and
    MFA; tokens cannot issue tokens; the token acts for its creator with one role and stops when it is revoked, when the
    creator is disabled or loses the role; only `x-token` operations; last-used time and address are recorded.
  - `api_token.created` audits `never_expires: true` instead of `expires_in`.
- **Alternatives:** longer maximum expiry (still lapses unattended); automatic renewal (needs a credential that can mint
  tokens, which ADR-0052 rules out).
- **Consequences:** **security-relevant relaxation of ADR-0052's mandatory expiry.** A leaked token without expiry stays
  valid until someone revokes it or its creator is disabled or loses the role (THREAT_MODEL T-23). Operators should
  store it like a root password, watch its last-used time and address, and revoke it when it is no longer needed.

### ADR-0054 — Scheduled backups to S3-compatible object storage (security-relevant change)

- **Status:** accepted (operator request, 2026-10-25). **Security-relevant change, flagged for operator review:** a new
  outbound channel carries every backup off the host, and a new sealed format (HPBAK1) has not been externally
  reviewed (R-02).
- **Context:** backups were a CLI command the operator had to schedule and ship elsewhere. Operators asked for built-in
  backups to object storage.
- **Decision:**
  - One target (`backup_target`), configured in the console, the API (`/api/v1/system/backups/*`, `system.settings`
    with recent authentication and MFA, usable by API tokens) and Terraform. The secret access key is sealed with the
    credential key (resealed by the keyring job) and write-only.
  - A small S3 client in `internal/s3client` (Signature Version 4 with the standard library's HMAC-SHA256; verified
    against the AWS documentation examples and against a real S3 server) instead of an SDK dependency. TLS is always
    verified, there is no proxy and no redirect following, and private networks are refused at connect time unless
    `allow_private_network` is set, like OIDC. `http://` endpoints only in development mode.
  - Each run is the consistent backup of `hallpass backup create`: the database snapshot and the manifest are sealed as
    HPBAK1 objects (docs/formats/hpbak1.md) with a fresh data key wrapped by the KEK, because keyring purpose keys
    live inside the database being protected. Segments are uploaded as stored (HPREC1 ciphertext), once, and reused
    until their data key is rewrapped. The manifest is uploaded last and marks a complete backup.
  - Retention keeps the newest `keep_last` backups plus the newest of each of `keep_daily_days` days. A segment object
    is deleted only when no kept backup was taken while the segment existed (`backup_remote_segments` records the
    first backup that included it and the first that no longer did).
  - Restore on a new host: `hallpass backup remote-list` / `remote-download` with the bucket details as flags, the
    standard `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` variables and the KEK, producing an ordinary backup
    directory for `backup verify` and `restore`.
  - Runs, results and errors are kept in `backup_runs`. Failures and configuration changes are audited; successful
    scheduled runs are not, so the audit chain does not grow by one entry per hour.
- **Alternatives:** the AWS SDK or minio-go (large dependency trees for five requests); age encryption (a new crypto
  dependency, and a second key the operator must keep); encrypting the snapshot with a keyring purpose key (stored
  inside the snapshot itself); uploading full copies of every recording each run (cost grows with retention).
- **Consequences:** the bucket holds only ciphertext, but object keys and sizes reveal session and segment IDs, counts
  and timing (THREAT_MODEL T-24). Someone with the access key can delete or withhold backups (availability) or make an
  older backup look like the newest (rollback); they cannot read or forge one without the KEK. Losing the KEK still
  loses every backup. The database snapshot must stay under 5 GiB (single-request upload).

### ADR-0055 — Web terminals for administrators (security-relevant change)

- **Status:** accepted (operator request, 2026-10-25). **Security-relevant change, flagged for operator review:**
  administrators open shells without a request or approver.
- **Context:** operators asked to reach a server from the console instead of an SSH client of their own. The operator
  chose direct access for administrators (no approval), on by default with a configuration switch, and the audit log as
  the only record besides the recording (no chat notification).
- **Decision:**
  - `POST /api/v1/terminals` (permission `terminal.open`: administrators, only while `console.terminal` is true;
    recent authentication and MFA; no API tokens) creates an ordinary request → decision → grant → access session in
    one transaction: the operator's own approval in the web channel, `terminal.opened` audited. The role must be
    enabled with `shell` and `pty`; the duration is a preset up to the role maximum and the global ceiling; lockdown
    and disabled servers or roles refuse it.
  - The grant's agent is a built-in agent (`agt_00000000000000000000000000`) created disabled and already deleted with
    its only key revoked, so it never authenticates over SSH and appears in no list or policy. `operator_id` on the
    request, the grant and the connection names the administrator. Agent policy rules do not apply
    (`Snapshot.EvaluateConsole`); policy reconciliation leaves these grants alone.
  - The browser connects to `GET /api/v1/terminals/{id}/stream` (a WebSocket over the same origin and web session,
    with a single-use ticket valid for one minute). The socket is adapted to an SSH channel and run through the same
    data plane as agent sessions: mandatory recording before forwarding, destination host-key pinning, the role's
    login credential, enforcer termination on expiry or revocation, idle timeout. Closing the socket revokes the
    grant (`terminal_closed`).
  - Every channel open re-reads the operator; a sweep every 2 s revokes terminals of operators who were disabled or
    lost the administrator role (`operator_ineligible`). At most 8 live terminals per operator.
  - The terminal renders destination output with the replay hardening (no links, OSC 52/8/0–2 swallowed).
- **Alternatives:** web terminals through the normal request and approval flow (the operator preferred direct
  access); a separate session model for operators (duplicates recording, replay and enforcement); a per-operator hidden
  agent (more rows to hide everywhere).
- **Consequences:** an administrator session (or a stolen one that passes step-up) can open a shell on any enabled
  server role without a second person. It is recorded and audited, and `console.terminal: false` removes the
  capability. Approvers are not notified (THREAT_MODEL T-25).

### ADR-0056 — Default sign-in provider

- **Status:** accepted (operator request, 2026-10-25). Not a security-relevant change: it changes which page the
  browser sees first, not who can sign in or how.
- **Context:** installations that sign in through one identity provider asked for the sign-in page to go there
  directly, as Porch does, with a separate URL for email and password.
- **Decision:**
  - The setting `auth.direct_provider` holds a provider ID (so renaming the slug keeps it). The API exposes it as the
    slug `direct_provider` on `GET/PUT /api/v1/settings/auth` (same permission, recent authentication and MFA as the
    other sign-in settings; audited as `auth.direct_provider.changed`) and on the public `GET /api/v1/auth/config`. A
    `PUT` without the field leaves it unchanged, so older Terraform providers do not clear it. Only an enabled provider
    can be chosen; a disabled or deleted one stops being the default.
  - `/login` starts the normal OIDC login flow (`purpose=login`, same state, nonce, PKCE and binding cookie) for that
    provider. `/login/password` shows every sign-in method and never redirects.
  - The page does not redirect after an SSO error (`sso_error`), while a limited session is pending, before bootstrap,
    or after a sign-out in that tab (a sessionStorage marker set on sign-out and cleared once a session is back). This
    prevents a sign-out from signing straight back in through the provider session.
- **Alternatives:** a `?all=1` query parameter on `/login` (the operator asked for a separate URL); a server-side
  redirect of `/login` (the page needs the error and signed-out state that only the browser has); changing the
  post-logout redirect URI to carry a flag (registered URIs at providers would break).
- **Consequences:** password login and the other providers are unchanged and stay reachable at `/login/password`. A
  session that expires sends the browser through the provider again, which signs in silently while the provider
  session lasts.

### ADR-0057 — Publish audit and session events to Pulse (security-relevant change)

- **Status:** accepted (operator request, 2026-10-26). **Security-relevant change, flagged for operator review:** a new
  outbound channel carries audit metadata and session lifecycle events off the host in plaintext (to the operator's
  Pulse). Off by default.
- **Context:** the operator's other services (Porch) publish their events to Pulse, an event bus on NATS JetStream, and
  the operator asked HallPass to publish everything it decides to send in the same way.
- **Decision:**
  - `events.pulse` in the configuration file (`enabled`, `url`, `creds_file`, `ca_file`, `source`), mirroring Porch.
    Production requires `tls://`. Authentication is the Pulse client `.creds` file; HallPass only publishes.
  - A transactional outbox (`event_outbox`, migration 0030) written in the transaction of the change, only while
    publishing is enabled. A relay (`internal/events`) publishes with the go-pulse SDK, waits for the JetStream
    acknowledgement, uses the source event's ID as `Nats-Msg-Id` (JetStream deduplicates a re-publish after a crash),
    retries with capped exponential backoff (1 s to 5 min, ±50 % jitter) and dead-letters after 50 attempts or
    24 hours, like Porch. One failure ends the round, so an outage does not time out on every row. Rows are deleted
    7 days after they were written.
  - Every audit event is published as `evt.hallpass.<action>` with the record the audit file sink receives
    (`log.audit_file`), never the sealed sensitive details. Session lifecycle events from the timeline
    (connections, channels, exec, git, file-transfer summaries, recording failures, session closed) are published as
    `evt.hallpass.session.<event>` with the grant's agent, server and role; their data already excludes command text
    and content. Request and grant timeline events are not published again, single file operations and destination
    audit records are not published.
  - CloudEvents type `hallpass.<name>.v1`; the subject grammar of Pulse (four or more `[a-z0-9_-]` tokens) is enforced
    when the event is recorded.
- **Alternatives:** publishing from the audit chain with a cursor (session events have no global sequence, and two
  sources would need two cursors); the notification outbox (encrypted bodies, per-attempt history rows and 8 attempts
  are built for chat messages, not a high-volume feed); an HTTP webhook (no deduplication or replay, and the operator
  already runs Pulse); replaying history when publishing is first enabled (could flood Pulse with years of audit
  events; the audit log stays the complete record).
- **Consequences:** whoever can subscribe to `evt.hallpass.>` sees what the audit file contains, including operator and
  agent source IP addresses and plaintext audit details (THREAT_MODEL T-26). A Pulse outage longer than 24 hours loses
  events from the feed, not from HallPass. Each audit event and published session event costs one more row in its
  write transaction while publishing is enabled. New dependencies: go-pulse and nats.go (plus nats-server in tests).

### ADR-0058 — API tokens for any role, issued by administrator tokens (security-relevant change)

- **Status:** accepted (operator request, 2026-10-26). **Security-relevant change, flagged for operator review:** it
  relaxes ADR-0052's "a token carries one of its creator's roles" and "tokens cannot issue tokens".
- **Context:** the operator wants Terraform to manage API tokens, starting with a read-only (Auditor) token for an
  integration. Under ADR-0052 a person had to hold Auditor to mint it, and only in the console, while Terraform's own
  token is an Administrator token that could not issue tokens.
- **Decision:**
  - An administrator may issue a token with **any** role, because the administrator role holds every permission of
    every other role (`rbac.New`). A token then works while its creator is enabled and holds its role **or**
    administrator. Other operators still choose one of their own roles.
  - `createAPIToken`, `revokeAPIToken` and a new `getAPIToken` are `x-token`. Since they need `operators.manage`, only
    administrator tokens can use them, without recent authentication or MFA (as ADR-0052 for the other `x-token`
    operations).
  - A token issued by a token records `parent_token_id` (migration 0031). The parent sees and revokes only its own
    children (others answer 404); `listAPITokens` stays console-only. Revoking a token revokes its children in the same
    transaction, each audited. A child cannot issue tokens, so the chain is at most one level deep.
  - `api_token.created` from a token names the parent (`via: api_token:<id>`, `parent_token_id`).
- **Alternatives:** service-account operators without console login (a new principal with its own role assignment and
  UI; can be added later, and a token issued by Terraform already acts for an accountable administrator); limiting
  token-issued tokens to non-administrator roles (little gain once ADR-0059 lets an administrator token create
  administrator operators).
- **Consequences:** a leaked administrator token can mint further tokens; revoking it revokes them too, and they all
  stop when the creating administrator is disabled. A token for a role the creator does not hold no longer depends on
  that role assignment, only on the creator staying administrator.

### ADR-0059 — Operator management with API tokens, and a read-only egress endpoint (security-relevant change)

- **Status:** accepted (operator decision, 2026-10-26: "full operator management"). **Security-relevant change,
  flagged for operator review:** privilege changes no longer need a person with recent authentication and MFA.
- **Context:** the operator wants operators, their roles, single sign-on identities and chat accounts declared in
  Terraform. ADR-0052 kept operator changes console-only.
- **Decision:**
  - `createOperator`, `updateOperator` (manual roles, operator groups, enabled), `list/link/unlinkOperatorIdentity`
    and `list/link/unlinkOperatorProvider` (chat accounts) are `x-token`. They need `operators.manage`
    (administrator tokens) and skip recent authentication and MFA. Every change is audited under the token's operator
    with `via: api_token:<id>`. The last-administrator and SSO-administrator guards apply unchanged.
  - A token cannot change the roles, groups or enabled state of the operator it acts for, so automation cannot lock
    out or re-shape the account its token depends on. It may link SSO identities and chat accounts to that operator.
  - Invitations, password-reset and link-invite tokens, operator sessions and break-glass stay console-only.
  - `GET /api/v1/system/egress` (`inventory.address.read`, `x-token`) shows `egress.allow_cidrs`,
    `egress.allow_special_cidrs` and `egress.source_addresses` read-only. **They stay in the configuration file:**
    the egress allow list is the guard against a compromised administrator session or token aiming a server at internal
    or metadata addresses (THREAT_MODEL T-19), so it is neither managed through the API nor derived from servers.
- **Alternatives:** non-administrator role assignments only (the operator chose full management); an API-managed
  egress list within a configuration ceiling (no gain over setting the configuration range to the destination
  subnets).
- **Consequences:** **a leaked administrator token can now take over access approval**: create an administrator or
  approver operator, link an attacker's SSO identity or chat account to it (or to an existing approver), and approve
  requests as that operator. ADR-0052's "a leaked token cannot approve the resulting requests" no longer holds for
  administrator tokens. Keep Terraform's token in a secret manager, watch its last use, prefer non-administrator tokens
  for everything that only reads, and review `operator.*` audit events with `via: api_token:*`.

### ADR-0060 — API targets: HTTPS APIs through a credential-injecting proxy (security-relevant change)

- **Status:** accepted (operator request, 2026-10-27: agents need GitHub, Cloudflare and Google Cloud APIs without
  holding the operator's tokens, and only when approved). **Security-relevant change, flagged for operator review:**
  it relaxes HP-SSH-007 (one kind of `direct-tcpip` forward is accepted), HallPass terminates TLS for third-party API
  hosts with its own CAs, and API calls are recorded as metadata rather than byte streams.
- **Context:** agents run `gh`, `wrangler`, `gcloud` and `curl` against public APIs. Handing them a token gives
  unlimited, unrecorded use for the token's lifetime. A base-URL override (for example `GH_HOST`) works only for
  some tools and some APIs, so the proxy works at the HTTP layer and every tool that honors `HTTPS_PROXY` works.
- **Decision:**
  - An **API target** is a server with `kind = api` and `api.hosts` (exact names or `*.domain` wildcards, never IP
    addresses, port 443 only). Its roles are access profiles with the `api` capability and `api.rules`: allow/deny
    rules on method, host, path (segment globs, `*`, `**`, `{a,b}`) and, for GraphQL endpoints, operation type. A
    matching deny wins, no match is refused, matching is case-insensitive, an escaped `/` stays inside its segment and
    dot segments are refused. GraphQL requests are classified from the document (every operation counts, whatever
    `operationName` says); unparsable, persisted or oversized (> 1 MiB) bodies are "unknown", which allow rules with
    GraphQL types never match and deny rules always do. Policy rules, requests, approvals, auto-approval and grants
    work unchanged.
  - Each profile has one **credential** (`bearer`, `header`, `basic`, or a `google_service_account` key from which
    HallPass mints short-lived access tokens at `https://oauth2.googleapis.com/token`). It is sealed with the keyring's
    credential key, write-only in the API, destroyed when the profile is deleted, and never sent to agents, shown, or
    written to logs, audit details or timeline events.
  - **Transport:** the agent opens an SSH local forward to the name `hallpass` (`ssh -fN -L 18080:hallpass:443
    <gateway>`); the gateway accepts `direct-tcpip` channels to that name only (when `api_proxy.enabled`, the default)
    and refuses and audits every other forward as before. The agent's identity is the SSH connection's key; no new
    secret exists. Each channel carries one HTTP `CONNECT`; the host must belong to an API target visible to the
    agent, otherwise 403 before TLS.
  - **TLS:** each target has its own ECDSA P-256 CA (sealed private key), path length 0, critical name constraints
    permitting only the target's hosts and excluding all IP addresses, so an agent that trusts it lets HallPass
    intercept that API and nothing else. It is replaced when the hosts change. Agents fetch the bundle of the targets
    visible to them with `ssh <gateway> api ca` or `api env`. Leaves (7 days) are minted in memory.
  - **Per request:** the profile is the first (active grant, then auto-approve, then requestable; then alias) whose
    rules allow it. The grant is re-read for every request. An auto-approve profile gets its grant on first use; a
    requestable one answers 403 with the exact `request` command. The agent's `Authorization`, `Cookie`,
    `Proxy-Authorization`, the credential's header and forwarding headers are removed, the credential is added and the
    request goes to the host through a separate **public-only egress guard** (`api_proxy.allow_cidrs`, default all;
    private, shared, benchmarking and special ranges denied unless `api_proxy.allow_special_cidrs`), with system
    roots verifying the API's certificate, no environment proxy and no redirect following. Protocol upgrades
    (WebSocket) are refused.
  - **Recording:** each tunnel opens one channel per grant it uses (concurrency limits apply; the enforcer ends the
    tunnel on expiry, revocation, lockdown or policy change). Every request, forwarded or refused under a grant, is an
    `api.request` timeline event with method, host, path, query (values of token-, key-, secret-, signature-,
    code-like parameters redacted), status, sizes, duration, profile, deciding rule and GraphQL operation types.
    Headers and bodies are **not** recorded. Refusals without a grant are rate-limited audit events
    (`api.connect.denied`, `api.request.denied`).
  - Refusals are JSON that `gh` (`message`), Cloudflare tools (`errors`) and Google tools (`error.message`) all show,
    with `X-Hallpass-Error`.
  - **`hallpass-api` (operator request, 2026-10-27):** an agent-side wrapper shipped in the release archives runs one
    tool with the tunnel (system `ssh`), the CA bundle and the proxy variables set for that process only. A local
    pass-through proxy adds `Hallpass-Command`, `Hallpass-Reason` and `Hallpass-Invocation` headers to each CONNECT
    (outside TLS; base64url, sanitized and bounded to 1000 characters). The command is recorded on the tunnel's
    channel and every `api.request` event. When a call needs a requestable profile and the wrapper sent a reason (or
    the profile needs none), the proxy files the request itself with the reason followed by `Command (reported by the
    agent): …` and answers 403 `approval_pending` with `X-Hallpass-Request`; `api requests <invocation>` lists what it
    filed (in memory, per agent, one hour). The wrapper waits with `status --wait` and runs the command again once
    approved. The command is the agent's claim and is labeled so; it never widens access. Values of secret-looking
    options are redacted by the wrapper before reporting.
- **Alternatives:** a short-lived token broker (GitHub App installation tokens, Cloudflare tokens with expiry, GCP
  impersonation) gives the agent a real, if scoped, token and records only issuance — possible later for APIs where
  interception is impractical; base-URL overrides (`GH_HOST`, `CLOUDFLARE_API_BASE_URL`) need no CA but cover few
  tools and need per-API path mapping; a plain HTTP proxy listener would need a new bearer secret for agents.
- **Consequences:** HallPass holds long-lived API tokens and can read every API response it forwards: it is now also a
  plaintext-capable component for those APIs (THREAT_MODEL T-27). HallPass limits **which** calls are made and
  records them, but not what an allowed call does; the token's own scopes remain the real limit, so profiles should
  use least-privilege tokens. Agents must trust the target CAs (`SSL_CERT_FILE` and friends, or the macOS keychain).
  A leaked target CA key lets its holder intercept only that target's hosts, for agents that trust it.

## 2. Open review items (operator decisions required)

| ID | Item | Proposal | Blocks |
|---|---|---|---|
| R-01 | **License** for the open-source release. | **Resolved 2026-10-24 (operator decision): Apache-2.0.** LICENSE (canonical text) and NOTICE added; history rewritten so LICENSE exists from the first commit (ADR-0045). | Resolved |
| R-02 | **External cryptographic review** of HPREC1, HPBAK1 (ADR-0054), the keyring and field encryption. | **Operator decision 2026-10-24:** no external review for now; releases use the RG-9 alternative and are labeled "recording format and keyring not externally reviewed" in CHANGELOG and release notes. A review remains recommended before 1.0. | RG-9 |
| R-03 | **KMS/Vault/HSM backend** in v1 (`KeyWrapper`, `Signer`). | Ship interfaces plus local implementation in v1. Add Vault Transit/AWS KMS wrappers post-1.0 unless required. | — |
| R-04 | **Litestream** as optional continuous DB replication for backup. | Document as optional and test compatibility (WAL, checkpoints) in WP23. Not a supported HA mode. | — |
| R-05 | **Default global grant-duration ceiling.** | 24 h (matches the largest preset). Roles default to a 6 h max and a 30 m default. | — |
| R-06 | **SFTP/SCP subsystem** as a separately authorized capability. | **Resolved 2026-10-24 (operator request):** the `file-transfer` capability serves SFTP (and scp over SFTP) with per-file metadata recording (ADR-0049, security-relevant). | Resolved |
| R-07 | **Log schema**: ECS-aligned names vs a custom namespace. | ECS-aligned core fields plus a `hallpass.*` namespace. | WP02 |
| R-08 | **Trademark/name/domain check** for "HallPass". | **Resolved 2026-10-25 (operator decision):** the operator accepted the name for the public 0.1.0 release. No trademark search was done by the agents. | Resolved |
| R-09 | **Self-approval default.** | Prohibited by default for agent owners. Configurable. | WP08 |
| R-10 | **Chat approvals for privileged roles.** | Allowed by default, with a per-role `approval_channels` restriction (e.g. web-only for `administrator`-class roles), and optionally require that the approver completed web MFA within N hours. | WP16 |
| R-11 | **CSP for CSS-in-JS** (Ant Design). | Try nonce or static extraction in WP19. Otherwise accept `style-src 'unsafe-inline'` with strict `script-src`. | WP19 |
| R-12 | **Breached-password check** (offline k-anonymity list). | Not in v1. Revisit for local-auth-heavy deployments. | — |
| R-13 | **`restore --force`** moves existing data aside instead of refusing (ADR-0032 item 2, security-relevant). | Keep: explicit, non-destructive, lock + KEK required. | — |
| R-14 | **Trivy unfixed-findings waiver** (ADR-0033 item 3, security-relevant). | Add `.trivyignore` with per-finding justification and expiry before 1.0; until then manual review. | RG-2 |
| R-15 | **Versioning policy commitments** in docs/VERSIONING.md (ADR-0033 item 9). | **Resolved 2026-10-25 (operator decision):** accepted as written. | Resolved |
| R-16 | **Built-in reverse-tunnel connector** for destinations behind NAT (operator request). | Today: Tailscale, WireGuard or reverse SSH tunnels (docs/operator/remote-networks.md). Proposal: a `hallpass-connector` that dials out over mutually authenticated TLS or SSH with an enrolled Ed25519 identity, is bound to an explicit set of servers, carries only TCP to those servers' port 22 (host keys still pinned end to end), and has every stream audited. Needs operator approval of scope before implementation. | Before 1.0 or later |
