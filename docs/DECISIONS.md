# Hallpass — Architectural Decisions

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
- **Context:** Hallpass needs gateway-controlled login credentials that agents never see, with safe rotation.
- **Decision:** Default: a distinct Ed25519 key per server-role binding, generated in Hallpass, sealed at rest, with the public key shown as a
  `restrict,from="<egress>"` authorized_keys line. Rotation `pending → probe → active → retiring → retired`, with immediate revocation.
  Alternative: a Hallpass user CA signing per-connection certificates (TTL 120 s, explicit principals, minimal extensions) behind a `Signer`
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
    PKCE, and a Hallpass key set built on `go-jose/v4`. go-oidc's remote key set refetches on every unknown `kid`; HP-OIDC-004
    requires rate limiting (one refetch per 10 s, cached keys stay usable during outages). The key set accepts only RSA
    ≥ 2048 bits, ECDSA P-256 and Ed25519 keys.
  - **Clock skew:** go-oidc checks `exp` without leeway. Hallpass verifies with the clock shifted back 60 s, which gives
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
  - **Deviation:** the Keycloak/Dex interop smoke tests (PLAN WP14 tests, nightly CI) are not implemented yet. They are
    tracked as an open item and are not claimed as done.

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

## 2. Open review items (operator decisions required)

| ID | Item | Proposal | Blocks |
|---|---|---|---|
| R-01 | **License** for the future open-source release. | No proposal is made without authorization. Candidates to evaluate: Apache-2.0, MPL-2.0, AGPL-3.0. No LICENSE file until decided. | Public release (RG-11) |
| R-02 | **External cryptographic review** of HPREC1, the keyring and field encryption. | Engage a reviewer before 1.0. If not done, release notes must say so (RG-9). | RG-9 |
| R-03 | **KMS/Vault/HSM backend** in v1 (`KeyWrapper`, `Signer`). | Ship interfaces plus local implementation in v1. Add Vault Transit/AWS KMS wrappers post-1.0 unless required. | — |
| R-04 | **Litestream** as optional continuous DB replication for backup. | Document as optional and test compatibility (WAL, checkpoints) in WP23. Not a supported HA mode. | — |
| R-05 | **Default global grant-duration ceiling.** | 24 h (matches the largest preset). Roles default to a 6 h max and a 30 m default. | — |
| R-06 | **SFTP/SCP subsystem** as a separately authorized capability. | Out of v1. A future design needs a separate capability, recording of file metadata and policy. | — |
| R-07 | **Log schema**: ECS-aligned names vs a custom namespace. | ECS-aligned core fields plus a `hallpass.*` namespace. | WP02 |
| R-08 | **Trademark/name/domain check** for "Hallpass". | Not verified. The operator should check before public release. | Public release |
| R-09 | **Self-approval default.** | Prohibited by default for agent owners. Configurable. | WP08 |
| R-10 | **Chat approvals for privileged roles.** | Allowed by default, with a per-role `approval_channels` restriction (e.g. web-only for `administrator`-class roles), and optionally require that the approver completed web MFA within N hours. | WP16 |
| R-11 | **CSP for CSS-in-JS** (Ant Design). | Try nonce or static extraction in WP19. Otherwise accept `style-src 'unsafe-inline'` with strict `script-src`. | WP19 |
| R-12 | **Breached-password check** (offline k-anonymity list). | Not in v1. Revisit for local-auth-heavy deployments. | — |
| R-13 | **`restore --force`** moves existing data aside instead of refusing (ADR-0032 item 2, security-relevant). | Keep: explicit, non-destructive, lock + KEK required. | — |
| R-14 | **Trivy unfixed-findings waiver** (ADR-0033 item 3, security-relevant). | Add `.trivyignore` with per-finding justification and expiry before 1.0; until then manual review. | RG-2 |
| R-15 | **Versioning policy commitments** in docs/VERSIONING.md (ADR-0033 item 9). | Accept as written. | Public release |
