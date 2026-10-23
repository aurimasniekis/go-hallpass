# Hallpass — Implementation Plan

> **Status:** active execution plan. Created at WP00 on 2026-10-23.
> The product contract is `docs/GOAL.md`, and when the two disagree, GOAL.md wins. Fix this plan to match and record the change in DECISIONS.md.
> Decisions: `docs/DECISIONS.md` · Threats: `docs/THREAT_MODEL.md` · Tests: `docs/TEST_STRATEGY.md` · Brief: `docs/PROMPT.md`.
> Progress lives in §19.2 (work-package status) and §21 (acceptance checklist). Keep both current.

Contents: 1 Summary · 2 Requirements · 3 Architecture · 4 SQLite · 5 Domain/state machines · 6 Schema · 7 SSH grammar ·
8 API/SSE · 9 Policy · 10 Approvals · 11 Key lifecycle · 12 Operator auth/RBAC · 13 Recording format/consistency ·
14 UI · 15 Repository layout · 16 Threat model · 17 Tests/release gates · 18 Operations · 19 Work packages ·
20 Risks/review items · 21 Acceptance checklist · 22 Docs and commit workflow

---

## 1. Summary and assumptions

Hallpass is a single Go binary (`hallpass`) that runs a terminating SSH gateway for AI agents, an operator web console
and REST API, approval integrations (web/Slack/Telegram), and an encrypted recorder. State lives in a local SQLite
database. High-volume session content lives in encrypted segment files. Exactly one process owns a data
directory at a time. The design is a **modular monolith**: internal packages with explicit interfaces, one process,
no external infrastructure required beyond a filesystem and a KEK source.

**Firm decisions** are recorded as ADRs in DECISIONS.md (ADR-0001 to ADR-0024). **Proposals needing review** are listed as
R-01 to R-12 in DECISIONS.md §2 and summarized in §20 here.

### 1.1 Assumptions

| # | Assumption | Consequence if false |
|---|---|---|
| A-1 | Repository `aurimasniekis/go-hallpass` was empty at WP00, so there are no existing conventions to preserve. | n/a (verified at WP00). |
| A-2 | Latest stable Go (1.27.3 at WP01, per user instruction 2026-10-23). `go.mod` declares `go 1.27.3`, and the toolchain auto-downloads where older. Bump to new stable releases as they ship. | Older distro toolchains are not supported; use the official toolchain or the container build. |
| A-3 | Node 24 LTS + pnpm (via corepack) for the frontend. | Adjust in WP19. |
| A-4 | Destinations run OpenSSH `sshd` ≥ 8.2 on POSIX systems with a POSIX-compatible login shell. | Windows/other sshd are unsupported in v1. |
| A-5 | Deployments are Linux (amd64/arm64) on local block storage (ext4/xfs/btrfs/zfs). macOS is supported for development only. | Storage checks (HP-DB-007) are Linux-specific. |
| A-6 | Hallpass's web UI sits behind HTTPS, either native TLS or a TLS-terminating reverse proxy with configured `trusted_proxies`. | Production config refuses an HTTP-only public base URL. |
| A-7 | Expected scale for v1 design: ≤ 1,000 agents, ≤ 2,000 servers, ≤ 500 concurrently active channels per instance. | Larger scale needs new measurements, not claims. |
| A-8 | Operators can provision a KEK file/secret on the host and back it up separately. | Without it, production mode will not start (by design). |
| A-9 | Slack and Telegram are reachable from the gateway for outbound API calls, and the gateway's webhook endpoints are reachable from them (or the integration stays disabled). | Approvals fall back to web. |
| A-10 | Agents use OpenSSH-compatible clients. Examples assume `~/.ssh/config` host alias `center`. | Other clients must honor the documented grammar. |

---

## 2. Canonical requirements

The canonical list (239 requirements, stable IDs `HP-<AREA>-NNN`) is in `docs/GOAL.md` §6. Areas:
SSH (front end and data plane), AGT (agents), SRV (servers/roles/host identity), KEY (login credentials/signing),
POL (policy), REQ (requests), GRT (grants/enforcement), SES (access sessions), REC (events/recording), CRY (crypto/keys),
DB (SQLite), AUTH (operator auth/sessions), OIDC, RBAC, API, UI, NTF (approvals/notifications), OPS, OBS, TST, DOC.
Each requirement maps to exactly one owning work package (§19) and to test layers (TEST_STRATEGY.md §2).

---

## 3. Architecture and trust boundaries

### 3.1 Component view

```
                         ┌──────────────────────────── hallpass (single process) ──────────────────────────────┐
 Agent (ssh) ──TB-1────▶ │ sshfront ─▶ grammar ─▶ access (requests/grants/sessions) ◀─▶ policy (snapshots)     │
                         │    │                       │        ▲                                               │
                         │    ▼                       ▼        │ decisions                                     │
                         │ sshproxy ──▶ credentials ──┘   notify (web/slack/telegram) ◀──TB-4── Slack/Telegram │
 Destination sshd ◀─TB-2─│    │  (egress guard, hostkey verify)    │ outbox (jobs)                             │
                         │    ▼                                    ▼                                           │
                         │ recording (HPREC1 writer/reader) ── keyring (KEK→purpose keys) ◀──TB-7── KEK file   │
                         │    │                                    ▲                                           │
                         │    ▼                                    │                                           │
                         │ store (SQLite writer + readers) ─ audit ─ jobs/scheduler ─ enforcer ─ eventbus      │
                         │    ▲                                                                                │
 Operator browser ─TB-3─▶│ httpapi (REST /api/v1, SSE, embedded UI) ─ opauth (local) ─ oidc ──TB-5──▶ IdP      │
                         │ obs (slog, OTel, /metrics, /healthz, /readyz)                                       │
                         └───────────────▲─────────────────────────────────────────────────────────────────────┘
 Host admin (CLI: bootstrap, recover, backup, restore, verify, keys) ──TB-8── data dir (0700) ──TB-6
```

### 3.2 Internal interfaces (firm)

| Interface | Package | Purpose |
|---|---|---|
| `store.Writer` / `store.Reader` | `internal/store` | Typed sqlc queries. `Writer.Tx(ctx, func(q *db.Queries) error)` runs `BEGIN IMMEDIATE` with bounded retry. It has no network I/O inside. |
| `keyring.Keyring` | `internal/keyring` | `Seal/Open(purpose, aad, plaintext)`, `WrapDEK/UnwrapDEK`, `ActiveKeyID(purpose)`. Backed by `KeyWrapper` (local KEK in v1). |
| `keyring.KeyWrapper` | `internal/keyring` | `Wrap/Unwrap(keyID, dek)`. Implementations: `localkek` (v1) and `kms`/`vault` (R-03). |
| `credentials.Signer` | `internal/credentials` | `PublicKey()`, `Sign(rand, data)` for login keys and CAs. v1: `sealedKeySigner`. |
| `policy.Snapshot` | `internal/policy` | Immutable compiled policy at a `policy_version`: `Visible`, `Level`, `Explain`, `Approvers`. |
| `access.Service` | `internal/access` | `CreateRequest`, `Decide`, `Cancel`, `FindActiveGrant`, `RegisterChannel`, `CloseChannel`, `Revoke`. Every state transition goes through it. |
| `access.Enforcer` | `internal/access` | Registry of live channels by grant. Terminates them on events, the 1 s ticker and DB reconciliation. |
| `recording.Recorder` | `internal/recording` | `OpenSegment`, `Append(record)` (blocking with bounded queue), `Finalize`, `Fail`. |
| `notify.Provider` | `internal/notify` | `Deliver(ctx, msg)`, `HandleCallback(r)`. Providers: web (in-app), slack, telegram. |
| `eventbus.Bus` | `internal/eventbus` | In-process typed pub/sub with bounded subscriber queues. Used to cut latency only, never as the durability mechanism. |
| `egress.Guard` | `internal/egress` | `Resolve(ctx, host, port) (netip.AddrPort, error)` enforcing the egress CIDR policy. |

### 3.3 Trust boundaries

| TB | Boundary | Authentication | Primary controls |
|---|---|---|---|
| TB-1 | Agent → gateway SSH | Agent public key | Algorithm policy, pre-auth limits, uniform errors, grammar without shell, policy + grant checks. |
| TB-2 | Gateway → destination SSH | Gateway login credential; destination host key | Strict host verification, egress guard, per-binding credentials, deadline enforcement. |
| TB-3 | Browser → web/API | Server session cookie (+ MFA, recent auth) | CSRF, CSP, RBAC, rate limits, no optimistic security UI. |
| TB-4 | Slack/Telegram → webhooks | Provider signature/secret token | HMAC/timestamp/replay, allowlists, action tokens, identity mapping, transactional decision. |
| TB-5 | Gateway → OIDC IdP | TLS + ID token signature | Discovery validation, PKCE/state/nonce, claim checks, JWKS rotation. |
| TB-6 | Gateway → filesystem | OS permissions | 0700/0600, flock, local FS only, fsync protocol, AEAD on content. |
| TB-7 | Gateway → KEK source | OS permissions / secret mount | KEK outside data dir, 0400, refuse-start-if-missing, separate backup. |
| TB-8 | Host admin → CLI | Shell access on the host + KEK | Break-glass only offline with lock and KEK, audited. |

### 3.4 Process lifecycle

`hallpass serve` startup order. Each step fails closed with an actionable error.

1. Parse and validate config (mode `production` by default). Reject dev-only settings in production.
2. Check data dir: exists, owned by the process user, mode `0700`, local filesystem (Linux `statfs`).
3. Acquire `flock(LOCK_EX|LOCK_NB)` on `<data>/hallpass.lock`. Failure → exit "another process owns this data directory".
4. Load KEK (file/env/mount). Missing in production → exit. Check KEK file mode `0400`/`0600` and that it lives outside the data dir.
5. Open SQLite. Apply pragmas, run `PRAGMA quick_check`, check schema version (refuse if newer than the binary), take a `VACUUM INTO`
   snapshot if migrations are pending, then run migrations.
6. Load keyring purpose keys (unwrap), the gateway host key and policy snapshot.
7. Run reconciliation (§13.6): mark interrupted connections/channels, reconcile segments, expire due grants/requests.
8. Start jobs (outbox, expiry, retention, maintenance), the enforcer, the event bus and the SSE hub.
9. Start the HTTP listener (API/UI/hooks/metrics/health), then the SSH listener. Set `/readyz` ready.

Shutdown (SIGTERM): `/readyz` → not ready. Stop accepting SSH and HTTP. Write `hallpass: gateway shutting down` to
agent channels (stderr/PTY). Drain up to `shutdown.drain_timeout` (30 s). Close channels with exit 80. Finalize
segments, flush the outbox state, close the DB (WAL checkpoint `TRUNCATE`) and release the lock.

---

## 4. SQLite deployment and recovery design

### 4.1 Driver and build (ADR-0002)

- `modernc.org/sqlite` (pure Go, a translation of the C SQLite). Build with `CGO_ENABLED=0`, which gives static binaries, easy
  multi-arch builds and a distroless image. Trade-off: roughly 1.5–3× slower than CGO `mattn/go-sqlite3` on write-heavy
  benchmarks, which is acceptable because high-volume payloads go to files (§13). This is re-measured in WP03 benchmarks.
- `database/sql` with two `*sql.DB` handles on the same file:
  - **writer**: `SetMaxOpenConns(1)`, `SetMaxIdleConns(1)`, `SetConnMaxLifetime(0)`. All writes go through
    `Writer.Tx`, which issues `BEGIN IMMEDIATE`, so write locks are taken up front and lock-upgrade deadlocks are avoided.
  - **readers**: `SetMaxOpenConns(max(4, GOMAXPROCS))`, with `PRAGMA query_only=ON`.
- DSN pragmas (applied by the driver on **every** new connection, via `_pragma=`):
  `journal_mode(WAL)`, `synchronous(FULL)`, `foreign_keys(ON)`, `busy_timeout(5000)`, `trusted_schema(OFF)`,
  `cache_size(-32000)`, `temp_store(MEMORY)`. Startup asserts each pragma on every pooled connection
  (HP-DB-002) by checking out `MaxOpenConns` connections concurrently.
- `synchronous=FULL` in WAL mode makes every commit durable across power loss. `NORMAL` would risk losing the last
  commits, which audit trails must not do. Measured cost is accepted because writes are low-volume metadata.
- WAL maintenance: `wal_autocheckpoint=1000` pages (default), plus a maintenance job every 5 min running
  `PRAGMA wal_checkpoint(TRUNCATE)` when no long reader is active. WAL size is exported as a metric (HP-DB-011).
- `auto_vacuum=INCREMENTAL` is set at creation (migration 0001), with `PRAGMA incremental_vacuum(N)` after retention runs.

### 4.2 Transactions and contention

- **Rule:** a write transaction never spans network I/O, SSH traffic, approval waits, file fsyncs, or calls into
  `notify`/`sshproxy`/`recording`. This is enforced structurally: `Writer.Tx` callbacks receive only `*db.Queries` and a clock,
  and a `go vet`-style analyzer (WP01 `tools/analyzers/txscope`) flags calls to banned packages inside `Tx` closures.
- Tx duration histogram; tests fail if any Tx exceeds 100 ms (HP-DB-004).
- Busy handling: `busy_timeout=5000` covers reader/checkpoint interplay. On `SQLITE_BUSY`/`SQLITE_LOCKED` the writer retries
  with full-jitter backoff (10 ms base, 5 attempts, 1 s cap), then returns `ErrStorageBusy`, which maps to readiness
  degradation if sustained > 30 s.
- Writer queue: callers block on the single writer with context deadlines. Queue depth and wait time are exported as metrics.
- High-frequency writes (sequence reservation, heartbeats) are batched. Terminal data never goes to SQLite.

### 4.3 Migrations (HP-DB-005)

- `pressly/goose/v3` with embedded `internal/store/migrations/NNNN_name.sql`, one goose transaction per migration.
  Forward-only. Down migrations are not shipped (rollback = restore snapshot, §18.5).
- Run only under the process flock (step 3 of §3.4), so a second process cannot migrate concurrently.
- Before applying pending migrations: `VACUUM INTO '<data>/backups/pre-migrate-<from>-<to>-<ts>.db'`, fsync, record
  the path in the log. Keep the last 3 (configurable).
- Failure: the failing migration's transaction rolls back, leaving the DB at the prior version. The process exits non-zero with
  the snapshot path. If corruption is suspected, the operator can restore the snapshot.
- Schema newer than the binary → refuse to start (no downgrade).
- `sqlc` generates typed queries from `internal/store/queries/*.sql` against the migrated schema. CI checks that `sqlc diff` is clean.

### 4.4 Topology, failover and recovery

- **Supported:** exactly one active `hallpass serve` per data directory on local storage. Active-active, shared-DB
  and NFS/SMB-hosted DBs are unsupported and refused where detectable (HP-DB-006, HP-DB-007).
- **Prevention of concurrent owners:** `flock` on `hallpass.lock` (works across containers that share the volume on the same host).
  Admin CLIs that mutate state (`restore`, `admin recover`, `keys rotate-kek`, `migrate`) take the same lock and
  therefore require the server to be stopped. Read-only CLIs (`verify --offline`, `backup`) use a read-only DB connection and
  `VACUUM INTO`, which is safe alongside the server. `backup` is also exposed online via the admin API.
- **Failover model:** cold standby. On host loss, provision a new host, provide the KEK, `hallpass restore <backup>`,
  start, and repoint DNS/VIP for SSH and HTTPS. Agents see the same gateway host key, because it is restored from the
  encrypted DB and needs no re-pinning.
- **Recovery objectives:** RPO = 0 for committed transactions on process/OS crash (`synchronous=FULL`). Recording
  RPO ≤ 250 ms in `group` mode, 0 in `strict` mode (§13.5). Host-loss RPO = backup interval (recommended hourly DB
  snapshot plus continuous segment sync, R-04 Litestream optional). RTO target ≤ 15 min on the reference hardware for a
  10 GiB data set, verified in the WP23 drill (HP-DB-014).
- **Established SSH sessions cannot migrate:** SSH transport keys, sequence numbers, channel windows and the
  destination-side session all live in the gateway process memory and its TCP connections. A new process cannot
  resume them. After failover agents reconnect, and active grants remain valid until expiry because grants are DB state.
- **State surviving restart:** all DB state (agents, inventory, policy, requests, grants, sessions, audit, outbox, jobs),
  finalized and interrupted segments, keyring. **Lost on restart:** live SSH connections and channels (reconciled as
  `interrupted`), in-memory rate-limit counters (conservatively re-initialized), and the SSE replay ring (clients get `reset`).

### 4.5 Failure behavior

| Condition | Behavior |
|---|---|
| Disk full (`SQLITE_FULL`, `ENOSPC` on segments) | Fail closed: reject new channels/requests with exit 80 and `storage_unavailable`. Terminate mandatory-recording channels whose writer fails. Readiness `degraded`. Alert. Reserve-space check refuses new sessions below `storage.min_free` (default 2 GiB or 5%). |
| I/O error (`SQLITE_IOERR`, `EIO`) | Same as disk full. Repeated errors → readiness `failed`. Operator must investigate. No automatic retry loops that could corrupt state. |
| Corruption (`SQLITE_CORRUPT`, `quick_check` failure) | At startup: refuse to start, print restore guidance. At runtime: stop accepting writes, readiness `failed`, alert. |
| Abrupt shutdown / crash | SQLite WAL recovery on next open. Startup reconciliation (§13.6). Outbox/jobs resume with leases. |
| Busy beyond retries | Request-level error `storage_busy` (exit 80 for agents, 503 for API). Sustained → degraded readiness. |
| KEK missing/wrong | Refuse to start. A wrong KEK is detected by failing to unwrap the keyring canary. |

### 4.6 Permissions (HP-DB-010)

Process `umask 0077`. Data dir `0700` and all files `0600`. The KEK file is `0400`, owned by the service user, outside the data dir.
Startup refuses data dirs or KEK files readable by group or others. The container runs as UID 65532 (distroless nonroot).

### 4.7 Database growth (HP-DB-011)

SQLite stores metadata only: one row per request, decision, grant, session, connection, channel and segment; lifecycle
timeline events (≈ 10–30 per channel); audit events; outbox. Terminal I/O, exec strings and other payloads go to
segments. Retention (§18.7) deletes expired rows in batches of 500 per transaction. Estimated growth is about 2–5 KiB per
channel plus audit. Capacity guidance comes in WP22 from measurements.

### 4.8 Metadata in SQLite and confidentiality (ADR-0003)

Stock SQLite has no encryption. SQLCipher would require CGO, which conflicts with ADR-0002, so it is not used. Instead:

- **Encrypted columns** (AES-256-GCM via keyring `field`/`credential`/`token` purposes, AAD = `table|column|row_id|key_id`):
  request reasons, decision comments, revocation reasons (free text), TOTP secrets, OIDC client secrets, Slack/Telegram bot
  tokens and signing secrets, login private keys, CA private keys, gateway host private key, SMTP password.
- **Hashed** (HMAC-SHA-256 with the `token` key, or SHA-256 for 256-bit random values): session IDs, CSRF secrets,
  action tokens, invitation/reset/setup/recovery tokens, link codes.
- **Plaintext metadata**, documented as such: IDs, names, aliases, descriptions, labels, groups, destination addresses and ports,
  usernames, key fingerprints and public keys, timestamps, states, policy rules, operator emails/display names, IP
  addresses of agents and operators, counts, durations, segment sizes and hashes, audit actions/targets.
- **Implication:** anyone with read access to the DB file learns the inventory topology, who accessed what and when, and
  the policy. They do not learn reasons, credentials or session content. Full-disk encryption of the data volume is the
  recommended baseline, and backups must be stored with equivalent protection.

---

## 5. Domain model and state machines

### 5.1 Entities

```
Agent 1─* AgentKey                     Server 1─* HostIdentity        Server 1─* ServerRole 1─1 LoginBinding ─▶ LoginCredential | UserCA
Agent *─* Group(kind=agent)            Server *─* Group(kind=server)  ServerRole *─ labels
Agent *─* Operator (owners)            HostCA ─* HostCABinding(server)

AccessRequest 1─0..1 ApprovalDecision 1─0..1 Grant 1─1 AccessSession 1─* SshConnection 1─* SshChannel 1─* RecordingSegment
AccessSession 1─* TimelineEvent        AuditEvent (global, hash-chained)    OutboxMessage 1─* DeliveryAttempt
Operator 1─* OperatorIdentity(local|oidc) · 1─* OperatorRoleAssignment · 1─* WebSession · 1─* ProviderLink(slack|telegram)
```

IDs are type-prefixed lowercase Crockford base32 encodings of UUIDv7: `agt_`, `key_`, `srv_`, `hid_`, `rol_`, `cred_`, `ca_`,
`pol_`, `apr_`, `req_`, `dec_`, `grt_`, `ses_`, `con_`, `chn_`, `seg_`, `evt_`, `aud_`, `opr_`, `wss_`, `obx_`, `job_` (ADR-0010).
Timestamps are `INTEGER` Unix microseconds UTC.

### 5.2 Access request

```
            create (dedup per agent+server+role)
                 │
                 ▼
             ┌────────┐ approve (Decide tx) ┌──────────┐
             │pending │────────────────────▶│ approved │──▶ Grant(active)+AccessSession created in same tx
             └────────┘                     └──────────┘
              │  │  │ deny                  ┌────────┐
              │  │  └──────────────────────▶│ denied │
              │  │ expires_at ≤ now (sweep/decision-time check)   ┌─────────┐
              │  └───────────────────────────────────────────────▶│ expired │
              │ cancel (agent/operator) | policy_changed | target/agent disabled | lockdown   ┌──────────┐
              └──────────────────────────────────────────────────────────────────────────────▶│ canceled │
```

All transitions use `UPDATE … SET state=? WHERE id=? AND state='pending'` and require `rows_affected = 1`. Otherwise the
caller re-reads and returns `conflict` with the current state (HP-REQ-001, HP-GRT-007). Cancel reasons:
`agent`, `operator`, `policy_changed`, `agent_disabled`, `target_disabled`, `lockdown`.

### 5.3 Grant

```
 active ──expires_at ≤ now──▶ expired
   │
   └──revoke(operator | policy_changed | agent_disabled | key_revoked* | target_disabled | credential_revoked | lockdown)──▶ revoked
```

`*key_revoked` revokes only when the agent has no other active key. Otherwise only connections authenticated with that key are terminated.
Expiry is *time-authoritative*: a grant whose `expires_at ≤ now` is treated as expired by every check even before the
sweep updates its state. The sweep (1 s ticker) records the `expired` transition and timeline event.

### 5.4 Access session (1:1 with grant, ADR-0007)

`open` (created with grant) → `closing` (grant no longer active, channels still terminating) → `closed`
(`close_reason` = `expired|revoked|…`). Approving a new request after expiry creates a new grant and a new session (HP-GRT-010).

### 5.5 Connection and channel

Connection: `open` → `closed` (`client_closed|idle_timeout|grant_ended|shutdown|error`) or `interrupted` (reconciled after crash).
A connection is created at authentication, before any grant is known, so `access_session_id` is nullable. Connections
used only for `list`/`status` never attach to a session. A connection attaches to sessions through its channels.

Channel: `opening` (registered in tx, concurrency slot reserved) → `active` (destination channel open, recording ready) →
`closed` (`exit_status|exit_signal|eof|grant_ended|recording_failed|dest_error|client_closed|shutdown`) or
`failed` (never became active) or `interrupted`.

### 5.6 Channel establishment sequence (HP-SSH-025, HP-GRT-006, HP-REC-007)

1. Agent channel request (`exec`/`shell`) → grammar → target resolution via current policy snapshot (read only).
2. Find the active grant (§9.6 selection). None → request flow (§7.6).
3. **Writer tx `RegisterChannel`:** re-read grant (`state='active' AND expires_at > now`). Check agent, key, server, role,
   credential and host identity enabled/active, lockdown off, and current `policy_version` permits ≥ `requestable` (snapshot
   for that version; if the cached snapshot is older, reload outside the tx and retry). Count `opening|active` channels for
   role/agent limits. Insert channel `opening`. Insert segment row `open`. Reserve a sequence block. Commit.
4. Outside tx: create segment file, write and fsync header plus key block, fsync dir (mandatory recording prerequisite).
5. Resolve destination via egress guard. Dial with credential and strict host verification. Open the destination session channel
   and replay allowed `pty-req`/`env`, then `exec`/`shell`.
6. Register with the enforcer: if the enforcer has already seen a terminal event for this grant (revocation committed
   after step 3), terminate immediately. Write tx: channel → `active`, timeline `channel.opened`.
7. Forward data. On any failure in steps 4–6: channel → `failed`, release slot, gateway error to agent.

### 5.7 Enforcer (HP-GRT-008)

- Registry: `grant_id → set(live channel handles)` plus `connection_id → key_id`.
- Inputs: (a) event bus (`grant.revoked`, `agent.disabled`, `key.revoked`, `target.disabled`, `policy.changed`,
  `lockdown.enabled`). (b) A 1 s ticker over a min-heap of grant expiries. (c) A 1 s DB reconciliation query for grants
  `updated_at > cursor`, as a safety net for missed events. (d) Policy-change re-evaluation of live grants.
- Termination: write a gateway notice (`hallpass: access ended (expired)`) to agent stderr or the PTY, send `exit-status 87`,
  close the agent channel, send `signal HUP` then close to the destination channel, finalize recording, close the channel row.
- Bound: event path ≤ 100 ms typical. Ticker or reconciliation path ≤ 2 s. Documented and tested bound: **5 s**, including
  slow-client close (channel close does not wait for the client to drain).

### 5.8 Race catalogue (HP-GRT-007)

| Race | Resolution |
|---|---|
| Two approvers approve/deny concurrently | CAS on `pending`. The first commit wins and the second gets `conflict` with the winning decision. Slack/Telegram messages update to the outcome. |
| Approve vs request expiry | Decide tx checks `expires_at > now` inside the tx. An expired request cannot be approved even if the sweep hasn't run. |
| Approve vs cancel | CAS. First commit wins. |
| Approve vs policy change | Decide tx evaluates against the current `policy_version` read in the tx. A policy change that commits first causes `no_longer_permitted`. |
| Approve vs agent/target disable | Decide tx checks enabled flags. Disable tx cancels pending requests (CAS). |
| Revoke vs channel registration | Registration tx re-reads the grant. If revocation commits after registration, the enforcer catches the channel at step 6 or via reconciliation. |
| Expiry vs channel registration | Registration requires `expires_at > now + min_remaining (2 s)` so it doesn't start channels that would be killed immediately. |
| Concurrent channel registrations near limit | Counted and inserted in the single writer tx, so it is atomic. |
| Duplicate request submissions | Partial unique index plus CAS. The loser returns the existing request (`deduplicated`). |
| Callback replay | Action token single-use plus replay cache plus idempotent decision lookup. |

---

## 6. Schema, constraints, indexes, migrations

All tables are `STRICT`, `WITHOUT ROWID` where the PK is a text ID, with FKs `ON DELETE RESTRICT` unless stated. Abbreviated DDL
(full DDL lands in WP03–WP16 migrations). `ts` = INTEGER µs UTC.

```sql
-- 0001_core
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL, updated_by TEXT) STRICT;
CREATE TABLE keyring_keys (id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK (purpose IN ('field','credential','recording','manifest','token')),
  version INTEGER NOT NULL, wrapped BLOB NOT NULL, wrap_kek_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('active','decrypt_only','retired')), created_at INTEGER NOT NULL,
  UNIQUE (purpose, version)) STRICT, WITHOUT ROWID;
CREATE UNIQUE INDEX ux_keyring_active ON keyring_keys(purpose) WHERE state = 'active';
CREATE TABLE policy_state (id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL, lockdown INTEGER NOT NULL DEFAULT 0,
  lockdown_by TEXT, lockdown_at INTEGER) STRICT;

-- 0002_audit_jobs
CREATE TABLE audit_events (id TEXT PRIMARY KEY, seq INTEGER NOT NULL UNIQUE, at INTEGER NOT NULL, actor_type TEXT NOT NULL,
  actor_id TEXT, action TEXT NOT NULL, target_type TEXT, target_id TEXT, outcome TEXT NOT NULL, source_ip TEXT,
  correlation_id TEXT, details_json TEXT, details_enc BLOB, prev_hash BLOB NOT NULL, hash BLOB NOT NULL) STRICT, WITHOUT ROWID;
CREATE INDEX ix_audit_at ON audit_events(at); CREATE INDEX ix_audit_target ON audit_events(target_type, target_id, at);
CREATE TABLE jobs (id TEXT PRIMARY KEY, kind TEXT NOT NULL, run_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL, lease_until INTEGER, state TEXT NOT NULL CHECK (state IN ('queued','running','done','dead')),
  payload_json TEXT NOT NULL, last_error TEXT, dedup_key TEXT UNIQUE) STRICT, WITHOUT ROWID;
CREATE INDEX ix_jobs_due ON jobs(state, run_at);
CREATE TABLE outbox_messages (id TEXT PRIMARY KEY, provider TEXT NOT NULL, destination TEXT NOT NULL, kind TEXT NOT NULL,
  request_id TEXT REFERENCES access_requests(id), body_enc BLOB NOT NULL, state TEXT NOT NULL
  CHECK (state IN ('queued','sending','delivered','failed','dead')), attempts INTEGER NOT NULL DEFAULT 0, next_at INTEGER NOT NULL,
  provider_ref TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL) STRICT, WITHOUT ROWID;
CREATE TABLE delivery_attempts (id INTEGER PRIMARY KEY, outbox_id TEXT NOT NULL REFERENCES outbox_messages(id) ON DELETE CASCADE,
  at INTEGER NOT NULL, outcome TEXT NOT NULL, http_status INTEGER, error_code TEXT, duration_ms INTEGER NOT NULL) STRICT;

-- 0003_agents
CREATE TABLE groups (id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('agent','server','operator')), name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '', UNIQUE (kind, name)) STRICT, WITHOUT ROWID;
CREATE TABLE agents (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL,
  source_cidrs_json TEXT NOT NULL DEFAULT '[]', created_at INTEGER NOT NULL, created_by TEXT NOT NULL,
  updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL, disabled_at INTEGER, disabled_by TEXT) STRICT, WITHOUT ROWID;
CREATE TABLE agent_keys (id TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(id), fingerprint_sha256 TEXT NOT NULL UNIQUE,
  algorithm TEXT NOT NULL, public_key TEXT NOT NULL, comment TEXT NOT NULL DEFAULT '', state TEXT NOT NULL CHECK (state IN ('active','revoked')),
  created_at INTEGER NOT NULL, created_by TEXT NOT NULL, revoked_at INTEGER, revoked_by TEXT, revoke_reason TEXT, last_used_at INTEGER) STRICT, WITHOUT ROWID;
CREATE TABLE agent_groups (agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE, group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  PRIMARY KEY (agent_id, group_id)) STRICT, WITHOUT ROWID;
CREATE TABLE labels (entity_type TEXT NOT NULL CHECK (entity_type IN ('agent','server','role')), entity_id TEXT NOT NULL,
  key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (entity_type, entity_id, key)) STRICT, WITHOUT ROWID;
CREATE TABLE agent_owners (agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE, operator_id TEXT NOT NULL REFERENCES operators(id),
  PRIMARY KEY (agent_id, operator_id)) STRICT, WITHOUT ROWID;

-- 0004_inventory
CREATE TABLE servers (id TEXT PRIMARY KEY, alias TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL, description TEXT NOT NULL,
  environment TEXT NOT NULL, address TEXT NOT NULL, port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535), enabled INTEGER NOT NULL,
  host_ca_id TEXT REFERENCES host_cas(id), metadata_json TEXT NOT NULL DEFAULT '{}', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL) STRICT, WITHOUT ROWID;
CREATE TABLE server_groups (server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE, group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  PRIMARY KEY (server_id, group_id)) STRICT, WITHOUT ROWID;
CREATE TABLE host_identities (id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id), algorithm TEXT NOT NULL,
  public_key TEXT NOT NULL, fingerprint_sha256 TEXT NOT NULL, state TEXT NOT NULL CHECK (state IN ('pending','active','retired')),
  enrolled_via TEXT NOT NULL CHECK (enrolled_via IN ('paste','scan_confirmed')), confirmed_by TEXT, created_at INTEGER NOT NULL, retired_at INTEGER) STRICT, WITHOUT ROWID;
CREATE UNIQUE INDEX ux_hostid_server_fp ON host_identities(server_id, fingerprint_sha256);
CREATE TABLE host_duplicate_exceptions (id TEXT PRIMARY KEY, fingerprint_sha256 TEXT NOT NULL, server_a TEXT NOT NULL REFERENCES servers(id),
  server_b TEXT NOT NULL REFERENCES servers(id), justification TEXT NOT NULL, created_by TEXT NOT NULL, created_at INTEGER NOT NULL,
  CHECK (server_a < server_b), UNIQUE (fingerprint_sha256, server_a, server_b)) STRICT, WITHOUT ROWID;
-- duplicate detection is enforced in the service layer within the writer tx (needs the exception lookup), and tested.
CREATE TABLE host_cas (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL, fingerprint_sha256 TEXT NOT NULL UNIQUE,
  max_validity_s INTEGER NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL) STRICT, WITHOUT ROWID;
CREATE TABLE host_ca_principals (server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE, principal TEXT NOT NULL,
  PRIMARY KEY (server_id, principal)) STRICT, WITHOUT ROWID;
CREATE TABLE server_roles (id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id), alias TEXT NOT NULL, display_name TEXT NOT NULL,
  description TEXT NOT NULL, remote_user TEXT NOT NULL, capabilities_json TEXT NOT NULL, default_duration_s INTEGER NOT NULL,
  max_duration_s INTEGER NOT NULL, max_concurrent INTEGER NOT NULL, max_concurrent_per_agent INTEGER NOT NULL,
  record_input INTEGER NOT NULL DEFAULT 0, recording_mode TEXT NOT NULL DEFAULT 'mandatory' CHECK (recording_mode IN ('mandatory','best_effort')),
  env_allow_json TEXT NOT NULL DEFAULT '[]', restriction_notes TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, UNIQUE (server_id, alias)) STRICT, WITHOUT ROWID;

-- 0005_credentials
CREATE TABLE login_credentials (id TEXT PRIMARY KEY, role_id TEXT NOT NULL REFERENCES server_roles(id), kind TEXT NOT NULL
  CHECK (kind IN ('managed_key','imported_key')), algorithm TEXT NOT NULL, public_key TEXT NOT NULL, fingerprint_sha256 TEXT NOT NULL UNIQUE,
  private_enc BLOB NOT NULL, state TEXT NOT NULL CHECK (state IN ('pending','active','retiring','retired','revoked')),
  probe_ok_at INTEGER, activated_at INTEGER, retire_after INTEGER, created_at INTEGER NOT NULL, created_by TEXT NOT NULL) STRICT, WITHOUT ROWID;
CREATE UNIQUE INDEX ux_logincred_active ON login_credentials(role_id) WHERE state = 'active';
CREATE TABLE user_cas (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, algorithm TEXT NOT NULL, public_key TEXT NOT NULL,
  private_enc BLOB, signer_ref TEXT, state TEXT NOT NULL, created_at INTEGER NOT NULL) STRICT, WITHOUT ROWID;
CREATE TABLE role_cert_bindings (role_id TEXT PRIMARY KEY REFERENCES server_roles(id), user_ca_id TEXT NOT NULL REFERENCES user_cas(id),
  principals_json TEXT NOT NULL, ttl_s INTEGER NOT NULL DEFAULT 120, extensions_json TEXT NOT NULL) STRICT, WITHOUT ROWID;
CREATE TABLE gateway_host_keys (id TEXT PRIMARY KEY, algorithm TEXT NOT NULL, public_key TEXT NOT NULL, fingerprint_sha256 TEXT NOT NULL,
  private_enc BLOB NOT NULL, state TEXT NOT NULL CHECK (state IN ('next','active','previous','retired')), created_at INTEGER NOT NULL) STRICT, WITHOUT ROWID;

-- 0006_policy
CREATE TABLE policy_rules (id TEXT PRIMARY KEY, name TEXT NOT NULL, effect TEXT NOT NULL CHECK (effect IN ('allow','deny')),
  level TEXT CHECK (level IN ('visible','requestable','auto_approve')), subjects_json TEXT NOT NULL, targets_json TEXT NOT NULL,
  roles_json TEXT NOT NULL, max_duration_s INTEGER, auto_max_duration_s INTEGER, require_reason INTEGER NOT NULL DEFAULT 1,
  enabled INTEGER NOT NULL, priority_note TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL,
  CHECK ((effect = 'deny' AND level IS NULL) OR (effect = 'allow' AND level IS NOT NULL))) STRICT, WITHOUT ROWID;
CREATE TABLE approver_rules (id TEXT PRIMARY KEY, name TEXT NOT NULL, operators_json TEXT NOT NULL, targets_json TEXT NOT NULL,
  roles_json TEXT NOT NULL, max_duration_s INTEGER, enabled INTEGER NOT NULL, updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL) STRICT, WITHOUT ROWID;

-- 0007_access
CREATE TABLE access_requests (id TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(id), agent_key_id TEXT NOT NULL REFERENCES agent_keys(id),
  server_id TEXT NOT NULL REFERENCES servers(id), role_id TEXT NOT NULL REFERENCES server_roles(id), reason_enc BLOB,
  requested_duration_s INTEGER NOT NULL, state TEXT NOT NULL CHECK (state IN ('pending','approved','denied','expired','canceled')),
  state_reason TEXT, idempotency_key TEXT, policy_version INTEGER NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  decided_at INTEGER, UNIQUE (agent_id, idempotency_key)) STRICT, WITHOUT ROWID;
CREATE UNIQUE INDEX ux_req_pending ON access_requests(agent_id, server_id, role_id) WHERE state = 'pending';
CREATE INDEX ix_req_state_exp ON access_requests(state, expires_at); CREATE INDEX ix_req_created ON access_requests(created_at);
CREATE TABLE approval_decisions (id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE REFERENCES access_requests(id),
  outcome TEXT NOT NULL CHECK (outcome IN ('approved','denied')), actor_type TEXT NOT NULL CHECK (actor_type IN ('operator','policy')),
  actor_id TEXT NOT NULL, channel TEXT NOT NULL CHECK (channel IN ('web','slack','telegram','policy','api')), approved_duration_s INTEGER,
  comment_enc BLOB, policy_version INTEGER NOT NULL, approver_rule_id TEXT, decided_at INTEGER NOT NULL) STRICT, WITHOUT ROWID;
CREATE TABLE grants (id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE REFERENCES access_requests(id), decision_id TEXT NOT NULL UNIQUE
  REFERENCES approval_decisions(id), agent_id TEXT NOT NULL, server_id TEXT NOT NULL, role_id TEXT NOT NULL, remote_user TEXT NOT NULL,
  capabilities_json TEXT NOT NULL, policy_version INTEGER NOT NULL, starts_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('active','expired','revoked')), ended_at INTEGER, end_reason TEXT, revoked_by TEXT,
  updated_at INTEGER NOT NULL, CHECK (expires_at > starts_at)) STRICT, WITHOUT ROWID;
CREATE INDEX ix_grant_lookup ON grants(agent_id, server_id, role_id, state, expires_at);
CREATE INDEX ix_grant_active_exp ON grants(state, expires_at); CREATE INDEX ix_grant_updated ON grants(updated_at);
CREATE TABLE access_sessions (id TEXT PRIMARY KEY, grant_id TEXT NOT NULL UNIQUE REFERENCES grants(id), state TEXT NOT NULL
  CHECK (state IN ('open','closing','closed')), seq_reserved INTEGER NOT NULL DEFAULT 0, opened_at INTEGER NOT NULL,
  closed_at INTEGER, close_reason TEXT, retention_class TEXT NOT NULL, delete_after INTEGER) STRICT, WITHOUT ROWID;
CREATE TABLE ssh_connections (id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, agent_key_id TEXT NOT NULL, client_user TEXT NOT NULL,
  client_version TEXT NOT NULL, source_ip TEXT NOT NULL, state TEXT NOT NULL CHECK (state IN ('open','closed','interrupted')),
  opened_at INTEGER NOT NULL, closed_at INTEGER, close_reason TEXT, boot_id TEXT NOT NULL) STRICT, WITHOUT ROWID;
CREATE TABLE ssh_channels (id TEXT PRIMARY KEY, connection_id TEXT NOT NULL REFERENCES ssh_connections(id), access_session_id TEXT NOT NULL
  REFERENCES access_sessions(id), grant_id TEXT NOT NULL REFERENCES grants(id), role_id TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('shell','exec')),
  pty INTEGER NOT NULL, state TEXT NOT NULL CHECK (state IN ('opening','active','closed','failed','interrupted')), exit_status INTEGER, exit_signal TEXT,
  opened_at INTEGER NOT NULL, closed_at INTEGER, close_reason TEXT) STRICT, WITHOUT ROWID;
CREATE INDEX ix_chan_live ON ssh_channels(state, role_id); CREATE INDEX ix_chan_session ON ssh_channels(access_session_id, opened_at);
CREATE TABLE timeline_events (id TEXT PRIMARY KEY, access_session_id TEXT REFERENCES access_sessions(id) ON DELETE CASCADE,
  request_id TEXT REFERENCES access_requests(id), seq INTEGER, type TEXT NOT NULL, schema_version INTEGER NOT NULL, at INTEGER NOT NULL,
  connection_id TEXT, channel_id TEXT, segment_id TEXT, data_json TEXT NOT NULL DEFAULT '{}', idempotency_key TEXT NOT NULL UNIQUE) STRICT, WITHOUT ROWID;
CREATE UNIQUE INDEX ux_tl_seq ON timeline_events(access_session_id, seq) WHERE seq IS NOT NULL;
CREATE INDEX ix_tl_request ON timeline_events(request_id, at);

-- 0008_recording
CREATE TABLE recording_segments (id TEXT PRIMARY KEY, access_session_id TEXT NOT NULL REFERENCES access_sessions(id), channel_id TEXT NOT NULL
  REFERENCES ssh_channels(id), ordinal INTEGER NOT NULL, path TEXT NOT NULL UNIQUE, format TEXT NOT NULL DEFAULT 'HPREC1',
  recording_key_id TEXT NOT NULL REFERENCES keyring_keys(id), wrapped_dek BLOB NOT NULL, header_sha256 BLOB NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('open','finalized','interrupted','failed','missing','deleted')),
  first_seq INTEGER, last_seq INTEGER, frames INTEGER, bytes INTEGER, ciphertext_sha256 BLOB, chain_hash BLOB,
  opened_at INTEGER NOT NULL, finalized_at INTEGER, verified_at INTEGER, verify_result TEXT, UNIQUE (channel_id, ordinal)) STRICT, WITHOUT ROWID;
CREATE TABLE integrity_chain (seq INTEGER PRIMARY KEY, segment_id TEXT NOT NULL UNIQUE, manifest_sha256 BLOB NOT NULL,
  prev_hash BLOB NOT NULL, hash BLOB NOT NULL, mac BLOB NOT NULL, at INTEGER NOT NULL) STRICT;
CREATE TABLE quarantine_files (id INTEGER PRIMARY KEY, original_path TEXT NOT NULL, quarantine_path TEXT NOT NULL, reason TEXT NOT NULL, at INTEGER NOT NULL) STRICT;

-- 0009_operators (WP13) / 0010_oidc (WP14) / 0011_notify (WP16)
CREATE TABLE operators (id TEXT PRIMARY KEY, email TEXT UNIQUE COLLATE NOCASE, display_name TEXT NOT NULL, enabled INTEGER NOT NULL,
  provisioned_via TEXT NOT NULL CHECK (provisioned_via IN ('bootstrap','admin','invite','jit','recovery')), created_at INTEGER NOT NULL,
  disabled_at INTEGER, last_login_at INTEGER) STRICT, WITHOUT ROWID;
CREATE TABLE operator_local_credentials (operator_id TEXT PRIMARY KEY REFERENCES operators(id) ON DELETE CASCADE, password_phc TEXT NOT NULL,
  params_version INTEGER NOT NULL, changed_at INTEGER NOT NULL, must_change INTEGER NOT NULL DEFAULT 0) STRICT, WITHOUT ROWID;
CREATE TABLE operator_oidc_identities (provider_id TEXT NOT NULL REFERENCES oidc_providers(id), issuer TEXT NOT NULL, subject TEXT NOT NULL,
  operator_id TEXT NOT NULL REFERENCES operators(id) ON DELETE CASCADE, linked_at INTEGER NOT NULL, linked_via TEXT NOT NULL,
  last_claims_json TEXT, PRIMARY KEY (issuer, subject)) STRICT, WITHOUT ROWID;
CREATE TABLE operator_roles (operator_id TEXT NOT NULL REFERENCES operators(id) ON DELETE CASCADE, role TEXT NOT NULL
  CHECK (role IN ('administrator','approver','auditor','viewer')), source TEXT NOT NULL CHECK (source IN ('manual','sso')),
  source_ref TEXT, PRIMARY KEY (operator_id, role, source)) STRICT, WITHOUT ROWID;
CREATE TABLE operator_group_members (group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE, operator_id TEXT NOT NULL
  REFERENCES operators(id) ON DELETE CASCADE, source TEXT NOT NULL, PRIMARY KEY (group_id, operator_id, source)) STRICT, WITHOUT ROWID;
CREATE TABLE mfa_totp (operator_id TEXT PRIMARY KEY REFERENCES operators(id) ON DELETE CASCADE, secret_enc BLOB NOT NULL,
  confirmed_at INTEGER, last_step INTEGER NOT NULL DEFAULT 0) STRICT, WITHOUT ROWID;
CREATE TABLE recovery_codes (operator_id TEXT NOT NULL REFERENCES operators(id) ON DELETE CASCADE, code_hash BLOB NOT NULL,
  used_at INTEGER, PRIMARY KEY (operator_id, code_hash)) STRICT, WITHOUT ROWID;
CREATE TABLE one_time_tokens (hash BLOB PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('setup','invite','reset','recovery_login','link_code','oidc_test')),
  operator_id TEXT, data_json TEXT NOT NULL DEFAULT '{}', expires_at INTEGER NOT NULL, used_at INTEGER, created_by TEXT NOT NULL) STRICT, WITHOUT ROWID;
CREATE TABLE web_sessions (id_hash BLOB PRIMARY KEY, operator_id TEXT NOT NULL REFERENCES operators(id) ON DELETE CASCADE, csrf_secret_hash BLOB NOT NULL,
  auth_method TEXT NOT NULL, mfa_at INTEGER, auth_at INTEGER NOT NULL, created_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL,
  absolute_expires_at INTEGER NOT NULL, ip TEXT, user_agent TEXT, revoked_at INTEGER, revoke_reason TEXT) STRICT, WITHOUT ROWID;
CREATE TABLE login_throttle (key TEXT PRIMARY KEY, failures INTEGER NOT NULL, next_allowed_at INTEGER NOT NULL, updated_at INTEGER NOT NULL) STRICT, WITHOUT ROWID;
CREATE TABLE oidc_providers (id TEXT PRIMARY KEY, display_name TEXT NOT NULL, issuer TEXT NOT NULL UNIQUE, client_id TEXT NOT NULL,
  client_secret_enc BLOB, scopes_json TEXT NOT NULL, groups_claim TEXT, provisioning TEXT NOT NULL CHECK (provisioning IN ('preprovisioned','jit')),
  restrictions_json TEXT NOT NULL, ca_bundle_pem TEXT, allow_private_network INTEGER NOT NULL DEFAULT 0, stepup_json TEXT NOT NULL,
  enabled INTEGER NOT NULL, test_login_ok_at INTEGER, test_login_by TEXT, updated_at INTEGER NOT NULL) STRICT, WITHOUT ROWID;
CREATE TABLE oidc_group_mappings (id TEXT PRIMARY KEY, provider_id TEXT NOT NULL REFERENCES oidc_providers(id) ON DELETE CASCADE,
  group_value TEXT NOT NULL, internal_role TEXT, operator_group_id TEXT REFERENCES groups(id), UNIQUE (provider_id, group_value, internal_role, operator_group_id)) STRICT, WITHOUT ROWID;
CREATE TABLE oidc_auth_states (state_hash BLOB PRIMARY KEY, provider_id TEXT NOT NULL, nonce_hash BLOB NOT NULL, pkce_verifier_enc BLOB NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('login','link','stepup','test')), return_to TEXT NOT NULL, session_binding BLOB,
  expires_at INTEGER NOT NULL) STRICT, WITHOUT ROWID;
CREATE TABLE integrations (id TEXT PRIMARY KEY, provider TEXT NOT NULL CHECK (provider IN ('slack','telegram','smtp')), name TEXT NOT NULL,
  config_json TEXT NOT NULL, secrets_enc BLOB NOT NULL, enabled INTEGER NOT NULL, updated_at INTEGER NOT NULL) STRICT, WITHOUT ROWID;
CREATE TABLE provider_links (provider TEXT NOT NULL, workspace TEXT NOT NULL, provider_user_id TEXT NOT NULL, operator_id TEXT NOT NULL
  REFERENCES operators(id) ON DELETE CASCADE, linked_at INTEGER NOT NULL, linked_via TEXT NOT NULL, PRIMARY KEY (provider, workspace, provider_user_id)) STRICT, WITHOUT ROWID;
CREATE TABLE notification_routes (id TEXT PRIMARY KEY, integration_id TEXT NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
  destination TEXT NOT NULL, targets_json TEXT NOT NULL, enabled INTEGER NOT NULL) STRICT, WITHOUT ROWID;
CREATE TABLE action_tokens (hash BLOB PRIMARY KEY, request_id TEXT NOT NULL REFERENCES access_requests(id), action TEXT NOT NULL
  CHECK (action IN ('approve','deny')), duration_s INTEGER, provider TEXT NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER,
  used_by_operator TEXT, decision_id TEXT) STRICT, WITHOUT ROWID;
CREATE TABLE webhook_replay (provider TEXT NOT NULL, fingerprint BLOB NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY (provider, fingerprint)) STRICT, WITHOUT ROWID;
```

Migration plan: each WP adds only its own tables, numbered in the order the migrations are committed (never inserted
before an already-committed number, because goose refuses out-of-order history). Actual order so far: 0001 core, 0002 audit/jobs,
0003 agents, 0004 inventory, 0005 credentials, 0006 policy, 0007 access, 0008 operators (WP13); recording, OIDC and notify
tables take the next free numbers. The schema version is in the `goose_db_version` table. The `audit_events` hash chain is
`hash = SHA-256(prev_hash || canonical(row without hash))`, MAC-free (the chain detects reordering and deletion within the DB.
External anchoring covers a key-holding attacker, §13.8).

---

## 7. SSH grammar (agent interface)

### 7.1 Invocation model

OpenSSH sends either a `shell` request (`ssh center`, `ssh -t center`) or an `exec` request carrying a single string
(`ssh center <words…>`; the client joins argv with spaces). Hallpass parses that string with its own tokenizer.
**It never passes the gateway-command portion to a shell.**

### 7.2 Tokenizer (HP-SSH-016)

- Input must be valid UTF-8, ≤ 16 KiB before `--` and ≤ 64 KiB total. Otherwise exit 81.
- Whitespace (SP, TAB) separates tokens. `'…'` is literal. `"…"` is literal except `\"` and `\\`. Outside quotes, `\x` → `x`.
  Unterminated quotes → exit 81. NUL and other C0 controls except TAB → exit 81.
- No `$`, glob, tilde, brace, or command-substitution semantics. Those characters are ordinary.
- The first standalone unquoted `--` token ends gateway parsing. The **raw byte substring** after that token and the single
  whitespace run following it is the destination command (HP-SSH-023). It is forwarded unchanged as the destination `exec`
  payload and interpreted by the destination user's login shell.

### 7.3 Grammar (EBNF)

```
invocation   = [ command ] ;                       (* empty exec or shell request → "list" in human format *)
command      = list | roles | request | status | cancel | connect | exec | sessions
             | "help" [ word ] | "version" [ json ] | "whoami" [ json ] | shorthand ;
list         = ( "list" | "ls" ) { list-opt } ;              list-opt = json | "--server" alias ;
roles        = "roles" alias [ json ] ;
request      = "request" alias { req-opt } ;
status       = "status" request-id [ json ] [ "--wait" [ "=" bool ] ] [ wait-timeout ] ;
cancel       = "cancel" request-id [ json ] ;
connect      = "connect" alias { conn-opt } ;
exec         = "exec" alias { conn-opt } "--" remote-command ;
sessions     = "sessions" [ json ] [ "--all" ] ;
shorthand    = alias { conn-opt } ;                            (* ≡ connect alias … *)
req-opt      = role | reason | duration | wait | wait-timeout | idem | json ;
conn-opt     = role | reason | duration | wait | wait-timeout | idem | json ;
role         = "--role" ( "=" | ws ) role-alias ;
reason       = "--reason" ( "=" | ws ) text ;                  (* 1..1000 scalars after sanitization *)
duration     = "--duration" ( "=" | ws ) go-duration ;         (* must be an allowed preset ≤ policy max *)
wait         = "--wait" [ "=" bool ] | "--no-wait" ;
wait-timeout = "--wait-timeout" ( "=" | ws ) go-duration ;     (* 0s..15m, default 120s *)
idem         = "--idempotency-key" ( "=" | ws ) token ;        (* [A-Za-z0-9._-]{8,128} *)
json         = "--json" ;
alias        = /[a-z][a-z0-9-]{0,62}/ ;  role-alias = alias ;   request-id = /req_[0-9a-z]{26}/ ;
```

Options may appear in any order. Unknown options → exit 81. Repeated options → exit 81. A shorthand alias followed by
non-option words (e.g. `ssh center web1 uptime`) → exit 81 with a hint to use `exec web1 -- uptime`.

### 7.4 Reserved words and aliases (HP-SSH-017)

Reserved: `list ls roles request status cancel connect exec sessions help version whoami admin api login logout shell ssh
sftp scp hallpass`, plus any word starting with `-`. Server and role alias validation rejects them at create/rename.
Reserved-word additions in future versions are checked by a migration that refuses to apply while conflicting aliases exist,
and the operator must rename first (documented in the upgrade notes).

### 7.5 Command semantics

| Command | Behavior | Default output |
|---|---|---|
| (empty), `list` | Visible servers with description and visible roles (alias, description, level `requestable`/`auto`, active grant remaining time). | Table on stdout |
| `roles <alias>` | Roles for one visible server, with capabilities, max duration and allowed durations. | Table |
| `request <alias>` | Create/reuse pending request. `--wait` (default false for `request`) waits for a decision without connecting. | Request summary |
| `status <req>` | Request state (own requests only), with grant summary if approved. `--wait` waits for a terminal state. | Summary |
| `cancel <req>` | Cancel own pending request. | Summary |
| `connect <alias>`, shorthand | Reuse an active grant, or create/reuse a request, wait (default true) and connect: shell (PTY if allocated). | Destination stream |
| `exec <alias> -- cmd` | As connect, but runs `cmd` via destination exec. stdout/stderr kept separate. | Destination stream |
| `sessions` | Agent's active grants/sessions (and recent ones with `--all`), remaining time, connection counts. | Table |
| `whoami` | Agent ID, name, authenticated key fingerprint, source IP. | Text |
| `version` | Gateway version and grammar/schema versions. | Text |

Role resolution (HP-SSH-022): `--role` given → that role (must be visible). Otherwise, if there's exactly one role with an
active grant, use it. Else if exactly one requestable role, use it. Else: PTY → interactive numbered prompt. No PTY → exit 81 listing choices.

### 7.6 Connect/exec flow and waiting

1. Active grant found → connect immediately (HP-GRT-004).
2. Otherwise a reason is required (per policy `require_reason`). From `--reason`, or prompted on the PTY (line editor with a
   1000-scalar limit and echo). No PTY and no reason → exit 90 `input_required` (HP-SSH-019).
3. Create/reuse pending request (dedup). Auto-approve → grant immediately.
4. Print to stderr (or PTY): `hallpass: request req_… pending approval (expires 14:32Z); waiting up to 2m0s`. Then
   wait on the event bus plus a 2 s DB poll fallback. No DB transaction is held. A spinner on PTY only.
5. Approved → connect. Denied → exit 83. Expired → 84. Canceled → 85. Wait timeout → exit 86 with request ID and
   instructions (`ssh center status req_… --wait`). The request stays pending (HP-SSH-021).
6. Agent disconnects while waiting → wait is abandoned. The request is untouched.

### 7.7 Exit codes and JSON

Gateway exit codes (destination exit status passes through unchanged when the destination ran):

| Code | Name | Meaning |
|---|---|---|
| 0 | ok | Gateway-only command succeeded (`list`, `status`, …). |
| 80 | internal | Internal or storage failure, gateway degraded, shutdown. |
| 81 | usage | Parse error, unknown option, ambiguous role, invalid duration. |
| 82 | not_found_or_forbidden | Target/role/request unknown **or** not permitted (identical response, HP-POL-010). |
| 83 | denied | Request denied. |
| 84 | expired | Request expired before decision. |
| 85 | canceled | Request canceled. |
| 86 | wait_timeout | Still pending after the wait timeout. |
| 87 | access_ended | Grant expired/revoked/disabled during or before activity. |
| 88 | destination_unavailable | Dial, host-key verification or destination auth failed (generic to agent). |
| 89 | limit_exceeded | Rate limit, concurrency limit, too many pending requests. |
| 90 | input_required | Required input missing without PTY. |

Ambiguity note: a destination command may itself exit 80–90. In that case the gateway emits no JSON error on stderr, so
the absence of a `hallpass.error/v1` line means the code came from the destination. If the destination is killed by a
signal, `exit-signal` is forwarded and the OpenSSH client exits 255.

Every gateway error writes exactly one line to stderr when `--json` is set, or when stderr is not a PTY:

```json
{"schema":"hallpass.error/v1","source":"gateway","code":"not_found_or_forbidden","exit_code":82,"message":"server or role not found or not permitted","request_id":null}
```

JSON success schemas (stdout, single JSON document, `--json`): `hallpass.list/v1`, `hallpass.roles/v1`, `hallpass.request/v1`,
`hallpass.status/v1`, `hallpass.sessions/v1`, `hallpass.whoami/v1`, `hallpass.version/v1`. JSON Schema files live in
`api/ssh-schemas/*.json` and are tested against golden outputs. For example, `hallpass.request/v1`:

```json
{"schema":"hallpass.request/v1","request":{"id":"req_…","server":"foo-server","role":"inspect","state":"pending",
 "deduplicated":false,"created_at":"2026-10-23T14:02:11Z","expires_at":"2026-10-23T14:32:11Z","requested_duration":"30m",
 "grant":null}}
```

Timestamps are RFC 3339 UTC. Durations are Go duration strings. Field additions are allowed within `/v1`. Removals and renames are not.

### 7.8 Stream semantics (HP-SSH-006/009/010)

- PTY: one merged stream. Gateway messages appear only before the destination session starts and after it ends, prefixed `hallpass: `.
- Non-PTY: destination stdout → agent stdout, destination stderr → agent extended data (stderr). Gateway messages → stderr.
- EOF: agent EOF → destination `CloseWrite`. Destination EOF → agent `CloseWrite`. Half-close is preserved.
- Signals: `signal` requests are forwarded (destination sshd honors them only if supported; OpenSSH ≥ 7.9 handles common
  ones). `exit-status`/`exit-signal` are forwarded, then the channel closes.
- `env`: allowlisted only (HP-SSH-008), forwarded before `shell`/`exec`.
- Window changes are forwarded and recorded (`terminal.resized`).
- Gateway host key: Ed25519 (`gateway_host_keys.state='active'`). Rotation: generate `next`, publish both fingerprints (UI/CLI
  `hallpass hostkey show`), operators update agent `known_hosts`, then promote. Because `x/crypto/ssh` offers only one key per
  algorithm and does not implement `hostkeys-00@openssh.com`, overlap is achieved either by (a) serving the new key
  under a second algorithm (ECDSA P-256) during the window, or (b) a gateway host certificate signed by a gateway host CA
  that agents trust through `@cert-authority` (recommended for fleets). Documented in the agent guide (HP-SSH-005).

---

## 8. API and live-event contracts

### 8.1 Conventions

- Spec-first: `api/openapi.yaml` (OpenAPI 3.1). `oapi-codegen` generates a strict `net/http` server interface into
  `internal/httpapi/gen`. `openapi-typescript` generates `web/src/api/schema.d.ts`. CI regenerates both and fails on diff (HP-API-001).
- Base path `/api/v1`. JSON only. Cursor pagination: `?limit=50&cursor=…` → `{items, next_cursor}`, max limit 200.
  Filters as query params (`state=pending&server=…`), sort `?sort=-created_at` over allowlisted fields.
- Errors: RFC 9457 `application/problem+json` `{type, title, status, code, detail, instance, errors[]}`.
  Codes are stable strings (`forbidden`, `not_found`, `conflict`, `reauth_required`, `mfa_required`, `rate_limited`, `validation_failed`, …).
- Mutations: `POST`/`PATCH`/`DELETE` require session cookie, `X-CSRF-Token`, and an Origin match. Security-sensitive mutations
  return the authoritative new state and the UI never assumes success. `Idempotency-Key` header is accepted on non-idempotent POSTs
  (stored 24 h per operator) (HP-API-006).
- Concurrency control: resources carry `version` (integer). `PATCH` requires `If-Match: "<version>"`, otherwise 428.

### 8.2 Resource map (v1)

| Area | Endpoints (abbrev.) | Permission |
|---|---|---|
| Auth | `GET /auth/config` (public: login modes, providers), `POST /auth/login`, `POST /auth/mfa`, `POST /auth/logout`, `POST /auth/reauth`, `GET /auth/oidc/{provider}/start`, `GET /auth/oidc/callback` (outside `/api`), `POST /auth/bootstrap`, `POST /auth/invitations/{token}/accept`, `POST /auth/reset/{token}` | public/session |
| Me | `GET /me`, `GET/DELETE /me/sessions[/{id}]`, `POST /me/password`, `POST/DELETE /me/mfa/totp`, `POST /me/recovery-codes`, `POST /me/provider-link-codes`, `POST /me/oidc-links` | self |
| Operators | `GET/POST /operators`, `GET/PATCH /operators/{id}`, `POST /operators/{id}/disable`, `/roles`, `/reset-token`, `/sessions`, `POST /invitations` | operators.manage |
| Agents | `GET/POST /agents`, `GET/PATCH /agents/{id}`, `POST /agents/{id}/disable|enable`, `POST /agents/{id}/keys`, `POST /agents/{id}/keys/{kid}/revoke`, `GET /agents/{id}/effective-access` | inventory.read/write |
| Groups/labels | `GET/POST /groups`, membership endpoints | inventory.write |
| Servers | `GET/POST /servers`, `GET/PATCH /servers/{id}`, `POST /servers/{id}/host-identities:scan`, `POST …/host-identities`, `POST …/{hid}/confirm|retire`, `GET/POST /servers/{id}/roles`, `PATCH /roles/{id}` | inventory.*, address fields need inventory.address.read |
| Host CAs | `GET/POST /host-cas`, `POST /host-duplicate-exceptions` | inventory.write + reauth |
| Credentials | `GET /roles/{id}/credentials`, `POST /roles/{id}/credentials:generate`, `POST /credentials/{id}/probe|activate|retire|revoke`, `GET/POST /user-cas`, `PUT /roles/{id}/cert-binding` | credentials.manage + reauth |
| Policy | `GET/POST /policy/rules`, `PATCH/DELETE /policy/rules/{id}`, `GET/POST /policy/approver-rules`, `POST /policy/preview`, `GET /policy/version` | policy.read/write |
| Requests | `GET /requests`, `GET /requests/{id}`, `POST /requests/{id}/approve {duration}`, `POST …/deny {comment}`, `POST …/cancel` | requests.read/decide |
| Grants | `GET /grants`, `POST /grants/{id}/revoke {reason}` | grants.revoke |
| Sessions | `GET /access-sessions`, `GET /access-sessions/{id}`, `GET …/timeline?cursor`, `GET …/channels` | sessions.read |
| Recordings | `GET /recordings/{seg}`, `GET /recordings/{seg}/records?from_seq&limit` (decrypted, ≤ 256 KiB per page), `POST /recordings/export` | recording.play / recording.export + reauth |
| Activities | `GET /activities` (live channels), `POST /activities/{chn}/terminate` | sessions.read / grants.revoke |
| Audit | `GET /audit-events`, `GET /audit-events/verify` | audit.read |
| Integrations | `GET/PUT /integrations/{slack|telegram|smtp}`, `POST …/test`, `GET /notification-deliveries`, `GET/POST /notification-routes` | integrations.manage |
| Auth settings | `GET/PUT /settings/auth`, `GET/POST/PATCH /oidc-providers`, `POST /oidc-providers/{id}/discover`, `POST …/test-login`, `GET/PUT …/group-mappings` | auth.settings + reauth |
| System | `GET /system/status`, `GET /system/storage`, `GET /system/keys`, `POST/DELETE /system/lockdown`, `GET/PUT /system/retention`, `POST /system/backup` | system.* |
| Stats | `GET /stats/requests|sessions|activity|storage?range=24h&bucket=1h` | dashboard.view |
| Live | `GET /events` (SSE) | session |
| Webhooks | `POST /hooks/slack/interactions`, `POST /hooks/slack/commands`, `POST /hooks/telegram/{integration_id}` | provider-verified |
| Ops | `GET /healthz`, `GET /readyz`, `GET /metrics` (separate listener or `metrics.bind`) | public/infra |

### 8.3 SSE contract (ADR-0012, HP-API-005)

- `GET /api/v1/events` with `Accept: text/event-stream`, cookie auth (EventSource sends cookies same-origin).
- Frames: `id: <boot_id>.<n>` · `event: <type>` · `data: {"type","resource","resource_id","version","at","summary"}`.
  `summary` holds only non-sensitive fields the subscriber may see. Clients refetch details via REST and never get secrets or reasons over SSE.
- Types: `request.created`, `request.updated`, `grant.updated`, `session.updated`, `activity.started`, `activity.ended`,
  `notification.updated`, `audit.appended` (audit.read only), `system.status`, `policy.changed`, `reset`.
- Heartbeat comment `: hb` every 15 s. `retry: 3000`.
- Resume: a server-side ring buffer of the last 4,096 events per boot. A valid `Last-Event-ID` replays the missed authorized events.
  An unknown ID, a different boot, or an overflowed per-client buffer (256 events) sends `event: reset`, and the client invalidates all queries.
- Authorization: events are filtered per subscriber at fan-out using the subscriber's current permissions, which are re-read when
  `operator.updated` affects them. Session revocation closes the stream.
- Limits: ≤ 4 concurrent streams per web session, ≤ 512 total.

---

## 9. Visibility, policy and role semantics

### 9.1 Rule model (ADR-0008)

```yaml
id: pol_…
name: sre-agents-inspect-prod
effect: allow                 # allow | deny
level: requestable            # visible | requestable | auto_approve   (allow only)
subjects:                     # agent selector
  agents: [agt_…]             # IDs
  agent_groups: [sre-bots]    # group names
  agent_labels: {matchLabels: {team: sre}, matchExpressions: [{key: env, operator: In, values: [prod]}]}
  all: false
targets:                      # server selector
  servers: [srv_…]
  server_groups: [prod-web]
  server_labels: {matchLabels: {tier: web}}
  all: false
roles:                        # role selector
  names: [inspect]            # role aliases
  ids: []
  role_labels: {matchLabels: {class: readonly}}
  all: false
max_duration: 6h              # optional cap for requests matched by this rule
auto_approve: {max_duration: 15m}   # only when level = auto_approve
require_reason: true
enabled: true
```

### 9.2 Evaluation

For agent *a*, server *s*, role *r* (all enabled; disabled → no access):

1. `M` = enabled rules whose subjects match *a*, targets match *s* and roles match *r*.
2. If any rule in `M` has `effect=deny` → **deny** (invisible, not requestable). Deny overrides any allow.
3. Else level = max over allow rules in `M` (`visible` < `requestable` < `auto_approve`). Empty `M` → deny (default deny).
4. Max duration = min(role.max_duration, global ceiling `policy.max_grant_duration` (default 24h, R-05), max over
   `max_duration` of matching allow rules with level ≥ requestable that set one, else role max).
5. Auto-approve applies only if level = `auto_approve` and requested ≤ min over matching auto rules' `auto_approve.max_duration`.
6. Allowed durations = configured presets (`5m 15m 30m 1h 3h 6h 24h`) ≤ max duration. Agents may request only presets.
7. `require_reason` = true if any matching allow rule requires it (default true).

The deciding rule (highest-level allow, or the deny) is reported by `Explain` for the effective-access preview.

### 9.3 Selector semantics (HP-POL-003)

- A selector matches if **any** of its clauses matches (IDs ∪ groups ∪ labels). `all: true` matches every object of that kind,
  including objects created later.
- Label clause: all `matchLabels` pairs AND all `matchExpressions` must hold (Kubernetes semantics). **Unlike Kubernetes,
  an empty label clause matches nothing.**
- An empty selector (no clauses, `all` false) matches nothing. The API rejects rules whose selectors are all empty, so typos can't create dead rules.
- Group membership overlap: an agent in groups A and B matches rules for either, which yields the union of allows, and denies still win.
- References to deleted groups or IDs are rejected on write. Deleting a referenced group requires removing references first.

### 9.4 Role and server visibility

Role visible ⇔ level(a,s,r) ≥ visible. Server visible ⇔ ∃ visible role on it. `list` shows only visible servers and roles.
Role classes are expressed as role labels (`class=readonly|deploy|admin`).

### 9.5 Separation of concerns (HP-POL-006)

| Question | Mechanism |
|---|---|
| Can the agent see it? | Policy level ≥ visible. |
| Can the agent request it? | Level ≥ requestable. |
| Who may approve? | Approver rules (§9.7) + internal role. |
| May activity start now? | Active grant + channel revalidation (§5.6). |

### 9.6 Grant selection for activity (HP-GRT-005)

Among grants for (agent, server, role) with `state='active' AND expires_at > now + 2s`: pick max `expires_at`, tie → min `id`.

### 9.7 Approver rules (HP-POL-011)

`{operators: {ids, groups, all}, targets: <server selector>, roles: <role selector>, max_duration?}`. An operator may decide
a request if they hold `approver` or `administrator`, are enabled, have MFA satisfied when required, match some enabled approver rule
for the request's server and role, are within that rule's `max_duration`, and are not blocked by the self-approval rule. Administrators
need an approver rule too (ADR-0008). The bootstrap creates no approver rules, and the setup checklist in the UI prompts for one.

### 9.8 Change effects (HP-POL-007/008)

Every write to `policy_rules`, `approver_rules`, group memberships, labels, or agent/server/role enablement increments `policy_state.version`
in the same tx and publishes `policy.changed`. Then a job (not inside that tx) evaluates the following against the new snapshot:
- pending requests: no longer ≥ requestable → `canceled(policy_changed)`. Still requestable → unchanged, and decision time rechecks.
- active grants: no longer ≥ requestable → `revoked(policy_changed)`. New max duration shorter → `expires_at = min(expires_at,
  starts_at + new_max)`. Both are audited and enforced within the bound.
- Approver rule changes affect only future decisions.

### 9.9 Hidden-target non-disclosure (HP-POL-010)

Agent-facing lookups go through `policy.Snapshot.ResolveVisible(agent, alias, role?)`. This single function returns either the
visible target or `ErrNotFoundOrForbidden`. Every not-found/hidden/disabled/no-role path returns the same error value,
message, exit code and JSON. No destination lookup, DNS or dial happens before visibility is decided. `status`/`cancel` on
another agent's request also returns 82. Tests compare the byte output of all variants. Timing is constant because evaluation is in-memory.

---

## 10. Approval-provider design

### 10.1 Decision service (single path, HP-NTF-008)

`access.Service.Decide(ctx, DecideInput{RequestID, Outcome, Duration, Actor{OperatorID, Channel}, Comment, IdempotencyKey})`. It is used by
web, Slack and Telegram alike, and auto-approval uses `DecideByPolicy`. Inside one writer tx it checks: request pending and not
expired; lockdown off; operator enabled; role ∈ {approver, administrator}; MFA requirement satisfied (web: session `mfa_at`;
Slack/Telegram: operator must have MFA-enrolled web login and `approvals.chat_requires_recent_web_mfa` policy, see R-10);
approver rule match; self-approval rule; current policy level ≥ requestable; duration ∈ allowed presets and ≤ approver max.
Then it writes CAS request → approved/denied, decision, grant + session (approve), audit, timeline `request.approved|denied` and
`grant.activated`, and outbox messages to update provider messages. After commit it publishes bus events.

### 10.2 Notification core (HP-NTF-001..004)

- On `request.created` (pending, not auto-approved), the tx inserts outbox rows for each matching `notification_route`
  (Slack channel / Telegram chat), plus the in-app web notification.
- Message content: agent name + ID + key fingerprint (verified identity), server alias + description, role alias +
  description + capabilities, **reason** in a quoted block labeled "Agent-provided reason (untrusted)", request expiry,
  approve buttons for allowed durations (max 5 shown, smallest first), Deny, and a "Details" link to `/requests/{id}`.
  No addresses, remote usernames or credentials.
- Sanitization: strip C0/C1 controls and bidi overrides. Slack: escape `& < >`, set `"parse":"none"`,
  `unfurl_links:false`, `unfurl_media:false`, `<!` sequences neutralized. Telegram: plain text (no `parse_mode`), with
  `disable_web_page_preview`. Reason truncated to 500 scalars in chat, with the full text in the UI.
- Delivery worker: claims `queued` rows with a lease (30 s), sends with a 10 s timeout, records `delivery_attempts`. On failure it
  backs off exponentially (2 s → 5 min, jitter), max 8 attempts, then `dead`. Dead deliveries appear in the UI and metrics.
  Failure never changes the request (HP-NTF-010).
- Decision follow-up: outbox `update` messages edit the original messages to show the outcome (best effort).

### 10.3 Action tokens (HP-NTF-007)

Per notification: one token per button (approve:<duration>, deny). Token = 16 random bytes, base64url (22 chars). Stored as
HMAC-SHA-256(token_key, token), bound to request, action, duration and provider, expiring at request expiry. Single use: the first
successful decision marks `used_at`. Redelivery of the same token returns the recorded outcome (idempotent, HP-NTF-009).
A token never authorizes by itself. The clicking provider user must map to an operator who passes §10.1.

### 10.4 Slack (WP17, HP-NTF-005)

- Slack app with bot token (`chat:write`, `commands`), signing secret, interactivity URL `/hooks/slack/interactions`,
  slash command `/hallpass` (`link <code>`, `status <req>`). Secrets encrypted (integration `secrets_enc`).
- Verification order: body size ≤ 64 KiB → `X-Slack-Request-Timestamp` within ±300 s → compute
  `v0=HMAC_SHA256(signing_secret, "v0:" + ts + ":" + raw_body)` → constant-time compare with `X-Slack-Signature` →
  replay cache insert of `(slack, sha256(signature))` with a 10 min TTL (DB table, so it survives restart) → parse.
- Identity: `team.id` + `user.id` → `provider_links`. Unlinked user → ephemeral "your Slack account is not linked to a Hallpass approver".
- Respond within 3 s: ack immediately, decide synchronously (fast tx), update the message via `response_url` or outbox.

### 10.5 Telegram (WP18, HP-NTF-006)

- Bot token encrypted. `setWebhook` with `secret_token` (32 random bytes, base64url) and `allowed_updates=["callback_query","message"]`.
  Endpoint `/hooks/telegram/{integration_id}`. The header `X-Telegram-Bot-Api-Secret-Token` is compared in constant time.
- Allowlists: `allowed_chat_ids` (routes) and the user must be linked (`provider_links`, workspace = bot ID). Updates from other chats or users are ignored and audited (rate limited).
- `callback_data = "hp1:" + token` (26 bytes ≤ 64). `update_id` replay cache. `answerCallbackQuery` always, `editMessageText` with the outcome.
- Linking: the operator generates a link code in the web UI and sends `/link <code>` to the bot in a private chat. The bot records `from.id`.

### 10.6 Provider identity linking (HP-NTF-011)

Link codes: 8 chars Crockford base32 (40 bits), 10 min expiry, hashed, single use, bound to the issuing operator and provider.
An admin can also link manually (audited, reauth). Unlinking is immediate. Disabled operators' links are inert.

### 10.7 Rate limits (HP-NTF-012)

Webhooks: 20 req/s per integration, 5/s per provider user. Decisions: 30/min per operator. Excess → 429 (Slack/Telegram get a
polite message). Limits are configurable.

---

## 11. Agent/server key and credential lifecycle

### 11.1 Agent keys (HP-AGT-*)

- Add: paste an OpenSSH public key line. Parse with `ssh.ParseAuthorizedKey`. Reject options, certs, disallowed algorithms and
  RSA < 3072. Compute `SHA256:` fingerprint, check global uniqueness (DB unique index, tombstones included), audit `agent.key.added`.
- Auth: `PublicKeyCallback` looks up the fingerprint (reader pool, LRU cache invalidated on key events) and returns
  `*ssh.Permissions{Extensions: {"hp-agent": id, "hp-key": key_id}}`. **Identity is taken only from the `Permissions`
  returned for the key whose signature verified** (`ServerConn.Permissions`), never from the last key the callback saw
  (CVE-2024-45337 class). Requires `golang.org/x/crypto` ≥ v0.31.0, pinned by the CI vuln scan.
- Rotation: add new key → agent switches → revoke old (immediate). Last-used timestamps help detect stale keys.
- Revocation: `state=revoked`, enforcer terminates connections authenticated by the key (HP-AGT-005).

### 11.2 Destination host identities (HP-SRV-004..007)

- Enroll by paste (operator supplies a known_hosts or `.pub` line), or by scan: Hallpass dials through the egress guard, collects
  offered host keys (one handshake per algorithm), and shows fingerprints as `pending`. An operator confirms each against an
  out-of-band source, and the identity becomes `active` (audited with the confirmer). The UI warns that scan-confirm is only as good as the
  out-of-band check.
- Verification: `HostKeyCallback` accepts only `active` identities of that server (any algorithm), or a host certificate signed
  by the server's bound host CA with `CertType=HostCert`, a valid window ≤ CA `max_validity`, and a principal ∈ server's
  `host_ca_principals`. `HostKeyAlgorithms` is set to the algorithms of enrolled identities (or cert algorithms) to avoid
  negotiating an unenrolled key type.
- Rotation: enroll new (`pending`→`active`) alongside old, then retire old. A mismatch fails with an alert event
  `server.host_key_mismatch` (fingerprint presented) and exit 88 to the agent.
- Duplicates: on activate, if the fingerprint is active on another server without an exception → reject with a list of conflicts.
  Exceptions record justification and actor and require reauth.

### 11.3 Destination login credentials (ADR-0006, HP-KEY-*)

- **Default: managed Ed25519 key per server-role binding.** Generate with `ed25519.GenerateKey(crypto/rand)` and seal the private key
  with the `credential` purpose key (AAD = `login_credentials|private_enc|<id>|<kid>`). The UI shows the public key and
  `restrict,pty,from="<egress CIDRs>" ssh-ed25519 AAAA… hallpass:<server>/<role>` (drop `pty` if the role lacks the capability).
- Lifecycle: `generate` → `pending` → `probe` (Hallpass connects with the pending key, verifies host identity and
  authentication, then closes without running anything) → `activate` (the previous active one becomes `retiring` with `retire_after`, default 24 h)
  → automatic `retired` → (operator removes it from authorized_keys). `revoke` is immediate and terminates channels using it.
  Only one `active` per role (partial unique index). New channels always use `active`.
- **Alternative: OpenSSH user certificates.** A user CA (Ed25519, sealed) signs a certificate per outbound connection:
  ephemeral Ed25519 key pair in memory; `KeyId = "hallpass:<grant>:<connection>"`; `ValidPrincipals` = role binding principals
  (explicit, never derived from agent input); `ValidAfter = now-30s`, `ValidBefore = now+ttl` (default 120 s, it only needs to
  cover authentication; sessions are cut by the enforcer since certificate expiry does not end sessions); extensions limited
  to role capabilities (`permit-pty` only if `pty`); no `permit-port-forwarding`, `permit-agent-forwarding` or
  `permit-X11-forwarding`. Destinations trust the CA via `TrustedUserCAKeys` with `AuthorizedPrincipalsFile`.
- **Signer abstraction (HP-KEY-005):** `Signer{PublicKey() ssh.PublicKey; Sign(io.Reader, []byte) (*ssh.Signature, error)}`. External
  signers must produce SSH signature formats: Ed25519 raw (64 B), ECDSA P-256/384 converted from DER to SSH `(r,s)` mpints,
  RSA PKCS#1 v1.5 with SHA-256/512. KMS backends that support only other schemes (e.g. RSA-PSS only) are incompatible.
  v1 ships only the sealed local signer, and the KMS/HSM adapter is review item R-03.
- **Imported keys:** permitted for migrations (`kind=imported_key`), shown with a warning, never exported.
- Separation (HP-KEY-006): Go types `HostIdentity`, `HostCA`, `LoginCredential`, `UserCA` and `GatewayHostKey` have no shared
  interface that would allow substitution. Separate tables, API resources, UI pages and doc sections.

---

## 12. Operator authentication and RBAC

### 12.1 Login modes

`auth.local.enabled` and `auth.oidc.enabled` (≥ 1 provider). The login page renders from `GET /auth/config`: local form, SSO buttons,
or both. Disabling local login requires (HP-AUTH-015): an enabled OIDC provider with `test_login_ok_at` within 24 h by an
administrator who currently holds `administrator` via that provider (manual or mapped), and confirmation with reauth.
Break-glass (`hallpass admin recover`) works even when local login is disabled, because it creates a single-use recovery login
that is valid regardless of mode.

### 12.2 Local accounts (HP-AUTH-*)

- Bootstrap: `hallpass admin bootstrap` (server may be running, it uses the DB writer via the admin socket
  `<data>/admin.sock` (0600), or the server is stopped and the CLI takes the lock) prints a one-time URL with the setup token. The
  token is accepted only while no administrator exists. Setup forces password + TOTP enrollment.
- Argon2id: `golang.org/x/crypto/argon2.IDKey`, params `v1: m=65536 KiB, t=3, p=2, salt 16 B, key 32 B`. `hallpass admin
  calibrate` tunes t so one hash takes about 250–500 ms. Stored PHC `$argon2id$v=19$m=…,t=…,p=…$salt$hash` plus `params_version`.
  Rehash on successful login when below current version. Concurrent hash computations are limited by a semaphore (CPU/memory DoS guard).
- Normalization: NFKC, then byte length check 12–1024. Over-limit input is rejected, never truncated. No composition rules.
  An optional offline breached-password list is a review item, not v1.
- Throttle: keys `acct:<id>` and `ip:<prefix>` (IPv4 /32, IPv6 /64). Delay = min(2^(failures-3) s, 15 min) after 3
  failures. The counter decays after 24 h idle. Successful login resets the account key. The response is uniform `invalid credentials`,
  with a dummy Argon2id verification for unknown users.
- TOTP: `pquerna/otp` (or an equivalent minimal implementation tested against RFC 6238 vectors). Secret 20 B, encrypted. Enrollment needs a confirmation
  code. `last_step` prevents reuse. Recovery codes: 10 × 12 Crockford chars, HMAC-hashed, single use.
- Reset: an admin issues a reset token (reauth). Delivery by email if SMTP is configured, else shown once to the admin to pass out
  of band. Reset forces MFA re-verification if enrolled, and invalidates all sessions.
- Invitations: admin creates with a preset role. Single-use link with 72 h expiry. Accepting sets the password (and MFA if required).

### 12.3 Browser sessions (HP-AUTH-012..014)

- Cookie `__Host-hp_session` (Path=/, Secure, HttpOnly, SameSite=Lax). The value is 32 random bytes and the DB stores SHA-256. In development
  over `http://localhost`, the cookie name drops `__Host-` and the `Secure` flag (dev mode only).
- SameSite=Lax is required so the top-level GET redirect from the IdP to `/auth/oidc/callback` carries the pre-login state cookie
  (`__Host-hp_oidc`, 10 min, bound to `oidc_auth_states.session_binding`). Mutations are protected by CSRF (below), not SameSite alone.
- CSRF: per-session secret, token `HMAC(secret, session_id)` delivered in `GET /me` and sent as `X-CSRF-Token`. Requests must also carry
  `Sec-Fetch-Site: same-origin` or a matching `Origin`. Login itself (login-CSRF) uses a pre-session CSRF cookie plus header.
- Expiry: idle 30 min, absolute 12 h (configurable). `last_seen_at` writes are debounced (≥ 60 s).
- Rotation: new session ID on login, MFA completion, reauth, and role changes. Old IDs revoked.
- Recent auth: `auth_at` (and `mfa_at`) within `auth.reauth_window` (5 min) for the actions in HP-AUTH-014. Otherwise 401
  `reauth_required`. The UI then prompts for password (+TOTP) or an OIDC step-up redirect (§12.4).
- Security headers (HP-API-007): CSP `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'` (Ant Design
  CSS-in-JS needs runtime style injection; nonce-based styles are evaluated in WP19, tracked as R-11); `img-src 'self' data:`;
  `connect-src 'self'`; `frame-ancestors 'none'`; `base-uri 'none'`; `form-action 'self'` (+ IdP origin for the form-post response mode if used).

### 12.4 OIDC (HP-OIDC-*)

- Libraries: `github.com/coreos/go-oidc/v3` (discovery, ID token verification, remote JWKS with refetch on unknown `kid`) and
  `golang.org/x/oauth2` (code exchange with `oauth2.S256ChallengeOption`/`VerifierOption`).
- Flow: `/auth/oidc/{provider}/start?return_to=/x` → create state (32 B), nonce (32 B), PKCE verifier. Store hashes and encrypted
  verifier in `oidc_auth_states` (10 min). Set `__Host-hp_oidc` binding cookie → redirect. Callback: look up the state hash, check the
  binding cookie and expiry, delete the state (single use), exchange the code with the verifier, verify the ID token (`go-oidc` verifier with
  ClientID; `SupportedSigningAlgs = [RS256, ES256, EdDSA]`; skew 60 s; `azp` == client_id when `aud` has multiple values)
  and nonce. Discard access/refresh tokens.
- Identity: `(iss, sub)`. Known → operator. Unknown → `preprovisioned` mode: reject with "not provisioned" (no account
  existence leak beyond that). `jit` mode: require restrictions (`email_verified=true` with domain ∈ allowlist, `tid`/`hd` claims,
  or group ∈ allowlist), then create the operator with no roles unless mappings apply.
- Pre-provisioned operators: an admin creates the operator with an "expected identity" (`issuer` + `sub`, or a one-time link
  invitation the user completes by SSO login). Email match alone never links (HP-OIDC-009).
- Group mapping: the `groups_claim` value (string array) is matched exactly against allowlisted mapping rows. Results are internal roles and/or
  operator groups. At each login, `source='sso'` assignments are replaced with the mapped set, and `manual` ones are untouched.
  Effective roles = union. A removed group drops its role at next login. Admins can force re-login (revoke sessions). Absolute
  session expiry (12 h) bounds staleness (HP-OIDC-011).
- Validation of provider config: issuer must be `https://` (except `http://localhost` / `127.0.0.1` in dev mode). The discovery
  document's `issuer` must equal the configured issuer exactly. Endpoints must be https and, unless `allow_cross_origin_endpoints`,
  share the issuer's registrable domain. Resolved IPs that are private, loopback or link-local are refused unless
  `allow_private_network=true` (explicit, audited). An optional `ca_bundle_pem` adds trust roots and never disables verification.
- Step-up: `prompt=login&max_age=0` (purpose `stepup`). Accept if `auth_time` ≥ request time - skew. If `acr_values` are configured, verify
  `acr`. If the provider omits `auth_time`, step-up fails unless `stepup.fallback = local_totp` is configured. Then the operator must have
  TOTP enrolled in Hallpass.
- Test login: the admin starts the purpose `test` flow from settings, completes the IdP login, and Hallpass shows the claims, the mapping outcome and the
  role result without creating a session. Stores `test_login_ok_at` (HP-OIDC-014).
- Outage: discovery/JWKS fetch failures → login error page "identity provider unavailable". Cached JWKS is used for in-flight
  callbacks. Existing sessions are unaffected (HP-OIDC-012).
- Logout: revoke the Hallpass session. If `end_session_endpoint` exists and is enabled, redirect with `id_token_hint` omitted
  (not retained) and `client_id` + `post_logout_redirect_uri`.

### 12.5 RBAC matrix (HP-RBAC-*)

| Permission | Administrator | Approver | Auditor | Viewer |
|---|:-:|:-:|:-:|:-:|
| dashboard.view, inventory.read (no addresses), requests.read, sessions.read | ✓ | ✓ | ✓ | ✓ |
| requests.reason.read | ✓ | ✓ (in scope) | ✓ | — |
| inventory.address.read | ✓ | — | configurable | — |
| inventory.write, policy.write | ✓ (reauth for deletes) | — | — | — |
| policy.read, effective-access preview | ✓ | ✓ | ✓ | ✓ |
| credentials.manage, keys.manage (keyring, gateway host key) | ✓ + reauth + MFA | — | — | — |
| requests.decide, requests.cancel | ✓ (needs approver rule) | ✓ (approver rule) | — | — |
| grants.revoke, activities.terminate | ✓ | ✓ (in scope) | — | — |
| recording.play | ✓ | — (configurable per scope) | ✓ | — |
| recording.export | ✓ + reauth | — | configurable + reauth | — |
| audit.read, audit.verify | ✓ | — | ✓ | — |
| retention.manage | ✓ + reauth | — | — | — |
| operators.manage, auth.settings, integrations.manage | ✓ + reauth | — | — | — |
| system.lockdown (enable) | ✓ + reauth | ✓ (enable only, if `approvers_can_lockdown`) | — | — |
| system.lockdown (lift), system.settings | ✓ + reauth | — | — | — |

Authorization is one `rbac.Authorize(ctx, principal, permission, resource)` call per handler, generated from an OpenAPI
`x-permission` extension. CI verifies every operation declares one. A parameterized suite runs the whole matrix for local and SSO principals
(HP-RBAC-006).

---

## 13. Encrypted event/history format and consistency protocol

### 13.1 Keyring (ADR-0004, HP-CRY-001/002)

- KEK: 32 random bytes, provisioned as `HALLPASS_KEK_FILE` (default `/etc/hallpass/kek`, base64 or raw), `HALLPASS_KEK` (base64,
  discouraged), or a secret mount. `hallpass keys init-kek --out FILE` generates one. The KEK ID = first 8 bytes of
  SHA-256("hallpass-kek-id" || KEK), hex.
- Purpose keys: random 32 B per purpose and version, wrapped with AES-256-GCM (nonce 12 B random, AAD = `hallpass/keyring/v1|purpose|version|kek_id`),
  stored in `keyring_keys`. A keyring canary (`settings.keyring_canary` sealed with the field key) detects a wrong KEK at startup.
- KEK rotation (`hallpass keys rotate-kek --new FILE`, offline, lock held): unwrap all purpose keys with the old KEK, rewrap with the new one in one tx,
  and verify the canary. Old KEK no longer needed after a successful backup. Documented sequence with backups.
- Purpose-key rotation (online, admin + reauth): create version n+1 as `active`, mark n `decrypt_only`. A background job re-seals fields
  (batches), and for recordings rewraps segment DEKs (§13.4, key slots). Once nothing references n, mark it `retired` (wrapped key kept until the
  next backup cycle, then deleted).
- Development mode: if no KEK is provided, generate `<data>/dev-kek` (0600) with a startup warning. `mode=production` refuses any KEK inside the data dir.

### 13.2 Field encryption (HP-CRY-003)

`Seal(purpose, aad, pt)` → `0x01 | key_version(u32) | nonce(12) | AES-256-GCM(ct||tag)`. AAD = `table|column|row_id|key_version`.
Random 96-bit nonces are within safe limits at expected volumes (≪ 2^32 encryptions per key). Rotation also resets the count.

### 13.3 HPREC1 segment file (HP-CRY-004, ADR-0005)

```
┌ magic "HPREC1\n\0" (8 B)
├ header_len u32 BE │ header: canonical JSON (sorted keys, no whitespace, ≤ 4 KiB)
│   {"v":1,"segment_id","session_id","channel_id","ordinal","created_at","payload_salt"(16 B b64),
│    "aead":"chacha20poly1305-stream","frame_max":65536,"kind":"pty|exec","prev_segment_sha256"}
├ key slots: 2 × 256 B fixed (A/B), each {"gen":n,"key_id","wrap":"A256GCM","nonce","wrapped_dek"} zero-padded
│   (NOT covered by H; the wrapped DEK is authenticated by GCM with AAD = "hallpass/rec/dek/v1|"+segment_id+"|"+hex(H))
└ frames: repeat { ct_len u32 BE │ ciphertext }
```

- `H = SHA-256(magic || header_len || header)`. Stored in SQLite (`header_sha256`).
- `DEK` = 32 random bytes per segment. `K = HKDF-SHA256(ikm=DEK, salt=payload_salt, info="hallpass/rec/payload/v1")`.
- Frame *i* (0-based): `nonce = BE88(i) || flag` (11-byte counter + 1 byte flag, 0x01 for final frame, 0x00 otherwise).
  `ct = ChaCha20-Poly1305.Seal(K, nonce, plaintext_i, aad=H)`. This is the STREAM construction (Hoang–Reyhanitabar–Rogaway–Vizár)
  as used by age, which gives nonce uniqueness (fresh key per segment + counter), reordering/truncation detection (counter,
  final flag), and header binding (AAD).
- Frame plaintext ≤ 64 KiB: concatenated records `type u8 | seq uvarint | t_us (delta from previous record, zigzag varint) |
  mono_ns uvarint (since channel open) | stream u8 (0 pty, 1 stdout, 2 stderr, 3 stdin, 4 meta) | len uvarint | payload`.
  Record types: `exec.requested`, `pty.requested`, `env.accepted`, `terminal.output`, `terminal.input`, `terminal.resized`,
  `stdout`, `stderr`, `signal`, `eof`, `exit`, `gateway.notice`, `segment.footer`.
- Final frame ends with `segment.footer` {records, first_seq, last_seq, end_reason, plaintext_sha256}.
- Readers stream frame by frame (bounded memory). The REST replay API returns decoded records in pages ≤ 256 KiB.
- Rollover: new segment at 64 MiB ciphertext or 1 h per channel. `prev_segment_sha256` links ordinals.
- Rejected alternatives: AES-GCM per frame with random nonces (truncation not detected without extra structure), age
  library directly (designed for recipients and files, gives no access to per-frame flushing and in-place key-slot rewrap). See ADR-0005.
  **External crypto review required before 1.0 (R-02).**

### 13.4 Key-slot rewrap

Rewrapping a DEK writes the slot with the lower `gen` (the inactive one) as a full 256-byte block, then fsyncs. Readers choose the valid slot with
the highest `gen`. A torn write leaves the other slot intact. The DB `wrapped_dek` copy is updated in the same job (tx after the file fsync).
On startup, if neither slot unwraps but the DB copy does, the slot is repaired.

### 13.5 Write and commit protocol (HP-REC-007/008, HP-DB-012)

1. **Register** (writer tx, §5.6 step 3): `recording_segments` row `open` with path, key ID, wrapped DEK, `header_sha256`.
2. **Create**: `open(path + ".partial", O_CREAT|O_EXCL|O_WRONLY, 0600)`. Write header + key slots. `fsync(file)`, `fsync(dir)`.
   → *Recording established.* Only now may the gateway forward destination data (mandatory mode).
3. **Append**: records go through a bounded queue (1,024 records / 1 MiB) to a per-segment writer goroutine that seals frames when 64 KiB
   accumulate or the flush timer fires. Durability modes:
   - `group` (default): `fsync` at most every 250 ms (and on each final frame). Data reaches disk ≤ 250 ms after capture.
   - `strict`: each frame is sealed and fsynced before the corresponding bytes are forwarded to the agent (higher latency).
   A full queue blocks the producer, which stops reading from the SSH channel so the SSH window closes and backpressure reaches the
   source. Blocking > 10 s, or any write/fsync error → channel terminated (`recording_failed`), timeline `recording.failed`, segment `failed`.
4. **Finalize**: seal the final frame (flag 1, footer), `fsync(file)`, `rename(.partial → .hprec)`, `fsync(dir)`, then writer tx:
   state `finalized`, `ciphertext_sha256`, `frames`, `bytes`, seq range, plus append to `integrity_chain`
   (`hash = SHA-256(prev_hash || manifest_sha256)`, `mac = HMAC(manifest_key, hash)`).
   → *Recording durable and complete* only after this tx commits.
5. **Best-effort mode** (`recording_mode=best_effort`, opt-in per role): recorder failure marks the segment `failed` and emits
   `recording.failed`, but forwarding continues. The UI flags such sessions prominently.

Lifecycle timeline events (`channel.opened`, `exec.requested` (metadata only, no command text), `channel.exited`, …) go to
`timeline_events` in SQLite with non-sensitive `data_json`. Payloads (command strings, terminal bytes, input) exist only in segments.

### 13.6 Startup reconciliation (HP-DB-013, HP-REC-009)

1. Connections/channels in `open|opening|active` with a different `boot_id` → `interrupted` (closed_at = last known activity or boot time).
2. Segments `open` in DB:
   - file `.partial` exists → scan frames, authenticating each, stop at the first failure or EOF → rename to `.hprec`, state `interrupted`,
     record `frames`, `last_seq`, `ciphertext_sha256` of the valid prefix, and truncate any trailing partial frame (after copying the original
     to quarantine).
   - final `.hprec` exists (crash between rename and DB update) → verify all frames including the final frame → `finalized`
     with hashes computed now, and append the integrity-chain entry.
   - no file → state `missing` if the channel had become `active`, `failed` otherwise.
3. Files in the recordings tree with no DB row → move to `<data>/quarantine/` and record in `quarantine_files` (orphan) with an operator alert.
4. Finalized rows whose file is absent → `missing`, with an alert.
5. Grants past expiry → `expired`. Sessions with no live channels and inactive grant → `closed`. Requests past expiry → `expired`.
6. Jobs with expired leases → requeued. Outbox `sending` → `queued`.

### 13.7 Verification (HP-CRY-005)

`hallpass verify [--session X | --all] [--offline]` checks every segment: header hash matches DB, a slot unwraps, all frames
authenticate in order, final flag present (finalized), ciphertext SHA-256 matches, and integrity chain hashes and MACs are valid.
It reports per segment `ok|interrupted|corrupt|missing|orphan`. A scheduled online verification of a 1% sample per day plus newly finalized segments
writes `verified_at`/`verify_result`.

### 13.8 Tamper evidence limits and external anchoring (HP-CRY-008)

An attacker with the KEK and write access can forge consistent segments, chain entries and MACs. Hallpass therefore offers
`hallpass anchors export --since <seq>`, which emits chain heads (`seq`, `hash`, timestamp) for shipping to external append-only
storage (object lock/WORM bucket, transparency log, or a separate log host). A later verification compares local chain heads to the anchors.
This detects rewriting of history **before** the latest exported anchor. It cannot protect data written after compromise or prevent deletion of
not-yet-anchored data. A built-in scheduled anchor push to S3 Object Lock is a stretch goal, not v1 scope.

### 13.9 Retention and deletion (HP-REC-013)

Retention classes (`default` 90 d, configurable per server group/role). The retention job selects closed sessions past `delete_after`.
It deletes segment files (fsync dir), sets segment state `deleted` (keeping the hash, chain entry and tombstone), deletes `timeline_events` payload rows
but keeps a summary, and writes an audit event. Backups taken earlier still contain the data until they expire, which the operator guide documents.

### 13.10 Backup consistency (HP-OPS-003)

`hallpass backup --out DIR` (online):
1. `VACUUM INTO DIR/hallpass.db` gives a consistent snapshot at time T.
2. Read the snapshot's `recording_segments` rows. Copy each `finalized`/`interrupted` file with a hash check against the DB. For segments
   `open` at T, copy the current `.partial` and record it as "open at snapshot". Restore will reconcile it as interrupted.
3. Write `DIR/manifest.json` {version, created_at, binary version, schema version, kek_id, files[{path, sha256, size}]} and `manifest.sha256`.
4. KEK is **not** included (`kek_id` lets restore check that the right KEK is supplied). Operators back up the KEK separately (HP-CRY-007).
Files created after T aren't in the snapshot and are excluded, which matches the DB view.

---

## 14. UI architecture and design system

### 14.1 Stack (ADR-0013)

React 19 + TypeScript (strict) + Vite. TanStack Router (file-based routes, type-safe search params for filters), TanStack Query
(server state; SSE events → `queryClient.invalidateQueries`), TanStack Store (client-only: theme, density, SSE status, table
column prefs, saved filters cache), and TanStack Devtools loaded via `import.meta.env.DEV` dynamic import (tree-shaken from prod).
Ant Design v5 (tables, forms, layout, a11y-reviewed components), Apache ECharts via `echarts-for-react`-style thin wrapper
with theme registration, xterm.js (+ fit addon) for replay. Package manager pnpm. Lint: ESLint (typescript-eslint strict,
jsx-a11y), Prettier. Unit/component tests: Vitest + Testing Library. E2E: Playwright (Chromium; ADR-0038) + `@axe-core/playwright`.

### 14.2 Design system (`web/src/ds/`)

- Tokens: `borderRadius 4` (cards 6), `controlHeight 32` (compact tables 28), font: system UI stack plus `JetBrains Mono` for
  code/fingerprints (self-hosted, no external fonts due to CSP). Neutral grays, one brand accent, semantic success/warning/error/info,
  subtle 1px borders, `boxShadow` level 1 only for overlays. Light and dark via `theme.darkAlgorithm` with custom token
  overrides. Contrast is checked by a token test (WCAG AA 4.5:1 for text).
- Components: `PageHeader`, `DataTable` (server-side pagination/sort/filter, column chooser, saved filters, empty/error/stale
  states), `StatusBadge` (restrained, no pills), `Countdown` (server-offset-corrected), `Fingerprint` (monospace + copy),
  `ConfirmAction` (typed confirmation for high impact), `ReauthGate`, `UntrustedText` (renders agent-provided text as plain text with
  label), `ChartCard` (ECharts + accessible summary table toggle), `Timeline`, `TerminalReplay`, `KeyValueGrid`, `CopyField`,
  `PermissionGate`, `ConnectionBanner` (SSE disconnected/stale).
- Storybook-free: a `/__ds` route available only in dev builds acts as the visual-regression gallery for Playwright snapshots.

### 14.3 Routes

`/login`, `/setup`, `/` (dashboard), `/requests`, `/requests/$id`, `/sessions`, `/sessions/$id` (detail with timeline + replay),
`/activities`, `/agents`, `/agents/$id` (keys, groups, labels, effective access, audit), `/servers`, `/servers/$id` (host identities,
roles, credentials), `/roles/$id`, `/groups`, `/policy` (rules, approver rules, preview), `/operators`, `/operators/$id`,
`/settings/auth`, `/settings/integrations`, `/settings/storage` (retention, storage, key status), `/settings/system` (health, lockdown),
`/audit`, `/me`.

### 14.4 Data and live updates

- `api/client.ts`: fetch wrapper adding CSRF and handling `problem+json`, `reauth_required` (opens ReauthGate then retries once), and 401 → login.
- Query keys mirror resources (`['requests', filters]`, `['request', id]`). SSE manager maps event `resource` → keys to invalidate.
  Exponential reconnect. `reset` → invalidate all. Connection status goes to the store and `ConnectionBanner`.
- Server time offset is computed from the `Date` response headers plus `GET /system/time`, smoothed. Countdowns render from server timestamps.
- No optimistic updates on security mutations (approve/deny/revoke/keys/policy/auth). Buttons show pending state until the server confirms.

### 14.5 Replay safety (HP-UI-013)

xterm.js with `linkHandler: null`, no WebLinks addon, OSC 8 (hyperlinks) and OSC 52 (clipboard) handlers registered to swallow,
title-change events ignored, bell muted, `allowProposedApi: false`. Data fed in bounded chunks from the records API.
Exec stdout/stderr shown in separate panes. Command strings and reasons rendered via `UntrustedText` (no HTML). A per-stream selector handles concurrent
channels. Timeline playback is positioned by `mono_ns`, and the exec provenance badge says `captured` (exec request), `destination-audit`
(WP25) or `inferred`.

### 14.6 Charts (HP-UI-009)

Dashboard: requests by state over time, decisions latency (p50/p95), active sessions/channels, recording storage growth, notification
delivery success. All are backed by `/stats/*` endpoints that aggregate SQLite data (and Prometheus-equivalent in-process counters for live values).
Every chart has a "View as table" toggle and an `aria-describedby` summary.

---

## 15. Repository and module layout

Module: `github.com/aurimasniekis/go-hallpass`. Binary: `hallpass`.

```
cmd/hallpass/                 main: serve, migrate, backup, restore, verify, keys, hostkey, admin {bootstrap,recover,calibrate}, anchors, version
internal/app/                 wiring, lifecycle, shutdown, admin socket
internal/config/              config schema, validation, modes
internal/obs/                 slog setup, redaction, OTel, metrics, health/readiness
internal/store/               open, pragmas, pools, Tx, retry, flock, statfs check, backup primitive
internal/store/migrations/    NNNN_*.sql (goose, embedded)
internal/store/queries/       *.sql (sqlc input)       internal/store/db/   (sqlc output)
internal/keyring/             KEK loading, KeyWrapper, purpose keys, field AEAD
internal/audit/               audit writer, hash chain, verifier
internal/jobs/                scheduler, leases, outbox worker framework
internal/eventbus/            typed in-process pub/sub
internal/ids/                 prefixed UUIDv7 IDs
internal/agents/              agent + key service, key parsing/policy
internal/inventory/           servers, roles, host identities, host CAs, duplicate exceptions
internal/credentials/         login keys, user CAs, Signer, cert issuance, probe
internal/egress/              anti-SSRF guard, dialer
internal/policy/              rules, selectors, snapshot compiler, evaluator, explain, approver rules
internal/access/              requests, decisions, grants, sessions, channels, enforcer, reconciler
internal/sshfront/            SSH server, auth, limits, command dispatch
internal/sshfront/grammar/    tokenizer, parser, JSON schemas, exit codes
internal/sshproxy/            outbound client, channel bridging, PTY/env/signals, host verification
internal/recording/           recorder, queue, writer, reader, reconciliation, verify
internal/recording/hprec/     HPREC1 format (pure, fuzzed)
internal/opauth/              local auth, argon2id, TOTP, recovery codes, sessions, CSRF, throttling, bootstrap, break-glass
internal/oidc/                provider config, discovery validation, flows, mapping
internal/rbac/                permissions, matrix, Authorize
internal/httpapi/             router, middleware, handlers, SSE hub, static UI embed
internal/httpapi/gen/         oapi-codegen output
internal/notify/              core, outbox delivery, action tokens, sanitization
internal/notify/slack/  internal/notify/telegram/  internal/notify/web/
internal/backup/              backup/restore/verify orchestration, anchors export
internal/destaudit/           (WP25) destination audit ingestion
api/openapi.yaml              api/ssh-schemas/*.json
web/                          Vite app (src/{app,routes,features,ds,api,sse,stores}), e2e/, package.json
deploy/                       Dockerfile, compose.yaml, systemd/hallpass.service, examples/hallpass.example.yaml
test/openssh/                 container fixtures (sshd variants, ssh client), Go integration tests
test/fault/                   fault-injection harness (failing FS, ENOSPC, kill -9 scenarios)
test/soak/  test/recovery/    soak driver, restore drills
tools/analyzers/              custom vet analyzers (txscope, no-insecure-hostkey)
docs/                         GOAL, PLAN, DECISIONS, THREAT_MODEL, TEST_STRATEGY, PROMPT, formats/, operator/, agent/, destination/, evidence/
.github/workflows/            ci.yaml, release.yaml, codeql.yaml
```

Rules: `internal/` only. `hprec`, `grammar`, `policy` have no I/O dependencies (pure, fuzzable). `depguard` forbids
`math/rand` in security packages, `log` and `fmt.Print*` outside `cmd/`, and `ssh.InsecureIgnoreHostKey` anywhere.

---

## 16. Threat model

See `docs/THREAT_MODEL.md` (assets, trust boundaries TB-1..TB-8, adversaries, threats T-01..T-22 covering all 17 brief scenarios
with requirement-ID mitigations, assumptions, residual risks). Key statement: **Hallpass is a high-value trusted component
that can access plaintext proxied session data. Its compromise is equivalent to compromise of all destination access it brokers
during the compromise window.**

---

## 17. Test matrix and release gates

See `docs/TEST_STRATEGY.md` for layers, the per-requirement matrix, the fault-injection catalog FI-01..FI-24, performance
methodology and reference hardware, and release-gate evidence. Release gates RG-1..RG-11 are defined in `docs/GOAL.md` §8.

---

## 18. Operational procedures

Each procedure becomes a page in `docs/operator/` during the WP listed.

| # | Procedure | Outline | WP |
|---|---|---|---|
| 18.1 | Install | Create service user, data dir `0700`, `hallpass keys init-kek --out /etc/hallpass/kek` (0400), write config from `deploy/examples`, `hallpass migrate`, `hallpass serve`, `hallpass admin bootstrap`. Container: mount data volume + KEK secret. | WP24 |
| 18.2 | Gateway host-key publication | `hallpass hostkey show` → distribute known_hosts line or set up host CA. Rotation per §7.8. | WP10 |
| 18.3 | Register agent | Create agent → add public key → assign groups/labels → verify with effective-access preview → agent tests `ssh center list`. | WP20 |
| 18.4 | Enroll server | Create server (egress check) → enroll host identity (paste or scan+confirm) → create role → generate login key → install authorized_keys line on destination → probe → activate. | WP20 |
| 18.5 | Upgrade | Read release notes → `hallpass backup` → stop → replace binary/image → start (auto pre-migration snapshot) → check `/readyz` and `hallpass verify --sample`. Rollback = stop, restore pre-upgrade backup/snapshot with the previous binary. Data written after upgrade is lost. Never run an older binary on a newer schema (refused). | WP23 |
| 18.6 | Backup | Hourly `hallpass backup` (online) to a separate volume plus an off-host copy. Segments can additionally be rsynced continuously (immutable once finalized). KEK backed up separately, offline, at least two copies. Optional Litestream (R-04). | WP23 |
| 18.7 | Retention | Configure classes. Retention job daily. Watch `hallpass_storage_*` metrics. | WP12/WP20 |
| 18.8 | Restore / disaster recovery | New host → install binary → provide KEK → `hallpass restore BACKUP_DIR --data /var/lib/hallpass` (empty target, checks manifest hashes and `kek_id`) → `hallpass verify --all` → start → reconciliation marks open segments interrupted → repoint DNS. Drill quarterly. | WP23 |
| 18.9 | KEK rotation | Backup → stop → `hallpass keys rotate-kek --old … --new …` → start → backup → retire old KEK after the retention of backups made with it. | WP23 |
| 18.10 | Purpose-key rotation | UI/CLI (admin + reauth). Background rewrap progress on the storage page. | WP23 |
| 18.11 | Login-credential rotation | Generate → install → probe → activate → wait overlap → remove old authorized_keys line → retire. | WP20 |
| 18.12 | Incident: suspected agent compromise | Revoke agent keys or disable agent (terminates within 5 s) → review sessions/recordings → rotate destination credentials if the agent had shell on them → export anchors. | WP23 |
| 18.13 | Incident: suspected gateway compromise | Enable lockdown → isolate host → rotate all login credentials and CA trust on destinations → rotate gateway host key → new KEK → restore from a pre-compromise backup on a clean host → compare chain heads with external anchors. | WP23 |
| 18.14 | Disk full / storage degraded | `/readyz` degraded + alert → free space or expand volume → readiness recovers automatically once checks pass. Interrupted recordings stay labeled. | WP22 |
| 18.15 | Corruption | Stop → `hallpass verify --offline` + `sqlite integrity_check` report → restore latest good backup → reconcile. | WP23 |
| 18.16 | Lost administrator (break-glass) | On the host: stop service (or use admin socket in offline mode) → `hallpass admin recover --operator EMAIL|--new-admin` (requires lock + KEK) → one-time recovery login URL (30 min) → audit event `breakglass.used` → raise alert on next start. | WP23 |
| 18.17 | Lockdown | Admin enables (UI/CLI) → all grants revoked, requests/channels refused → investigate → lift with reauth. | WP09/WP20 |
| 18.18 | Capacity planning | Measured per-channel storage rates (WP26) → sizing table in docs. Disk alerts at 80/90%. `storage.min_free` reserve. | WP22 |

Graceful shutdown and draining are in §3.4. Destination firewalling: allow inbound 22 only from gateway egress IPs, and pair that with
`from=` on authorized_keys (HP-DOC-003).

---

## 19. Implementation work packages

Ordering is dependency-driven. Each WP ends with a **local commit** (message via `/cc`, `git commit`, never push).
"Owns" lists requirement IDs whose box in §21 is checked when the WP completes.

### 19.1 Packages

#### WP00 — Planning documents *(this phase)*
- **Goal:** persist the product contract, plan, decisions, threat model, test strategy, brief and agent rules.
- **Depends:** none. **Files:** `docs/{GOAL,PLAN,DECISIONS,THREAT_MODEL,TEST_STRATEGY,PROMPT}.md`, `AGENTS.md`.
- **Acceptance:** all files present, requirement IDs consistent across GOAL/PLAN/TEST_STRATEGY, PROMPT.md identical to the brief.
- **Commit:** `docs: add hallpass product contract, plan, and threat model`.

#### WP01 — Repository scaffolding, CI and lint
- **Goal:** buildable skeleton with quality gates from day one.
- **Depends:** WP00.
- **Files:** `go.mod`, `cmd/hallpass/main.go` (version only), `.golangci.yml`, `tools/analyzers/{txscope,nohostkeyignore}`, `Makefile`
  (or `justfile`), `.github/workflows/ci.yaml`, `.gitignore`, `.editorconfig`, `.gitleaks.toml`, `docs/README.md` index.
- **Design:** golangci-lint (govet, staticcheck, errcheck, gosec, depguard, forbidigo, revive, bodyclose, contextcheck),
  `go test -race ./...`, `govulncheck`, gitleaks, coverage report with per-package floor script (HP-TST-009), fuzz-smoke job placeholder.
  CI uses pinned action SHAs.
- **Tests:** analyzer tests (`analysistest`) proving `InsecureIgnoreHostKey` and tx-scope violations are flagged.
- **Acceptance:** CI green on skeleton. Owns: `HP-CRY-006`, `HP-OPS-008`, `HP-OPS-012`, `HP-TST-001`, `HP-TST-009`.
- **Docs:** `CONTRIBUTING.md` draft (dev setup, commit rules). **Commit:** `build: scaffold go module, lint, and ci pipeline`.

#### WP02 — Configuration, runtime modes, logging foundation
- **Goal:** strict config and safe production/development modes; slog JSON with redaction.
- **Depends:** WP01. **Files:** `internal/config`, `internal/obs/{log,redact}`, `deploy/examples/hallpass.example.yaml`.
- **Design:** YAML file + `HALLPASS_*` env overrides (`knadh/koanf` or a minimal custom loader; pick in WP02 and record an ADR),
  unknown keys rejected, durations typed, `mode: production|development`. Production rejects: HTTP public base URL (except
  localhost), dev KEK, `devauth`, KEK inside data dir. Logger: `slog.JSONHandler` with ECS-aligned keys (`@timestamp`,
  `log.level`, `message`, `event.action`, `event.outcome`, `trace.id`, `hallpass.*`). `redact.Secret[T]` type with `LogValue`, plus a key
  denylist (`reason`, `command`, `password`, `token`, `secret`, `cookie`, `authorization`).
- **Tests:** config validation table tests. Redaction tests that capture handler output and assert absence of planted secrets.
- **Acceptance:** Owns: `HP-OPS-013`, `HP-OBS-001`, `HP-OBS-002`. **Docs:** `docs/operator/configuration.md` skeleton, `docs/operator/logging.md` (field schema).
- **Commit:** `feat(config): add validated config, runtime modes, and redacted logging`.

#### WP03 — SQLite storage, migrations, process lock, backup primitive
- **Goal:** the storage layer of §4.
- **Depends:** WP02. **Files:** `internal/store/*`, migrations `0001`, `sqlc.yaml`, `internal/ids`.
- **Design:** §4. `Writer.Tx` with `BEGIN IMMEDIATE`, retry, duration histogram. Reader pool `query_only`. flock. statfs check
  (Linux magic numbers for NFS, SMB/CIFS, SMB2, FUSE-sshfs, 9p). `quick_check`. Snapshot-before-migrate. `VACUUM INTO` backup primitive. Permission checks.
- **Tests:** pragmas on every pooled connection; concurrent writers (100 goroutines) with no `SQLITE_BUSY` surfacing; tx-duration
  guard; second process lock failure; migration failure rollback (injected bad migration); newer-schema refusal; snapshot restore round-trip; permissions refusal.
- **Acceptance:** Owns: `HP-DB-001`, `HP-DB-002`, `HP-DB-003`, `HP-DB-004`, `HP-DB-005`, `HP-DB-006`, `HP-DB-007`, `HP-DB-008`, `HP-DB-009`, `HP-DB-010`, `HP-DB-011`, `HP-DB-012`. **Docs:** `docs/operator/storage.md`. **Commit:** `feat(store): add sqlite storage with migrations, locking, and snapshots`.

#### WP04 — Keyring and field encryption
- **Depends:** WP03. **Files:** `internal/keyring`, migration additions (keyring table in 0001), `cmd/hallpass keys init-kek|rotate-kek|status`.
- **Design:** §13.1–13.2. KEK loaders, canary, purpose keys, `Seal/Open`, rotation job hooks.
- **Tests:** round-trip, AAD mismatch rejection, wrong KEK detection, KEK rotation (offline), purpose-key rotation with re-seal, nonce
  uniqueness property test, production refusal without KEK.
- **Acceptance:** Owns: `HP-CRY-001`, `HP-CRY-002`, `HP-CRY-003`. **Docs:** `docs/operator/keys.md`. **Commit:** `feat(keyring): add kek-wrapped purpose keys and field encryption`.

#### WP05 — Audit events, jobs and outbox framework
- **Depends:** WP04. **Files:** `internal/audit`, `internal/jobs`, `internal/eventbus`, migration `0002`.
- **Design:** audit append within the caller's tx (hash chain computed in tx, `seq` from `MAX+1` under the single writer). Job scheduler with leases,
  exponential retry, dedup keys. Outbox worker framework (provider-agnostic). Bounded event bus with drop-to-reconcile semantics for
  *latency-only* subscribers (security consumers also reconcile from DB).
- **Tests:** chain verification and tamper detection, job lease expiry/requeue, retry bounds, outbox crash recovery.
- **Acceptance:** Owns: `HP-OPS-014`, `HP-OBS-005`. **Commit:** `feat(audit): add hash-chained audit log, durable jobs, and outbox`.

#### WP06 — Agents and agent keys
- **Depends:** WP05. **Files:** `internal/agents`, migration `0003`.
- **Design:** §11.1. Service API used later by HTTP. Uniqueness, tombstones, algorithm policy.
- **Tests:** key parsing table (all algorithms, RSA sizes, options, certs, garbage) + fuzz; uniqueness across agents; revocation events.
- **Acceptance:** Owns: `HP-AGT-001`, `HP-AGT-002`, `HP-AGT-003`, `HP-AGT-004`, `HP-AGT-006`, `HP-AGT-009`. **Commit:** `feat(agents): add agent registry with key lifecycle`.

#### WP07 — Servers, host identities, roles, login credentials and CAs
- **Depends:** WP06. **Files:** `internal/inventory`, `internal/credentials`, `internal/egress`, migrations `0004`, `0005`.
- **Design:** §11.2–11.3, alias rules, egress guard (`netip` prefixes, metadata deny list, re-check after DNS, dial by IP), probe
  (requires WP11 dialer core, so the probe uses a minimal `credentials.Probe` built on `x/crypto/ssh` client + `egress`), gateway host key generation.
- **Tests:** alias/reserved validation; duplicate host detection + exceptions; host CA binding acceptance/rejection; egress guard
  table (loopback, link-local, metadata v4/v6, IPv4-mapped IPv6, DNS rebinding simulation); credential generation/sealing; cert
  issuance fields; signer conversion tests (ECDSA DER → SSH).
- **Acceptance:** Owns: `HP-SRV-001`, `HP-SRV-002`, `HP-SRV-004`, `HP-SRV-005`, `HP-SRV-006`, `HP-SRV-007`, `HP-SRV-009`, `HP-KEY-001`, `HP-KEY-002`, `HP-KEY-003`, `HP-KEY-004`, `HP-KEY-005`, `HP-KEY-006`, `HP-KEY-007`. **Commit:** `feat(inventory): add servers, host identities, roles, and login credentials`.

#### WP08 — Policy engine and effective access
- **Depends:** WP07. **Files:** `internal/policy`, migration `0006`.
- **Design:** §9. Compiled immutable snapshots per version, `Explain`, what-if evaluation, approver rules, self-approval.
- **Tests:** table tests per semantic rule; property tests (deny dominance, monotonicity of adding allow rules, empty selector
  matches nothing, `all` includes newly created objects); fuzz selector parser; benchmark evaluation (target ≤ 50 µs per (agent, server) pair at A-7 scale).
- **Acceptance:** Owns: `HP-POL-001`, `HP-POL-002`, `HP-POL-003`, `HP-POL-004`, `HP-POL-005`, `HP-POL-006`, `HP-POL-007`, `HP-POL-009`, `HP-POL-011`, `HP-POL-012`, `HP-POL-013`, `HP-POL-014`. **Commit:** `feat(policy): add default-deny policy engine with effective-access preview`.

#### WP09 — Requests, decisions, grants, sessions and the enforcer
- **Depends:** WP08. **Files:** `internal/access`, migration `0007`.
- **Design:** §5. CAS transitions, dedup, idempotency, decision tx, grant selection, channel registration, enforcer (events +
  ticker + DB reconciliation), policy-change job, lockdown, disablement cascades, reconciliation (non-recording parts).
- **Tests:** state-machine property tests (random op sequences preserve invariants), race tests (N concurrent deciders, decide vs
  expire vs cancel, register vs revoke) under `-race`, enforcement bound timing test (≤ 5 s, p99 measured), restart reconciliation.
- **Acceptance:** Owns: `HP-AGT-005`, `HP-AGT-008`, `HP-SRV-008`, `HP-POL-008`, `HP-REQ-001`, `HP-REQ-002`, `HP-REQ-003`, `HP-REQ-004`, `HP-REQ-006`, `HP-REQ-007`, `HP-REQ-008`, `HP-GRT-001`, `HP-GRT-002`, `HP-GRT-003`, `HP-GRT-004`, `HP-GRT-005`, `HP-GRT-006`, `HP-GRT-007`, `HP-GRT-008`, `HP-GRT-009`, `HP-GRT-010`, `HP-GRT-011`, `HP-SES-001`, `HP-SES-002`, `HP-SES-003`, `HP-DB-013`. **Commit:** `feat(access): add request, grant, and session lifecycle with enforcer`.

#### WP10 — SSH front end: auth, limits, grammar, gateway commands
- **Depends:** WP09. **Files:** `internal/sshfront`, `internal/sshfront/grammar`, `api/ssh-schemas`, `test/openssh` harness, `docs/agent/*`.
- **Design:** §7, §11.1. `ssh.ServerConfig` with only PublicKeyCallback, restricted algorithms, `MaxAuthTries`, pre-auth semaphore,
  per-IP limiter, handshake deadline. Global request and channel type rejection. Dispatcher for gateway commands. Waiting logic. JSON
  output. Gateway host key management CLI (`hallpass hostkey show|rotate`).
- **Tests:** grammar unit + fuzz + golden JSON; OpenSSH harness (real `ssh` client in container) covering: unknown/revoked keys, username
  spoofing, list/roles visibility, hidden target byte equality, request dedup, wait/timeout/disconnect, exit codes, no-PTY reason → 90,
  forwarding/subsystem denial.
- **Acceptance:** Owns: `HP-SSH-001`, `HP-SSH-002`, `HP-SSH-003`, `HP-SSH-004`, `HP-SSH-005`, `HP-SSH-007`, `HP-SSH-009`, `HP-SSH-013`, `HP-SSH-016`, `HP-SSH-017`, `HP-SSH-018`, `HP-SSH-019`, `HP-SSH-020`, `HP-SSH-021`, `HP-SSH-022`, `HP-SSH-024`, `HP-AGT-007`, `HP-POL-010`, `HP-REQ-005`, `HP-REQ-009`, `HP-TST-003`, `HP-DOC-002`. **Docs:** `docs/agent/guide.md`, `docs/agent/json-schemas.md`, `docs/agent/exit-codes.md`.
- **Commit:** `feat(ssh): add agent ssh front end with command grammar and request flow`.

#### WP11 — SSH data plane
- **Depends:** WP10. **Files:** `internal/sshproxy`, integration with `access` and `egress`.
- **Design:** §5.6, §7.8, §11.2. Outbound client with strict host verification, PTY/env/signal/window-change, EOF/half-close,
  exit-status/exit-signal, keepalive/idle, bounded copy buffers (32 KiB) respecting windows, enforcer registration, graceful shutdown.
  Recording hooks are interfaces with a no-op recorder that **refuses** in mandatory mode until WP12 lands (so no unrecorded forwarding ever ships).
- **Tests:** OpenSSH matrix (sshd 8.x/9.x containers): shell with `-t`, exec stdout/stderr separation, large output, stdin
  streaming, EOF semantics (`ssh … exec -- cat` with closed stdin), exit codes and signals, resize, idle timeout, slow client
  backpressure (bounded RSS), host key mismatch, egress denial, expiry mid-session (≤ 5 s), revocation mid-session, leak checks (goleak).
- **Acceptance:** Owns: `HP-SSH-006`, `HP-SSH-008`, `HP-SSH-010`, `HP-SSH-011`, `HP-SSH-012`, `HP-SSH-014`, `HP-SSH-015`, `HP-SSH-023`, `HP-SSH-025`, `HP-OPS-002`. **Commit:** `feat(ssh): add destination data plane with strict host verification`.

#### WP12 — Recording format, recorder and reconciliation
- **Depends:** WP11, WP04. **Files:** `internal/recording`, `internal/recording/hprec`, migration `0008`, `docs/formats/hprec1.md`.
- **Design:** §13.3–13.7, timeline event writer, sequence block reservation, bounded queue/backpressure, durability modes, retention job.
- **Tests:** format round-trip; tamper tests (bit flip each region, reorder, truncate, drop final, swap segments between sessions → detected);
  fuzz reader; crash tests (kill -9 at each protocol step via fault hooks) → reconciliation results; ENOSPC/EIO → fail closed;
  backpressure under slow disk; verification CLI.
- **Acceptance:** Owns: `HP-REC-001`, `HP-REC-002`, `HP-REC-003`, `HP-REC-004`, `HP-REC-005`, `HP-REC-007`, `HP-REC-008`, `HP-REC-009`, `HP-REC-011`, `HP-REC-013`, `HP-CRY-004`, `HP-CRY-005`, `HP-DOC-005`. **Commit:** `feat(recording): add encrypted hprec1 recorder with crash reconciliation`.

> **Milestone M1, "Core gateway" (WP01–WP12):** agents can list, request (auto-approve policy), connect and exec through
> real OpenSSH with mandatory encrypted recording, enforcement and reconciliation. There is no operator UI yet, and inventory is
> configured through service-level test fixtures and admin CLI seed commands (`hallpass admin seed --file`, dev mode only).

#### WP13 — Local operator authentication, sessions, MFA
- **Depends:** WP05. **Files:** `internal/opauth`, `internal/httpapi` (router, middleware skeleton), `api/openapi.yaml` (auth paths), migration `0009`.
- **Design:** §12.2–12.3, bootstrap via admin socket/CLI, throttling, CSRF, recent-auth middleware, `devauth` build tag.
- **Tests:** Argon2id vectors and param upgrade; throttle progression and no permanent lockout; enumeration timing (statistical
  check: unknown vs known user median within 10%); TOTP RFC vectors and step reuse; recovery codes single use; session rotation,
  idle/absolute expiry, invalidation triggers; CSRF and Origin checks; lockout prevention; prod rejects devauth.
- **Acceptance:** Owns: `HP-AUTH-001`, `HP-AUTH-002`, `HP-AUTH-003`, `HP-AUTH-004`, `HP-AUTH-005`, `HP-AUTH-006`, `HP-AUTH-007`, `HP-AUTH-008`, `HP-AUTH-009`, `HP-AUTH-010`, `HP-AUTH-011`, `HP-AUTH-012`, `HP-AUTH-013`, `HP-AUTH-014`, `HP-AUTH-015`, `HP-AUTH-017`, `HP-AUTH-018`. **Commit:** `feat(auth): add local operator authentication with mfa and sessions`.

#### WP14 — OIDC SSO
- **Depends:** WP13. **Files:** `internal/oidc`, migration `0010`, mock IdP in `internal/oidc/oidctest`.
- **Design:** §12.4.
- **Tests:** mock IdP (Go, in-process, with key rotation, malformed tokens, wrong iss/aud/azp/nonce, expired, alg confusion `none`/HS256,
  missing `auth_time`) plus interop smoke tests against Keycloak and Dex containers in CI (nightly). State replay, open redirect
  attempts, JIT restrictions, email-collision non-merge, group removal, outage.
- **Acceptance:** Owns: `HP-OIDC-001`, `HP-OIDC-002`, `HP-OIDC-003`, `HP-OIDC-004`, `HP-OIDC-005`, `HP-OIDC-006`, `HP-OIDC-007`, `HP-OIDC-008`, `HP-OIDC-009`, `HP-OIDC-010`, `HP-OIDC-011`, `HP-OIDC-012`, `HP-OIDC-013`, `HP-OIDC-014`, `HP-OIDC-015`. **Commit:** `feat(auth): add generic oidc sso with pkce and group mapping`.

#### WP15 — RBAC, REST API and SSE
- **Depends:** WP14, WP12. **Files:** `internal/rbac`, `internal/httpapi` handlers, `api/openapi.yaml` (complete v1), SSE hub, codegen config.
- **Design:** §8, §12.5. Every handler goes through `rbac.Authorize`, `x-permission` CI check, problem details, cursor pagination,
  idempotency keys, rate limits, security headers.
- **Tests:** RBAC matrix suite (local and SSO principals); address-field redaction for non-permitted roles; SSE resume/reset/authorization
  filtering/limits; problem+json shapes; CSP headers.
- **Acceptance:** Owns: `HP-SRV-010`, `HP-RBAC-001`, `HP-RBAC-002`, `HP-RBAC-003`, `HP-RBAC-004`, `HP-RBAC-005`, `HP-RBAC-006`, `HP-RBAC-007`, `HP-API-001`, `HP-API-002`, `HP-API-003`, `HP-API-004`, `HP-API-005`, `HP-API-006`, `HP-API-007`, `HP-API-008`. **Commit:** `feat(api): add rbac-enforced rest api v1 and sse live events`.

#### WP16 — Web approvals and notification core
- **Depends:** WP15. **Files:** `internal/notify`, `internal/notify/web`, migration `0011`.
- **Design:** §10.1–10.3, §10.6–10.7.
- **Tests:** decision authorization table (role, scope, self-approval, MFA, duration bounds); concurrent decisions; outbox retries
  and dead letters with a failing fake provider; failure never approves; sanitization fuzz.
- **Acceptance:** Owns: `HP-API-009`, `HP-NTF-001`, `HP-NTF-002`, `HP-NTF-003`, `HP-NTF-004`, `HP-NTF-007`, `HP-NTF-008`, `HP-NTF-009`, `HP-NTF-010`, `HP-NTF-011`, `HP-NTF-012`, `HP-NTF-013`. **Commit:** `feat(approvals): add decision service, outbox delivery, and web approvals`.

#### WP17 — Slack approvals
- **Depends:** WP16. **Files:** `internal/notify/slack`.
- **Tests:** signature vectors (valid, wrong secret, skewed timestamp, replay), payload fuzz, link flow, unlinked user, message escaping
  (mentions `<!channel>`, `<@U…>`, links), fake Slack API server for delivery/update. Manual verification against a real Slack
  workspace is recorded as **externally verified** evidence.
- **Acceptance:** Owns: `HP-NTF-005`. **Commit:** `feat(approvals): add slack interactive approvals`.

#### WP18 — Telegram approvals
- **Depends:** WP16. **Files:** `internal/notify/telegram`.
- **Tests:** secret token check, chat/user allowlists, callback_data length, update_id replay, fake Bot API server, link flow.
- **Acceptance:** Owns: `HP-NTF-006`. **Commit:** `feat(approvals): add telegram bot approvals`.

> **Milestone M2, "Operable backend" (WP13–WP18):** full API with auth, RBAC and all approval channels.

#### WP19 — Frontend foundation and design system
- **Depends:** WP15. **Files:** `web/*` scaffold, `web/src/ds`, `web/src/api` (generated types), SSE manager, login/setup/MFA pages, Go embed.
- **Design:** §14.
- **Tests:** Vitest for ds components and countdown offset math; Playwright login flows for all three modes; axe on every page;
  visual snapshots of `/__ds` in both themes.
- **Acceptance:** Owns: `HP-UI-001`, `HP-UI-002`, `HP-UI-006`, `HP-UI-007`, `HP-UI-010`, `HP-UI-011`, `HP-UI-012`, `HP-UI-014`, `HP-UI-015`, `HP-UI-016`, `HP-TST-004`. **Commit:** `feat(web): add frontend foundation, design system, and login flows`.

#### WP20 — Operational pages
- **Depends:** WP19, WP16. **Files:** `web/src/routes/*`, `web/src/features/*` for dashboard, requests, sessions list, activities, agents, servers,
  roles, groups, policy + preview, operators, auth settings (incl. test login), integrations, audit, storage/keys, system/lockdown.
- **Tests:** Playwright workflows: register agent → enroll server → policy → agent requests (via the SSH harness) → approve in UI → session
  shows live; revoke; auth settings SSO-only enforcement gating; destructive confirmations; denied states per role; saved filters.
- **Acceptance:** Owns: `HP-SRV-003`, `HP-SES-005`, `HP-UI-003`, `HP-UI-005`, `HP-UI-008`, `HP-UI-009`. **Commit:** `feat(web): add operational console pages`.

#### WP21 — Timeline and replay UI
- **Depends:** WP20. **Files:** `web/src/features/sessions/{timeline,replay}`, records API usage.
- **Tests:** malicious-escape corpus replay (OSC 8/52, title, hyperlinks, huge lines, invalid UTF-8) without side effects; concurrent streams
  separated; exec stdout/stderr panes; provenance badges; export permission/reauth; visual snapshots.
- **Acceptance:** Owns: `HP-REC-006`, `HP-REC-010`, `HP-REC-014`, `HP-UI-004`, `HP-UI-013`. **Commit:** `feat(web): add session timeline and safe terminal replay`.

> **Milestone M3, "Complete console" (WP19–WP21).**

#### WP22 — Observability
- **Depends:** WP15. **Files:** `internal/obs/{otel,metrics,health}`, `docs/operator/observability.md` (metric catalog, log schema, alert rules).
- **Design:** OTel SDK with OTLP exporter (optional) and Prometheus exporter. Spans for HTTP, SSH auth, authorization, dial, decision tx. Readiness
  checks (§4.5). Disk alerts. Correlation IDs propagated through context.
- **Tests:** metrics presence/names golden test, readiness transitions under injected faults, log correlation fields.
- **Acceptance:** Owns: `HP-OPS-001`, `HP-OPS-006`, `HP-OBS-003`, `HP-OBS-004`. **Commit:** `feat(obs): add opentelemetry traces, metrics, and readiness checks`.

#### WP23 — Backup, restore, upgrade, break-glass
- **Depends:** WP12, WP13. **Files:** `internal/backup`, `cmd/hallpass {backup,restore,verify,anchors,admin recover}`, `test/recovery`, `docs/operator/*`.
- **Design:** §13.10, §18.5–18.16.
- **Tests:** scripted drill (create data → backup during active sessions → restore on clean container → verify → sessions reconciled);
  upgrade test from previous release DB fixture (generated, secret-free); break-glass requires lock + KEK and writes audit; anchor export/verify.
- **Acceptance:** Owns: `HP-CRY-007`, `HP-CRY-008`, `HP-CRY-009`, `HP-DB-014`, `HP-AUTH-016`, `HP-OPS-003`, `HP-OPS-004`, `HP-OPS-005`. **Commit:** `feat(ops): add backup, restore, verify, and break-glass recovery`.

#### WP24 — Packaging and release pipeline
- **Depends:** WP22, WP23. **Files:** `deploy/Dockerfile` (multi-stage, `gcr.io/distroless/static-debian12:nonroot`), `deploy/compose.yaml`,
  `deploy/systemd/hallpass.service` (hardening: `ProtectSystem=strict`, `NoNewPrivileges`, etc.), `.github/workflows/release.yaml`
  (goreleaser or scripted: multi-arch binaries, image, syft SBOM, `actions/attest-build-provenance`, checksums), `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`.
- **Tests:** container smoke test (start, readyz, ssh list against fixture), Trivy scan, SBOM presence.
- **Acceptance:** Owns: `HP-OPS-007`, `HP-OPS-009`, `HP-OPS-010`, `HP-OPS-011`, `HP-DOC-001`, `HP-DOC-006`. No LICENSE file until R-01 is resolved. **Commit:** `build(release): add container image, compose, and release pipeline`.

#### WP25 — Optional destination-side audit integration
- **Depends:** WP12, WP21. **Files:** `internal/destaudit`, `docs/destination/*`.
- **Design:** a small collector mode (`hallpass collector`, separate binary target) on destinations reads auditd `EXECVE` records (or
  journald), tags them with `auid`/`ses` and the Hallpass key ID from the SSH certificate or the login key comment, signs batches with a
  per-destination Ed25519 key enrolled in Hallpass, and posts to `/api/v1/destaudit/ingest`. Hallpass correlates by remote user + time window +
  session markers (`HALLPASS_SESSION` env var allowlisted on destination `AcceptEnv`), and labels results `destination-audit` provenance with
  confidence. Docs explain limits: shell built-ins aren't exec'd, history files are user-writable, kernel audit sees exec but not intent,
  a root user can tamper with destination logs.
- **Tests:** correlation unit tests, signature verification, OpenSSH + auditd container test.
- **Acceptance:** Owns: `HP-SES-004`, `HP-REC-012`, `HP-DOC-003`. **Commit:** `feat(destaudit): add optional destination-side exec audit integration`.

#### WP26 — Hardening
- **Depends:** WP01–WP25. **Files:** `test/fault`, `test/soak`, fuzz corpora, `docs/evidence/<rc>/`.
- **Design:** run long fuzzing, the full fault catalog, the 24 h soak and the performance suite on the reference hardware. Do an internal security review
  (checklist in TEST_STRATEGY.md §6) with findings tracked in DECISIONS.md or issues.
- **Acceptance:** Owns: `HP-TST-002`, `HP-TST-005`, `HP-TST-006`, `HP-TST-007`, `HP-TST-008`. **Commit(s):** `test: add fault injection, soak, and fuzz hardening` (+ fix commits per finding).

#### WP27 — Release-gate validation and RC
- **Depends:** WP26. **Files:** `docs/evidence/<version>/*`, `docs/security-guarantees.md`, release notes.
- **Design:** evaluate RG-1..RG-11, assemble evidence, tag RC **locally only** (no push without instruction).
- **Acceptance:** Owns: `HP-DOC-004`. All gates documented as pass/fail. **Commit:** `chore(release): record release-gate evidence for vX.Y.Z-rc.N`.

> **Milestone M4, "Release candidate" (WP22–WP27).**

### 19.2 Status table

Update this table at every WP commit. Status values: `planned`, `in-progress`, `implemented`, `tested`, `externally-verified`, `blocked`.

| WP | Title | Depends | Status | Commit |
|---|---|---|---|---|
| WP00 | Planning documents | — | implemented | e15801b |
| WP01 | Scaffolding, CI, lint | WP00 | tested | 89620d3 |
| WP02 | Config, runtime modes, logging | WP01 | tested | 860e1a7 |
| WP03 | SQLite storage, migrations, lock, backup primitive | WP02 | tested | f0b96c0 |
| WP04 | Keyring and field crypto | WP03 | tested | dc3680d |
| WP05 | Audit, jobs, outbox | WP04 | tested | 3327bc9 |
| WP06 | Agents and keys | WP05 | tested | bdf3f05 |
| WP07 | Servers, host identities, roles, credentials/CA | WP06 | tested | 6284850 |
| WP08 | Policy engine and effective access | WP07 | tested | d4b4e2a |
| WP09 | Request/grant/session lifecycle and enforcer | WP08 | tested | 0fdc035 |
| WP10 | SSH front end | WP09 | implemented | 42ada72, d948bf8 |
| WP11 | SSH data plane | WP10 | implemented | d948bf8 |
| WP12 | Recording format, recorder, reconciliation | WP11, WP04 | implemented | 88bbd7f, d948bf8 |
| WP13 | Local operator auth, sessions, MFA | WP05 | implemented | 1540b43 |
| WP14 | OIDC SSO | WP13 | implemented | |
| WP15 | RBAC, REST API, SSE | WP14, WP12 | implemented | |
| WP16 | Web approvals and notification core | WP15 | implemented | |
| WP17 | Slack | WP16 | implemented | |
| WP18 | Telegram | WP16 | implemented | |
| WP19 | Frontend foundation and design system | WP15 | in-progress | |
| WP20 | Operational pages | WP19, WP16 | planned | |
| WP21 | Timeline and replay UI | WP20 | planned | |
| WP22 | Observability | WP15 | implemented | |
| WP23 | Backup/restore/upgrade/break-glass | WP12, WP13 | implemented | |
| WP24 | Packaging and release pipeline | WP22, WP23 | implemented | |
| WP25 | Destination-side audit integration | WP12, WP21 | implemented | |
| WP26 | Hardening | WP01–WP25 | planned | |
| WP27 | Release-gate validation and RC | WP26 | planned | |

### 19.3 Progress log

Newest last. Each entry states what is **implemented**, what is **tested** (and where: local `make check` vs GitHub CI), and what is
**externally verified**, plus deviations. Until the repository is pushed (only on explicit user instruction), "CI" evidence means a
local run of the same targets the workflow executes, and the entry says so. Checklist marks in §21: `✅` = done (box checked),
`◐` = partial progress (box stays unchecked).

- **WP00** (2026-10-23): planning documents committed (`e15801b`).
- **WP01** (2026-10-23): Go module (`go 1.27.3`, latest stable per user instruction; A-2 updated), `hallpass version`, golangci-lint v2 config (depguard: no math/rand, no log; forbidigo), custom analyzers `nohostkeyignore` and `txscope` with analysistest suites (tools module), Makefile, coverage-floor script, CI workflow (actions pinned by SHA, actionlint-clean), gitleaks config, CONTRIBUTING.md, docs index. Tested locally: `make vet custom-vet lint race tools-test coverage` green, gitleaks clean. Not yet run on GitHub (not pushed).
- **WP02** (2026-10-23): `internal/config` (YAML via go.yaml.in/yaml/v3 with KnownFields, reflective HALLPASS_* overrides, aggregated validation, production vs development rules incl. KEK location and dev-feature rejection), `internal/obs` (ECS-aligned slog JSON, LevelVar) and `internal/obs/redact` (Secret[T], sensitive-key redaction), `hallpass config check|env`, example config, docs/operator/{configuration,logging}.md. Config loader is hand-rolled (no koanf), recorded as ADR-0025. Tested locally (race, lint, vet).
- **WP03** (2026-10-23): `internal/store` (modernc SQLite, writer/reader pools with per-connection pragma verification, BEGIN IMMEDIATE Tx with jittered busy retry and after-commit hooks, error classification and Health tracking, flock process lock, Linux/macOS network-FS refusal, data-dir permission checks, goose migrations with pre-migration snapshots, quick/integrity checks, VACUUM INTO snapshot), sqlc (pinned v1.31.1 binary with checksum, drift check in CI), `internal/ids` (prefixed monotonic UUIDv7), `internal/clock`, `internal/store/storetest`, `hallpass migrate`, docs/operator/storage.md. Tested locally on macOS and in a Linux container (incl. FUSE refusal via `make test-netfs`).
- **WP04** (2026-10-23): `internal/keyring` (LocalKEK AES-256-GCM KeyWrapper, KEK file/env/dev loading with permission checks, purpose keys field/credential/recording/manifest/token, Seal/Open with location-binding AAD, MAC/MACAll/VerifyMAC, purpose rotation with canary reseal, retire, offline KEK rotation), `hallpass keys init-kek|status|rotate|rotate-kek`, docs/operator/keys.md. Found and fixed during testing: retiring a rotated field key orphaned the canary; rotation now reseals it in the same transaction. Coverage 80.6%. Tested locally.
- **WP05** (2026-10-23): migration 0002 (audit_events, jobs, outbox_messages, delivery_attempts), `internal/audit` (hash chain, Verify, sealed sensitive details, sinks), `internal/jobs` (leased durable queue, retries, dedup, Periodic), `internal/outbox` (encrypted bodies, provider registry, leased delivery, bounded retries, dead-letter, attempt history), `internal/eventbus` (bounded, drop-counting), `internal/keyring/keyringtest`. Tested locally under -race.
- **WP06** (2026-10-23): migration 0003 (groups, labels, agents, agent_keys, agent_groups), `internal/agents` (strict key parsing/algorithm policy, global key uniqueness with tombstones, revocation with sealed reasons, enable/disable, in-transaction hooks for WP09 cascades, Authenticate with failure reasons and source CIDRs, policy-version bumps, audit), `internal/groups` (group/label validation and persistence), `internal/apperr`, `internal/testutil/sshkeys`, audit request metadata. Tested locally (-race), FuzzParseAgentKey 20 s.
- **WP07** (2026-10-23): migrations 0004/0005, `internal/inventory` (servers, roles, aliases/reserved words, host identities with paste/scan/confirm/retire, duplicate detection + audited exceptions, host CAs with principal binding, strict Verifier), `internal/credentials` (managed/imported login keys sealed with the credential key, authorized_keys suggestion, probe/activate/overlap/retire/revoke, user CAs + per-connection certificates, Signer/SignerResolver abstraction, gateway host keys with staged rotation), `internal/egress` (anti-SSRF guard), `internal/destssh` (sole outbound dialer, verifier mandatory), `internal/sshalg`, `internal/testutil/sshtest` (in-process destination), config `egress.source_addresses`. txscope analyzer refined (SSH I/O only; AfterCommit callbacks exempt). Tested locally (-race); real-OpenSSH interop deferred to WP10/WP11 harness.
- **WP08** (2026-10-23): migration 0006 (policy_rules, approver_rules, agent_owners), `internal/policy` (selectors with Kubernetes-style label expressions and empty-matches-nothing semantics, immutable compiled Snapshot: Evaluate/Visible/ResolveServer/ResolveRole with single ErrNotFoundOrForbidden, durations/presets/auto-approve, CanApprove with self-approval prohibition; Engine with per-version cache, consistent ReadTx loading, WhatIf; CRUD service with in-tx version bump + audit + policy.changed), `store.ReadTx`, docs/operator/policy.md. Evaluate ≈1.2 µs, Visible over 2,000 servers × 3 roles × 100 rules ≈8.5 ms (M-series laptop, not RH-1). Coverage 81.8%. Tested locally (-race), FuzzRuleJSON 20 s.
- **WP09** (2026-10-23): migration 0007 (requests, decisions, grants, sessions, connections, channels, timeline), `internal/access` (CreateRequest with dedup/idempotency/rate limits/sealed sanitized reasons/auto-approval; Decide via one transactional path with authority, self-approval, channel, policy and duration rechecks; grants with time-authoritative expiry; lockdown; disable/key-revoke/target cascades; ReconcilePolicy (cancel/revoke/clamp); channel registration with atomic concurrency limits and full revalidation; per-session Sequencer with DB-reserved blocks; timeline events with idempotency keys; Enforcer (events + ticker + DB reconciliation, registration-race guard); startup reconciliation; background loop). Decide no longer writes state on its rejection paths (would roll back). Tests: 30+ cases incl. concurrency races, enforcement bound (in-process), lost-event path; coverage 80.8%; FuzzSanitizeReason 15 s. Frontend foundation, HPREC1 format and SSH grammar started in parallel by sub-agents (separate directories; committed separately after review).
- **WP13 (service layer)** (2026-10-23): migration 0009 (operators, local credentials, roles, operator groups, TOTP, recovery codes, one-time tokens, web sessions, throttle), `internal/opauth` (Argon2id with versioned params, NFKC passwords, TOTP RFC 6238, recovery codes, setup/invite/reset/recovery-login tokens, login with throttling and enumeration resistance, MFA verification, reauth, server-side sessions with rotation/idle/absolute expiry and CSRF tokens, last-admin protection, break-glass). HTTP endpoints, cookies and Origin/CSRF middleware are delivered with the API in WP15 (deviation from PLAN WP13 file list: avoids building the router twice). Bug found by the new timing test and fixed: the unknown-account dummy hash was computed once at init and could diverge from current parameters (35× timing difference in tests). Coverage 81.0%.
- 2026-10-23 — WP10–WP12: SSH front end (auth, limits, grammar, list/roles/request/status/cancel/sessions/whoami/version/help), data plane (exec/shell/PTY, env allowlist, signals, exit propagation, strict host verification, enforcer termination, idle timeout, graceful drain, `hallpass serve`) and mandatory recording (HPREC1, recorder with backpressure, rollover, integrity chain, startup reconciliation, retention, `hallpass verify`). In-process e2e and real-OpenSSH tests (`make test-openssh`). Status *implemented*, not *tested*, because of open partial items: HP-SSH-012 keepalive tests, HP-SSH-013 load test, HP-REC-003 idempotency keys, HP-REC-013 per-class retention, HP-CRY-004 external review. Found and fixed during WP: out-of-order recording appends under concurrent streams (ADR-0028), implicit role selection deviating from HP-SSH-022, x/crypto CloseWrite/Write race on termination notices. ADR-0026..0028.
- 2026-10-23 — WP19 (partial): web foundation: design system with light/dark tokens and a contrast test, API client (CSRF, problem+json, reauth), SSE client, login/setup/shell routes, security lint rules, CSP-safe build check. Unit tests: 232. Still open: Go embedding (HP-UI-016), WP20/21 pages, Playwright flows against a live backend (HP-TST-004), API shapes to reconcile with OpenAPI (WP15). ADR-0029.
- 2026-10-23 — WP14: generic OIDC SSO (internal/oidc, migration 0010): PKCE code flow, rate-limited JWKS key set, strict ID-token checks, identity by iss+sub, preprovisioned/JIT, group→role sync with last-admin guard, upstream step-up with TOTP fallback, test login gating SSO-only mode, link invitations, RP logout URL; in-process mock IdP (oidctest). Status *implemented*: HTTP endpoints/cookies come with WP15; Keycloak/Dex interop tests not yet run (ADR-0030).
- 2026-10-23 — WP23: backup/restore/anchors/break-glass CLI (internal/backup, cmd backup|restore|anchors|admin): read-only online snapshot, ciphertext-only segment copy, manifest with hashes and KEK ID, verify, restore with staging and KEK check, anchor export/verify, offline bootstrap/recover. Partial items: restore drill, RTO, upgrade fixture, break-glass alert. ADR-0032 (restore --force security-relevant, R-13).
- 2026-10-23 — WP24: packaging (root Dockerfile, distroless nonroot, compose, systemd unit), scripted reproducible release builds, release workflow (SBOM, provenance, Trivy, draft release), install/container/upgrade docs, CHANGELOG, VERSIONING, SECURITY.md. Not run on GitHub yet; ADR-0033 (Trivy waiver gap security-relevant, R-14).
- 2026-10-23 — WP15 + WP22: REST API v1 (spec-first OpenAPI 3.1, in-repo generator, RBAC matrix, problem details, pagination, idempotency, SSE hub, OIDC browser endpoints, embedded UI) and observability (metrics registry, readiness checks, tracing, correlation, call-site instrumentation, serve wiring). Remaining API resources (integrations, retention, recording export) arrive with WP16-18/WP23 follow-ups. ADR-0031, ADR-0034.
- 2026-10-23 — WP16-WP18: notification core (internal/notify, migration 0012): integrations and routes with sealed write-only secrets, action tokens, provider identity links and link codes, durable replay cache, outbox delivery through the Slack/Telegram adapters with delivery-time rendering, message updates, webhook routing under /hooks, chat MFA requirement and rate limits; API endpoints for integrations, routes, deliveries and links. THREAT_MODEL T-05 corrected (ADR-0035, security-relevant). Real Slack/Telegram verification pending (WP17/WP18 status implemented, not externally verified).
WP25 (2026-10-23): destination-side audit integration (internal/destaudit, cmd/hallpass-collector, migration 0014, /hooks/destaudit/{collector_id}, collector and record API). Deviations in ADR-0037 (route, separate binary, no HALLPASS_SESSION marker). Fixed unbounded webhook rate-limiter key table. OpenSSH+auditd container test pending.
<!-- progress-log-end -->

---

## 20. Risks, trade-offs and review decisions

### 20.1 Risks

| # | Risk | Impact | Mitigation |
|---|---|---|---|
| K-1 | `modernc.org/sqlite` throughput lower than CGO driver | Writer contention at high event rates | Payloads in files, batched seq reservation, WP03 benchmarks. Fallback ADR to `ncruces/go-sqlite3` (wasm, also CGO-free) if needed. |
| K-2 | `x/crypto/ssh` server limitations (no `hostkeys-00`, one key per algorithm, past auth-callback pitfalls) | Host-key rotation UX, auth bugs | §7.8 rotation approaches, Permissions-based identity, pinned minimum version, OpenSSH interop matrix. |
| K-3 | Custom recording format (composition of vetted primitives) has a subtle flaw | Integrity/confidentiality of recordings | Mirrors the age STREAM design, fuzzing and tamper tests, external review R-02 before 1.0, format versioning for fixes. |
| K-4 | Single active instance and cold standby | Downtime on host loss (RTO ≈ 15 min) | Documented. Backups and drills. Active-active explicitly out of scope. |
| K-5 | Recording backpressure degrades interactive latency | Agent UX | `group` mode default, measured p99 latency target, `strict` opt-in. |
| K-6 | OIDC provider variance (groups claim, `auth_time`, `acr`) | Mapping/step-up failures | Mock IdP plus Keycloak/Dex interop, explicit config, test-login gate, local TOTP fallback. |
| K-7 | Ant Design CSS-in-JS vs strict CSP | Need `'unsafe-inline'` for styles | Evaluate static extraction / nonce in WP19 (R-11). Scripts stay strict. |
| K-8 | Scope size | Schedule | Dependency-ordered WPs and milestones that never reduce final scope. |
| K-9 | Chat-based approvals have weaker assurance than web+MFA | Approval via a compromised Slack/Telegram account | Explicit linking, scope checks, optional per-role "web-only approval" flag (`approval_channels` on role), R-10. |
| K-10 | Clock skew on host | Expiry accuracy | Monotonic timers for in-process deadlines, wall-clock UTC for persisted times, NTP required (documented), and a skew check against the HTTP Date of IdP/Slack responses logged as a warning. |

### 20.2 Review items (decisions deferred to operator; details in DECISIONS.md §2)

R-01 license · R-02 external crypto review of HPREC1/keyring · R-03 KMS/Vault/HSM backend in v1 · R-04 Litestream optional
streaming backup · R-05 default global grant-duration ceiling (proposed 24h; presets up to 24h) · R-06 SFTP/SCP as separately
authorized capability (post-v1) · R-07 ECS vs custom log schema · R-08 trademark/name/domain check · R-09 self-approval default
(proposed: prohibited) · R-10 chat approvals for privileged roles (proposed: allowed; per-role `web_only` flag) · R-11 CSP for
CSS-in-JS styles · R-12 offline breached-password list.

---

## 21. Acceptance checklist (mapped to requirement IDs)

A box is checked only when the requirement meets the definition of done (GOAL.md §7). Append the evidence pointer after the line,
e.g. `— ✅ tested @ abc1234 (test/openssh/hidden_test.go)`. Evidence codes: U unit · P property · Z fuzz · I integration ·
O OpenSSH interop · E browser E2E · A accessibility · V visual regression · FI fault injection · S soak/load/perf · C CI/static
check · R recovery drill · SR security review · D documentation review.

#### HP-SSH — SSH front end and data plane

- [x] `HP-SSH-001` Public-key-only agent auth — WP10 — evidence: U, O — ✅ tested: internal/app/e2e_test.go TestGatewayAuthMethodsAndAlgorithms
- [x] `HP-SSH-002` Identity from key, not username — WP10 — evidence: O, I — ✅ tested: identity from Permissions extensions; whoami e2e; agents.Authenticate tests
- [x] `HP-SSH-003` Uniform rejection of unknown/revoked keys — WP10 — evidence: O, I — ✅ tested: agents auth tests; e2e/OpenSSH unknown key rejected
- [x] `HP-SSH-004` Algorithm policy — WP10 — evidence: U, O — ✅ tested: sshalg allowlists; agents key tests; e2e SHA-1 ssh-rsa refused
- [x] `HP-SSH-005` Gateway host key lifecycle — WP10 — evidence: U, O, D — ✅ tested: credentials host-key tests; hostkey CLI test; docs/agent/guide.md pinning
- [x] `HP-SSH-006` Shell, exec, PTY completeness — WP11 — evidence: O — ✅ tested: shell/exec/PTY/env/signal/eof/exit in internal/app/e2e_test.go and test/openssh/gateway_test.go (real ssh + sshd)
- [x] `HP-SSH-007` Forwarding and unknown channels denied — WP10 — evidence: O, I — ✅ tested: internal/app/e2e_test.go TestGatewayDeniesForwarding; test/openssh/gateway_test.go (real ssh + sshd) TestOpenSSHForwardingDenied
- [x] `HP-SSH-008` Environment allowlist — WP11 — evidence: U, O — ✅ tested: internal/app/e2e_test.go TestGatewayEnvAllowlist (per-role extension implemented, not separately tested)
- [x] `HP-SSH-009` Stdout purity — WP10 — evidence: O — ✅ tested: byte-exact stdout in test/openssh/gateway_test.go (real ssh + sshd) TestOpenSSHExec
- [x] `HP-SSH-010` Exit status and signal propagation — WP11 — evidence: O — ✅ tested: exit-status (test/openssh/gateway_test.go (real ssh + sshd)) and exit-signal (internal/app/e2e_test.go TestGatewayExitSignal)
- [x] `HP-SSH-011` Strict destination host verification — WP11 — evidence: C, O — ✅ tested: internal/app/e2e_test.go TestGatewayHostKeyMismatch; test/openssh/gateway_test.go (real ssh + sshd) TestOpenSSHHostKeyChanged; nohostkeyignore analyzer
- [x] `HP-SSH-012` Keepalive and idle timeouts — WP11 — evidence: I, O — ✅ tested: agent and destination legs probe keepalive@openssh.com (internal/sshkeepalive unit tests; internal/app TestGatewayAgentKeepalive, TestGatewayDestinationKeepalive exit 88; fault TestFI15), idle timeout (TestGatewayIdleTimeout)
- [ ] `HP-SSH-013` Pre-auth and connection limits — WP10 — evidence: S, FI — ◐ partial: global/per-IP pre-auth limits + handshake timeout implemented; per-IP limit tested (internal/app/e2e_test.go TestGatewayPreAuthLimit); load test pending WP26
- [x] `HP-SSH-014` Bounded buffering and backpressure — WP11 — evidence: S, I — ✅ tested: 5 MB output through OpenSSH; recorder backpressure test; soak pending WP26
- [x] `HP-SSH-015` Cancellation and cleanup — WP11 — evidence: U, S — ✅ tested: internal/app/e2e_test.go TestGatewayNoGoroutineLeak, revocation/shutdown termination; fd soak pending WP26
- [x] `HP-SSH-016` Shell-free command grammar — WP10 — evidence: U, Z — ✅ tested: grammar unit + fuzz tests (98.9%)
- [x] `HP-SSH-017` Reserved words — WP10 — evidence: U, O — ✅ tested: grammar tests; reserved words incl. ps (ADR-0027)
- [x] `HP-SSH-018` Stable JSON output — WP10 — evidence: U, O — ✅ tested: strict schema validation in grammar tests; api/ssh-schemas
- [x] `HP-SSH-019` No hang without input — WP10 — evidence: O — ✅ tested: internal/app/e2e_test.go TestGatewayReasonRequiredWithoutPTY (exit 90)
- [x] `HP-SSH-020` Bounded wait with auto-connect — WP10 — evidence: O, I — ✅ tested: internal/app/e2e_test.go TestGatewayWaitTimeoutAndDisconnect, TestGatewayRequestLifecycle
- [x] `HP-SSH-021` Disconnect does not mutate requests — WP10 — evidence: O, I — ✅ tested: internal/app/e2e_test.go TestGatewayWaitTimeoutAndDisconnect
- [x] `HP-SSH-022` Unambiguous default role — WP10 — evidence: U, O — ✅ tested: implicit role only with one candidate (TestGatewayImplicitRole); PTY role prompt with valid and invalid answers (TestGatewayPTYRolePrompt)
- [x] `HP-SSH-023` Remote exec encoding — WP11 — evidence: U, O, D — ✅ tested: test/openssh/gateway_test.go (real ssh + sshd) TestOpenSSHExec; docs/agent/guide.md quoting
- [x] `HP-SSH-024` Introspection commands — WP10 — evidence: O — ✅ tested: internal/app/e2e_test.go TestGatewayRequestLifecycle
- [x] `HP-SSH-025` Grant revalidation per channel — WP11 — evidence: U, I — ✅ tested: access RegisterChannel tests; e2e revocation

#### HP-AGT — Agent registration

- [x] `HP-AGT-001` Agent record — WP06 — evidence: U, I — ✅ tested (local) @ WP06: agents table + service (name rules, CIDRs, groups, labels, optimistic version)
- [x] `HP-AGT-002` Multiple keys per agent — WP06 — evidence: U, I — ✅ tested (local) @ WP06: multiple keys per agent, active/revoked, actor/time history
- [x] `HP-AGT-003` Globally unique key ownership — WP06 — evidence: I — ✅ tested (local) @ WP06: unique fingerprint incl. tombstoned revoked keys (TestKeyUniquenessAcrossAgents)
- [x] `HP-AGT-004` Validated key parsing — WP06 — evidence: U, Z — ✅ tested (local) @ WP06: ParseAgentKey policy table + FuzzParseAgentKey (20 s local smoke)
- [x] `HP-AGT-005` Immediate key revocation — WP09 — evidence: O, I — ✅ tested: key revocation terminates live sessions through real OpenSSH within ms and the key no longer authenticates (test/openssh TestOpenSSHKeyRevocation)
- [x] `HP-AGT-006` No agent private keys — WP06 — evidence: U — ✅ tested (local) @ WP06: private-key input rejected without echo; no private-key storage path exists
- [x] `HP-AGT-007` Source CIDR restriction — WP10 — evidence: O, D — ✅ tested: source CIDR enforced at SSH auth (internal/app/e2e_test.go TestGatewaySourceCIDR); agents unit tests incl. IPv4-mapped
- [x] `HP-AGT-008` Agent disablement — WP09 — evidence: I, O — ✅ tested: agent disable terminates live sessions through real OpenSSH and refuses new logins (test/openssh TestOpenSSHAgentDisable)
- [x] `HP-AGT-009` Agent audit history — WP06 — evidence: I — ✅ tested (local) @ WP06: audit events for create/update/enable/disable/key add/revoke (hash-chain verified)

#### HP-SRV — Destination servers and roles

- [x] `HP-SRV-001` Server record — WP07 — evidence: U, I — ✅ tested (local) @ WP07: servers + groups/labels/metadata, alias rules, optimistic version
- [x] `HP-SRV-002` Role record — WP07 — evidence: U, I — ✅ tested (local) @ WP07: roles with capabilities, durations, concurrency, recording mode, env allowlist, approval channels, labels
- [ ] `HP-SRV-003` Descriptions are not enforcement — WP20 — evidence: E, D
- [x] `HP-SRV-004` Explicit host identity enrollment — WP07 — evidence: I, O — ✅ tested: explicit enrollment against real sshd (test/openssh/gateway_test.go) and in-process; scan->confirm flow (inventory tests)
- [x] `HP-SRV-005` Host key rotation — WP07 — evidence: I, O — ✅ tested: changed key refused before auth with exit 88 + audit alert (internal/app/e2e_test.go TestGatewayHostKeyMismatch, test/openssh/gateway_test.go TestOpenSSHHostKeyChanged)
- [x] `HP-SRV-006` Duplicate host identity detection — WP07 — evidence: I — ✅ tested (local) @ WP07: duplicate active fingerprint rejected; justified, audited exception required
- [ ] `HP-SRV-007` Host CA model — WP07 — evidence: U, O — ◐ WP07: host CA enrollment + principal binding, validity/CA/type checks (unit); real-sshd host-cert interop pending WP11
- [x] `HP-SRV-008` Server/role disablement — WP09 — evidence: I, O — ✅ tested: server disable terminates live activity through real OpenSSH and blocks new exec (test/openssh TestOpenSSHServerDisable); role disable via the same hooks (access tests)
- [x] `HP-SRV-009` Egress validation (anti-SSRF) — WP07 — evidence: U, I — ✅ tested (local) @ WP07: internal/egress default-deny special ranges, allow CIDRs, mixed-DNS refusal, IP-pinned dial with Control re-check
- [x] `HP-SRV-010` Address confidentiality — WP15 — evidence: I, E — ✅ tested: addresses redacted in API without permission, absent from agent output (SSH e2e)

#### HP-KEY — Destination login credentials and signing keys

- [x] `HP-KEY-001` Managed login key default — WP07 — evidence: U, I — ✅ tested (local) @ WP07: per-role managed Ed25519, sealed with credential key, no export path
- [ ] `HP-KEY-002` Public key installation aid — WP07 — evidence: E, I — ◐ WP07: AuthorizedKeysLine (restrict[,pty],from=egress.source_addresses) tested; UI copy action pending WP20
- [x] `HP-KEY-003` Login key rotation — WP07 — evidence: I, O — ✅ tested: probe/activate against real sshd (test/openssh/gateway_test.go), rotation with overlap (credentials tests)
- [x] `HP-KEY-004` OpenSSH user certificates — WP07 — evidence: U, O — ✅ tested: short-lived user certificates accepted by real sshd (test/openssh/gateway_test.go TestOpenSSHCertificateLogin)
- [x] `HP-KEY-005` Signer abstraction — WP07 — evidence: U — ✅ tested (local) @ WP07: credentials.Signer/SignerResolver + FromCryptoSigner adapter (ECDSA DER→SSH) test; no external backend shipped (R-03)
- [ ] `HP-KEY-006` Distinct key types — WP07 — evidence: C, SR — ◐ WP07: separate types/tables (host_identities, host_cas, login_credentials, user_cas, gateway_host_keys) and packages; API/UI separation WP15/WP20; SR WP26
- [ ] `HP-KEY-007` Credential isolation — WP07 — evidence: U, I, SR — ◐ WP07: DTOs carry no private material (JSON test), imported keys flagged/never exported, credentials never presented to untrusted hosts; API/log review WP15/WP26

#### HP-POL — Visibility and policy

- [x] `HP-POL-001` Default deny — WP08 — evidence: U, P — ✅ tested (local) @ WP08: TestDefaultDeny + property tests
- [x] `HP-POL-002` Deny overrides — WP08 — evidence: U, P — ✅ tested (local) @ WP08: deny overrides any allow (table + randomized property)
- [x] `HP-POL-003` Selector semantics — WP08 — evidence: U, P — ✅ tested (local) @ WP08: union clauses, k8s label AND, empty selector/label clause matches nothing, all:true future objects; FuzzRuleJSON 20 s
- [x] `HP-POL-004` Level lattice — WP08 — evidence: U, P — ✅ tested (local) @ WP08: level lattice, group union, smallest auto max
- [x] `HP-POL-005` Role and server visibility — WP08 — evidence: U — ✅ tested (local) @ WP08: role/server visibility, disabled invisible
- [x] `HP-POL-006` Separated permissions — WP08 — evidence: U, I — ✅ tested (local) @ WP08: separate Evaluate (visibility/request), CanApprove (approval authority); activity check = grant revalidation in WP09
- [x] `HP-POL-007` Policy versioning — WP08 — evidence: I — ✅ tested (local) @ WP08: policy_version bumped in-tx by policy, agent, inventory changes; engine rebuilds snapshot on version change
- [x] `HP-POL-008` Policy change effects — WP09 — evidence: I — ✅ tested (local) @ WP09: ReconcilePolicy cancels/revokes/clamps; run on policy.changed + every minute (TestBackgroundLoopAppliesPolicyAndExpiry)
- [ ] `HP-POL-009` Effective-access preview — WP08 — evidence: U, E — ◐ WP08: PreviewAgent/PreviewServer with deciding rule + Engine.WhatIf tested; UI pending WP20
- [x] `HP-POL-010` Hidden-target non-disclosure — WP10 — evidence: U, O, I — ✅ tested: unknown and hidden targets indistinguishable (internal/app/e2e_test.go TestGatewayHiddenTarget, test/openssh/gateway_test.go TestOpenSSHHiddenTarget)
- [x] `HP-POL-011` Approver authority rules — WP08 — evidence: U, I — ✅ tested (local) @ WP08: approver rules + internal role required; admins need rules too
- [x] `HP-POL-012` Self-approval prohibition — WP08 — evidence: U, I — ✅ tested (local) @ WP08: agent owners + policy.prohibit_self_approval (default prohibited)
- [x] `HP-POL-013` Auto-approval within limits — WP08 — evidence: U, I — ✅ tested (local) @ WP08: AutoApproves only ≤ auto max; longer requests need a human; decision recording in WP09
- [x] `HP-POL-014` Command allowlists are not a sandbox — WP08 — evidence: D — ✅ done: docs/operator/policy.md (capabilities are channel types) + docs/destination/hardening.md (allowlists are not a sandbox; ForceCommand/sudoers)

#### HP-REQ — Access requests

- [ ] `HP-REQ-001` Request state machine — WP09 — evidence: U, P — ◐ WP09: CAS transitions from pending only (TransitionRequest WHERE state='pending'); unit + concurrency tests; randomized op-sequence property test pending WP26
- [x] `HP-REQ-002` Request record — WP09 — evidence: U, I — ✅ tested (local) @ WP09: request record incl. sealed reason, key, policy version, timestamps, actors
- [x] `HP-REQ-003` Deduplication and idempotency — WP09 — evidence: I, O — ✅ tested: dedup per agent/server/role over SSH (internal/app/e2e_test.go TestGatewayWaitTimeoutAndDisconnect) + idempotency keys (access tests)
- [x] `HP-REQ-004` Pending expiry — WP09 — evidence: I — ✅ tested (local) @ WP09: 30m default pending expiry, sweep + time-authoritative decision check
- [x] `HP-REQ-005` Wait vs expiry vs duration — WP10 — evidence: O, D — ✅ tested: wait timeout vs pending expiry vs grant duration over SSH (internal/app/e2e_test.go) + docs/agent/guide.md
- [x] `HP-REQ-006` Cancellation — WP09 — evidence: I, O — ✅ tested: agent cancel over SSH (internal/app/e2e_test.go TestGatewayRequestLifecycle), operator cancel via API
- [ ] `HP-REQ-007` Request rate limits — WP09 — evidence: I, S — ◐ WP09: per-agent hourly + pending caps (tested); load test pending WP26
- [x] `HP-REQ-008` Bounded untrusted reason — WP09 — evidence: U, Z — ✅ tested (local) @ WP09: SanitizeReason strips C0/C1/Cf (bidi, zero-width), collapses whitespace, ≤1000 runes; FuzzSanitizeReason 15 s
- [x] `HP-REQ-009` Status polling — WP10 — evidence: O — ✅ tested: status polling over SSH (internal/app/e2e_test.go TestGatewayRequestLifecycle)

#### HP-GRT — Grants and enforcement

- [ ] `HP-GRT-001` Transactional decision and grant — WP09 — evidence: I, FI — ◐ WP09: decision+grant+session in one writer tx, start = tx time (tested); crash fault injection FI-01 pending WP26
- [x] `HP-GRT-002` Grant record — WP09 — evidence: U, I — ✅ tested (local) @ WP09: grant record with scope, capabilities, policy version
- [x] `HP-GRT-003` No implicit extension — WP09 — evidence: U, I — ✅ tested (local) @ WP09: reuse never changes expiry; extensions only via new requests
- [x] `HP-GRT-004` Active grant reuse — WP09 — evidence: I, O — ✅ tested: second exec reuses the active grant (internal/app/e2e_test.go TestGatewayExecEndToEnd)
- [ ] `HP-GRT-005` Deterministic overlap selection — WP09 — evidence: U, P — ◐ WP09: latest expiry then lowest ID (SQL ORDER BY) + min-remaining cutoff tested; property test pending WP26
- [ ] `HP-GRT-006` Atomic concurrency limits — WP09 — evidence: I, S — ◐ WP09: counts + insert in one writer tx; 12 concurrent registrations vs limit 2 → exactly 2 (tested); load test WP26
- [x] `HP-GRT-007` Race resolution — WP09 — evidence: U, I — ✅ tested (local) @ WP09: CAS + 20 concurrent deciders exactly one decision; replay idempotent; expiry/policy rechecked in-tx
- [ ] `HP-GRT-008` Enforcement bound — WP09 — evidence: I, O, S — ◐ tested: revocation terminates real OpenSSH sessions in ms (test/openssh/gateway_test.go TestOpenSSHRevocation), lost-event path <5s (access tests); load test pending WP26
- [ ] `HP-GRT-009` Operator revocation — WP09 — evidence: I, E — ◐ WP09: RevokeGrant (admin or in-scope approver, audited, sealed note, event) tested; UI WP20
- [x] `HP-GRT-010` Approval after expiry — WP09 — evidence: I — ✅ tested (local) @ WP09: expired request not approvable; new approval → new grant + session
- [ ] `HP-GRT-011` Emergency lockdown — WP09 — evidence: I, E — ◐ WP09: SetLockdown revokes all grants, cancels pending, blocks requests/channels (tested); UI/CLI WP20/WP23

#### HP-SES — Access sessions

- [x] `HP-SES-001` Session per grant — WP09 — evidence: I — ✅ tested (local) @ WP09: 1:1 session created in approval tx
- [x] `HP-SES-002` Connections and channels — WP09 — evidence: I, O — ✅ tested: connections/channels recorded with states and close reasons over SSH (e2e)
- [x] `HP-SES-003` Session closure — WP09 — evidence: I — ✅ tested (local) @ WP09: closing while channels live, closed with reason when grant ended and channels closed
- [x] `HP-SES-004` Detached processes — WP25 — evidence: D — ✅ done: docs/destination/hardening.md (logind KillUserProcesses, cgroups, PAM limits, ClientAlive*); destination audit flags after_session_end records
- [ ] `HP-SES-005` Live activity view — WP20 — evidence: E

#### HP-REC — Event history and recording

- [x] `HP-REC-001` Versioned event schema — WP12 — evidence: U, I — ✅ tested: hprec versioned record types (terminal.output@1), per-session seq
- [x] `HP-REC-002` Ordering and causality — WP12 — evidence: U, I, P — ✅ tested: shared per-session sequencer; TestRecorderConcurrentProducers
- [ ] `HP-REC-003` Idempotent events — WP12 — evidence: U, I — ◐ partial: recorder has no retry path (append failure fails closed); deterministic idempotency keys not implemented
- [x] `HP-REC-004` Capture fidelity — WP12 — evidence: O, I — ✅ tested: recorder round-trip (exec cmd, stdout/stderr, PTY output, resize, signal, exit)
- [ ] `HP-REC-005` Input recording opt-in — WP12 — evidence: I, D — ◐ partial: input recording off by default, per-role opt-in tested; UI warning pending WP21
- [ ] `HP-REC-006` No false command claims — WP21 — evidence: E, D
- [x] `HP-REC-007` Mandatory recording fail-closed — WP12 — evidence: FI, O — ✅ tested: segment established before forwarding; failure fails closed (TestRecorderFailureFailsClosed, OpenSSH)
- [x] `HP-REC-008` Durability guarantee — WP12 — evidence: FI, I — ✅ tested: group commit ≤250 ms / strict mode; crash-recovery tests; fault injection pending WP26
- [x] `HP-REC-009` Accurate incomplete marking — WP12 — evidence: FI, I — ✅ tested: TestReconcileStartup, TestReconcileUnrecoverableAndVerifyMissing
- [ ] `HP-REC-010` Unified timeline, distinct streams — WP21 — evidence: E
- [x] `HP-REC-011` No silent event drops — WP12 — evidence: U, FI, S — ✅ tested: TestRecorderBackpressure (block then fail, never drop)
- [ ] `HP-REC-012` Destination-side audit integration — WP25 — evidence: O, D — ◐ implemented + tested (unit/integration): signed collector batches, certificate/managed-key correlation, sealed details, provenance labels (internal/destaudit, cmd/hallpass-collector, httpapi TestAdministrationFlow); OpenSSH+auditd container test pending; ADR-0037
- [ ] `HP-REC-013` Retention and deletion — WP12 — evidence: I, E — ◐ tested: per-role-class retention (recording.retention_classes) + tombstones (config + recording tests); UI display pending WP20
- [x] `HP-REC-014` Restricted, audited download — WP21 — evidence: E, I — ✅ tested: playback (recording.play) and export (recording.export, recent auth + MFA) separate and audited; default export is the ciphertext bundle, plaintext opt-in (httpapi TestAdministrationFlow checkBundle; ADR-0040); UI encrypted/decrypted export actions (ExportButton)

#### HP-CRY — Cryptography and key management

- [x] `HP-CRY-001` Master KEK provisioning — WP04 — evidence: U, I — ✅ tested (local) @ WP04: LoadKEK file/env/dev, production refusal, perms/owner checks, canary detects wrong KEK; `hallpass keys init-kek`
- [x] `HP-CRY-002` Purpose keys and rotation — WP04 — evidence: U, I — ✅ tested: purpose keys versioned, rotation, background re-encryption job (keyring + app TestResealRegistry) and guarded retire CLI (cmd TestKeysRetireGuard); audit/recording/manifest exceptions documented
- [x] `HP-CRY-003` Field encryption — WP04 — evidence: U, P — ✅ tested (local) @ WP04: Keyring.Seal/Open with FieldAAD(table|column|row) + key version; bit-flip, row-swap and purpose-confusion tests
- [ ] `HP-CRY-004` Recording file format — WP12 — evidence: U, Z, SR — ◐ partial: HPREC1 implemented, unit + fuzz tested (94.8%); external crypto review pending (R-02)
- [x] `HP-CRY-005` Integrity verification — WP12 — evidence: I, R — ✅ tested: hallpass verify (segments, ciphertext hash, final frame, chain links + MACs); TestVerifyDetectsTampering
- [ ] `HP-CRY-006` Vetted cryptography only — WP01 — evidence: C, SR — ◐ WP01: depguard bans math/rand; nohostkeyignore analyzer; ongoing constraint, SR at WP26
- [ ] `HP-CRY-007` Key loss and recovery — WP23 — evidence: D, R — ◐ partial: documented, KEK exclusion enforced/tested; recovery drill evidence pending
- [x] `HP-CRY-008` External integrity anchoring — WP23 — evidence: I, D — ✅ tested: anchors export/verify incl. rewritten history (internal/backup tests anchors_test)
- [x] `HP-CRY-009` Ciphertext-only archival — WP23 — evidence: I, R — ✅ tested: ciphertext-only backups, KEK excluded (internal/backup tests)

#### HP-DB — SQLite storage

- [x] `HP-DB-001` Pure-Go driver — WP03 — evidence: C — ✅ tested (local) @ WP03: modernc.org/sqlite; `CGO_ENABLED=0` linux/amd64+arm64 builds
- [x] `HP-DB-002` Per-connection pragmas — WP03 — evidence: I — ✅ tested (local) @ WP03: DSN pragmas; VerifyPragmas over every pooled conn at startup + TestPragmasEveryConnection
- [ ] `HP-DB-003` Writer/reader split — WP03 — evidence: I, S — ◐ WP03: single writer (BEGIN IMMEDIATE via _txlock), query_only readers, 5 jittered retries (TestConcurrentWriters, TestBusyRetryAndGiveUp); queue/wait metrics export pending WP22
- [x] `HP-DB-004` Short transactions — WP03 — evidence: I, C — ✅ tested (local) @ WP03: txscope analyzer + storetest fails tx > 100 ms
- [x] `HP-DB-005` Safe migrations — WP03 — evidence: I, FI — ✅ tested (local) @ WP03: goose embedded forward-only, under flock, pre-migration VACUUM INTO snapshot, failure rollback + newer-schema refusal tests
- [x] `HP-DB-006` Single active instance — WP03 — evidence: I — ✅ tested (local) @ WP03: flock hallpass.lock (TestSecondOwnerRefused)
- [x] `HP-DB-007` Unsupported storage refusal — WP03 — evidence: I — ✅ tested (local, Linux container) @ WP03: statfs magic check; `make test-netfs` verifies refusal on a FUSE mount
- [x] `HP-DB-008` Corruption checks — WP03 — evidence: I, FI — ✅ tested: startup quick_check refusal, daily integrity_check job, readiness store health (store + obs/health tests)
- [ ] `HP-DB-009` Disk-full and I/O failure — WP03 — evidence: FI — ◐ WP03: error classification + Health (degraded/failed, fail-closed AcceptsWrites); fault tests FI-06 and recording termination pending WP12/WP26
- [x] `HP-DB-010` Filesystem permissions — WP03 — evidence: I — ✅ tested (local) @ WP03/WP04: data dir 0700 + owner, DB files 0600, KEK file mode/owner refusal
- [ ] `HP-DB-011` Bounded growth — WP03 — evidence: I, S — ◐ WP03: incremental auto_vacuum, Checkpoint/IncrementalVacuum/Sizes; retention jobs + metrics pending WP05/WP12/WP22
- [x] `HP-DB-012` Consistent backup primitive — WP03 — evidence: I, R — ✅ tested: snapshot + segment copy + manifest (backup package)
- [ ] `HP-DB-013` Crash reconciliation — WP09 — evidence: FI, I — ◐ WP09: ReconcileStartup (interrupted connections/channels + timeline, expiry, policy, sessions) tested; segment reconciliation WP12; kill -9 fault tests WP26
- [ ] `HP-DB-014` Recovery objectives — WP23 — evidence: R, D — ◐ partial: documented; RTO not measured

#### HP-AUTH — Operator authentication and browser sessions

- [x] `HP-AUTH-001` Secure bootstrap — WP13 — evidence: I, E — ✅ tested: setup token bootstrap (opauth) + hallpass admin bootstrap CLI
- [x] `HP-AUTH-002` Argon2id hashing — WP13 — evidence: U — ✅ tested (local) @ WP13: Argon2id PHC, 16-byte salts, versioned params (prod m=64MiB t=3 p=2 guarded by test), rehash-on-login, Calibrate
- [ ] `HP-AUTH-003` Password policy — WP13 — evidence: U, E — ◐ WP13: NFKC, 12..1024 bytes, no truncation (tested incl. >72-byte difference); UI paste/password-manager E2E pending WP19
- [x] `HP-AUTH-004` Throttling without permanent lockout — WP13 — evidence: I — ✅ tested (local) @ WP13: per-account and per-IP (/64) progressive throttle capped at 15 min, decays after 24 h, admin clear; no permanent lockout
- [x] `HP-AUTH-005` Enumeration resistance — WP13 — evidence: U, I — ✅ tested (local) @ WP13: identical error for unknown/wrong/disabled; dummy hash at current params; timing medians within 25% (asserted; found and fixed a stale-dummy-hash timing leak)
- [ ] `HP-AUTH-006` TOTP MFA — WP13 — evidence: U, I, E — ◐ WP13: RFC 6238 vectors, ±1 step, step-reuse rejection, sealed secret, confirmed enrollment (tested); UI E2E pending WP19
- [x] `HP-AUTH-007` Recovery codes — WP13 — evidence: U, I — ✅ tested (local) @ WP13: 10 HMAC-hashed single-use recovery codes, shown once, regenerable with recent auth
- [ ] `HP-AUTH-008` Mandatory MFA for privileged accounts — WP13 — evidence: I, E — ◐ WP13: admins/approvers (local) forced to enroll; sessions limited until MFA (tested); UI E2E pending WP19
- [ ] `HP-AUTH-009` Password change and reset — WP13 — evidence: I, E — ◐ WP13: admin-issued single-use 1 h hashed reset tokens; change requires current password (tested); SMTP delivery + UI pending WP16/WP20
- [x] `HP-AUTH-010` Session invalidation — WP13 — evidence: I — ✅ tested (local) @ WP13: reset/change/disable/MFA change/role reduction revoke sessions
- [ ] `HP-AUTH-011` Invitations — WP13 — evidence: I, E — ◐ WP13: single-use 72 h hashed invitations with preset roles (tested); UI pending WP20
- [x] `HP-AUTH-012` Server-side sessions — WP13 — evidence: I, E — ✅ tested: server-side sessions, __Host- cookie (Secure) / hp_session in dev, idle+absolute expiry
- [x] `HP-AUTH-013` CSRF protection — WP13 — evidence: I, E — ✅ tested: CSRF token + Origin/Sec-Fetch-Site on mutations (internal/httpapi/api_test.go)
- [x] `HP-AUTH-014` Recent authentication — WP13 — evidence: I, E — ✅ tested: per-operation x-reauth/x-mfa gating (internal/httpapi tests incl. stale-session refusal)
- [x] `HP-AUTH-015` Lockout prevention — WP13 — evidence: I, E — ✅ tested: last admin guard (opauth) + SSO-only preconditions and protection (internal/oidc/oidc_test.go (mock IdP) TestTestLoginAndSSOOnly)
- [x] `HP-AUTH-016` Break-glass recovery — WP23 — evidence: I, R — ✅ tested: offline admin recover CLI (backup/cmd tests) + alert at start and in system status until acknowledged (opauth TestBreakGlassAlert, API)
- [x] `HP-AUTH-017` Dev auth isolation — WP13 — evidence: C, I — ✅ tested: no dev-auth code exists; production config rejects dev.* (config tests, fuzz)
- [x] `HP-AUTH-018` Credential secrecy — WP13 — evidence: U, I — ✅ tested (local) @ WP13: no passwords/TOTP/codes in audit or plaintext storage; redaction layer from WP02

#### HP-OIDC — Generic OpenID Connect SSO

- [x] `HP-OIDC-001` Provider configuration — WP14 — evidence: U, I — ✅ tested: provider config + discovery exact issuer (internal/oidc/oidc_test.go (mock IdP) TestProviderValidation)
- [x] `HP-OIDC-002` Code flow with PKCE — WP14 — evidence: I — ✅ tested: PKCE S256, single-use 10 min state bound by cookie (internal/oidc/oidc_test.go (mock IdP) TestStateSafety)
- [x] `HP-OIDC-003` ID token validation — WP14 — evidence: U, I — ✅ tested: alg none/HS256, iss/aud/azp, exp/iat/nbf skew, nonce (internal/oidc/oidc_test.go (mock IdP) TestIDTokenValidation)
- [x] `HP-OIDC-004` JWKS caching and rotation — WP14 — evidence: I — ✅ tested: JWKS cache, rotation refetch, rate limit (internal/oidc/oidc_test.go (mock IdP) TestJWKSRotation)
- [x] `HP-OIDC-005` TLS and redirect safety — WP14 — evidence: U, I — ✅ tested: https issuer, exact redirect URI, return_to allowlist, binding cookie over HTTP (oidc + httpapi TestOIDCBrowserFlow)
- [x] `HP-OIDC-006` Endpoint validation — WP14 — evidence: U, I — ✅ tested: endpoint site check, private-network refusal, untrusted TLS refused
- [x] `HP-OIDC-007` Secret handling — WP14 — evidence: I, E — ✅ tested: encrypted at rest, write-only in API (oidc + httpapi tests); UI pending WP20
- [ ] `HP-OIDC-008` Token minimization — WP14 — evidence: I — ◐ implemented: access/refresh tokens dropped after exchange, ID token not stored (code review; no persistence path)
- [x] `HP-OIDC-009` Identity by issuer+subject — WP14 — evidence: I, E — ✅ tested: identity by iss+sub, no email merge, link via session/invite/admin (internal/oidc/oidc_test.go (mock IdP) TestNoEmailMerge, TestLinking)
- [x] `HP-OIDC-010` Provisioning modes — WP14 — evidence: I — ✅ tested: preprovisioned default, JIT restrictions, no roles without mapping (internal/oidc/oidc_test.go (mock IdP) TestJITAndGroupSync)
- [x] `HP-OIDC-011` Group mapping — WP14 — evidence: U, I — ✅ tested: allowlisted mapping replaced per login, manual kept, last-admin guard (internal/oidc/oidc_test.go (mock IdP) TestJITAndGroupSync, TestSyncKeepsLastAdmin)
- [x] `HP-OIDC-012` Provider outage behavior — WP14 — evidence: I, FI — ✅ tested: discovery/token outage fails closed, sessions + local login unaffected (internal/oidc/oidc_test.go (mock IdP) TestOutage)
- [x] `HP-OIDC-013` Upstream step-up — WP14 — evidence: I — ✅ tested: prompt=login/max_age, auth_time, acr, TOTP fallback (internal/oidc/oidc_test.go (mock IdP) TestStepUp)
- [x] `HP-OIDC-014` Test-login before enforcement — WP14 — evidence: E — ✅ tested: test login preview + required before SSO-only (internal/oidc/oidc_test.go (mock IdP) TestTestLoginAndSSOOnly)
- [x] `HP-OIDC-015` Logout semantics — WP14 — evidence: I, E — ✅ tested: session revoke + optional end-session URL without id_token_hint (internal/oidc/oidc_test.go (mock IdP) TestLogoutURL)

#### HP-RBAC — Operator RBAC

- [x] `HP-RBAC-001` Internal roles and matrix — WP15 — evidence: U, I — ✅ tested: matrix over every operation x role (internal/httpapi/api_test.go TestRBACMatrix) + SSE filtering (TestSSE)
- [x] `HP-RBAC-002` Address visibility permission — WP15 — evidence: I — ✅ tested: address redaction and host-identity permission (internal/httpapi/api_test.go TestAdministrationFlow)
- [x] `HP-RBAC-003` Approval requires role and scope — WP15 — evidence: I — ✅ tested: approve/deny need role + approver rule (access.Decide tests; API matrix)
- [x] `HP-RBAC-004` Recording permissions — WP15 — evidence: I, E — ✅ tested: play vs export permissions and defaults (rbac tests, API matrix, export endpoint)
- [x] `HP-RBAC-005` Retention and revocation permissions — WP15 — evidence: I — ✅ tested: revocation admin or in-scope approver (API matrix, access tests); retention is configuration-only (no API), changed by administrators with host access (ADR-0036)
- [x] `HP-RBAC-006` Auth-method-independent RBAC — WP15 — evidence: I — ✅ tested: identical local vs SSO decisions (internal/httpapi/api_test.go TestRBACMatrix)
- [x] `HP-RBAC-007` No default privilege — WP15 — evidence: I — ✅ tested: no roles = no permissions (rbac tests, API matrix, JIT test)

#### HP-API — REST API and live events

- [x] `HP-API-001` Spec-first OpenAPI — WP15 — evidence: C, I — ✅ tested: in-repo generator from OpenAPI 3.1 + TS types, drift check (make api-check, CI), response schema validation (ADR-0031)
- [ ] `HP-API-002` API versioning — WP15 — evidence: D, C — ◐ implemented: /api/v1 with additive policy (docs/VERSIONING.md)
- [x] `HP-API-003` Problem details — WP15 — evidence: U, I — ✅ tested: RFC 9457 problem details, no internals (internal/httpapi/api_test.go)
- [x] `HP-API-004` Server-side pagination — WP15 — evidence: I, E — ✅ tested: cursor pagination with bounds (internal/httpapi/api_test.go TestAdministrationFlow)
- [x] `HP-API-005` SSE live events — WP15 — evidence: I, E — ✅ tested: SSE IDs, resume, reset, filtering, limits, heartbeat (internal/httpapi/api_test.go TestSSE)
- [x] `HP-API-006` Idempotent mutations — WP15 — evidence: I — ✅ tested: Idempotency-Key replay and conflict (internal/httpapi/api_test.go)
- [x] `HP-API-007` Security headers — WP15 — evidence: I — ✅ tested: CSP, frame-ancestors, nosniff, referrer policy, no CORS (internal/httpapi/api_test.go TestAuthFlowAndProtections); HSTS when https
- [x] `HP-API-008` API rate limiting — WP15 — evidence: I — ✅ tested: per-IP/session/auth rate limits (internal/httpapi/api_test.go TestRateLimit)
- [x] `HP-API-009` Webhook isolation — WP16 — evidence: I — ✅ tested: /hooks/* without cookies, verified before parsing, rate limited (internal/notify/notify_test.go)

#### HP-UI — Web UI

- [ ] `HP-UI-001` Frontend stack — WP19 — evidence: C
- [ ] `HP-UI-002` Design system and themes — WP19 — evidence: V, E
- [ ] `HP-UI-003` Complete page set — WP20 — evidence: E
- [ ] `HP-UI-004` Access-session detail — WP21 — evidence: E
- [ ] `HP-UI-005` Authentication settings — WP20 — evidence: E
- [ ] `HP-UI-006` Login modes — WP19 — evidence: E, V
- [ ] `HP-UI-007` Real UI states — WP19 — evidence: E, V
- [ ] `HP-UI-008` Tables and saved filters — WP20 — evidence: E
- [ ] `HP-UI-009` Charts with real data — WP20 — evidence: E, A
- [ ] `HP-UI-010` Destructive confirmation — WP19 — evidence: E
- [ ] `HP-UI-011` Server-derived countdowns — WP19 — evidence: U, E
- [ ] `HP-UI-012` No optimistic security success — WP19 — evidence: E
- [ ] `HP-UI-013` Safe replay rendering — WP21 — evidence: U, E, SR
- [ ] `HP-UI-014` Accessibility — WP19 — evidence: A
- [ ] `HP-UI-015` Visual regression — WP19 — evidence: V
- [x] `HP-UI-016` Embedded build — WP19 — evidence: C, I — ✅ tested: embedui build tag embeds web/dist; SPA handler tests; serve smoke test

#### HP-NTF — Approvals and notifications

- [x] `HP-NTF-001` Durable outbox — WP16 — evidence: I, FI — ✅ tested: durable outbox with retries/dead letters, delivery history API (internal/notify/notify_test.go TestDeliveryFailureNeverApproves)
- [x] `HP-NTF-002` Notification content — WP16 — evidence: U, E — ✅ tested: content (verified agent, server/role context, untrusted reason, expiry, durations, deny, link) (internal/notify/notify_test.go TestSlackApprovalFlow)
- [x] `HP-NTF-003` Escaping and mention suppression — WP16 — evidence: U, Z — ✅ tested: escaping/mention suppression (adapter fuzz + internal/notify/notify_test.go)
- [x] `HP-NTF-004` No infrastructure disclosure — WP16 — evidence: U — ✅ tested: no addresses in messages (internal/notify/notify_test.go TestSlackApprovalFlow)
- [ ] `HP-NTF-005` Slack verification — WP17 — evidence: U, I — ◐ tested against fake Slack API (signature, timestamp, replay); real workspace verification pending
- [ ] `HP-NTF-006` Telegram verification — WP18 — evidence: U, I — ◐ tested against fake Bot API (secret token, allowlist, callback_data, replay); real bot verification pending
- [x] `HP-NTF-007` Action tokens — WP16 — evidence: U, I — ✅ tested: hashed single-use bound tokens, kind binding, never sufficient alone (internal/notify/notify_test.go)
- [x] `HP-NTF-008` Unified transactional decision — WP16 — evidence: I, FI — ✅ tested: chat decisions via access.Decide with linked operator (internal/notify/notify_test.go)
- [x] `HP-NTF-009` Idempotent callbacks — WP16 — evidence: I — ✅ tested: redelivery returns recorded outcome (internal/notify/notify_test.go)
- [x] `HP-NTF-010` No approval on failure — WP16 — evidence: FI, I — ✅ tested: delivery failure leaves request pending (internal/notify/notify_test.go TestDeliveryFailureNeverApproves)
- [x] `HP-NTF-011` Explicit provider identity mapping — WP16 — evidence: I, E — ✅ tested: link codes (single use, private chat), admin links, unlinking (internal/notify/notify_test.go)
- [x] `HP-NTF-012` Callback rate limits — WP16 — evidence: I — ✅ tested: per-integration webhook rate limit, per-operator decision limit, per-session API limits
- [x] `HP-NTF-013` Web approvals — WP16 — evidence: I, E — ✅ tested: web approval via API with duration choice and same decision service (internal/httpapi tests)

#### HP-OPS — Operations and distribution

- [x] `HP-OPS-001` Health and readiness — WP22 — evidence: I — ✅ tested: /healthz, /readyz lifecycle and checks (obs/health tests, app e2e)
- [x] `HP-OPS-002` Graceful shutdown — WP11 — evidence: I, O — ✅ tested: drain then terminate on SIGTERM (internal/app/e2e_test.go TestGatewayShutdownTerminates), container/systemd stop tests (WP24)
- [x] `HP-OPS-003` Backup command — WP23 — evidence: I, R — ✅ tested: backup create/verify/restore round trip, tamper cases (internal/backup tests)
- [ ] `HP-OPS-004` Restore onto clean machine — WP23 — evidence: R — ◐ partial: in-process restore tested; scripted clean-container drill pending
- [ ] `HP-OPS-005` Upgrade and rollback — WP23 — evidence: R, D — ◐ partial: forward-only migrations + docs; previous-release upgrade fixture test pending
- [ ] `HP-OPS-006` Capacity and disk alerts — WP22 — evidence: I, D — ◐ partial: disk metrics, reserve check refusing channels, readiness degrade; capacity guide pending WP26
- [ ] `HP-OPS-007` Container and standalone deploy — WP24 — evidence: I, D — ◐ partial: Dockerfile/compose/systemd tested locally (smoke script, compose, systemd-in-container); /readyz + ssh list in smoke pending
- [ ] `HP-OPS-008` CI pipeline — WP01 — evidence: C — ◐ implemented: CI jobs for lint/vet/analyzers/race/coverage/fuzz smoke/govulncheck/gitleaks/OpenSSH/web+API drift; Trivy in release workflow; not yet run on GitHub
- [ ] `HP-OPS-009` Release provenance — WP24 — evidence: C — ◐ implemented: release workflow with SBOM, provenance, Trivy; locally exercised, not yet run in CI
- [ ] `HP-OPS-010` Project documents — WP24 — evidence: D — ◐ partial: SECURITY.md, CONTRIBUTING.md, CHANGELOG.md, VERSIONING.md present; LICENSE pending R-01
- [ ] `HP-OPS-011` License decision — WP24 — evidence: D
- [x] `HP-OPS-012` No secrets in repo — WP01 — evidence: C — ✅ tested (local) @ WP01: gitleaks v8.30.1 clean; CI job `security`; .gitignore excludes keys/DBs/recordings
- [x] `HP-OPS-013` Config and runtime modes — WP02 — evidence: U, I — ✅ tested (local) @ WP02: internal/config (strict YAML, HALLPASS_* env, unknown-key/env rejection, production restrictions), `hallpass config check`
- [x] `HP-OPS-014` Durable jobs — WP05 — evidence: I — ✅ tested (local) @ WP05: durable jobs (lease, backoff, dead-letter, dedup, crash reclaim) + Periodic sweeps; outbox worker shares the model

#### HP-OBS — Observability

- [x] `HP-OBS-001` Structured JSON logs — WP02 — evidence: U, C — ✅ tested (local) @ WP02: internal/obs ECS-aligned JSON handler; schema in docs/operator/logging.md
- [x] `HP-OBS-002` Redaction layer — WP02 — evidence: U — ✅ tested (local) @ WP02: redact.Secret + key denylist in all handlers; planted-secret tests (internal/obs)
- [ ] `HP-OBS-003` Correlation IDs — WP22 — evidence: I — ◐ partial: correlation handler + HTTP request IDs + audit hook; SSH-side context propagation partial
- [ ] `HP-OBS-004` Metrics and traces — WP22 — evidence: I — ◐ tested: Prometheus metrics wired and checked end to end (internal/app TestGatewayHealthAndMetrics); OTLP traces; OTLP metrics not implemented
- [x] `HP-OBS-005` Audit log — WP05 — evidence: I — ✅ tested: hash-chained audit with verify (audit tests, API verify) + optional JSON-lines sink (log.audit_file)

#### HP-TST — Testing and quality

- [x] `HP-TST-001` Race detector — WP01 — evidence: C — ✅ tested (local) @ WP01: `make race` runs `go test -race -count=1 ./...`; CI job `go` configured
- [ ] `HP-TST-002` Fuzzing — WP26 — evidence: Z
- [ ] `HP-TST-003` Real OpenSSH integration — WP10 — evidence: O — ◐ tested locally: make test-openssh (8 tests, real ssh + sshd container); CI job added, not yet run in CI
- [ ] `HP-TST-004` Browser E2E — WP19 — evidence: E
- [ ] `HP-TST-005` Fault injection — WP26 — evidence: FI
- [ ] `HP-TST-006` Soak — WP26 — evidence: S
- [ ] `HP-TST-007` Measured performance — WP26 — evidence: S
- [ ] `HP-TST-008` Security review — WP26 — evidence: SR
- [ ] `HP-TST-009` Coverage floor — WP01 — evidence: C — ◐ WP01: floor script `scripts/coverage-floor.sh` (80%) in CI; enforced as each listed package lands

#### HP-DOC — Documentation

- [x] `HP-DOC-001` Operator guide — WP24 — evidence: D — ✅ done: docs/operator/{install,configuration,keys,backup,upgrade,storage,recording,observability,logging,sso,approvals,slack,telegram,container,policy,incidents}.md; root README.md
- [x] `HP-DOC-002` Agent guide — WP10 — evidence: D — ✅ done: docs/agent/{guide,exit-codes,json-schemas}.md
- [x] `HP-DOC-003` Destination hardening guide — WP25 — evidence: D — ✅ done: docs/destination/hardening.md + docs/destination/audit-collector.md
- [ ] `HP-DOC-004` Guarantees and non-guarantees — WP27 — evidence: D — ◐ written: docs/security-guarantees.md (G-1..G-10 with status, non-guarantees, assumptions) consistent with THREAT_MODEL; release-time consistency review is part of RG-10 (WP27)
- [x] `HP-DOC-005` Recording format spec — WP12 — evidence: D — ✅ done: docs/formats/hprec1.md + docs/operator/recording.md
- [ ] `HP-DOC-006` Changelog and versioning — WP24 — evidence: D — ◐ done: CHANGELOG.md + docs/VERSIONING.md (policy commitments await operator review, R-15)


---

## 22. Documentation and commit workflow

### 22.1 Documentation duties

- Before starting a WP: read `AGENTS.md`, `docs/GOAL.md` and this plan, then check §19.2 status and open review items.
- During a WP: record any design change as an ADR (new or superseding) in DECISIONS.md. Update the affected sections here.
  Never weaken a GOAL.md requirement without an ADR explicitly marked **security-relevant change** plus operator review.
- At WP completion: update §19.2 status and the commit column (hash after commit, in the next commit or the same WP's follow-up), check
  the owned boxes in §21 with evidence, and update operator/agent/API docs named by the WP.
- Status words follow GOAL.md §7 (`implemented` vs `tested` vs `externally verified`) and must not be inflated.

### 22.2 Commit workflow (local only)

1. `git status` and inspect the diff. Identify only the WP's files and make sure no unrelated user work or secrets are included.
2. `git add <explicit paths>` (never `git add -A` blindly in a dirty tree).
3. Run the `/cc` skill to generate a Conventional Commits message from the staged diff. `/cc` only prints a message and does
   not commit or push (verified at WP00: `~/.claude/skills/cc/SKILL.md` forbids running `git commit`).
4. `git commit` with that message (plus any attribution trailer the environment requires).
5. Report the commit hash. **Never `git push`**, and never create remotes, tags pushed to remotes, or PRs without an explicit user
   instruction for that specific action.
6. Do not amend, rebase, force-switch branches or discard changes. If work on `main` is blocked by unrelated changes,
   preserve them and report the blocker.
7. If `/cc` is unavailable, leave changes uncommitted, report that the required workflow is unavailable, and do not invent its output.
