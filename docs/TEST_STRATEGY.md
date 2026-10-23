# Hallpass — Test Strategy

> Defines how every requirement in `docs/GOAL.md` is verified, plus the fault-injection catalog, performance methodology and
> release-gate evidence. Requirement IDs here must match GOAL.md exactly. When a requirement is added, add it here in the same commit.

## 1. Principles

1. **Requirements drive tests.** Every requirement has at least one listed layer (§3). A requirement is not "tested" until those
   layers exist and pass in CI, or have recorded evidence for drills, soak and reviews.
2. **Real components at boundaries.** Real SQLite files, real filesystems, real OpenSSH clients and servers, a real browser. Mocks are
   used only for third-party SaaS (Slack/Telegram/IdP), and each mock is paired with interop smoke tests.
3. **Security tests are negative-first.** For each control, test that the forbidden thing fails, as well as that the allowed thing works.
4. **Deterministic and race-checked.** All Go tests run with `-race`. Time is injected through a clock interface. Randomness is seeded in
   property tests and logged.
5. **No secrets in fixtures.** Keys, tokens and certificates are generated at test time. Golden files contain no secret-bearing data
   (HP-OPS-012).
6. **Never inflate status.** "Implemented", "tested" and "externally verified" are distinct (GOAL.md §7).

## 2. Test layers

| Code | Layer | Tooling | Where | Cadence |
|---|---|---|---|---|
| U | Unit | `go test`, Vitest | package-local `_test.go`, `web/src/**/*.test.ts(x)` | every push |
| P | Property | `testing/quick` or `pgregory.net/rapid` | `internal/policy`, `internal/access`, `internal/keyring` | every push |
| Z | Fuzz | Go native fuzzing | `Fuzz*` in grammar, agent key parsing, hprec reader, selectors, webhook parsing, sanitizer | 30 s smoke per target each push; ≥ 10 min per target nightly and per release |
| I | Integration | `go test` with real SQLite + temp dirs + in-process SSH | `internal/**` `_integration_test.go` (build tag `integration`) | every push |
| O | OpenSSH interop | Docker: `openssh-client` + `sshd` images (OpenSSH 8.9, 9.6, latest), Go test driver | `test/openssh` | every push (latest only), nightly (full matrix) |
| E | Browser E2E | Playwright (Chromium) against a real `hallpass serve` + OpenSSH fixtures | `web/e2e` | every push |
| A | Accessibility | `@axe-core/playwright` on every route, both themes | `web/e2e/a11y` | every push |
| V | Visual regression | Playwright screenshots (`/__ds` gallery + key pages, light/dark, fixed fonts) | `web/e2e/visual` | every push; baselines updated only in reviewed commits |
| FI | Fault injection | Fault hooks (`internal/testhooks`, build tag `faults`), failing FS wrapper, `kill -9` harness, `dm-flakey`/VM reset nightly | `test/fault` | nightly + release |
| S | Soak/load/perf | Go load driver (`test/soak`), `pprof`, Prometheus scrape | dedicated reference hardware | perf weekly + release; soak per release |
| C | CI/static | golangci-lint, custom analyzers, `sqlc diff`, OpenAPI drift, `x-permission` check, govulncheck, Trivy, gitleaks, coverage floor | `.github/workflows/ci.yaml` | every push |
| R | Recovery drill | Scripted backup → clean-host restore → verify; upgrade from previous release fixture | `test/recovery` | nightly (container) + release (VM) |
| SR | Security review | Checklist §6, manual code review, optional external pentest | `docs/evidence/<release>/security-review.md` | per RC |
| D | Documentation review | Checklist against GOAL/THREAT_MODEL consistency | `docs/evidence/<release>/docs-review.md` | per RC |

### 2.1 OpenSSH interop harness (O)

- Images are built from pinned distro packages: Ubuntu 22.04 (OpenSSH 8.9), Ubuntu 24.04 (9.6), Alpine latest. The gateway runs in-process
  (Go test), and client and destination run in containers on an isolated Docker network. A Go driver runs `ssh` with
  generated keys and `-o UserKnownHostsFile` pinned to the gateway's key.
- Destination fixtures: a normal user, a user with `restrict` authorized_keys, a TrustedUserCAKeys configuration, a host-cert-presenting sshd,
  and a "changed host key" variant.
- Assertions compare stdout/stderr bytes, exit codes, timing bounds and recorded segments (decrypted in-test).

### 2.2 OIDC test strategy

An in-process mock IdP (`internal/oidc/oidctest`) supports discovery, JWKS rotation, configurable claims and deliberate malformation
(bad signature, `alg=none`, HS256 with the public key as the secret, wrong `iss`/`aud`/`azp`, expired, future `iat`, missing or
replayed nonce, missing `auth_time`). Nightly interop runs against Keycloak and Dex containers. Results against real commercial IdPs
(Entra ID, Okta, Google) are recorded as **externally verified** evidence when performed.

## 3. Requirement → test matrix

Layer codes per §2. "Location" names the primary package or suite where those tests live. Every requirement in GOAL.md §6 is listed
(239 total).

#### HP-SSH — SSH front end and data plane (`internal/sshfront`, `internal/sshproxy`, `test/openssh`)

| ID | Title | Layers | WP |
|---|---|---|---|
| HP-SSH-001 | Public-key-only agent auth | U (unit), O (OpenSSH interop) | WP10 |
| HP-SSH-002 | Identity from key, not username | O (OpenSSH interop), I (integration) | WP10 |
| HP-SSH-003 | Uniform rejection of unknown/revoked keys | O (OpenSSH interop), I (integration) | WP10 |
| HP-SSH-004 | Algorithm policy | U (unit), O (OpenSSH interop) | WP10 |
| HP-SSH-005 | Gateway host key lifecycle | U (unit), O (OpenSSH interop), D (documentation review) | WP10 |
| HP-SSH-006 | Shell, exec, PTY completeness | O (OpenSSH interop) | WP11 |
| HP-SSH-007 | Forwarding and unknown channels denied | O (OpenSSH interop), I (integration) | WP10 |
| HP-SSH-008 | Environment allowlist | U (unit), O (OpenSSH interop) | WP11 |
| HP-SSH-009 | Stdout purity | O (OpenSSH interop) | WP10 |
| HP-SSH-010 | Exit status and signal propagation | O (OpenSSH interop) | WP11 |
| HP-SSH-011 | Strict destination host verification | C (CI/static check), O (OpenSSH interop) | WP11 |
| HP-SSH-012 | Keepalive and idle timeouts | I (integration), O (OpenSSH interop) | WP11 |
| HP-SSH-013 | Pre-auth and connection limits | S (soak/load/perf), FI (fault injection) | WP10 |
| HP-SSH-014 | Bounded buffering and backpressure | S (soak/load/perf), I (integration) | WP11 |
| HP-SSH-015 | Cancellation and cleanup | U (unit), S (soak/load/perf) | WP11 |
| HP-SSH-016 | Shell-free command grammar | U (unit), Z (fuzz) | WP10 |
| HP-SSH-017 | Reserved words | U (unit), O (OpenSSH interop) | WP10 |
| HP-SSH-018 | Stable JSON output | U (unit), O (OpenSSH interop) | WP10 |
| HP-SSH-019 | No hang without input | O (OpenSSH interop) | WP10 |
| HP-SSH-020 | Bounded wait with auto-connect | O (OpenSSH interop), I (integration) | WP10 |
| HP-SSH-021 | Disconnect does not mutate requests | O (OpenSSH interop), I (integration) | WP10 |
| HP-SSH-022 | Unambiguous default role | U (unit), O (OpenSSH interop) | WP10 |
| HP-SSH-023 | Remote exec encoding | U (unit), O (OpenSSH interop), D (documentation review) | WP11 |
| HP-SSH-024 | Introspection commands | O (OpenSSH interop) | WP10 |
| HP-SSH-025 | Grant revalidation per channel | U (unit), I (integration) | WP11 |

#### HP-AGT — Agent registration (`internal/agents`, `test/openssh`)

| ID | Title | Layers | WP |
|---|---|---|---|
| HP-AGT-001 | Agent record | U (unit), I (integration) | WP06 |
| HP-AGT-002 | Multiple keys per agent | U (unit), I (integration) | WP06 |
| HP-AGT-003 | Globally unique key ownership | I (integration) | WP06 |
| HP-AGT-004 | Validated key parsing | U (unit), Z (fuzz) | WP06 |
| HP-AGT-005 | Immediate key revocation | O (OpenSSH interop), I (integration) | WP09 |
| HP-AGT-006 | No agent private keys | U (unit) | WP06 |
| HP-AGT-007 | Source CIDR restriction | O (OpenSSH interop), D (documentation review) | WP10 |
| HP-AGT-008 | Agent disablement | I (integration), O (OpenSSH interop) | WP09 |
| HP-AGT-009 | Agent audit history | I (integration) | WP06 |

#### HP-SRV — Destination servers and roles (`internal/inventory`, `internal/egress`)

| ID | Title | Layers | WP |
|---|---|---|---|
| HP-SRV-001 | Server record | U (unit), I (integration) | WP07 |
| HP-SRV-002 | Role record | U (unit), I (integration) | WP07 |
| HP-SRV-003 | Descriptions are not enforcement | E (browser E2E), D (documentation review) | WP20 |
| HP-SRV-004 | Explicit host identity enrollment | I (integration), O (OpenSSH interop) | WP07 |
| HP-SRV-005 | Host key rotation | I (integration), O (OpenSSH interop) | WP07 |
| HP-SRV-006 | Duplicate host identity detection | I (integration) | WP07 |
| HP-SRV-007 | Host CA model | U (unit), O (OpenSSH interop) | WP07 |
| HP-SRV-008 | Server/role disablement | I (integration), O (OpenSSH interop) | WP09 |
| HP-SRV-009 | Egress validation (anti-SSRF) | U (unit), I (integration) | WP07 |
| HP-SRV-010 | Address confidentiality | I (integration), E (browser E2E) | WP15 |

#### HP-KEY — Destination login credentials and signing keys (`internal/credentials`, `test/openssh`)

| ID | Title | Layers | WP |
|---|---|---|---|
| HP-KEY-001 | Managed login key default | U (unit), I (integration) | WP07 |
| HP-KEY-002 | Public key installation aid | E (browser E2E), I (integration) | WP07 |
| HP-KEY-003 | Login key rotation | I (integration), O (OpenSSH interop) | WP07 |
| HP-KEY-004 | OpenSSH user certificates | U (unit), O (OpenSSH interop) | WP07 |
| HP-KEY-005 | Signer abstraction | U (unit) | WP07 |
| HP-KEY-006 | Distinct key types | C (CI/static check), SR (security review) | WP07 |
| HP-KEY-007 | Credential isolation | U (unit), I (integration), SR (security review) | WP07 |

#### HP-POL — Visibility and policy (`internal/policy`)

| ID | Title | Layers | WP |
|---|---|---|---|
| HP-POL-001 | Default deny | U (unit), P (property) | WP08 |
| HP-POL-002 | Deny overrides | U (unit), P (property) | WP08 |
| HP-POL-003 | Selector semantics | U (unit), P (property) | WP08 |
| HP-POL-004 | Level lattice | U (unit), P (property) | WP08 |
| HP-POL-005 | Role and server visibility | U (unit) | WP08 |
| HP-POL-006 | Separated permissions | U (unit), I (integration) | WP08 |
| HP-POL-007 | Policy versioning | I (integration) | WP08 |
| HP-POL-008 | Policy change effects | I (integration) | WP09 |
| HP-POL-009 | Effective-access preview | U (unit), E (browser E2E) | WP08 |
| HP-POL-010 | Hidden-target non-disclosure | U (unit), O (OpenSSH interop), I (integration) | WP10 |
| HP-POL-011 | Approver authority rules | U (unit), I (integration) | WP08 |
| HP-POL-012 | Self-approval prohibition | U (unit), I (integration) | WP08 |
| HP-POL-013 | Auto-approval within limits | U (unit), I (integration) | WP08 |
| HP-POL-014 | Command allowlists are not a sandbox | D (documentation review) | WP08 |

#### HP-REQ — Access requests (`internal/access`)

| ID | Title | Layers | WP |
|---|---|---|---|
| HP-REQ-001 | Request state machine | U (unit), P (property) | WP09 |
| HP-REQ-002 | Request record | U (unit), I (integration) | WP09 |
| HP-REQ-003 | Deduplication and idempotency | I (integration), O (OpenSSH interop) | WP09 |
| HP-REQ-004 | Pending expiry | I (integration) | WP09 |
| HP-REQ-005 | Wait vs expiry vs duration | O (OpenSSH interop), D (documentation review) | WP10 |
| HP-REQ-006 | Cancellation | I (integration), O (OpenSSH interop) | WP09 |
| HP-REQ-007 | Request rate limits | I (integration), S (soak/load/perf) | WP09 |
| HP-REQ-008 | Bounded untrusted reason | U (unit), Z (fuzz) | WP09 |
| HP-REQ-009 | Status polling | O (OpenSSH interop) | WP10 |

#### HP-GRT — Grants and enforcement (`internal/access`, `test/openssh`)

| ID | Title | Layers | WP |
|---|---|---|---|
| HP-GRT-001 | Transactional decision and grant | I (integration), FI (fault injection) | WP09 |
| HP-GRT-002 | Grant record | U (unit), I (integration) | WP09 |
| HP-GRT-003 | No implicit extension | U (unit), I (integration) | WP09 |
| HP-GRT-004 | Active grant reuse | I (integration), O (OpenSSH interop) | WP09 |
| HP-GRT-005 | Deterministic overlap selection | U (unit), P (property) | WP09 |
| HP-GRT-006 | Atomic concurrency limits | I (integration), S (soak/load/perf) | WP09 |
| HP-GRT-007 | Race resolution | U (unit), I (integration) | WP09 |
| HP-GRT-008 | Enforcement bound | I (integration), O (OpenSSH interop), S (soak/load/perf) | WP09 |
| HP-GRT-009 | Operator revocation | I (integration), E (browser E2E) | WP09 |
| HP-GRT-010 | Approval after expiry | I (integration) | WP09 |
| HP-GRT-011 | Emergency lockdown | I (integration), E (browser E2E) | WP09 |

#### HP-SES — Access sessions (`internal/access`)

| ID | Title | Layers | WP |
|---|---|---|---|
| HP-SES-001 | Session per grant | I (integration) | WP09 |
| HP-SES-002 | Connections and channels | I (integration), O (OpenSSH interop) | WP09 |
| HP-SES-003 | Session closure | I (integration) | WP09 |
| HP-SES-004 | Detached processes | D (documentation review) | WP25 |
| HP-SES-005 | Live activity view | E (browser E2E) | WP20 |

#### HP-REC — Event history and recording (`internal/recording`, `test/fault`)

| ID | Title | Layers | WP |
|---|---|---|---|
| HP-REC-001 | Versioned event schema | U (unit), I (integration) | WP12 |
| HP-REC-002 | Ordering and causality | U (unit), I (integration), P (property) | WP12 |
| HP-REC-003 | Idempotent events | U (unit), I (integration) | WP12 |
| HP-REC-004 | Capture fidelity | O (OpenSSH interop), I (integration) | WP12 |
| HP-REC-005 | Input recording opt-in | I (integration), D (documentation review) | WP12 |
| HP-REC-006 | No false command claims | E (browser E2E), D (documentation review) | WP21 |
| HP-REC-007 | Mandatory recording fail-closed | FI (fault injection), O (OpenSSH interop) | WP12 |
| HP-REC-008 | Durability guarantee | FI (fault injection), I (integration) | WP12 |
| HP-REC-009 | Accurate incomplete marking | FI (fault injection), I (integration) | WP12 |
| HP-REC-010 | Unified timeline, distinct streams | E (browser E2E) | WP21 |
| HP-REC-011 | No silent event drops | U (unit), FI (fault injection), S (soak/load/perf) | WP12 |
| HP-REC-012 | Destination-side audit integration | O (OpenSSH interop), D (documentation review) | WP25 |
| HP-REC-013 | Retention and deletion | I (integration), E (browser E2E) | WP12 |
| HP-REC-014 | Restricted, audited download | E (browser E2E), I (integration) | WP21 |

#### HP-CRY — Cryptography and key management (`internal/keyring`, `internal/recording/hprec`)

| ID | Title | Layers | WP |
|---|---|---|---|
| HP-CRY-001 | Master KEK provisioning | U (unit), I (integration) | WP04 |
| HP-CRY-002 | Purpose keys and rotation | U (unit), I (integration) | WP04 |
| HP-CRY-003 | Field encryption | U (unit), P (property) | WP04 |
| HP-CRY-004 | Recording file format | U (unit), Z (fuzz), SR (security review) | WP12 |
| HP-CRY-005 | Integrity verification | I (integration), R (recovery drill) | WP12 |
| HP-CRY-006 | Vetted cryptography only | C (CI/static check), SR (security review) | WP01 |
| HP-CRY-007 | Key loss and recovery | D (documentation review), R (recovery drill) | WP23 |
| HP-CRY-008 | External integrity anchoring | I (integration), D (documentation review) | WP23 |
| HP-CRY-009 | Ciphertext-only archival | I (integration), R (recovery drill) | WP23 |

#### HP-DB — SQLite storage (`internal/store`, `test/fault`)

| ID | Title | Layers | WP |
|---|---|---|---|
| HP-DB-001 | Pure-Go driver | C (CI/static check) | WP03 |
| HP-DB-002 | Per-connection pragmas | I (integration) | WP03 |
| HP-DB-003 | Writer/reader split | I (integration), S (soak/load/perf) | WP03 |
| HP-DB-004 | Short transactions | I (integration), C (CI/static check) | WP03 |
| HP-DB-005 | Safe migrations | I (integration), FI (fault injection) | WP03 |
| HP-DB-006 | Single active instance | I (integration) | WP03 |
| HP-DB-007 | Unsupported storage refusal | I (integration) | WP03 |
| HP-DB-008 | Corruption checks | I (integration), FI (fault injection) | WP03 |
| HP-DB-009 | Disk-full and I/O failure | FI (fault injection) | WP03 |
| HP-DB-010 | Filesystem permissions | I (integration) | WP03 |
| HP-DB-011 | Bounded growth | I (integration), S (soak/load/perf) | WP03 |
| HP-DB-012 | Consistent backup primitive | I (integration), R (recovery drill) | WP03 |
| HP-DB-013 | Crash reconciliation | FI (fault injection), I (integration) | WP09 |
| HP-DB-014 | Recovery objectives | R (recovery drill), D (documentation review) | WP23 |

#### HP-AUTH — Operator authentication and browser sessions (`internal/opauth`, `web/e2e`)

| ID | Title | Layers | WP |
|---|---|---|---|
| HP-AUTH-001 | Secure bootstrap | I (integration), E (browser E2E) | WP13 |
| HP-AUTH-002 | Argon2id hashing | U (unit) | WP13 |
| HP-AUTH-003 | Password policy | U (unit), E (browser E2E) | WP13 |
| HP-AUTH-004 | Throttling without permanent lockout | I (integration) | WP13 |
| HP-AUTH-005 | Enumeration resistance | U (unit), I (integration) | WP13 |
| HP-AUTH-006 | TOTP MFA | U (unit), I (integration), E (browser E2E) | WP13 |
| HP-AUTH-007 | Recovery codes | U (unit), I (integration) | WP13 |
| HP-AUTH-008 | Mandatory MFA for privileged accounts | I (integration), E (browser E2E) | WP13 |
| HP-AUTH-009 | Password change and reset | I (integration), E (browser E2E) | WP13 |
| HP-AUTH-010 | Session invalidation | I (integration) | WP13 |
| HP-AUTH-011 | Invitations | I (integration), E (browser E2E) | WP13 |
| HP-AUTH-012 | Server-side sessions | I (integration), E (browser E2E) | WP13 |
| HP-AUTH-013 | CSRF protection | I (integration), E (browser E2E) | WP13 |
| HP-AUTH-014 | Recent authentication | I (integration), E (browser E2E) | WP13 |
| HP-AUTH-015 | Lockout prevention | I (integration), E (browser E2E) | WP13 |
| HP-AUTH-016 | Break-glass recovery | I (integration), R (recovery drill) | WP23 |
| HP-AUTH-017 | Dev auth isolation | C (CI/static check), I (integration) | WP13 |
| HP-AUTH-018 | Credential secrecy | U (unit), I (integration) | WP13 |

#### HP-OIDC — Generic OpenID Connect SSO (`internal/oidc` (mock IdP), `web/e2e`)

| ID | Title | Layers | WP |
|---|---|---|---|
| HP-OIDC-001 | Provider configuration | U (unit), I (integration) | WP14 |
| HP-OIDC-002 | Code flow with PKCE | I (integration) | WP14 |
| HP-OIDC-003 | ID token validation | U (unit), I (integration) | WP14 |
| HP-OIDC-004 | JWKS caching and rotation | I (integration) | WP14 |
| HP-OIDC-005 | TLS and redirect safety | U (unit), I (integration) | WP14 |
| HP-OIDC-006 | Endpoint validation | U (unit), I (integration) | WP14 |
| HP-OIDC-007 | Secret handling | I (integration), E (browser E2E) | WP14 |
| HP-OIDC-008 | Token minimization | I (integration) | WP14 |
| HP-OIDC-009 | Identity by issuer+subject | I (integration), E (browser E2E) | WP14 |
| HP-OIDC-010 | Provisioning modes | I (integration) | WP14 |
| HP-OIDC-011 | Group mapping | U (unit), I (integration) | WP14 |
| HP-OIDC-012 | Provider outage behavior | I (integration), FI (fault injection) | WP14 |
| HP-OIDC-013 | Upstream step-up | I (integration) | WP14 |
| HP-OIDC-014 | Test-login before enforcement | E (browser E2E) | WP14 |
| HP-OIDC-015 | Logout semantics | I (integration), E (browser E2E) | WP14 |

#### HP-RBAC — Operator RBAC (`internal/rbac`, `internal/httpapi`)

| ID | Title | Layers | WP |
|---|---|---|---|
| HP-RBAC-001 | Internal roles and matrix | U (unit), I (integration) | WP15 |
| HP-RBAC-002 | Address visibility permission | I (integration) | WP15 |
| HP-RBAC-003 | Approval requires role and scope | I (integration) | WP15 |
| HP-RBAC-004 | Recording permissions | I (integration), E (browser E2E) | WP15 |
| HP-RBAC-005 | Retention and revocation permissions | I (integration) | WP15 |
| HP-RBAC-006 | Auth-method-independent RBAC | I (integration) | WP15 |
| HP-RBAC-007 | No default privilege | I (integration) | WP15 |

#### HP-API — REST API and live events (`internal/httpapi`)

| ID | Title | Layers | WP |
|---|---|---|---|
| HP-API-001 | Spec-first OpenAPI | C (CI/static check), I (integration) | WP15 |
| HP-API-002 | API versioning | D (documentation review), C (CI/static check) | WP15 |
| HP-API-003 | Problem details | U (unit), I (integration) | WP15 |
| HP-API-004 | Server-side pagination | I (integration), E (browser E2E) | WP15 |
| HP-API-005 | SSE live events | I (integration), E (browser E2E) | WP15 |
| HP-API-006 | Idempotent mutations | I (integration) | WP15 |
| HP-API-007 | Security headers | I (integration) | WP15 |
| HP-API-008 | API rate limiting | I (integration) | WP15 |
| HP-API-009 | Webhook isolation | I (integration) | WP16 |

#### HP-UI — Web UI (`web/src`, `web/e2e`)

| ID | Title | Layers | WP |
|---|---|---|---|
| HP-UI-001 | Frontend stack | C (CI/static check) | WP19 |
| HP-UI-002 | Design system and themes | V (visual regression), E (browser E2E) | WP19 |
| HP-UI-003 | Complete page set | E (browser E2E) | WP20 |
| HP-UI-004 | Access-session detail | E (browser E2E) | WP21 |
| HP-UI-005 | Authentication settings | E (browser E2E) | WP20 |
| HP-UI-006 | Login modes | E (browser E2E), V (visual regression) | WP19 |
| HP-UI-007 | Real UI states | E (browser E2E), V (visual regression) | WP19 |
| HP-UI-008 | Tables and saved filters | E (browser E2E) | WP20 |
| HP-UI-009 | Charts with real data | E (browser E2E), A (accessibility) | WP20 |
| HP-UI-010 | Destructive confirmation | E (browser E2E) | WP19 |
| HP-UI-011 | Server-derived countdowns | U (unit), E (browser E2E) | WP19 |
| HP-UI-012 | No optimistic security success | E (browser E2E) | WP19 |
| HP-UI-013 | Safe replay rendering | U (unit), E (browser E2E), SR (security review) | WP21 |
| HP-UI-014 | Accessibility | A (accessibility) | WP19 |
| HP-UI-015 | Visual regression | V (visual regression) | WP19 |
| HP-UI-016 | Embedded build | C (CI/static check), I (integration) | WP19 |

#### HP-NTF — Approvals and notifications (`internal/notify/...`)

| ID | Title | Layers | WP |
|---|---|---|---|
| HP-NTF-001 | Durable outbox | I (integration), FI (fault injection) | WP16 |
| HP-NTF-002 | Notification content | U (unit), E (browser E2E) | WP16 |
| HP-NTF-003 | Escaping and mention suppression | U (unit), Z (fuzz) | WP16 |
| HP-NTF-004 | No infrastructure disclosure | U (unit) | WP16 |
| HP-NTF-005 | Slack verification | U (unit), I (integration) | WP17 |
| HP-NTF-006 | Telegram verification | U (unit), I (integration) | WP18 |
| HP-NTF-007 | Action tokens | U (unit), I (integration) | WP16 |
| HP-NTF-008 | Unified transactional decision | I (integration), FI (fault injection) | WP16 |
| HP-NTF-009 | Idempotent callbacks | I (integration) | WP16 |
| HP-NTF-010 | No approval on failure | FI (fault injection), I (integration) | WP16 |
| HP-NTF-011 | Explicit provider identity mapping | I (integration), E (browser E2E) | WP16 |
| HP-NTF-012 | Callback rate limits | I (integration) | WP16 |
| HP-NTF-013 | Web approvals | I (integration), E (browser E2E) | WP16 |

#### HP-OPS — Operations and distribution (`internal/app`, `test/recovery`, CI)

| ID | Title | Layers | WP |
|---|---|---|---|
| HP-OPS-001 | Health and readiness | I (integration) | WP22 |
| HP-OPS-002 | Graceful shutdown | I (integration), O (OpenSSH interop) | WP11 |
| HP-OPS-003 | Backup command | I (integration), R (recovery drill) | WP23 |
| HP-OPS-004 | Restore onto clean machine | R (recovery drill) | WP23 |
| HP-OPS-005 | Upgrade and rollback | R (recovery drill), D (documentation review) | WP23 |
| HP-OPS-006 | Capacity and disk alerts | I (integration), D (documentation review) | WP22 |
| HP-OPS-007 | Container and standalone deploy | I (integration), D (documentation review) | WP24 |
| HP-OPS-008 | CI pipeline | C (CI/static check) | WP01 |
| HP-OPS-009 | Release provenance | C (CI/static check) | WP24 |
| HP-OPS-010 | Project documents | D (documentation review) | WP24 |
| HP-OPS-011 | License decision | D (documentation review) | WP24 |
| HP-OPS-012 | No secrets in repo | C (CI/static check) | WP01 |
| HP-OPS-013 | Config and runtime modes | U (unit), I (integration) | WP02 |
| HP-OPS-014 | Durable jobs | I (integration) | WP05 |

#### HP-OBS — Observability (`internal/obs`)

| ID | Title | Layers | WP |
|---|---|---|---|
| HP-OBS-001 | Structured JSON logs | U (unit), C (CI/static check) | WP02 |
| HP-OBS-002 | Redaction layer | U (unit) | WP02 |
| HP-OBS-003 | Correlation IDs | I (integration) | WP22 |
| HP-OBS-004 | Metrics and traces | I (integration) | WP22 |
| HP-OBS-005 | Audit log | I (integration) | WP05 |

#### HP-TST — Testing and quality (CI, `test/*`)

| ID | Title | Layers | WP |
|---|---|---|---|
| HP-TST-001 | Race detector | C (CI/static check) | WP01 |
| HP-TST-002 | Fuzzing | Z (fuzz) | WP26 |
| HP-TST-003 | Real OpenSSH integration | O (OpenSSH interop) | WP10 |
| HP-TST-004 | Browser E2E | E (browser E2E) | WP19 |
| HP-TST-005 | Fault injection | FI (fault injection) | WP26 |
| HP-TST-006 | Soak | S (soak/load/perf) | WP26 |
| HP-TST-007 | Measured performance | S (soak/load/perf) | WP26 |
| HP-TST-008 | Security review | SR (security review) | WP26 |
| HP-TST-009 | Coverage floor | C (CI/static check) | WP01 |

#### HP-DOC — Documentation (`docs/`)

| ID | Title | Layers | WP |
|---|---|---|---|
| HP-DOC-001 | Operator guide | D (documentation review) | WP24 |
| HP-DOC-002 | Agent guide | D (documentation review) | WP10 |
| HP-DOC-003 | Destination hardening guide | D (documentation review) | WP25 |
| HP-DOC-004 | Guarantees and non-guarantees | D (documentation review) | WP27 |
| HP-DOC-005 | Recording format spec | D (documentation review) | WP12 |
| HP-DOC-006 | Changelog and versioning | D (documentation review) | WP24 |


### 3.1 Brief §23 coverage map

| Brief test topic | Requirements |
|---|---|
| Registered/unknown/revoked SSH keys | HP-SSH-001, HP-SSH-003, HP-AGT-005 |
| SSH username spoofing | HP-SSH-002 |
| Visibility and hidden-target non-disclosure | HP-POL-005, HP-POL-010 |
| Policy precedence and role restrictions | HP-POL-002..004, HP-SSH-022 |
| Request waiting/polling/deduplication | HP-SSH-020, HP-SSH-021, HP-REQ-003, HP-REQ-009 |
| Approval authorization, forgery, replay, concurrent decisions | HP-POL-011, HP-NTF-005..009, HP-GRT-007 |
| Grant reuse and expiry boundaries | HP-GRT-003..005, HP-GRT-010 |
| Revalidation for every channel | HP-SSH-025 |
| Revocation and disablement | HP-AGT-005, HP-AGT-008, HP-SRV-008, HP-GRT-008, HP-GRT-009 |
| Host verification and rotation | HP-SSH-011, HP-SRV-004..007 |
| Credential isolation | HP-KEY-007, HP-SRV-010 |
| Shell/exec/PTY stream semantics | HP-SSH-006, HP-SSH-009 |
| EOF, resize, exit status, disconnect cleanup | HP-SSH-006, HP-SSH-010, HP-SSH-015 |
| Denied forwarding/subsystems | HP-SSH-007 |
| Event ordering | HP-REC-001..003 |
| Durable recording and mandatory-recording failure | HP-REC-007..009, HP-REC-011 |
| Encryption, integrity, key rotation, recovery | HP-CRY-001..005, HP-CRY-007 |
| SQLite concurrency and crash consistency | HP-DB-002..005, HP-DB-013 |
| Disk exhaustion and storage/database failure | HP-DB-008, HP-DB-009 |
| Restart reconciliation | HP-DB-013, HP-REC-009 |
| Restore onto a clean machine | HP-OPS-004 |
| Long-running/concurrent-session load | HP-TST-006, HP-TST-007 |
| Resource leaks and bounded memory | HP-SSH-014, HP-SSH-015, HP-TST-006 |
| Accessibility and visual consistency | HP-UI-014, HP-UI-015 |
| Replay safety and recording permissions | HP-UI-013, HP-REC-014, HP-RBAC-004 |
| Supported-version upgrades | HP-OPS-005, HP-DB-005 |
| Secure bootstrap | HP-AUTH-001 |
| Password hashing/verification | HP-AUTH-002, HP-AUTH-003 |
| Throttling and enumeration resistance | HP-AUTH-004, HP-AUTH-005 |
| Password reset/session invalidation | HP-AUTH-009, HP-AUTH-010 |
| MFA enrollment/recovery/disablement | HP-AUTH-006..008, HP-AUTH-014 |
| OIDC state/nonce/PKCE/token/issuer checks | HP-OIDC-002, HP-OIDC-003 |
| JWKS rotation | HP-OIDC-004 |
| Provisioning restrictions | HP-OIDC-010 |
| Account-linking safety | HP-OIDC-009, HP-NTF-011 |
| Group-role mapping/removal | HP-OIDC-011 |
| All login modes | HP-UI-006, HP-AUTH-015 |
| Provider outages | HP-OIDC-012 |
| Administrator lockout prevention | HP-AUTH-015, HP-AUTH-016 |
| Secret redaction/encryption | HP-OBS-002, HP-AUTH-018, HP-CRY-003 |
| Identical RBAC across authentication methods | HP-RBAC-006 |

## 4. Fault-injection catalog

Each scenario passes only if the stated expected outcome holds **and** no security-relevant event is silently lost.

| ID | Fault | Injection | Expected outcome | Requirements |
|---|---|---|---|---|
| FI-01 | Crash during decision tx | `kill -9` via hook before/after `COMMIT` | Either the full decision+grant+session exists or nothing does. The request stays pending or becomes approved, with no partial rows. | HP-GRT-001 |
| FI-02 | Crash between channel registration and segment creation | hook + `kill -9` | Channel `failed`/`interrupted`, segment `failed`, no forwarding occurred. | HP-REC-007, HP-DB-013 |
| FI-03 | Crash mid-recording (`group` mode) | `kill -9` during W2 load | Segment `interrupted`, the valid prefix authenticates, loss ≤ 250 ms of output. | HP-REC-008, HP-REC-009 |
| FI-04 | Crash between rename and finalize tx | hook | Reconciliation marks `finalized` after verifying the final frame, and a chain entry is added. | HP-DB-013 |
| FI-05 | `ENOSPC` on segment write | failing-FS wrapper / small tmpfs | Channel terminated (exit 80 notice), `recording.failed`, readiness degraded, no new channels. | HP-REC-007, HP-DB-009 |
| FI-06 | `SQLITE_FULL` | tiny volume | New requests and channels refused, existing non-recording-affected channels continue, readiness degraded. | HP-DB-009 |
| FI-07 | `EIO` on fsync | failing-FS wrapper | Channel terminated, segment `failed`, no fsync retry, alert. | HP-REC-007, HP-DB-009 |
| FI-08 | Slow disk (2 s fsync) | latency-injecting FS | Backpressure, bounded RSS, no drops, terminate after 10 s block. | HP-REC-011, HP-SSH-014 |
| FI-09 | Writer contention / long reader | external connection holds a read tx and checkpoint starves | Bounded retries, `storage_busy` errors, readiness degraded after 30 s, recovery when released. | HP-DB-003 |
| FI-10 | Corrupted DB page | byte flip in a copy, then start | Startup refuses with restore guidance. | HP-DB-008 |
| FI-11 | Corrupted/truncated/reordered segment | byte flips, truncation, frame swaps, cross-segment swaps | `verify` reports `corrupt`/`interrupted`, and replay stops at the last authentic frame with a warning. | HP-CRY-004, HP-CRY-005 |
| FI-12 | Missing segment file | delete file | `missing` state, alert, UI shows it. | HP-CRY-005, HP-DB-013 |
| FI-13 | Orphan segment file | add a stray file | Quarantined and reported. | HP-DB-013 |
| FI-14 | KEK missing / wrong KEK | config | Production refuses to start, and the canary detects a wrong key. | HP-CRY-001 |
| FI-15 | Destination blackhole mid-session | `iptables DROP` in the fixture network | Keepalive detects within configured probes, channel closed, resources freed. | HP-SSH-012, HP-SSH-015 |
| FI-16 | Destination host key changed | swap the sshd host key | Connection refused (exit 88), alert event, no credential sent. | HP-SSH-011, HP-SRV-005 |
| FI-17 | Agent stops reading output | paused client | Bounded memory, destination throttled by window, idle/keepalive policies apply. | HP-SSH-014 |
| FI-18 | Slack/Telegram API failures | fake API returns 5xx, timeouts, 429 | Retries with backoff then `dead`, delivery history recorded, request never approved. | HP-NTF-001, HP-NTF-010 |
| FI-19 | IdP outage / JWKS rotation mid-login | stop mock IdP, rotate keys | Login fails closed with a clear error, existing sessions unaffected, recovers after rotation. | HP-OIDC-004, HP-OIDC-012 |
| FI-20 | Wall-clock jump ±1 h | fake clock / `faketime` | No grant extension. Expiry evaluated in UTC consistently. In-process deadlines are monotonic. Documented behavior holds. | HP-GRT-003, HP-GRT-008 |
| FI-21 | Lost revocation event | drop bus delivery via hook | DB reconciliation terminates channels within 5 s. | HP-GRT-008 |
| FI-22 | Second process on same data dir | start a second `serve` | Fails fast on lock, and the first process is unaffected. | HP-DB-006 |
| FI-23 | Restart during pending-request wait | restart gateway while an agent waits | Agent gets disconnected, request remains pending, `status` works after restart. | HP-SSH-021, HP-DB-013 |
| FI-24 | Power loss | VM hard reset (nightly, QEMU) during W3 load | All transactions acknowledged before the reset are present, and reconciliation is clean. | HP-DB-002, HP-DB-013 |

## 5. Performance methodology

### 5.1 Reference hardware (RH-1)

- Gateway: 4 vCPU x86-64 at ≥ 2.5 GHz (e.g. AWS `c6i.xlarge` class), 8 GiB RAM, local NVMe SSD (instance store or equivalent with
  reliable fsync), Linux kernel ≥ 6.1, ext4 (`data=ordered`), release build, `GOMAXPROCS=4`.
- Destinations: 4 sshd containers on a separate host. Load driver on a third host. All on the same LAN with < 1 ms RTT.
- Every report records exact instance types, kernel, filesystem, Go version, Hallpass commit and config. Results from other hardware
  are reported as such and never presented as RH-1 numbers.

### 5.2 Workloads

| ID | Workload |
|---|---|
| W1 | 200 concurrent PTY channels, each sending 5 keystrokes/s with echo and a 4 KiB output burst every 10 s. |
| W2 | 50 concurrent exec channels each streaming 1 MiB/s of random output (aggregate 50 MiB/s), mandatory recording `group`. |
| W3 | 50 new connections/s running `exec -- true` under active grants. |
| W4 | 1,000 authenticated idle connections. |
| W5 | 100 agents creating requests at 1/s each under auto-approve for 10 min. |

### 5.3 Provisional targets

These are design targets, not claims. They are validated or revised **with measurements** in WP26, and any revision is recorded as an ADR.

| Metric | Target on RH-1 |
|---|---|
| W1 added echo latency vs direct SSH | p50 ≤ 2 ms, p99 ≤ 10 ms |
| W2 sustained recorded throughput | ≥ 50 MiB/s aggregate, 0 dropped records, CPU ≤ 75% |
| W3 gateway-side connect overhead (auth → destination channel open, excluding destination sshd time) | p95 ≤ 300 ms, 0 errors |
| W4 memory | RSS ≤ 1 GiB, ≤ 6 goroutines per idle connection |
| W5 decision tx latency / writer queue wait | p99 ≤ 20 ms / p99 ≤ 50 ms |
| Enforcement under W1+W2 | revocation → channel closed p99 ≤ 1 s, max ≤ 5 s |
| Soak (24 h: W1×100 + W2×10 at 256 KiB/s + W3 at 5/s) | goroutine/FD drift ≤ 5%, RSS ±10% after 1 h warmup, 0 lost events, `verify --all` all `ok` |

### 5.4 Method

Warm up 5 min, measure 15 min (soak 24 h), repeat 3 runs and report the median plus spread. Capture pprof CPU/heap at the midpoint and Prometheus
metrics throughout. Latency is measured client-side with timestamps embedded in the echoed payloads.

## 6. Security review checklist (SR)

- Auth paths: SSH `PublicKeyCallback` uses only `Permissions` of the verified key. No username-based identity. Algorithm lists.
- Grammar and exec forwarding: no shell on the gateway, `--` substring correctness, length limits.
- Policy: default deny, deny precedence, empty selector, hidden-target equality, approver rules, self-approval.
- Access state machine: CAS on every transition, no tx spanning I/O, enforcer bound, reconciliation.
- Crypto: nonce construction, key separation, AAD binding, rotation, no `math/rand`, constant-time comparisons for MACs and tokens.
- Web: CSRF, CSP, cookie flags, session rotation, reauth gates, problem details leakage, SSE authorization filtering.
- OIDC: all checks of HP-OIDC-002..006, linking rules.
- Webhooks: verify-before-parse, replay caches, token binding, rate limits.
- Data handling: redaction coverage, no secrets in logs and fixtures, export permissions.
- Supply chain: dependency review, pinned actions, govulncheck/Trivy results, SBOM.
- Findings: severity, fix commit or ADR acceptance, retest evidence.

## 7. CI cadence

| Trigger | Jobs |
|---|---|
| Every push / local pre-commit | lint, vet, analyzers, unit + integration (`-race`), fuzz smoke, OpenSSH (latest), Vitest, Playwright Chromium + axe + visual, OpenAPI/sqlc drift, govulncheck, gitleaks, coverage floor |
| Nightly | full OpenSSH matrix, fuzz ≥ 10 min/target, fault catalog (container-level), recovery drill (container), OIDC interop (Keycloak, Dex), Trivy on image |
| Weekly | performance suite on RH-1 |
| Release candidate | everything above + 24 h soak + FI-24 VM power loss + VM-based restore drill + security review + docs review |

## 8. Release-gate evidence

Evidence is stored under `docs/evidence/<version>/` (secret-free) and referenced from PLAN.md §21.

| Gate (GOAL.md §8) | Evidence artifact |
|---|---|
| RG-1 Requirements | `requirements.md`: generated from PLAN.md §21 with per-ID links |
| RG-2 CI health | `ci.md`: run URL/log digest for the release commit, govulncheck/Trivy/gitleaks outputs |
| RG-3 Fuzzing | `fuzz.md`: per-target duration, exec count, corpus size, crashers (must be none open) |
| RG-4 Fault injection | `faults.md`: FI-01..FI-24 pass/fail with logs |
| RG-5 Soak | `soak.md`: graphs of goroutines, FDs, RSS, throughput, event counts, `verify --all` summary |
| RG-6 Performance | `performance.md`: RH-1 description, W1–W5 results vs §5.3 targets |
| RG-7 Recovery | `recovery.md`: drill transcript, measured RTO, upgrade test result |
| RG-8 Security review | `security-review.md`: checklist §6, findings, dispositions |
| RG-9 Crypto review | `crypto-review.md`: external letter, or the explicit "not externally reviewed" release-note label |
| RG-10 Docs | `docs-review.md`: checklist results |
| RG-11 Open decisions | DECISIONS.md §2 status snapshot |
