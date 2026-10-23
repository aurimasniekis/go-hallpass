# Security review checklist (HP-TST-008 preparation)

> **Status: this is a checklist, not a completed review.** It turns TEST_STRATEGY.md §6 into concrete review items.
> For each item it lists the code to read and the automated evidence that already exists. Every item below is still
> **unreviewed**. HP-TST-008 is not satisfied until a reviewer works through this list, writes
> `docs/evidence/<rc>/security-review.md` with findings, severities and dispositions, and tracks each finding to a fix
> commit or an ADR in DECISIONS.md. Existing tests are inputs to the review. They do not replace it.

How to use it:

- Work area by area. For each item, record **reviewed by / date / commit**, the outcome (*ok*, *finding F-n*, *n/a*)
  and notes in the evidence file. Leave the boxes here unticked. This file is the template.
- Test evidence listed here proves only what those tests assert. A reviewer should read the code paths and look for
  missing negative tests (TEST_STRATEGY.md §1.3).
- Layer codes follow TEST_STRATEGY.md §2: U unit, P property, Z fuzz, I integration, O OpenSSH interop, E browser E2E,
  FI fault injection.

## 0. Inputs found before the review (WP26 hardening run, 2026-10-23)

The fault suite (`test/fault`) and the new fuzz targets reported the issues below. These are **not** review
conclusions. They need triage, a severity and a disposition in the review. File:line references are for the commit
under test.

| # | Area | Observation | Where | Reproduction |
|---|---|---|---|---|
| P-1 | Recording / G-8 | When a mandatory recording write fails, the chunk that failed to record and every later chunk are still forwarded to the agent until the asynchronous termination lands. Up to 2 MiB was observed in strict mode. | `internal/sshproxy/proxy.go` `pump` (≈450–465) and `recFail` (≈354–363) | `go test -tags fault -run TestFI05FI07 ./test/fault/` |
| P-2 | Recording / HP-REC-011 | With storage stalled, termination waits for `recFail` → `rec.Abort` → `stop` (blocks on the recorder loop) and then `AppendSessionEvent` (a DB write) before `t.terminate`. The channel ended about 17 s after the stall with `block_timeout` = 1 s. `seq.Next` is also called with `context.Background()`, and it holds the global sequencer mutex across a writer transaction. | `proxy.go` ≈354–363; `internal/recording/recorder.go` ≈288 and ≈430–440; `internal/access/service.go` ≈266–290 | `-run TestFI08StalledStorage` |
| P-3 | Config / HP-REC-011 | `recording.queue_bytes` below one record (records are up to 32 KiB from the proxy) passes validation. Every channel with large output then stalls and is killed (and P-1 forwards its output unrecorded). | `internal/config/validate.go:99`; `recorder.go` token loop ≈300–310 | `-run TestQueueBytesBelowRecordSize` |
| P-4 | Storage / HP-DB-009 | The disk-full "degraded" state is cleared by any successful write. The readiness probe's empty transaction always succeeds, so new access is admitted again while the disk is still full, and the state flaps. | `internal/store/errors.go:119–123`; `internal/obs/health/checks.go:56` | `-run TestFI06SQLiteFull` |
| P-5 | Storage / HP-DB-008 | Corruption detected when the database is opened (before `quick_check`) refuses to start, but the error carries no restore guidance. | `internal/store/store.go:134` | `-run TestFI10` |
| P-6 | SSH / HP-SSH-012 | The destination leg sends no keepalives. A blackholed destination keeps the channel, goroutines and FDs until the idle timeout (default 30 m). Destination `NewSession`/`Start` have no deadline, so a channel can also hang in `opening`. | `internal/destssh/destssh.go` (`Dial`, ≈54); `proxy.go` ≈281, ≈330 | `-run TestFI15` |
| P-7 | SSH / HP-SSH-015 | An agent disconnect does not release the destination session when the remote command ignores stdin EOF and is silent, or when its path is dead. The input goroutine only closes destination stdin. | `proxy.go` ≈380–386 | `-run TestAgentDisconnectReleasesDestination` |
| P-8 | SSH / HP-SSH-012/015 | If an agent stops reading, the idle timeout closes the destination, but the output pump stays blocked in `Agent.Write` on the full window. `finish`/`CloseChannel` are never reached, and the channel row stays `active` until the agent disconnects. This also affects enforcement for stalled agents: the destination side ends, the agent side does not. | `proxy.go` `pump`, `terminator.terminate` (≈522), `outputs.Wait()` (≈401) | `-run TestFI17` |
| P-9 | Enforcement / HP-GRT-008 | After a backward wall-clock step, an in-process event that is lost is not caught by the DB safety net. The reconciliation cursor is `max(updated_at) − 5 s`, and new rows carry earlier timestamps. Separately, grant expiry follows the wall clock (documented NTP assumption; consider an explicit ADR). | `internal/access/enforcer.go:236`, `:255` | `-run 'TestFI21\|TestFI20BackwardJump'` |
| P-10 | OIDC / HP-OIDC-005 | `SanitizeReturnTo` checks the raw path for `/api` and `/auth` prefixes. Dot segments bypass the check: `/./api/v1/me` or `/%2e/auth/...` is returned unchanged, and the browser (and `http.ServeMux`) normalizes it to `/api/...`. The redirect stays same-origin; only the allowlist is bypassed. | `internal/oidc/flow.go:82–99` | `SanitizeReturnTo("/./api/v1/me") == "/./api/v1/me"` |
| P-11 | Egress / HP-SRV-009 | `DefaultDenied` does not list the local-use NAT64 prefix `64:ff9b:1::/48` or Teredo `2001::/32`. Both can embed IPv4 addresses, but this only matters if an operator puts them in `allow_cidrs`. | `internal/egress/egress.go:25–40` | review |

**Fix status (implementing session, not a review conclusion; reviewers should verify):**

| # | Status | Commit / test |
|---|---|---|
| P-1, P-2, P-3, P-7, P-8 | fixed | fee9b40; fault tests TestFI05FI07…, TestFI08…, TestQueueBytesBelowRecordSize, TestAgentDisconnectReleasesDestination, TestFI17 pass |
| P-4, P-5 | fixed | 86b565f; TestFI06SQLiteFull, TestFI10 pass |
| P-6 | fixed | bd08fce (keepalives on both legs, started before session setup); TestFI15 passes |
| P-9 | fixed (cursor) / documented (expiry) | cursor clamp + ADR-0039; TestFI21 passes |
| P-10, P-11 | fixed | dot segments rejected (FuzzSanitizeReturnTo seeds), NAT64 local-use and Teredo denied (TestAllowedAddr) |

## 1. Authentication paths

### 1.1 Agent SSH authentication (HP-SSH-001..005, HP-AGT-*)

- [ ] `PublicKeyCallback` derives identity only from the verified key's `Permissions`. The SSH username never selects an identity. Partial-success and multi-step auth cannot be combined to escalate.
  Code: `internal/sshfront/server.go`, `internal/agents/service.go` (`Authenticate`, `sourceAllowed`).
  Evidence: I `internal/app/e2e_test.go` `TestGatewayRejectsUnknownKey`, `TestGatewayAuthMethodsAndAlgorithms`; O `test/openssh`.
- [ ] Algorithm lists: no SHA-1 `ssh-rsa` signatures, RSA ≥ 3072, and only allowed KEX/ciphers/MACs on both legs.
  Code: `internal/sshalg/sshalg.go`, `internal/agents/keys.go`. Evidence: U `internal/agents/keys_test.go`; Z `FuzzParseAgentKey`.
- [ ] Key revocation and agent disable block new auth at once and terminate live channels within 5 s.
  Code: `internal/agents/service.go`, `internal/access/enforcer.go`. Evidence: FI `TestRevocationStorm` (agent disable).
- [ ] Pre-auth limits, handshake timeout, `max_auth_tries`, and per-agent connection/channel limits.
  Code: `internal/sshfront/server.go`. Evidence: I `TestGatewayPreAuthLimit`; load testing still pending (soak harness).

### 1.2 Operator authentication (HP-AUTH-*)

- [ ] Argon2id parameters, the timing-equalized unknown-user path (`dummyHash`), length/NFKC normalization without truncation, and the bounds on PHC parameters read from the database.
  Code: `internal/opauth/password.go`. Evidence: U `internal/opauth/*_test.go`; Z `FuzzNormalizePassword`.
- [ ] TOTP: the ±1 step window, no reuse (`lastStep`), constant-time comparison, and secrets sealed at rest.
  Code: `internal/opauth/totp.go`, `mfa.go`. Evidence: Z `FuzzVerifyTOTP`.
- [ ] Session tokens: stored only as hashes, idle/absolute timeouts, rotation on login and privilege change, CSRF token binding, and constant-time CSRF comparison.
  Code: `internal/opauth/sessions.go`, `internal/httpapi/server.go`. Evidence: U/I `internal/httpapi/api_test.go`.
- [ ] One-time tokens (invite, reset, setup, recovery): MAC-only storage, single use, expiry, and the break-glass path.
  Code: `internal/opauth/tokens.go`, `breakglass.go`.
- [ ] Throttling and lockout cannot be turned into an account-enumeration oracle or an administrator lockout (HP-AUTH-015/016).

### 1.3 OIDC (HP-OIDC-002..015)

- [ ] ID token checks: signature algorithm allowlist (no `none` or HMAC), key type/size, `iss`/`aud`/`azp`/`exp`/`iat`/`nbf`/nonce, ≤ 60 s skew, and JWKS refetch rate limit.
  Code: `internal/oidc/flow.go` (`verifyIDToken`), `remote.go` (`keySet`, `acceptableKey`).
  Evidence: U `internal/oidc/oidc_test.go` `TestIDTokenValidation`, `TestJWKSRotation`; Z `FuzzVerifyIDTokenClaims`, `FuzzKeySetVerifySignature`.
- [ ] State/PKCE/nonce: single use, 10 min TTL, server-side storage, and binding to the browser session.
  Code: `flow.go` `Start`/callback. Evidence: U `TestStateSafety`.
- [ ] Redirect safety: exact redirect URI and `return_to` allowlist (see P-10).
  Evidence: U `TestSanitizeReturnTo`; Z `FuzzSanitizeReturnTo`.
- [ ] Linking, JIT provisioning restrictions, no email-based merge, group→role mapping and removal, and the SSO-only last-admin guard.
  Code: `flow.go` (`provisionTx`, `link`, `jitAllowed`), `admin.go`. Evidence: U `TestNoEmailMerge`, `TestJITAndGroupSync`, `TestSyncKeepsLastAdmin`, `TestLinking`.
- [ ] Provider egress: `denyPrivate`, TLS always verified, endpoints restricted to the same site.
  Code: `remote.go`, `provider.go` (`checkEndpoint`, `validateIssuerURL`). Evidence: Z `FuzzValidateIssuerURL`.

## 2. Grammar and exec forwarding (HP-SSH-016..023)

- [ ] The gateway runs no shell. The `--` split is correct, the raw destination command is passed byte-exact, and length limits and printable checks are enforced.
  Code: `internal/sshfront/grammar/*`, `internal/sshfront/session.go`. Evidence: U grammar tests; Z `FuzzTokenize`, `FuzzParse`.
- [ ] Forwarding refusals: direct-tcpip, tcpip-forward, subsystems, agent/X11 forwarding, and late exec/shell requests. Environment allowlist.
  Code: `internal/sshfront/server.go`, `internal/sshproxy/proxy.go` (`agentRequests`, `FilterEnv`). Evidence: I `TestGatewayDeniesForwarding`, `TestGatewayEnvAllowlist`.
- [ ] Error output and help never reveal hidden targets (HP-POL-006). Evidence: I `TestGatewayHiddenTarget`.

## 3. Policy (HP-POL-*, HP-REQ-*, HP-GRT-*)

- [ ] Default deny, deny precedence, empty selectors match nothing, `all: true` is explicit, and hidden and unknown targets look identical.
  Code: `internal/policy/snapshot.go`, `selectors.go`. Evidence: P/U `internal/policy/snapshot_test.go`; Z `FuzzRuleJSON`, `FuzzLabelSelector`.
- [ ] Approver rules: no self-approval, approval scoped by target and role, RBAC role required, and the same checks on web, API, Slack and Telegram.
  Code: `internal/policy/snapshot.go` (`CanApprove`), `internal/access/decide.go`, `internal/notify/*`.
- [ ] Every request/grant transition is CAS (`WHERE state = …`). No transaction spans I/O (txscope analyzer). Decision, grant and session commit in one transaction.
  Code: `internal/access/*`, `tools/analyzers/txscope`. Evidence: FI `TestFI01CrashDuringDecisions`; U concurrency tests in `internal/access`.
- [ ] Enforcer: event path, 1 s ticker, DB reconciliation overlap window, registration-race guard (see P-9).
  Code: `internal/access/enforcer.go`. Evidence: I `TestGatewayRevocationTerminates`; FI `TestFI20*`, `TestFI21*`, `TestRevocationStorm`.
- [ ] Startup reconciliation of connections, channels, requests, grants and sessions.
  Code: `internal/access/reconcile.go`. Evidence: FI `TestFI02`, `TestFI23`.

## 4. SSH data plane (HP-SSH-011..015, HP-SRV-004..009)

- [ ] Strict destination host verification with no permissive callback (`nohostkeyignore` analyzer). On mismatch: alert, exit 88, and the credential is never offered.
  Code: `internal/inventory/hostid.go` (`NewVerifier`), `internal/destssh/destssh.go`. Evidence: I `TestGatewayHostKeyMismatch`; FI `TestFI16`; Z `FuzzParseHostKey`.
- [ ] Egress guard: resolve-then-dial to the validated IP, `Control` re-check, special ranges denied (see P-11).
  Code: `internal/egress/egress.go`. Evidence: U `egress_test.go`; Z `FuzzValidateDestination`, `FuzzAllowedAddr`.
- [ ] Credential isolation: private keys sealed, never exported, and never presented to unverified hosts. Certificate key IDs and validity.
  Code: `internal/credentials/*`. Evidence: U `credentials_test.go`.
- [ ] Bounded buffering, backpressure, keepalives on both legs, and cleanup on every close path (see P-6, P-7, P-8).
  Code: `internal/sshproxy/proxy.go`, `internal/sshfront/server.go`. Evidence: I `TestGatewayNoGoroutineLeak`, `TestGatewayIdleTimeout`; FI `TestFI15`, `TestFI17`, `TestAgentLegBlackhole`, `TestAgentDisconnectReleasesDestination`; S `test/soak`.

## 5. Cryptography (HP-CRY-*)

- [ ] KEK handling: file mode/owner checks, production refusal, the dev KEK rejected by production config, and wrong-KEK detection.
  Code: `internal/keyring/kek.go`. Evidence: U `keyring_test.go`; FI `TestFI14`; Z `FuzzParseKEK`.
- [ ] AEAD usage: random nonces from `crypto/rand`, nonce size, AAD binding of purpose, version and row context, key separation per purpose, rotation and reseal.
  Code: `internal/keyring/keyring.go`, `reseal.go`. Evidence: U `TestSealBindsContext`, `TestNonceUniqueness`; Z `FuzzSealedOpen`.
- [ ] MACs and token comparisons are constant-time (`hmac.Equal`, `subtle.ConstantTimeCompare`). Integrity-chain MACs.
  Code: `keyring.go` (`VerifyMAC`), `internal/recording/reconcile.go` (`verifyChain`). Evidence: Z `FuzzVerifyMAC`.
- [ ] HPREC1: header binding (segment, session, channel), per-segment DEK wrapping, frame authentication and ordering, final frame, and the recovery path.
  Code: `internal/recording/hprec/*`. Evidence: U/Z hprec tests (`FuzzReader`, `FuzzRecordDecode`, `tamper_test.go`); FI `TestFI03`, `TestFI04`, `TestFI11FI12*`.
- [ ] No `math/rand` (depguard) and no home-grown primitives (PLAN §13). External crypto review is RG-9.

## 6. Recording fail-closed (HP-REC-007..011, G-8)

- [ ] No forwarding before the segment header is durable, and recording failure stops forwarding (see P-1, P-2, P-3).
  Code: `internal/sshproxy/proxy.go` (`run`, `pump`, `recFail`), `internal/recording/recorder.go`.
  Evidence: FI `TestFI02`, `TestFI05*`, `TestFI08*`, `TestReadOnlyRecordingsDirFailsClosed`.
- [ ] Disk reserve, disk full and I/O errors fail closed for new access (see P-4).
  Code: `internal/store/errors.go`, `internal/obs/fsstat`, `internal/access/channels.go`. Evidence: FI `TestFI05DiskReserve*`, `TestFI06`.

## 7. Web and API (HP-AUTH, HP-API, HP-UI)

- [ ] CSRF on every mutating route, CSP and security headers, cookie flags (`Secure`, `HttpOnly`, `SameSite`), session rotation, and reauthentication gates for sensitive operations.
  Code: `internal/httpapi/server.go`, `h_auth.go`. Evidence: I `internal/httpapi/api_test.go`; E `web/e2e`.
- [ ] RBAC: every operation carries `x-permission`, the generated router enforces it, and RBAC is identical across authentication methods. Configurable matrix cells.
  Code: `internal/rbac/rbac.go`, `internal/httpapi/gen`. Evidence: C OpenAPI `x-permission` check; U `rbac_test.go`.
- [ ] Problem details leak no internals. Strict JSON decoding. Cursor and If-Match parsing.
  Code: `internal/httpapi/server.go` (`decode`, `ifMatch`), `support.go`. Evidence: Z `FuzzDecodeBody`, `FuzzDecodeCursor`, `FuzzIfMatch`.
- [ ] SSE: authorization filtering per event, and the connection is dropped on logout or role change.
  Code: `internal/httpapi/sse.go`.
- [ ] Trusted-proxy handling for client IPs (no header spoofing).

## 8. Webhooks (HP-NTF-*, HP-REC-012)

- [ ] Verify before parse: Slack v0 HMAC over the exact body, a single timestamp header, a ±5 min window, and a replay cache keyed on the decoded MAC. Telegram secret token compared in constant time. Destaudit Ed25519 over the domain-separated payload, verified before the batch is decoded.
  Code: `internal/notify/slack/verify.go`, `internal/notify/telegram/webhook.go`, `internal/destaudit/wire/wire.go`, `internal/destaudit/handler.go`.
  Evidence: U per-package tests; Z `FuzzVerifyBody`, `FuzzWebhookVerify`, `FuzzParseBody`, `FuzzParseUpdate`, `FuzzDecodeEnvelopeVerify`, `FuzzDecodeBatch`.
- [ ] Body size limits, per-source rate limits (`internal/ratelimit`), and replay caches bounded in memory.
- [ ] Action tokens: single use, bound to request and approver, expiring, and stored as MACs. Chat identity linking via link codes.
  Code: `internal/notify/*`, `internal/notify/chat`. Evidence: Z `FuzzParseCallbackData`, `FuzzParseActionID`, `FuzzCleanText`.
- [ ] Outbound chat clients: URL allowlists (`response_url`), no token in logs, retry/dead-letter behavior.
  Evidence: FI `TestFI18`; U client tests.

## 9. Data handling (HP-OBS-002, HP-OPS-012, HP-KEY-007)

- [ ] Redaction coverage in logs, traces, problem details and audit details. `redact.Secret` is used for every secret-bearing configuration value.
  Code: `internal/obs/redact`, `internal/obs/log.go`.
- [ ] No secrets in fixtures or golden files (gitleaks). Keys are generated at test time.
- [ ] Recording export and play permissions. Agent-supplied reasons are sanitized before they are shown in chat or UI.
  Evidence: Z `FuzzSanitizeReason`, `FuzzCleanText`.

## 10. Supply chain

- [ ] Dependency review of `go.mod`, including direct use of modules marked `// indirect` (go-oidc, go-jose). `govulncheck` and Trivy results attached.
- [ ] Pinned GitHub Actions, release signing, SBOM.
  Code: `.github/workflows/ci.yaml`, `release.yaml`, `Dockerfile`.

## 11. Findings ledger (filled by the reviewer)

| ID | Severity | Area | Summary | Disposition (fix commit / ADR) | Retest evidence |
|---|---|---|---|---|---|
| | | | | | |
