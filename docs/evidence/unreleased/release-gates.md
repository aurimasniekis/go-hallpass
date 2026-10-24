# Release-gate evaluation: unreleased `main` (2026-10-24, second pass)

WP27 evaluates RG-1..RG-11 from [GOAL.md §8](../../GOAL.md). **Result: not releasable as stable.** Five gates pass,
three are partial, and three fail. The failing gates need either an operator decision (license) or resources this
checkout does not have (24 h soak and benchmarks on reference hardware, green CI on GitHub). GOAL.md §8 allows a
pre-1.0 release candidate with an explicit known-gaps list. No tag has been created; tagging is the operator's
decision.

Status words follow GOAL.md §7. Local runs: Apple M1 Max, macOS 15.7, Go 1.27.3, Node 24.22 (not the RH-1 reference
hardware).

| Gate | Result | Evidence and gaps |
|---|---|---|
| RG-1 Requirements | **FAIL** | 172 of 240 requirements done in [PLAN.md §21](../../PLAN.md). The rest are partial, each with its gap named. Mostly: real Slack/Telegram workspace verification, reference-hardware load tests, UI end-to-end and visual coverage, CI not yet run green. |
| RG-2 CI health | **PARTIAL** | The private repository exists and CI has run. The first run passed web, security (govulncheck, gitleaks) and OpenSSH interop; the Go job failed on two timing-sensitive tests on the slower runners. Those are fixed and pass locally under `-race`: full `go test -race ./...`, lint, custom vet, coverage floor, sqlc/api drift, fault suite, OpenSSH interop, web lint/typecheck/test/build. gitleaks reports no leaks in the full history (Docker, v8.24.3). Not yet re-run on GitHub: the pushes are blocked by the local SSH agent. The release workflow (Trivy, SBOM) failed on GitHub's account-wide artifact storage quota; the operator must free artifact storage. |
| RG-3 Fuzzing | **PASS** | All 41 targets ran 10 min each with no crashers ([fuzz-campaign.txt](fuzz-campaign.txt)). A sampled corpus is committed under `testdata/fuzz` (the full corpus is 47 MB). |
| RG-4 Fault injection | **PARTIAL** | `make test-fault` passes every catalog scenario except FI-24 (power loss), which needs a VM hard reset. FI-19 is covered by the OIDC outage tests. |
| RG-5 Soak | **FAIL** | Operator decision: no 24 h soak on this machine. Only 30 s and 2 min in-process runs: thousands of sessions, 0 failures, no goroutine or FD growth. |
| RG-6 Performance | **FAIL** | Smoke numbers only, not the RH-1 suite. |
| RG-7 Recovery | **PARTIAL** | `scripts/recovery-drill.sh` passes ([recovery-drill.txt](recovery-drill.txt)). A 349 MiB / 4,981-segment data set was backed up, then restored with the release image into a clean, read-only, non-root container with no network. Every segment verified, the chain head matched the source, and RTO was 6.6 s. Gaps: no 10 GiB data set on reference hardware; upgrade-from-previous-release cannot run, because no previous release exists. The drill also found and fixed a broken container build. |
| RG-8 Security review | **PASS (internal)** | [review-2026-10-24.md](../../security/review-2026-10-24.md) is an internal review performed by AI agents (not an external review). Of its findings, both HIGH and all 20 MEDIUM are fixed with regression tests (ADR-0042..0044). One LOW is accepted (SR-34) and one LOW is open (SR-35, lint coverage). |
| RG-9 External crypto review | **PASS via label** | Operator decision (R-02): releases carry "recording format and keyring not externally reviewed" (CHANGELOG). |
| RG-10 Docs | **PASS** | Operator, agent, destination-hardening, API (OpenAPI) and recording-format docs, the incident runbooks, remote-networks guide and documentation site (`site/`). The guarantees page is consistent with THREAT_MODEL.md. Doc errors found while building the site were corrected. |
| RG-11 Open decisions | **FAIL** | R-01 (license) was deferred by the operator. Also open: R-08 (name/trademark), R-13, R-14, R-15, R-16. |

## Known gaps a pre-1.0 release candidate must state

- Not production-ready: RG-1, RG-5, RG-6 and RG-11 fail.
- Recording format and keyring are not externally reviewed (R-02).
- No 24 h soak and no reference-hardware benchmarks.
- No license (R-01).
- Slack and Telegram are tested only against recorded and fake provider APIs.
- UI end-to-end tests cover a subset of workflows, in Chromium only (ADR-0038). There are no visual regression
  snapshots.

## To reach a release candidate

1. Unlock the SSH agent so the 10+ local commits can be pushed. Free GitHub Actions artifact storage. Get CI and the
   release workflow green (Trivy, SBOM).
2. Decide R-01 (license).
3. Optionally: run the 24 h soak and RH-1 benchmarks; enable GitHub Pages.
4. Tag `v0.1.0-rc.1` locally once the operator agrees.
