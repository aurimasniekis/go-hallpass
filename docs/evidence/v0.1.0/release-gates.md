# Release-gate evaluation: v0.1.0 (2026-10-24, updated 2026-10-25 for the tag)

WP27 evaluates RG-1..RG-11 from [GOAL.md §8](../../GOAL.md) for the first release. **Result: to be released as 0.1.0,
a pre-1.0 version with known limitations (ADR-0046), not as stable.** Four gates pass, four are partial and three
fail.
GOAL.md §8 allows a pre-1.0 release with an explicit known-gaps list, which the CHANGELOG, README and the security
page carry. The tag itself is the operator's action ([RELEASING.md](../../RELEASING.md)).

Status words follow GOAL.md §7. Local runs: Apple M1 Max, macOS 15.7, Go 1.27.3, Node 24.22 (not the RH-1 reference
hardware).

| Gate | Result | Evidence and gaps |
|---|---|---|
| RG-1 Requirements | **FAIL** | 202 of 240 requirements done in [PLAN.md §21](../../PLAN.md). The rest are partial, each with its gap named. Mostly: real Slack/Telegram workspace verification, reference-hardware load tests, SSO and visual UI coverage, OTLP metrics, some UI pages. |
| RG-2 CI health | **PARTIAL** | The public repository runs CI on every push. Green on GitHub: web (lint, typecheck, unit tests, build, API drift), security (govulncheck, gitleaks), OpenSSH interop; the Go job (lint, vet, race, coverage floor, fuzz smoke) after the timing-test fixes. The browser E2E job (scripts/e2e.sh: fresh backend, Chromium, axe) is new and passes locally. Visual regression is not implemented. The release workflow (Trivy, SBOM, image push) has not run for a tag yet. |
| RG-3 Fuzzing | **PASS** | All 41 targets ran 10 min each with no crashers ([fuzz-campaign.txt](fuzz-campaign.txt)). A sampled corpus is committed under `testdata/fuzz` (the full corpus is 47 MB). |
| RG-4 Fault injection | **PARTIAL** | `make test-fault` passes every catalog scenario except FI-24 (power loss), which needs a VM hard reset. FI-19 is covered by the OIDC outage tests. |
| RG-5 Soak | **FAIL** | Operator decision: no 24 h soak on this machine. Only 30 s and 2 min in-process runs: thousands of sessions, 0 failures, no goroutine or FD growth. |
| RG-6 Performance | **FAIL** | Smoke numbers only, not the RH-1 suite. |
| RG-7 Recovery | **PARTIAL** | `scripts/recovery-drill.sh` passes ([recovery-drill.txt](recovery-drill.txt)). A 349 MiB / 4,981-segment data set was backed up, then restored with the release image into a clean, read-only, non-root container with no network. Every segment verified, the chain head matched the source, and RTO was 6.6 s. Gaps: no 10 GiB data set on reference hardware; upgrade-from-previous-release cannot run, because no previous release exists. The drill also found and fixed a broken container build. |
| RG-8 Security review | **PASS (internal)** | [review-2026-10-24.md](../../security/review-2026-10-24.md) is an internal review performed by AI agents (not an external review). Of its findings, both HIGH and all 20 MEDIUM are fixed with regression tests (ADR-0042..0044). One LOW is accepted (SR-34) and one LOW is open (SR-35, lint coverage). |
| RG-9 External crypto review | **PASS via label** | Operator decision (R-02): releases carry "recording format and keyring not externally reviewed" (CHANGELOG). |
| RG-10 Docs | **PASS** | Operator, agent, destination-hardening, API (OpenAPI) and recording-format docs, the incident runbooks, remote-networks guide and documentation site (`site/`). The guarantees page is consistent with THREAT_MODEL.md. Doc errors found while building the site were corrected. |
| RG-11 Open decisions | **PARTIAL** | R-01 resolved: Apache-2.0 (ADR-0045). R-02 resolved by the RG-9 label. R-08 (name check) and R-15 (versioning commitments) resolved by operator decision on 2026-10-25. Open, not blocking: R-13, R-14, R-16. |

## Known limitations stated with the release

- Pre-1.0: interfaces may change between minor versions.
- Recording format and keyring are not externally reviewed (R-02).
- No 24 h soak and no reference-hardware benchmarks (RG-5, RG-6).
- Slack and Telegram are tested only against recorded and fake provider APIs.
- UI end-to-end tests cover the main workflows, in Chromium only (ADR-0038). There are no visual regression
  snapshots.

## Before tagging

1. Operator: the R-08 name/trademark check and R-15 versioning commitments; the `DOCKERHUB_TOKEN` secret
   ([RELEASING.md](../../RELEASING.md)). Done 2026-10-25: both decisions recorded, the secret set, private
   vulnerability reporting enabled.
2. CI green on GitHub for the commit to tag, including the new E2E job.
3. Optionally: run the 24 h soak and RH-1 benchmarks.
