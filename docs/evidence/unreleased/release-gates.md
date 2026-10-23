# Release-gate evaluation: unreleased `main` (2026-10-24)

WP27 evaluates the release gates RG-1..RG-11 from [GOAL.md §8](../../GOAL.md). **Result: not releasable as stable.**
Several gates cannot pass from a local checkout: they need the repository on GitHub (CI), reference hardware, or
external parties. GOAL.md §8 allows a pre-1.0 release candidate with an explicit known-gaps list. No tag has been
created. Tagging is the operator's decision, and nothing has been pushed.

Status words follow GOAL.md §7. All runs below were local (Apple M1 Max, macOS 15.7, Go 1.27.3, Node 24.22) on `main`.

| Gate | Result | Evidence and gaps |
|---|---|---|
| RG-1 Requirements | **FAIL** | 173 of 240 requirements done in [PLAN.md §21](../../PLAN.md). Most of the remaining 67 are partial: implemented and tested, but waiting on external verification, CI, reference-hardware load tests or UI end-to-end coverage. Each one's gap is listed in §21. |
| RG-2 CI health | **FAIL (not run in CI)** | Locally passing: `make lint`, `custom-vet`, `coverage` (floor 80%), `sqlc-check`, `api-check`, `tools-test`, `test-openssh` (11 tests, real OpenSSH), `test-fault`, and the web lint/typecheck/test/build. `make race` passes per package; it failed once under full-suite parallel load on the 100 ms transaction guard and did not reproduce in isolation. `govulncheck`: 0 reachable vulnerabilities (1 in a required module that is not called). Not run: the GitHub Actions workflow (no remote), Trivy and syft (not installed locally, release workflow only), gitleaks (not installed locally; a manual pattern check of staged changes found nothing). |
| RG-3 Fuzzing | **FAIL** | 28 new targets plus the existing parsers ran 30 s each with no open crashers (`make fuzz-smoke`). The gate needs at least 10 min per target with the corpus committed. |
| RG-4 Fault injection | **PARTIAL** | `make test-fault` passes FI-01..FI-23 after fixing all 11 defects it found (PLAN §19.3, WP26). FI-19 is covered by the OIDC outage tests. FI-24 (power loss) needs a VM hard reset and was not run. |
| RG-5 Soak | **FAIL** | Only a 30 s in-process smoke run ([test/soak](../../../test/soak)): 1,386 sessions, 0 failures, no goroutine or FD growth. The 24 h run on reference hardware is pending. |
| RG-6 Performance | **FAIL** | Smoke numbers only, on non-reference hardware with everything in one process: exec p95 437 ms, revoke-to-closed max 155 ms. The TEST_STRATEGY §5 suite on RH-1 is pending. |
| RG-7 Recovery | **PARTIAL** | Backup → restore → verify passes in-process (internal/backup tests). Scripted clean-machine drill, measured RTO and upgrade-from-previous-release are pending (there is no previous release). |
| RG-8 Security review | **FAIL** | Checklist written ([docs/security/review-checklist.md](../../security/review-checklist.md)); its 11 pre-review findings are fixed. The review itself has not been performed. |
| RG-9 External crypto review | **FAIL / label required** | R-02 is open. Any release must be labeled "recording format not externally reviewed". |
| RG-10 Docs | **PARTIAL** | Operator (incl. incidents, remote networks), agent, destination-hardening, API (OpenAPI), recording-format docs and the [guarantees page](../../security-guarantees.md) exist. The docs review and the release-time guarantees/threat-model consistency review are pending. |
| RG-11 Open decisions | **FAIL** | R-01 (license) must be decided before any public release. R-02, R-08 (name/trademark), R-13, R-14, R-15 and R-16 are also open. |

## Known gaps a pre-1.0 release candidate would have to state

- Not production-ready. The gates above fail.
- Recording format and keyring not externally reviewed (R-02).
- CI, container image scanning, SBOM and provenance not yet exercised on GitHub.
- No 24 h soak or reference-hardware benchmarks.
- No license (R-01).
- Slack and Telegram tested only against recorded and fake provider APIs, not real workspaces.
- UI end-to-end tests cover a subset of operator workflows in Chromium only (ADR-0038). There are no visual
  regression snapshots.

## To reach a release candidate

1. Push to GitHub (operator decision) and get CI green, including Trivy, syft and gitleaks.
2. Run the long fuzz campaign, the 24 h soak and the performance suite on reference hardware, and the recovery
   drill. Commit the reports here.
3. Perform the internal security review (RG-8) and engage the external crypto review (R-02), or apply the label.
4. Decide R-01 and the other release-blocking review items.
5. Tag `v0.1.0-rc.1` locally once the operator agrees, and record the tag commit here.
