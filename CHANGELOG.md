# Changelog

All notable changes to HallPass are documented in this file. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and versions follow the policy in
[docs/VERSIONING.md](docs/VERSIONING.md) (Semantic Versioning for the binary, with separate versioning for the REST API,
agent JSON schemas, the recording format and the database schema).

## [Unreleased]

## [0.1.0] - 2026-10-24

First release. HallPass is a terminating SSH gateway for AI agents: agents use plain `ssh` with their own key,
policy and a human decide what they may reach and for how long, and HallPass logs in to the destination with a
credential the agent never sees and records the session.

> **Recording format and keyring not externally reviewed** (RG-9, review item R-02). The HPREC1 format, the keyring
> and field encryption have had internal review only ([docs/security/review-2026-10-24.md](docs/security/review-2026-10-24.md)).

### Known limitations

- Pre-1.0: interfaces may change between minor versions ([docs/VERSIONING.md](docs/VERSIONING.md)).
- No 24-hour soak test and no benchmarks on reference hardware (RG-5, RG-6). Short soak runs and smoke benchmarks
  passed.
- Slack and Telegram approvals are tested against recorded and fake provider APIs, not live workspaces.
- Browser end-to-end tests cover the main workflows in Chromium only. There are no visual regression snapshots.
- Not every requirement in [docs/GOAL.md](docs/GOAL.md) is complete. The per-requirement status is in
  [docs/PLAN.md](docs/PLAN.md) §21, and the gate evaluation in
  [docs/evidence/v0.1.0/release-gates.md](docs/evidence/v0.1.0/release-gates.md).

### Added

- **Agent SSH gateway.** A shell-free command grammar (`list`, `roles`, `request`, `status`, `cancel`, `connect`,
  `exec`, `sessions`, `whoami`, `version`, `help`) with versioned JSON output (`hallpass.*/v1`) and stable exit codes
  80–90. Exec, interactive shells and PTYs with an environment allowlist, signals and exit-status propagation.
  Port forwarding, agent forwarding, X11 and subsystems are refused and audited. Hidden and unknown servers give the
  same answer.
- **Destination credentials agents never see.** Managed Ed25519 login keys per server role, encrypted at rest, with
  a suggested `restrict,from="…"` line and overlap rotation, or OpenSSH user certificates from a HallPass CA that live
  about two minutes. Strict destination host-key pinning or host-CA trust, with no trust on first use. Anti-SSRF
  egress allowlist. A guided server-onboarding wizard.
- **Policy.** Default-deny rules by agent, server and role (names, groups or label selectors) with deny overrides,
  auto-approval limits, approver rules, an effective-access preview per agent or server, and a what-if preview of
  unsaved rule changes. Self-approval is prohibited by default.
- **Requests, approvals and grants.** Deduplicated requests with reasons, approvals in the web console, Slack and
  Telegram (chat buttons re-check the approver's authority at click time), time-bound grants that never extend,
  revocation, lockdown, and termination of live sessions within 5 seconds of expiry or revocation.
- **Recording and audit.** Mandatory, fail-closed session recording in the encrypted, integrity-chained HPREC1
  format; reconciliation after crashes; retention classes; export; `hallpass verify`; browser replay next to a session
  timeline; a hash-chained audit log with integrity anchors. An optional destination-side exec collector
  (`hallpass-collector`) adds correlated, unverified destination records.
- **Operators.** Local accounts with Argon2id passwords, TOTP and recovery codes; OIDC single sign-on with PKCE and
  group mapping; administrator, approver, auditor and viewer roles; invitations; recent-authentication checks for
  sensitive actions; a break-glass recovery command.
- **Web console and API.** A React web console embedded in the binary (light and dark themes): dashboard, requests,
  sessions with live activities, agents, servers, policy, operators, integrations, audit and system pages. A REST API
  (`/api/v1`, OpenAPI 3.1) and server-sent events for live updates.
- **Operations.** One static Go binary with SQLite storage (WAL, `synchronous=FULL`), forward-only migrations with
  pre-migration snapshots, a KEK with purpose-key and KEK rotation, backup, restore and verification, Prometheus
  metrics, `/healthz` and `/readyz`, optional OpenTelemetry tracing, and ECS-aligned JSON logs with redaction.
- **Distribution.** Static binaries for linux/amd64, linux/arm64 and darwin/arm64 with SHA-256 checksums, SPDX SBOMs
  and GitHub build provenance attestations. A distroless, non-root, multi-arch container image on Docker Hub
  (`aurimasniekis/hallpass`) and GHCR (`ghcr.io/aurimasniekis/go-hallpass`). A Docker Compose example and a hardened
  systemd unit.
- **Documentation.** Operator, agent, destination-hardening, API and recording-format documentation, incident
  runbooks, a security guarantees page, and the website at <https://aurimasniekis.github.io/go-hallpass/>.
- **Agent skill.** A `hallpass` skill and Claude Code plugin that teach coding agents to use the gateway properly.

### Security

- Internal security review ([docs/security/review-2026-10-24.md](docs/security/review-2026-10-24.md)), performed by AI
  agents: both HIGH and all MEDIUM findings fixed with regression tests. One LOW is accepted and one LOW is open.
- The recording format and keyring have not been externally reviewed (RG-9, R-02).

[Unreleased]: https://github.com/aurimasniekis/go-hallpass/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/aurimasniekis/go-hallpass/releases/tag/v0.1.0
