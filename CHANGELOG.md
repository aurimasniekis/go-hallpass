# Changelog

All notable changes to Hallpass are documented in this file. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and versions follow the policy in
[docs/VERSIONING.md](docs/VERSIONING.md) (Semantic Versioning for the binary, with separate versioning for the REST API,
agent JSON schemas, the recording format and the database schema).

Status words follow [docs/GOAL.md](docs/GOAL.md) §7. *Implemented* means the code exists. *Tested* means automated tests
cover it, and so far they have only been run locally because nothing has been pushed. Nothing here is *externally verified*
yet. The authoritative per-work-package status is [docs/PLAN.md](docs/PLAN.md) §19.2.

## [Unreleased]

No release has been tagged. This section lists what exists on `main`. No license has been chosen yet (review item R-01),
so no `LICENSE` file is included.

> **Recording format and keyring not externally reviewed** (RG-9, review item R-02). The HPREC1 format, the keyring
> and field encryption have had internal review only (docs/security/review-2026-10-24.md).

### Added

- **Foundation (WP01–WP03, tested locally):** Go module, `hallpass version`, lint/vet configuration with the custom
  analyzers `nohostkeyignore` and `txscope`, CI workflow, coverage floor, gitleaks configuration; strict YAML configuration
  with `HALLPASS_*` overrides and production/development modes (`hallpass config check|env`); ECS-aligned JSON logging with
  a redaction layer; SQLite storage (pure-Go driver, WAL, writer/reader pools, process lock, network-filesystem refusal,
  permission checks, forward-only migrations with pre-migration snapshots, `hallpass migrate`).
- **Keys and encryption at rest (WP04, tested locally):** KEK file handling with permission checks, AES-256-GCM purpose
  keys with location-bound associated data, purpose-key and offline KEK rotation (`hallpass keys init-kek|status|rotate|rotate-kek`).
- **Audit, jobs, outbox (WP05, tested locally):** hash-chained audit log, leased durable job queue, encrypted outbox with
  retries and dead-lettering, bounded event bus.
- **Agents and keys (WP06, tested locally):** agent registration, strict key parsing and algorithm policy, global key
  uniqueness, revocation, enable/disable, source CIDRs.
- **Servers and credentials (WP07, tested locally):** servers, roles, aliases, destination host identities and host CAs,
  managed/imported login keys, user CAs with per-connection certificates, gateway host keys with staged rotation,
  anti-SSRF egress guard, a single strict outbound SSH dialer.
- **Policy (WP08, tested locally):** label-selector policy rules, approver rules, immutable compiled policy snapshots,
  effective-access evaluation and what-if.
- **Access lifecycle (WP09, tested locally):** requests with deduplication and rate limits, decisions, grants with
  time-authoritative expiry, sessions, lockdown, cascades, enforcer, startup reconciliation.
- **SSH gateway (WP10–WP12, implemented; partial tests):** agent SSH front end with a shell-free command grammar
  (`list`, `roles`, `request`, `status`, `cancel`, `sessions`, `whoami`, `version`, `help`) and published JSON schemas
  (`hallpass.*/v1`); data plane for exec, shell and PTY with an environment allowlist, signals, exit propagation, strict
  destination host verification, enforced termination and graceful drain (`hallpass serve`); mandatory encrypted recording
  in the HPREC1 format with integrity chain, reconciliation, retention and `hallpass verify`; `hallpass hostkey show|stage|promote`.
  Open items: keepalive and load tests, recording idempotency keys, per-class retention, external crypto review.
- **Operator authentication service layer (WP13, in progress):** Argon2id passwords, TOTP, recovery codes, one-time tokens,
  server-side sessions, reauthentication, last-admin protection, break-glass primitives. HTTP endpoints arrive with WP15.
- **Web UI foundation (WP19, in progress):** design system with light/dark tokens, API and SSE clients, login/setup
  routes, CSP-safe production build check. Not yet served by the binary (HP-UI-016).
- **Packaging and release pipeline (WP24, in progress):** distroless non-root multi-arch container image, Docker Compose
  example, hardened systemd unit, release workflow (static binaries for linux/amd64, linux/arm64, darwin/arm64; checksums;
  syft SBOMs; GitHub build provenance attestations; Trivy gate; GHCR push on tags only), container smoke test, operator
  install/container/upgrade guides, this changelog and the versioning policy. The release workflow has not run on GitHub yet.

### Security

- The recording format and keyring have not been externally reviewed (RG-9, R-02).

[Unreleased]: #unreleased
