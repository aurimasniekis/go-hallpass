# Changelog

All notable changes to HallPass are documented in this file. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and versions follow the policy in
[docs/VERSIONING.md](docs/VERSIONING.md) (Semantic Versioning for the binary, with separate versioning for the REST API,
agent JSON schemas, the recording format and the database schema).

## [Unreleased]

### Added

- **Backups to object storage.** HallPass backs itself up on a schedule to an S3-compatible bucket (AWS S3,
  Cloudflare R2, MinIO and others): **Administration → Backups**, `/api/v1/system/backups`, or the Terraform
  `hallpass_backup_target` resource. The database snapshot is encrypted before upload; recordings, already encrypted,
  are uploaded once and shared by later backups. Retention keeps the newest backups plus one per day. Every run is
  listed with its result, and `hallpass_backup_remote_*` metrics track them. `hallpass backup remote-list` and
  `remote-download` restore a backup on a new host with the KEK.

### Security

- **API tokens that never expire.** Administrators can issue a token without expiry (**Never expires**,
  `never_expires: true`) for Terraform and break-glass automation. It still stops when revoked or when its operator is
  disabled or loses the role. This relaxes the mandatory 1–366 day expiry.

## [0.1.1] - 2026-10-25

> **Recording format and keyring not externally reviewed.** The known limitations of
> [0.1.0](https://github.com/aurimasniekis/go-hallpass/releases/tag/v0.1.0) still apply.

### Added

- The single sign-on groups claim can name a nested claim with a dotted path, such as `porch.groups` for Porch. A
  top-level claim with exactly that name still takes precedence, so names like `https://example.com/groups` keep
  working.

## [0.1.0] - 2026-10-25

First release. HallPass is a terminating SSH gateway for AI agents: agents use plain `ssh` with their own key,
policy and a human decide what they may reach and for how long, and HallPass logs in to the destination with a
credential the agent never sees and records the session. Agents can also use git and file transfer
through it.

> **Recording format and keyring not externally reviewed.** The HPREC1 format, the keyring and field encryption have
> had an internal review only.

### Known limitations

- Pre-1.0: interfaces may change between minor versions ([docs/VERSIONING.md](docs/VERSIONING.md)).
- No 24-hour soak test and no benchmarks on reference hardware. Short soak runs and smoke benchmarks
  passed.
- Slack and Telegram approvals are tested against recorded and fake provider APIs, not live workspaces.
- Browser end-to-end tests cover the main workflows in Chromium only. There are no visual regression snapshots.
- Not yet available: the Storage & keys page in the web console (use `hallpass keys status` and the storage
  metrics), OpenTelemetry metrics export (Prometheus `/metrics` works), visual regression tests, and a built-in
  connector for destinations behind NAT.

### Added

- **Agent SSH gateway.** A shell-free command grammar (`list`, `roles`, `request`, `status`, `cancel`, `connect`,
  `exec`, `sessions`, `whoami`, `version`, `help`) with versioned JSON output (`hallpass.*/v1`) and stable exit codes
  80–90. Exec, interactive shells and PTYs with an environment allowlist, signals and exit-status propagation.
  Port forwarding, agent forwarding, X11 and subsystems (except SFTP for file transfer) are refused and audited.
  Hidden and unknown servers give the same answer.
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
- **Git remotes.** Agents clone, fetch and push with plain git through the gateway
  (`git clone center:github/acme/api.git`), with requests, approvals and time-bound grants. Git remotes have their own
  page with presets for GitHub, GitLab.com and Bitbucket. Access profiles limit repositories with patterns
  (`acme/{api,web}`, `acme/*`, `**`) and pushes with branch, protected-branch and tag rules; refused pushes never
  reach the host. Force-pushes are refused unless a profile allows them: HallPass proves every branch update is a
  fast-forward from the pushed commits. Git operations are recorded as metadata (repository, ref updates, bytes),
  not as byte streams.
- **File transfer.** A role capability, `file-transfer`, lets agents use plain `scp` and `sftp`
  (`scp build.tar web1@center:/tmp/`, `web1+deploy@center` to name the role), with requests, approvals and grants as
  for shell access. Every upload, download, rename, deletion and failure is recorded with its path, size and SHA-256;
  file contents are not stored. Other SSH subsystems and the legacy scp protocol (`scp -O`) are refused.
- **Several approvers.** A role or git access profile can require 1–5 distinct approvers; the request stays pending
  until enough have approved, any denial ends it, and policy never auto-approves such roles.
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
- **Lifecycle.** Disable, enable and delete servers, git remotes, roles and access profiles, and delete agents. Disabling
  ends active access and cancels pending requests. Deleting also revokes the login keys and frees the name; the record
  stays so past sessions and the audit log can still name it.
- **API tokens and Terraform.** Bearer tokens for automation (**Administration → API tokens**) that act for their
  creator with one of the creator's roles, expire after 1–366 days, and work only on configuration and read
  operations. Every configuration create honors `Idempotency-Key`. The
  [Terraform provider](https://github.com/aurimasniekis/terraform-provider-hallpass) manages agents, servers, git
  remotes, roles, keys, policy, single sign-on and chat approvals with them.
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

- An internal security review, performed by AI agents, not an external party: both HIGH and all MEDIUM findings fixed with regression tests. One LOW is accepted and one LOW is open.
- The recording format and keyring have not been externally reviewed.
- API tokens skip recent authentication and MFA on the operations they may use, because issuing one requires both.
  They cannot decide requests, revoke grants, read recordings, manage operators or tokens, or use lockdown.

[Unreleased]: https://github.com/aurimasniekis/go-hallpass/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/aurimasniekis/go-hallpass/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/aurimasniekis/go-hallpass/releases/tag/v0.1.0
