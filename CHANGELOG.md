# Changelog

All notable changes to HallPass are documented in this file. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and versions follow the policy in
[docs/VERSIONING.md](docs/VERSIONING.md) (Semantic Versioning for the binary, with separate versioning for the REST API,
agent JSON schemas, the recording format and the database schema).

## [Unreleased]

## [0.7.3] - 2026-10-29

> **Recording format, backup format and keyring not externally reviewed.** The known limitations of
> [0.1.0](https://github.com/aurimasniekis/go-hallpass/releases/tag/v0.1.0) still apply.

### Changed

- `hallpass-api` keeps the `NO_PROXY` entries you set (after its own `localhost`, `127.0.0.1`, `::1`; `*` is
  ignored) instead of replacing them, so `NO_PROXY=tuf-repo-cdn.sigstore.dev,… hallpass-api -- gh attestation verify …`
  reaches public hosts that are not API targets directly.
- `help api`, the agent guide and the skill explain how to reach such public hosts, which need no credentials, and
  never to add them to a target with a credential.
- The git docs say how the access profile is chosen without `<remote>+<profile>` (an active grant first, then
  auto-approved, then requestable, ties by name) and show how to keep two identities apart with pinned remotes and
  git's `includeIf`.

## [0.7.2] - 2026-10-29

> **Recording format, backup format and keyring not externally reviewed.** The known limitations of
> [0.1.0](https://github.com/aurimasniekis/go-hallpass/releases/tag/v0.1.0) still apply.

0.7.1 was tagged but never published: the release image scan stopped it on the go-jose vulnerability below. Its
changes ship in this release: agents can name the git access profile in the SSH user
(`git clone github+acme-push@center:github/acme/api.git`); see the 0.7.1 section of the changelog.

### Changed

- The GitHub API target preset also lists `results-receiver.actions.githubusercontent.com`, where GitHub Actions logs
  (`gh run view --log`, `…/actions/{runs,jobs}/{id}/logs`) redirect. Without it the proxy refused the redirected
  request. Existing GitHub targets keep their hosts: add this one exact host to fetch logs, never
  `*.blob.core.windows.net` (it would send the GitHub token to any Azure storage account). The API targets page has
  complete GitHub and Cloudflare examples.

### Security

- go-jose 4.1.6 (CVE-2026-116587, HIGH): a crafted JWK set could make JWK parsing use excessive resources. HallPass
  parses the JWKs of configured SSO (OIDC) providers. govulncheck finds no reachable call; the release image scan
  (Trivy) flagged the dependency.

## [0.7.1] - 2026-10-28

> **Not published.** The release image scan found CVE-2026-116587 in go-jose; these changes ship in 0.7.2.

### Added

- **Git: pick the access profile in the SSH user.** `git clone github+acme-push@center:github/acme/api.git` uses only
  the access profile `acme-push` (reusing or requesting its grant), like `sftp <server>+<role>@center`. If that
  profile does not cover the repository or the operation, git gets `repository not found or not permitted`, with no
  fallback to another profile. The remote URL now carries the choice, so a wrapper or separate sessions per profile
  are no longer needed. Without `+<profile>` nothing changes.

### Changed

- For git, an SSH user containing `+` is no longer ignored: it must be `<remote>+<profile>` with the remote of the
  repository path, otherwise git gets a usage error (exit 81). Before, any user name was ignored for git.

## [0.7.0] - 2026-10-27

> **Recording format, backup format and keyring not externally reviewed.** The known limitations of
> [0.1.0](https://github.com/aurimasniekis/go-hallpass/releases/tag/v0.1.0) still apply.

### Added

- **Agent sessions.** Several conversations of one agent (for example several Claude Code sessions sharing a key) no
  longer share access. A command names its session with `HALLPASS_SESSION` or Claude Code's `CLAUDE_CODE_SESSION_ID`
  (add `SendEnv CLAUDE_CODE_SESSION_ID HALLPASS_SESSION` to the gateway's `Host` entry); requests and grants belong to
  that session and another session cannot use them. Approval messages and the request pages show the session, and
  `whoami` reports it. `hallpass-api` and `api env` carry it for API calls. Commands without a session share the
  agent's default session, as before. The session is stated by the agent: it separates conversations, it is not a
  security boundary.
- Database migration 0033 (adds the session to requests, grants and connections).

### Fixed

- The API proxy tunnel (`hallpass-api`, and the documented `ssh -fN -L …:hallpass:443`) never opened with the
  documented agent ssh configuration, whose `ClearAllForwardings yes` also drops forwards given on the command line.
  The tunnel now passes `-o ClearAllForwardings=no`.
- The Claude Code plugin version now follows HallPass releases (0.7.0), so installed plugins pick up skill updates; it
  had stayed at 0.1.0 since the first release.

## [0.6.1] - 2026-10-27

> **Recording format, backup format and keyring not externally reviewed.** The known limitations of
> [0.1.0](https://github.com/aurimasniekis/go-hallpass/releases/tag/v0.1.0) still apply.

### Added

- `hallpass-api --role <profile>` and `api env --role <profile>`: use one API access profile only. Without it the
  proxy picks a profile per call (active grant, then auto-approved, then requestable), so a target with an
  auto-approved profile never asked for another one that allows the same call. With a named profile, calls it does not
  allow are refused instead of falling back, and requests are filed for that profile. `api env --role` puts the
  profile into the proxy URL (`http://<profile>@127.0.0.1:18080`).

## [0.6.0] - 2026-10-27

> **Recording format, backup format and keyring not externally reviewed.** The known limitations of
> [0.1.0](https://github.com/aurimasniekis/go-hallpass/releases/tag/v0.1.0) still apply.

### Added

- **API targets.** Agents call HTTPS APIs (GitHub, Cloudflare, Google Cloud, or any API with a bearer, header or Basic
  credential) with their usual tools through the API proxy: `ssh -fN -L 18080:hallpass:443 <gateway>`, then
  `eval "$(ssh <gateway> api env)"`. HallPass replaces the agent's token with the access profile's credential, which
  agents never see, and allows each request only under a grant and the profile's rules (method, host, path patterns,
  and GraphQL query versus mutation). Every call is recorded in the session timeline (method, path, status, sizes;
  no bodies). Each target has its own CA, name-constrained to its hosts. New `api ca` and `api env` gateway commands,
  `kind: api` servers, `api` rules on roles and the `/roles/{id}/api-credential` and `/servers/{id}/api-ca` endpoints.
- **`hallpass-api`**, an agent-side wrapper in the release archives:
  `hallpass-api --gateway center --reason "…" -- gh issue comment 42 --body "…"` opens the tunnel and sets the proxy
  variables for that one command, and reports the command line. A call that needs approval is filed as a request that
  shows approvers the command next to the reason; `hallpass-api` waits for the decision and runs the command again.
  The reported command is also recorded with every API call in the session timeline.
- `api_proxy` configuration: `enabled` (default true), and the addresses API hosts may resolve to (public only by
  default).

### Security

- The gateway now accepts one kind of SSH forward: a local forward to the name `hallpass`, which reaches only the API
  proxy. Every other forward is still refused. HallPass holds API tokens and can read the API responses it forwards;
  give each access profile a least-privilege token.

## [0.5.0] - 2026-10-26

> **Recording format, backup format and keyring not externally reviewed.** The known limitations of
> [0.1.0](https://github.com/aurimasniekis/go-hallpass/releases/tag/v0.1.0) still apply.

### Added

- **Operators and API tokens from Terraform.** Administrator API tokens may create operators, set their roles,
  operator groups and enabled state, and link single sign-on identities and chat accounts; they may also issue, read and
  revoke tokens of their own. A token cannot change the roles or enabled state of the operator it acts for.
- `GET /api/v1/system/egress` shows the egress settings from the configuration file (read-only).

### Changed

- An administrator may issue an API token with **any** role, for example Auditor for a read-only integration, without
  holding that role. The token works while its creator stays an administrator.
- Revoking an API token also revokes the tokens it issued. A token issued by a token cannot issue tokens.

### Security

- Administrator API tokens can now manage operators without recent sign-in or MFA, so a leaked administrator token can
  create or re-link an approver account and approve requests with it. Use the least role an integration needs and
  review operator changes made through tokens.

## [0.4.0] - 2026-10-26

> **Recording format, backup format and keyring not externally reviewed.** The known limitations of
> [0.1.0](https://github.com/aurimasniekis/go-hallpass/releases/tag/v0.1.0) still apply.

### Added

- **Events to Pulse.** With `events.pulse` configured, HallPass publishes every audit event (`evt.hallpass.<action>`,
  for example `evt.hallpass.request.approved`) and agent session events (`evt.hallpass.session.*`: connections,
  channels, exec, git and file-transfer summaries, session closed) to [Pulse](https://github.com/aurimasniekis/go-pulse)
  over NATS JetStream. Events are written in the same transaction as the change, carry a stable ID for de-duplication
  and wait while Pulse is unreachable; HallPass never blocks on it. Encrypted audit details, command text and terminal
  content are never published. Off by default; see `docs/operator/events.md`.

## [0.3.0] - 2026-10-26

> **Recording format, backup format and keyring not externally reviewed.** The known limitations of
> [0.1.0](https://github.com/aurimasniekis/go-hallpass/releases/tag/v0.1.0) still apply.

### Added

- **Default sign-in provider.** The sign-in page can go straight to one SSO provider instead of showing the sign-in
  options (**Administration → Authentication → Default sign-in**, `direct_provider` in `/api/v1/settings/auth`).
  `/login/password` always shows every sign-in method, including email and password, as the fallback. The page still
  shows the options after a failed SSO sign-in and right after signing out.

## [0.2.1] - 2026-10-25

> **Recording format, backup format and keyring not externally reviewed.** The known limitations of
> [0.1.0](https://github.com/aurimasniekis/go-hallpass/releases/tag/v0.1.0) still apply.

### Fixed

- **The console works on phones.** Below tablet width the navigation opens from a menu button and the header stays in
  place; on phones every table shows one card per row, with the row's actions and details kept. No page scrolls
  sideways any more.
- Re-authenticating through single sign-on before a sensitive action no longer shows a red "recent authentication
  required" error while the browser goes to the identity provider.
- A request the browser abandons (for example when a page navigates away) is no longer logged as an error; it is
  logged at debug level with status 499. Failed API operations log the status actually sent instead of 400.
- Startup no longer warns "recording key slot repaired from the database copy" for every recording made since the last
  start. Writing the second key slot of a healthy recording is routine and is now logged once, at info level; the
  warning stays for slots that actually stopped working.

## [0.2.0] - 2026-10-25

> **Recording format, backup format and keyring not externally reviewed.** The known limitations of
> [0.1.0](https://github.com/aurimasniekis/go-hallpass/releases/tag/v0.1.0) still apply.

### Added

- **Backups to object storage.** HallPass backs itself up on a schedule to an S3-compatible bucket (AWS S3,
  Cloudflare R2, MinIO and others): **Administration → Backups**, `/api/v1/system/backups`, or the Terraform
  `hallpass_backup_target` resource. The database snapshot is encrypted before upload; recordings, already encrypted,
  are uploaded once and shared by later backups. Retention keeps the newest backups plus one per day. Every run is
  listed with its result, and `hallpass_backup_remote_*` metrics track them. `hallpass backup remote-list` and
  `remote-download` restore a backup on a new host with the KEK.
- The agent page shows how to set up the agent's machine: the key command, the gateway's `known_hosts` lines and a
  `~/.ssh/config` block with the gateway address. `ssh.public_address` sets that address when agents connect to
  another name or port than the public URL host and the SSH listener.

### Security

- **Web terminals.** Administrators can open a recorded shell on a server role from the console (**Servers → Roles →
  Terminal**) without a request or approver, after a recent sign-in with two-factor authentication. It runs through
  the same recording and enforcement as agent sessions and ends on close, expiry, lockdown or a disabled target, or
  when the administrator loses the role. On by default; `console.terminal: false` turns it off.
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

[Unreleased]: https://github.com/aurimasniekis/go-hallpass/compare/v0.7.3...HEAD
[0.7.3]: https://github.com/aurimasniekis/go-hallpass/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/aurimasniekis/go-hallpass/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/aurimasniekis/go-hallpass/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/aurimasniekis/go-hallpass/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/aurimasniekis/go-hallpass/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/aurimasniekis/go-hallpass/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/aurimasniekis/go-hallpass/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/aurimasniekis/go-hallpass/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/aurimasniekis/go-hallpass/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/aurimasniekis/go-hallpass/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/aurimasniekis/go-hallpass/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/aurimasniekis/go-hallpass/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/aurimasniekis/go-hallpass/releases/tag/v0.1.0
