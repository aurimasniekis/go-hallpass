# Hallpass documentation

| Document | Purpose |
|---|---|
| [GOAL.md](GOAL.md) | Canonical product contract: requirements (`HP-*` IDs), guarantees, definition of done, release gates. |
| [PLAN.md](PLAN.md) | Architecture and execution plan, work packages, progress and acceptance checklist. |
| [DECISIONS.md](DECISIONS.md) | Architectural decision records and open review items. |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Assets, trust boundaries, threats, mitigations, residual risks. |
| [security-guarantees.md](security-guarantees.md) | What Hallpass does and does not guarantee, with current status (HP-DOC-004). |
| [TEST_STRATEGY.md](TEST_STRATEGY.md) | Test layers, requirement→test matrix, fault catalog, performance method, release evidence. |
| [PROMPT.md](PROMPT.md) | Original project brief (verbatim). |

Operator, agent, destination and format documentation is added under `operator/`, `agent/`, `destination/` and `formats/`
as the corresponding work packages land:

| Document | Purpose |
|---|---|
| [agent/guide.md](agent/guide.md) | Agent guide: client config, host-key pinning, commands, quoting, streams (HP-DOC-002). |
| [agent/exit-codes.md](agent/exit-codes.md) | Gateway exit codes 80–90. |
| [agent/json-schemas.md](agent/json-schemas.md) | `--json` output schemas (`api/ssh-schemas/`). |
| [destination/hardening.md](destination/hardening.md) | Destination setup: authorized_keys restrictions, certificates, sshd hardening (HP-DOC-003). |
| [formats/hprec1.md](formats/hprec1.md) | HPREC1 encrypted recording segment format. |
| [operator/recording.md](operator/recording.md) | Recording durability, verification, reconciliation and retention. |
| [operator/install.md](operator/install.md) | Installation: binaries, container, Compose, systemd, KEK provisioning. |
| [operator/container.md](operator/container.md) | Container image details and hardening. |
| [operator/upgrade.md](operator/upgrade.md) | Upgrades, migrations and rollback. |
| [operator/backup.md](operator/backup.md) | Backup, restore drill, integrity anchors, break-glass recovery. |
| [operator/observability.md](operator/observability.md) | Logs, metrics, health/readiness, tracing, alerts. |
| [VERSIONING.md](VERSIONING.md) | Versioning policy for the binary, API, schemas, recording format and database. |
| [operator/approvals.md](operator/approvals.md) | Web and chat approvals, routes, account linking, delivery. |
| [operator/slack.md](operator/slack.md) | Slack approval app setup. |
| [operator/telegram.md](operator/telegram.md) | Telegram approval bot setup. |
| [operator/sso.md](operator/sso.md) | OIDC single sign-on: providers, linking, group mapping, step-up, SSO-only mode. |
