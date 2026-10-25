<p align="center">
  <img src="../site/public/logo.svg" alt="" width="72" height="72">
</p>

# HallPass documentation

The website at <https://aurimasniekis.github.io/go-hallpass/> covers getting started and the main guides. The files
here are the detailed reference.

## Operators

| Document | Purpose |
|---|---|
| [operator/install.md](operator/install.md) | Installation: release archives, container, Compose, systemd, KEK provisioning. |
| [operator/configuration.md](operator/configuration.md) | Every configuration key and `HALLPASS_*` variable. |
| [operator/container.md](operator/container.md) | Container image details and hardening. |
| [operator/upgrade.md](operator/upgrade.md) | Upgrades, migrations and rollback. |
| [operator/keys.md](operator/keys.md) | Keys and encryption at rest, rotation. |
| [operator/storage.md](operator/storage.md) | SQLite database, recordings directory, file permissions, disk space. |
| [operator/backup.md](operator/backup.md) | Backup, restore drill, integrity anchors, break-glass recovery. |
| [operator/policy.md](operator/policy.md) | Access rules, approver rules, selectors, effective access. |
| [operator/approvals.md](operator/approvals.md) | Web and chat approvals, routes, account linking, delivery. |
| [operator/slack.md](operator/slack.md) | Slack approval app setup. |
| [operator/telegram.md](operator/telegram.md) | Telegram approval bot setup. |
| [operator/sso.md](operator/sso.md) | OIDC single sign-on: providers, linking, group mapping, step-up, SSO-only mode. |
| [operator/recording.md](operator/recording.md) | Recording durability, verification, reconciliation and retention. |
| [operator/logging.md](operator/logging.md) | Log format and fields. |
| [operator/observability.md](operator/observability.md) | Metrics, health and readiness, tracing, alerts. |
| [operator/incidents.md](operator/incidents.md) | Incident runbooks: lockdown, compromise, host-key change, disk full, corruption, lost KEK, break-glass. |
| [operator/remote-networks.md](operator/remote-networks.md) | Reaching servers behind NAT: Tailscale, WireGuard, reverse SSH tunnels. |
| [security-guarantees.md](security-guarantees.md) | What HallPass does and does not guarantee, with current status. |

## Agents and destinations

| Document | Purpose |
|---|---|
| [agent/guide.md](agent/guide.md) | Agent guide: client config, host-key pinning, commands, quoting, streams. |
| [agent/exit-codes.md](agent/exit-codes.md) | Gateway exit codes 80–90. |
| [agent/json-schemas.md](agent/json-schemas.md) | `--json` output schemas (`api/ssh-schemas/`). |
| [destination/hardening.md](destination/hardening.md) | Destination setup: authorized_keys restrictions, certificates, sshd hardening. |
| [destination/audit-collector.md](destination/audit-collector.md) | Optional destination-side exec collector. |

## Formats and project

| Document | Purpose |
|---|---|
| [formats/hprec1.md](formats/hprec1.md) | HPREC1 encrypted recording segment format. |
| [VERSIONING.md](VERSIONING.md) | Versioning policy for the binary, API, schemas, recording format and database. |
| [RELEASING.md](RELEASING.md) | How a release is cut and published. |

## Logo

The HallPass mark is [logo.svg](../site/public/logo.svg) (vector, transparent background). PNG renders with a
transparent background are in [site/public/logo/](../site/public/logo/):
[16](../site/public/logo/logo-16.png), [32](../site/public/logo/logo-32.png), [48](../site/public/logo/logo-48.png),
[64](../site/public/logo/logo-64.png), [128](../site/public/logo/logo-128.png), [256](../site/public/logo/logo-256.png),
[512](../site/public/logo/logo-512.png) and [1024](../site/public/logo/logo-1024.png) pixels square. Regenerate them after
changing the SVG:

```sh
for s in 16 32 48 64 128 256 512 1024; do
  rsvg-convert -w "$s" -h "$s" site/public/logo.svg -o "site/public/logo/logo-$s.png"
done
```

## Project planning (internal)

Internal design and status documents. They use requirement IDs (`HP-*`); nothing above depends on them.

| Document | Purpose |
|---|---|
| [GOAL.md](GOAL.md) | Product contract: requirements, guarantees, definition of done, release gates. |
| [PLAN.md](PLAN.md) | Architecture and design, work-package status and requirement acceptance checklist. |
| [DECISIONS.md](DECISIONS.md) | Architectural decision records and open review items. |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Assets, trust boundaries, threats, mitigations, residual risks. |
| [TEST_STRATEGY.md](TEST_STRATEGY.md) | Test layers, requirement→test matrix, fault catalog, performance method. |
| [security/](security/) | Internal security review report and checklist. |
| [evidence/](evidence/) | Release-gate evaluations and test evidence. |
