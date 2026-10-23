# Hallpass documentation

| Document | Purpose |
|---|---|
| [GOAL.md](GOAL.md) | Canonical product contract: requirements (`HP-*` IDs), guarantees, definition of done, release gates. |
| [PLAN.md](PLAN.md) | Architecture and execution plan, work packages, progress and acceptance checklist. |
| [DECISIONS.md](DECISIONS.md) | Architectural decision records and open review items. |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Assets, trust boundaries, threats, mitigations, residual risks. |
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
| [operator/sso.md](operator/sso.md) | OIDC single sign-on: providers, linking, group mapping, step-up, SSO-only mode. |
