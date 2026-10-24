# Operator guides

Task-oriented guides for the people who run Hallpass and decide on access. Each guide links to the detailed reference
in the repository's [`docs/operator/`](https://github.com/aurimasniekis/go-hallpass/tree/main/docs/operator) where
there is more to know.

<Shot name="dashboard" themed alt="Dashboard" />

## Everyday work

| Task | Guide |
|---|---|
| Add a server, its roles and login credentials | [Servers and roles](/operators/servers) |
| Register an agent, rotate or revoke its key | [Agents and keys](/operators/agents) |
| Decide who sees, requests or auto-receives what | [Access policy](/operators/policy) |
| Approve or deny requests, revoke grants | [Approving requests](/operators/approvals) |
| Approve from chat | [Slack](/operators/slack), [Telegram](/operators/telegram) |
| Review what happened, replay a session | [Sessions and recordings](/operators/sessions) |

## Setup and operations

| Task | Guide |
|---|---|
| Sign operators in with your identity provider | [Single sign-on](/operators/sso) |
| Reach servers behind NAT (home lab, other networks) | [Home and lab servers](/operators/remote-networks) |
| Protect and rotate the master key | [Keys and the KEK](/operators/keys) |
| Back up, restore, export integrity anchors | [Backup and restore](/operators/backup) |
| Health checks, metrics, logs, alerts | [Monitoring](/operators/monitoring) |
| Upgrade and roll back | [Upgrades](/operators/upgrades) |
| Respond to an incident | [Incident runbooks](/operators/incidents) |

## Operator accounts

Invite operators under **Administration → Operators**. Each gets one or more roles: **Administrator**, **Approver**,
**Auditor** or **Viewer** (see [concepts](/guide/concepts#operators)). Operators sign in with a password plus TOTP or
with [SSO](/operators/sso). Sensitive actions (generating credentials, creating operators, changing integrations)
ask the operator to confirm it's them again if they have not authenticated in the last 5 minutes.

The audit log under **Governance → Audit log** records every security-relevant action in a hash chain. **Verify hash
chain** checks it.

<Shot name="audit" alt="Audit log with hash-chained entries and a Verify hash chain button" />
