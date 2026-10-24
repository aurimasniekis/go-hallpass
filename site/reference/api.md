# REST API

Everything the web console does goes through a JSON REST API under `/api/v1`. The contract is an OpenAPI 3.1 document:
[`api/openapi.yaml`](https://github.com/aurimasniekis/go-hallpass/blob/main/api/openapi.yaml).

## Conventions

- **JSON only.** Errors are RFC 9457 problem details (`application/problem+json`) with a stable `code`.
- **Authentication** uses the `__Host-hp_session` cookie from a browser sign-in (password plus TOTP, or SSO). There
  are no API tokens.
- **Mutations** require the `X-CSRF-Token` header and a same-origin `Origin` header.
- **Durations** are integer seconds; **timestamps** are RFC 3339 UTC.
- **Idempotency:** operations marked `x-idempotency-key` honor an `Idempotency-Key` header for 24 hours per operator,
  so a retried click never decides twice.
- **Addresses** of destinations are returned only to operators with the address permission.
- Changes within `/v1` are additive only.

Each operation in the document carries vendor extensions:

| Extension | Meaning |
|---|---|
| `x-permission` | The RBAC permission checked server-side. |
| `x-reauth` | Recent authentication (5 minutes) required; otherwise `reauth_required`. |
| `x-mfa` | Password sessions must have completed MFA recently; otherwise `mfa_required`. |
| `x-idempotency-key` | `Idempotency-Key` is honored. |
| `x-stream` | Server-Sent Events. |

## Areas

| Tag | Covers |
|---|---|
| `auth`, `me` | Sign-in, MFA, re-authentication, bootstrap, invitations, password reset, own sessions and chat links |
| `operators` | Operators, invitations, roles, sessions, identities |
| `agents` | Agents, keys, effective access |
| `inventory` | Servers and git remotes (`kind`), host identities and CAs, roles and access profiles, groups |
| `credentials` | Login keys (generate, import, probe, activate, revoke), user CAs, certificate bindings |
| `policy` | Access rules, approver rules, policy version |
| `access` | Requests (approve, deny, cancel), grants (revoke). An approval that still needs more approvers answers `202` with the pending request. |
| `sessions` | Access sessions, timeline, channels, segments, recordings, exports, destination records, activities |
| `audit` | Audit events and chain verification |
| `sso` | OIDC providers, group mappings, test login |
| `integrations` | Slack and Telegram integrations, notification routes, delivery history |
| `system` | Status, lockdown, break-glass acknowledgement, SSH bans, gateway host keys, statistics |
| `live` | `GET /api/v1/events`: Server-Sent Events for live updates |

## Outside the API

| Path | Purpose |
|---|---|
| `/healthz`, `/readyz` | Liveness and readiness ([Monitoring](/operators/monitoring)). |
| `/metrics` | Prometheus metrics, optionally on `http.metrics_listen`. |
| `/hooks/slack/<integration_id>`, `/hooks/telegram/<integration_id>` | Chat provider callbacks. No cookies; verified per provider. |
| `/hooks/destaudit/<collector_id>` | Signed batches from [`hallpass-collector`](/destinations/audit). |
| `/auth/oidc/callback` | OIDC redirect URI. |

The agent-facing SSH interface is described in [agent commands](/reference/agent-commands); its JSON output has its own
schemas in [`api/ssh-schemas/`](https://github.com/aurimasniekis/go-hallpass/tree/main/api/ssh-schemas).
