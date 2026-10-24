# Access policy

HallPass is **default deny**: an agent sees and can request nothing until a rule allows it. Policy has two parts:

- **Rules** decide what agents can see, request or get automatically.
- **Approver rules** decide which operators may approve which requests.

## Rules

A rule maps *subjects* (agents) × *targets* (servers) × *roles* to an effect:

| Effect / level | Meaning |
|---|---|
| `deny` | The agent cannot see or request the role. **Any matching deny overrides every allow.** |
| `allow` `visible` | The role appears in `ssh center list` but cannot be requested. |
| `allow` `requestable` | The agent can request it, and a human approves. |
| `allow` `auto_approve` | Requests up to `auto_max_duration` are approved by policy. Longer requests still go to a human. They are never silently shortened. |

When several allow rules match, the highest level wins. A server is visible when at least one of its roles is visible.
Disabled agents, servers and roles are invisible, and lockdown hides everything.

### Selectors

```yaml
subjects: {agents: [agt_…], agent_groups: [sre-bots], agent_labels: {matchLabels: {team: sre}}}
targets:  {servers: [srv_…], server_groups: [prod-web], server_labels: {matchExpressions: [{key: tier, operator: In, values: [web]}]}}
roles:    {names: [inspect], ids: [rol_…], role_labels: {matchLabels: {class: readonly}}}
```

- A selector matches when **any** of its clauses matches (IDs ∪ groups ∪ labels).
- Inside a label clause, every `matchLabels` pair and every `matchExpressions` entry must hold (`In`, `NotIn`, `Exists`, `DoesNotExist`).
- **An empty selector matches nothing**, and so does an empty label clause. This differs from Kubernetes. The API rejects rules with empty
  selectors so a typo cannot silently create a dead (or overly broad) rule.
- `all: true` must be written explicitly. It matches every object of that kind, **including ones created later**.
- An agent in several groups gets the union of what each group allows, and denies still win.

### Durations

The maximum grant for a request is the smallest of the role's `max_duration`, the global `access.max_grant_duration`, and
the largest `max_duration` among matching requestable rules (when any set one). Agents and approvers can choose only the
configured presets (`5m 15m 30m 1h 3h 6h 24h`) up to that maximum. A reason is required when any matching allow rule requires one.

## Approver rules

`operators × targets × roles → may approve (up to max_duration)`. To approve, an operator needs **both** the Approver or
Administrator internal role **and** a matching approver rule. Administrators get no implicit approval authority. When
self-approval is prohibited (the default), owners of the requesting agent cannot approve its requests.

## Changes take effect safely

Every change to rules, approver rules, group membership, labels, or the enable/disable state of agents, servers and roles
increments the policy version in the same transaction. Grants record the version they were issued under. When policy
changes, pending requests that are no longer requestable are canceled, active grants that are no longer allowed are
revoked, and grants whose maximum duration shrank are shortened. Active channels are terminated within the enforcement
bound (5 s).

## Effective-access preview

The policy page shows, per agent or per server, the decision for every server×role, including denied ones, along with the matching
rules and the deciding rule. A what-if mode evaluates unsaved rule edits against live inventory before you apply them.

## What policy does not do

- **Capabilities (`shell`, `exec`, `pty`) control SSH channel types, not commands.** HallPass does not offer command
  allowlists as a security boundary: shells, interpreters and many tools can run arbitrary commands, read files or open
  network connections. Reliable restrictions must be enforced **on the destination**: a dedicated account per role with
  least privilege, `sudoers` rules, `ForceCommand` or `authorized_keys` `command=` for single-purpose roles,
  filesystem permissions, and outbound firewalling. See `docs/destination/hardening.md`.
- Role descriptions and usernames (e.g. `readonly`) are informational, and they enforce nothing.
