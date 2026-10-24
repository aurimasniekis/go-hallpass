# Access policy

HallPass is **default deny**: an agent sees and can request nothing until a rule allows it. Policy has two parts:
**access rules** (what agents get) and **approver rules** (who may approve). The full semantics are in
[policy.md](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/operator/policy.md).

<Shot name="policy" themed alt="Policy page with five access rules: a deny rule, two auto-approve rules and two requestable rules" />

## Access rules

A rule maps **agents × servers × roles** to an effect:

| Effect / level | The agent… |
|---|---|
| `deny` | cannot see or request the role. **Any matching deny beats every allow.** |
| `allow` · `visible` | sees the role in `ssh center list` but cannot request it. |
| `allow` · `requestable` | can request it; a human approves. |
| `allow` · `auto_approve` | gets it approved by policy up to `auto_max_duration`. Longer requests still go to a human; they are never silently shortened. |

When several allow rules match, the highest level wins. A rule can also **require a reason**.

### Selectors

Each side of a rule is a selector. It matches when **any** of its clauses matches:

```yaml
subjects: {agents: [agt_…], agent_groups: [sre], agent_labels: {matchLabels: {team: sre}}}
targets:  {servers: [srv_…], server_groups: [prod-web], server_labels: {matchExpressions: [{key: tier, operator: In, values: [web]}]}}
roles:    {names: [inspect], ids: [rol_…], role_labels: {matchLabels: {class: readonly}}}
```

- **An empty selector matches nothing.** This differs from Kubernetes. To match everything, write `all: true`
  explicitly, and remember it also matches objects created later.
- Label clauses support `matchLabels` and `matchExpressions` with `In`, `NotIn`, `Exists` and `DoesNotExist`.

### Durations

The longest grant a request can get is the smallest of the role's maximum, the global `access.max_grant_duration`
(24 h by default) and the largest maximum among matching requestable rules. Agents and approvers pick durations within
that limit.

## Approver rules

`operators × servers × roles → may approve`. To approve a request, an operator needs **both** the Approver or
Administrator role **and** a matching approver rule. Administrators get no implicit approval authority. By default,
owners of the requesting agent cannot approve its requests (no self-approval).

## Preview before you rely on it

**Effective access** shows, per agent or per server, the decision for every server × role, including the denied ones,
and which rule decided each.

<Shot name="policy-effective" themed alt="Effective access preview for agent claude-sre" />

## Changes take effect immediately

Every change to rules, approver rules, groups, labels, or the enabled state of agents, servers and roles increments
the **policy version**. When policy changes:

- pending requests that are no longer requestable are canceled;
- active grants that are no longer allowed are revoked, and live channels end within 5 seconds;
- grants whose maximum shrank are shortened.

## What policy cannot do

Capabilities (`shell`, `exec`, `pty`) control SSH channel types, not commands. A shell, an interpreter or a tool such
as `find -exec` can run anything the remote account can. HallPass deliberately offers no command allowlists as a
security boundary. Restrict commands on the destination (`authorized_keys` `command=`, `ForceCommand`, `sudoers`);
see [destination hardening](/destinations/hardening).
