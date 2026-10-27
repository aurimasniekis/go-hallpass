# Agents and keys

An **agent** is anything that connects to HallPass with an SSH key: an AI coding agent, a container, a CI job, a VM.

<Shot name="agents" alt="Agents list with three agents" />

## Register an agent

**Agents → New agent**:

| Field | Notes |
|---|---|
| Name | Shown to operators and in notifications. |
| Description | For operators. |
| Groups, labels | What policy rules select on (`agent_groups`, `agent_labels`). Groups are created when first used. |
| Source CIDRs | Optional: only accept this agent from these networks. Defense in depth, not attestation. |
| Public keys | One or more OpenSSH public keys, one per line. |

The SSH username the agent sends is ignored. Identity comes only from the key. Unknown keys are rejected before
anything else happens and count toward [bans](/help/troubleshooting#banned-source).

## What an agent can do

The agent page shows its **effective access**: every server and role, the resulting level, and the rule that decided
it. Use it to check a new rule before telling the agent to try.

<Shot name="agent" alt="Agent detail with SSH keys and effective access" />

## Rotate or revoke a key

- Add the new key with **Add key**, switch the agent over, then **Revoke** the old one.
- Revoking a key, or disabling the agent, ends its live sessions within 5 seconds and refuses new logins.
- Key comments are shown as untrusted text: they come from whoever generated the key.

If you suspect an agent is compromised, follow the [incident runbook](/operators/incidents#suspected-agent-compromise).

## Disable or delete an agent

**Disable** (on the agent's page) stops it for now: it can no longer sign in or request access, its live sessions end
within 5 seconds, and **Enable** brings it back with its keys.

**Delete** is for good, and asks you to type the agent's name. It does what disabling does, revokes every key and
cancels pending requests. A revoked key can never be registered again, on any agent, so a replacement agent needs a
new key. The name can be used again, and past sessions and the audit log still show the deleted agent.

## Agent sessions

One agent often runs several conversations at once, for example several Claude Code sessions on one laptop that share
the agent's key. Each command can name an **agent session** (`HALLPASS_SESSION`, or Claude Code's
`CLAUDE_CODE_SESSION_ID` passed with `SendEnv`). Requests and grants then belong to that session:

- a grant approved for one conversation cannot be used by another; each asks for its own access with its own reason;
- approval messages, the request page and the request list show the session next to the agent;
- policy, visibility, limits and the audit log stay per agent; commands without a session share a default session.

The session is the agent's own claim. It keeps conversations apart, but anything with the agent's key can name any
session. Register separate agents (keys) where that matters.

## Hand the agent its configuration

Give the agent's owner:

1. the gateway `known_hosts` line (`hallpass hostkey show`), and
2. the `~/.ssh/config` block from [Connect your first agent](/guide/first-agent#_3-configure-the-ssh-client).

For AI coding agents, install the [HallPass skill](/agents/skill) so the agent knows how to request access properly.
