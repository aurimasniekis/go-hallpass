# Agent integrations

The **`hallpass` skill** teaches AI coding agents to use a HallPass gateway correctly:
- check the connection;
- list servers and roles;
- request time-bound access with an honest reason;
- wait for human approval without spamming requests;
- prefer focused `exec` commands;
- interpret gateway exit codes 80–90;
- never try to obtain destination credentials or work around a refusal.

The skill is a standard [`SKILL.md`](skills/hallpass/SKILL.md) with one [reference file](skills/hallpass/references/commands.md).
The same files work in Claude Code and Codex.

The agent still needs an SSH key registered in HallPass and a pinned gateway host entry in `~/.ssh/config`
(see [docs/agent/guide.md](../docs/agent/guide.md)). The skill assumes the host alias `center`. Tell your agent if
yours differs.

## Claude Code (plugin)

This repository is a plugin marketplace. In Claude Code:

```
/plugin install hallpass --marketplace aurimasniekis/go-hallpass
```

or in two steps:

```
/plugin marketplace add aurimasniekis/go-hallpass
/plugin install hallpass@hallpass
```

The repository is currently private, so installing needs GitHub access to it. To install from a local checkout, use
`/plugin marketplace add /path/to/go-hallpass`.

Without the plugin system, copy the skill directory instead:

```sh
mkdir -p ~/.claude/skills && cp -R integrations/skills/hallpass ~/.claude/skills/        # all projects
mkdir -p .claude/skills && cp -R /path/to/go-hallpass/integrations/skills/hallpass .claude/skills/   # one project
```

## Codex

Codex loads skills from `~/.codex/skills`:

```sh
mkdir -p ~/.codex/skills && cp -R integrations/skills/hallpass ~/.codex/skills/
```

Restart Codex. The skill is picked up when a task mentions HallPass or running commands on gateway-reached servers.

## Other agents

Any agent that reads an `AGENTS.md` or system prompt can use the skill text directly: paste the body of
[`SKILL.md`](skills/hallpass/SKILL.md) (without the front matter) into the agent's instructions.
