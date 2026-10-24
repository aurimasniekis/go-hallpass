# AI agent skill (Claude Code, Codex)

The **`hallpass` skill** teaches an AI coding agent to use a Hallpass gateway correctly: check the connection, list
servers and roles, request time-bound access with an honest reason, wait for approval without spamming requests,
prefer focused `exec` commands, interpret exit codes 80–90, and never try to obtain destination credentials or work
around a refusal.

It is a standard [`SKILL.md`](https://github.com/aurimasniekis/go-hallpass/blob/main/integrations/skills/hallpass/SKILL.md)
with one [reference file](https://github.com/aurimasniekis/go-hallpass/blob/main/integrations/skills/hallpass/references/commands.md).
The same files work in Claude Code and Codex. Installation details for every option are in
[integrations/README.md](https://github.com/aurimasniekis/go-hallpass/blob/main/integrations/README.md).

::: warning The repository is currently private
Installing from GitHub needs access to `aurimasniekis/go-hallpass`. You can also install from a local checkout.
:::

## Before you install

The agent still needs its own SSH key registered in Hallpass and a pinned gateway entry in `~/.ssh/config`
([Connect your first agent](/guide/first-agent)). The skill assumes the host alias `center`; tell your agent if yours
differs.

## Claude Code

The repository is a plugin marketplace:

```
/plugin install hallpass --marketplace aurimasniekis/go-hallpass
```

or in two steps:

```
/plugin marketplace add aurimasniekis/go-hallpass
/plugin install hallpass@hallpass
```

## Codex

```sh
mkdir -p ~/.codex/skills && cp -R integrations/skills/hallpass ~/.codex/skills/
```

Run it from a checkout of the repository, then restart Codex.

## Other agents

Any agent that reads an `AGENTS.md` or a system prompt can use the skill text directly: paste the body of `SKILL.md`
(without the front matter) into its instructions.
