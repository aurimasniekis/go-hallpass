# Connect your first agent

An agent needs three things: its own SSH key pair, a registration in HallPass, and an SSH client configuration that
pins the gateway's host key.

## 1. Create the agent's key

On the machine, container or VM where the agent runs:

```sh
ssh-keygen -t ed25519 -N "" -C my-agent -f ~/.ssh/agent_ed25519
cat ~/.ssh/agent_ed25519.pub
```

The private key never leaves that machine. HallPass only ever sees the public key.

## 2. Register the agent

In the console, open **Agents → New agent**. Give it a name, paste the public key, and add it to a **group** that your
access rule uses (for example `sre`). Optionally restrict **Source CIDRs** to where the agent runs.

<Shot name="agent" alt="Agent detail page: groups, labels, SSH key fingerprint and effective access" caption="The agent page shows its keys and exactly what policy allows it" />

## 3. Configure the SSH client

The agent's page in the console (**Set up the agent's machine**) shows all of this filled in for your gateway: the key
command, the `known_hosts` lines and the `~/.ssh/config` block. Otherwise, ask the operator for the gateway's
`known_hosts` line (`hallpass hostkey show` prints it) and install it. Do not accept the key on first use.

```
# ~/.ssh/known_hosts
[hallpass.example.com]:2222 ssh-ed25519 AAAAC3Nza…
```

```
# ~/.ssh/config
Host center
  HostName hallpass.example.com
  Port 2222
  User agent                  # any value works for commands; scp and sftp put the server here instead
  IdentityFile ~/.ssh/agent_ed25519
  IdentitiesOnly yes
  StrictHostKeyChecking yes
  ForwardAgent no
  ClearAllForwardings yes     # the API proxy tunnel overrides it with -o ClearAllForwardings=no
  ServerAliveInterval 30
  SendEnv CLAUDE_CODE_SESSION_ID HALLPASS_SESSION   # one agent session per conversation
```

The alias `center` is a convention used throughout these docs. Use any name you like.

## 4. Try it

```sh
ssh center whoami                                   # which agent and key the gateway sees
ssh center list                                     # servers and roles you may use
ssh center exec web1 --role inspect -- uptime       # run one command
ssh -t center connect web1 --role inspect           # interactive shell (needs -t)
```

When a role needs approval, `exec` and `connect` create a request and wait (2 minutes by default) while an approver
decides. Values with spaces need quoting **inside** the gateway command, so wrap the whole command in single quotes:

```sh
ssh center 'exec web1 --role deploy --reason "Deploy 1.4.3" -- ls /srv/app'
```

<Shot name="agent-terminal" alt="Terminal: list, an auto-approved exec, an exec that waits for approval, and a hidden server" caption="A real session: the deploy command waited for an approver, and the hidden server looks like a missing one" />

## 5. Approve and watch

The request appears on the dashboard and under **Requests**, and in Slack or Telegram if you set them up. After you
approve it, the agent's command continues. Under **Sessions** you can follow the timeline and replay the recording.

Next: the full [agent guide](/agents/) and the [agent skill](/agents/skill) for Claude Code and Codex.
