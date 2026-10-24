# FAQ

### Is Hallpass ready for production?

No. It is pre-release: no version has been tagged and the release gates are not met. See the
[security model](/security/#release-status).

### Can the agent see the server's IP address or credentials?

Not from Hallpass. Agents see aliases, role names and descriptions only, and Hallpass logs in with credentials it keeps
to itself. But once a shell is open, the destination can print anything it knows, including its own IP addresses or
application secrets. Hallpass does not redact session content.

### Does Hallpass restrict which commands an agent may run?

No. Capabilities choose between shell, exec and PTY, not commands. Command allowlists are easy to escape, so Hallpass
does not pretend to offer them. Restrict commands on the destination: a dedicated account per role, `command=` in
`authorized_keys`, `ForceCommand`, narrow `sudoers`. See [destination hardening](/destinations/hardening).

### Why does `ssh center connect web1` just hang?

It is waiting for input. Without `ssh -t` there is no terminal, so you get a non-interactive shell with no prompt. Use
`ssh -t center connect web1`, or `exec` for single commands.

### Why are errors printed as JSON?

The gateway prints errors as one `hallpass.error/v1` JSON line when you pass `--json` or when it sees no terminal,
which is the case for any command run without `ssh -t`. That makes them easy for agents to parse. With `ssh -t`, you
get a plain `hallpass: …` message.

### Why does `--reason "two words"` fail with exit 81?

ssh joins its arguments with spaces, so the gateway receives `--reason two words`. Wrap the whole gateway command in
single quotes: `ssh center 'request web1 --reason "two words"'`.

### Does reconnecting extend my access?

No. A grant runs from approval for its duration. Reconnecting, new channels and new requests for an active grant never
extend it.

### What happens to my running command when the grant expires?

The gateway ends the channel within 5 seconds and the command exits with 87. Processes the command detached on the
destination (`nohup`, tmux) may keep running unless the destination prevents it.

### Can I use `scp`, `sftp`, `rsync` or port forwarding?

No. SFTP and SCP subsystems, port forwarding, agent forwarding and X11 are refused and audited. Possible future support
would be a separately authorized capability.

### Can operators approve their own agent's requests?

Not by default: owners of the requesting agent cannot approve its requests. Every approver also needs an approver rule
that covers the server and role. Administrators have no implicit approval authority.

### What if Slack or Telegram is down?

Nothing changes for the request. It stays pending until someone decides in the web console, or it expires. A failed
notification never approves anything.

### Does Hallpass support Windows destinations?

Not in v1. Command encoding assumes POSIX shells.

### Can I run two Hallpass instances for high availability?

No. One active instance per data directory, and the data directory must be on a local filesystem. Recovery is a
restore onto a cold standby. See [Backup and restore](/operators/backup).

### What if I lose the KEK?

Encrypted data (credentials, recordings, sensitive fields) is unrecoverable, by design. Keep at least two offline
copies, separately from data backups. See [Keys and the KEK](/operators/keys).

### What is the license?

Hallpass is licensed under the Apache License 2.0.
