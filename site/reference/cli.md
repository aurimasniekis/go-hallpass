# Server CLI

The `hallpass` binary runs the gateway and its maintenance commands. Every command that reads the configuration takes
`--config PATH` (or `HALLPASS_CONFIG`). `hallpass <command> -h` prints the flags of each command.

::: tip Online and offline commands
**Offline** commands take the data-directory lock and refuse to run while `hallpass serve` is running: stop the
service first. `backup create`, `backup verify`, `anchors export`, `config` and `version` are safe while it runs.
:::

## Running

| Command | Purpose |
|---|---|
| `hallpass serve` | Run the gateway: agent SSH front end, web console and API, background workers. Applies pending migrations at startup. |
| `hallpass migrate` | Apply pending database migrations (offline). Prints `database schema at version N (binary supports N)`. |
| `hallpass version [--json]` | Print version information. |

## Configuration

| Command | Purpose |
|---|---|
| `hallpass config check` | Load and validate the configuration. |
| `hallpass config env` | List every supported `HALLPASS_*` environment override. |

## First administrator and break-glass

| Command | Purpose |
|---|---|
| `hallpass admin bootstrap` | Issue the one-time setup link for the first administrator (offline; 30 minutes; refused once an administrator exists). |
| `hallpass admin recover --email EMAIL` | Break-glass: issue a single-use, 30-minute recovery login for an existing operator, re-enabling it if disabled (offline; audited). |
| `hallpass admin recover --email EMAIL --new-admin` | Break-glass: create a new local administrator and issue its recovery login. |

Open the printed `/recover?token=…` link to use it; see
[the runbook](/operators/incidents#locked-out-of-administration).

## Keys

| Command | Purpose |
|---|---|
| `hallpass keys init-kek --out FILE` | Generate a new master key file (mode `0400`; refuses to overwrite). |
| `hallpass keys status [--json]` | Show the KEK ID and purpose-key versions (offline). |
| `hallpass keys rotate --purpose P` | Rotate a purpose key: `field`, `credential`, `recording`, `manifest` or `token` (offline). |
| `hallpass keys retire --purpose P --version N` | Retire a decrypt-only purpose-key version once nothing uses it (offline). |
| `hallpass keys rotate-kek --new FILE` | Rewrap every key under a new KEK (offline; back up first). |

## Gateway host key

| Command | Purpose |
|---|---|
| `hallpass hostkey show [--host center] [--json]` | Print host key fingerprints and `known_hosts` lines (offline). `--host` sets the name used in the lines. |
| `hallpass hostkey stage [--algorithm A]` | Generate the next host key to serve alongside the active one. `ecdsa-sha2-nistp256` (default) or `ssh-ed25519`; must differ from the active key. |
| `hallpass hostkey promote` | Make the staged key active. |

## Backup, restore and verification

| Command | Purpose |
|---|---|
| `hallpass backup create --out DIR [--json]` | Write a consistent backup (database snapshot, recordings, manifest) to a new directory. Online. |
| `hallpass backup verify DIR [--json]` | Check a backup without restoring it. Needs no KEK. |
| `hallpass restore [--data DIR] [--force] BACKUP` | Restore into an empty data directory (offline; needs the KEK). `--force` moves existing data aside. |
| `hallpass verify [--session ID] [--json]` | Verify recording segments and the integrity chain (offline). |
| `hallpass anchors export [--since SEQ] [--out FILE]` | Print integrity-chain heads after `SEQ` as JSON lines for append-only storage. Online. |
| `hallpass anchors verify [--json] FILE` | Compare exported anchors (`FILE`, or `-` for stdin) with the local chain. |

`backup`, `restore` and `verify` exit with `0` (ok), `1` (error), `2` (usage) or `3` (written with problems, or
verification failed). `anchors verify` exits `3` on any mismatch.

## Destination audit collector

`hallpass-collector` is a separate binary that runs on destinations: `keygen`, `pubkey`, `run`, `version`. See
[destination-side audit](/destinations/audit).
