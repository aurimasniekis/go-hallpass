# Contributing to Hallpass

Hallpass is a security-sensitive SSH access gateway. Read [`AGENTS.md`](AGENTS.md), [`docs/GOAL.md`](docs/GOAL.md) and
[`docs/PLAN.md`](docs/PLAN.md) before changing anything. GOAL.md is the product contract, and security requirements are never weakened
without a recorded decision in [`docs/DECISIONS.md`](docs/DECISIONS.md).

> License: Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Contributions are accepted under the same license.

## Development setup

- Go: the version in `go.mod` (latest stable). With `GOTOOLCHAIN=auto` (the default) an older local Go downloads it automatically.
- `golangci-lint` v2.
- Node 24 LTS with pnpm, for the web UI (once it lands in WP19).
- Docker, for the OpenSSH interop and E2E suites (once they land in WP10/WP19).

## Everyday commands

| Command | What it does |
|---|---|
| `make build` | Static (`CGO_ENABLED=0`) build into `bin/hallpass`. |
| `make race` | All Go tests with the race detector. |
| `make lint` | golangci-lint with the repository configuration. |
| `make custom-vet` | Hallpass analyzers: `nohostkeyignore` (bans `ssh.InsecureIgnoreHostKey`) and `txscope` (no I/O or waits inside store write transactions). |
| `make coverage` | Coverage floor (≥ 80%) for security-critical packages. |
| `make fuzz-smoke` | Every fuzz target for `FUZZTIME` (default 30 s). |
| `make check` | Everything CI runs for Go. |

## Rules

- Tests accompany every change. Security controls get negative tests (prove the forbidden thing fails).
- Never commit secrets, real infrastructure details or secret-bearing fixtures. Generate test keys at test time.
- Never use `ssh.InsecureIgnoreHostKey`, `math/rand`, or unauthenticated encryption.
- Keep write transactions short. No network, SSH, file fsync or waits inside `store.Writer.Tx`.
- Commits follow Conventional Commits. Agents commit locally per work package and never push (see AGENTS.md).
- Update PLAN.md progress and DECISIONS.md with every work package.

## Reporting security issues

See `SECURITY.md` (added in WP24). Until then, report privately to the repository owner. Do not open public issues.
