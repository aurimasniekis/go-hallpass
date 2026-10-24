# Contributing to HallPass

HallPass is a security-sensitive SSH access gateway. Read [docs/security-guarantees.md](docs/security-guarantees.md)
before changing anything: a change must never weaken a guarantee, default or check silently. If it relaxes one, say so
explicitly in the pull request and the CHANGELOG `Security` section, and explain why.

> License: Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Contributions are accepted under the same license.

## Development setup

- Go: the version in `go.mod` (latest stable). With `GOTOOLCHAIN=auto` (the default) an older local Go downloads it automatically.
- `golangci-lint` v2.
- Node 24 LTS with pnpm, for the web UI.
- Docker, for the OpenSSH and OIDC interop suites and the screenshot generator.

## Everyday commands

| Command | What it does |
|---|---|
| `make build` | Static (`CGO_ENABLED=0`) build into `bin/hallpass`. |
| `make race` | All Go tests with the race detector. |
| `make lint` | golangci-lint with the repository configuration. |
| `make custom-vet` | HallPass analyzers: `nohostkeyignore` (bans `ssh.InsecureIgnoreHostKey`) and `txscope` (no I/O or waits inside store write transactions). |
| `make coverage` | Coverage floor (≥ 80%) for security-critical packages. |
| `make fuzz-smoke` | Every fuzz target for `FUZZTIME` (default 30 s). |
| `make check` | Everything CI runs for Go. |

## Rules

- Tests accompany every change. Security controls get negative tests (prove the forbidden thing fails).
- Never commit secrets, real infrastructure details or secret-bearing fixtures. Generate test keys at test time.
- Never use `ssh.InsecureIgnoreHostKey`, `math/rand`, or unauthenticated encryption.
- Keep write transactions short. No network, SSH, file fsync or waits inside `store.Writer.Tx`.
- Commits follow Conventional Commits.
- User-facing changes get a CHANGELOG entry under `[Unreleased]`.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Report privately; do not open public issues.
