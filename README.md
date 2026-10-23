# Hallpass

Hallpass is a terminating SSH gateway for AI agents. Agents connect to Hallpass with their own key. Hallpass decides,
from policy and human approvals, which servers and roles they may use, then opens the destination session itself
with credentials the agent never sees. Every session is recorded and encrypted at rest.

```
agent ──ssh (agent key)──▶ Hallpass ──ssh (managed key or short-lived certificate)──▶ destination
                              │
                    policy · approvals (web, Slack, Telegram) · grants · encrypted recordings · audit chain
```

> **Status: pre-release, not production-ready.** No version has been tagged. The release gates in
> [docs/GOAL.md](docs/GOAL.md) §8 are not yet met: no 24-hour soak, no external crypto review of the recording
> format (R-02), no CI run on GitHub, and no license chosen (R-01). Per-requirement status, including what is only
> implemented versus tested, is in [docs/PLAN.md](docs/PLAN.md) §21.

## What it does

- **Agent identity from keys:** agents authenticate with registered public keys. The SSH username is ignored. Unknown
  and hidden servers are indistinguishable.
- **Policy and approvals:** default-deny rules decide what each agent can see, request or get automatically. Requests
  carry a reason. Operators approve or deny in the web console, Slack or Telegram. A chat button is never
  authorization on its own: the approver is re-checked when the decision is made.
- **Time-bound grants:** grants never extend implicitly. Expiry, revocation, key revocation, agent or server
  disablement and lockdown end live sessions within 5 seconds.
- **Credential isolation:** Hallpass generates and keeps the destination login keys (or signs short-lived OpenSSH
  certificates). Destination host keys are verified strictly; there is no trust on first use.
- **Recording:** recording is mandatory by default and fails closed. Recordings are encrypted per segment (HPREC1) and
  integrity-chained, can be replayed in the browser, and can be exported as an encrypted bundle.
- **Operators:** local accounts with Argon2id and TOTP, or generic OIDC SSO. Roles are administrator, approver,
  auditor and viewer, and sensitive actions require recent authentication.
- **Operations:** a single Go binary with an embedded web UI and SQLite storage. It provides backup/restore,
  integrity anchors, Prometheus metrics, health endpoints and optional OpenTelemetry tracing.

Read [docs/security-guarantees.md](docs/security-guarantees.md) before deploying: Hallpass can see every session in
plaintext and must be run like a bastion host.

## Quick look

An agent's `~/.ssh/config` pins the gateway's host key and points at the gateway:

```
Host center
  HostName hallpass.example.net
  Port 2222
  IdentityFile ~/.ssh/agent_ed25519
  IdentitiesOnly yes
  StrictHostKeyChecking yes
```

```sh
ssh center list                                              # servers and roles this agent may use
ssh center request web1 --role inspect --reason "disk alert" --duration 30m
ssh center exec web1 --role inspect -- df -h /var           # waits for approval if needed
ssh -t center connect web1 --role inspect                   # interactive shell
```

See the [agent guide](docs/agent/guide.md) for the full grammar, JSON output and exit codes.

## Running it

```sh
hallpass keys init-kek --out /etc/hallpass/kek    # master key (0400); back it up separately from the data
hallpass migrate --config /etc/hallpass/hallpass.yaml
hallpass serve --config /etc/hallpass/hallpass.yaml
hallpass admin bootstrap --config /etc/hallpass/hallpass.yaml   # one-time setup link for the first administrator
```

The [install guide](docs/operator/install.md) covers systemd, the container image and [Docker Compose](deploy/compose.yaml).
The web console listens on port 8080 and must sit behind a TLS reverse proxy. Agents connect on port 2222.

## Building from source

Requirements: Go 1.27 or later. Node 24 and pnpm are needed only for the web UI.

```sh
make build                                      # bin/hallpass and bin/hallpass-collector (no embedded UI)
(cd web && pnpm install && pnpm build)          # then build with the UI embedded:
go build -tags embedui -o bin/hallpass ./cmd/hallpass
```

Checks used before every commit:

```sh
make lint custom-vet race coverage sqlc-check api-check
(cd web && pnpm lint && pnpm typecheck && pnpm test)
make test-openssh        # real OpenSSH client and sshd (needs Docker)
make test-fault          # fault-injection catalog
make fuzz-smoke          # every fuzz target briefly
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and commit rules.

## Documentation

| Topic | Where |
|---|---|
| Product contract, requirements, release gates | [docs/GOAL.md](docs/GOAL.md) |
| Architecture, work packages, progress | [docs/PLAN.md](docs/PLAN.md) |
| Decisions and open review items | [docs/DECISIONS.md](docs/DECISIONS.md) |
| Threat model / guarantees | [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/security-guarantees.md](docs/security-guarantees.md) |
| Operator guides (install, keys, backup, SSO, approvals, incidents) | [docs/operator/](docs/operator/) |
| Agent guide | [docs/agent/guide.md](docs/agent/guide.md) |
| Destination hardening, destination-side audit | [docs/destination/](docs/destination/) |
| Recording format | [docs/formats/hprec1.md](docs/formats/hprec1.md) |
| Versioning, changelog | [docs/VERSIONING.md](docs/VERSIONING.md), [CHANGELOG.md](CHANGELOG.md) |

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

No license has been chosen yet (review item R-01).
