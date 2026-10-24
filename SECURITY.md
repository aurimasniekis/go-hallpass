# Security policy

HallPass is a security-sensitive gateway that can see plaintext SSH sessions. Please report vulnerabilities privately.

## Reporting

- Use GitHub's private vulnerability reporting: "Report a vulnerability" on the repository's
  [Security tab](https://github.com/aurimasniekis/go-hallpass/security/advisories/new).
- Do not open public issues for suspected vulnerabilities.
- Include affected versions, configuration, reproduction steps and impact. Never include real credentials, KEKs,
  recordings or production data.

We aim to acknowledge reports within 3 working days and to agree on a disclosure date with you. Fixes ship for the
latest minor release line ([docs/VERSIONING.md](docs/VERSIONING.md)).

## Scope and guarantees

What HallPass does and does not guarantee is documented in [docs/GOAL.md](docs/GOAL.md) (security guarantees and
non-guarantees) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) (assets, trust boundaries, residual risks). In
particular:

- A compromised gateway host that holds the KEK can read recordings and rewrite unanchored history. Export integrity
  anchors to external append-only storage ([docs/operator/backup.md](docs/operator/backup.md)).
- Destination-side commands run in the destination's shell; HallPass records but does not sandbox them.
- The HPREC1 recording format has **not** had an external cryptographic review yet (DECISIONS.md R-02).

## Hardening references

- Deployment and KEK handling: [docs/operator/install.md](docs/operator/install.md)
- Destination hardening: [docs/destination/hardening.md](docs/destination/hardening.md)
- Agent client configuration and host-key pinning: [docs/agent/guide.md](docs/agent/guide.md)
