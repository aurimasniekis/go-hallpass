---
layout: home

hero:
  name: HallPass
  text: SSH access for AI agents, on your terms
  tagline: >-
    Agents connect with their own key. Policy and a human decide what they get, for how long. HallPass logs in to
    your servers with credentials the agent never sees, and records every session.
  image:
    src: /logo.svg
    alt: HallPass
  actions:
    - theme: brand
      text: Get started
      link: /guide/what-is-hallpass
    - theme: alt
      text: Install
      link: /guide/install-docker
    - theme: alt
      text: Agent guide
      link: /agents/

features:
  - title: Agents never hold server credentials
    details: >-
      An agent only has its own SSH key, registered with HallPass. HallPass keeps the destination login keys
      (or signs short-lived OpenSSH certificates) and verifies every destination host key. No trust on first use.
  - title: Default-deny policy with human approval
    details: >-
      Rules decide what each agent can see, request or get automatically. Requests carry a reason. Approvers decide in
      the web console, Slack or Telegram, and are re-checked when they click.
  - title: Access that ends on time
    details: >-
      Grants are time-bound and never extend on reconnect. Expiry, revocation, a disabled agent or a lockdown end live
      gateway sessions within 5 seconds.
  - title: Every session recorded and replayable
    details: >-
      Recording is on by default and fails closed. Recordings are encrypted per segment and integrity-chained. Replay
      them in the browser, next to a timeline of what happened.
  - title: One binary, one database
    details: >-
      A single Go binary with an embedded web UI and SQLite storage. Backup, restore, integrity anchors, Prometheus
      metrics, health checks and optional OpenTelemetry tracing.
  - title: Honest about its limits
    details: >-
      HallPass sees every session in plaintext and is not a sandbox. The security page says exactly what it does and
      does not guarantee, and what is only implemented versus tested.
---

<div class="hp-home">

<div class="hp-status">

**Pre-release.** No version has been tagged and the release gates are not met yet. Read the
[security model](/security/) before you run HallPass anywhere that matters.

</div>

## How it works

<Flow />

1. You register an agent's **public key** and enroll your servers, each with one or more **roles** (a remote account
   plus what the role allows).
2. The agent runs ordinary `ssh` against HallPass: `ssh center list`, `ssh center exec web1 -- uptime`.
3. Policy decides: the role is hidden, requestable (a human approves), or approved automatically up to a limit.
4. HallPass opens the destination session itself, records it, and ends it when the grant ends.

## See it

<Shot name="dashboard" themed alt="HallPass dashboard with pending requests, active grants and a live session" caption="Dashboard: pending requests, active grants and live sessions" />

<div class="hp-gallery">
<Shot name="request-pending" themed alt="A pending access request with the agent's untrusted reason" caption="A request waiting for approval" />
<Shot name="session-replay" themed alt="Replay of a recorded interactive shell in the browser" caption="Replay of a recorded shell" />
<Shot name="session-timeline" themed alt="Timeline of an access session" caption="Session timeline" />
<Shot name="policy-effective" themed alt="Effective access preview for one agent" caption="Effective access preview" />
</div>

<Shot name="agent-terminal" alt="An agent listing servers, running a command and waiting for approval over SSH" caption="What the agent sees: plain ssh" />

## Where to go next

- New here? Read [What is HallPass?](/guide/what-is-hallpass) and the [concepts](/guide/concepts).
- Ready to install? [Docker Compose](/guide/install-docker) or [the binary with systemd](/guide/install-binary).
- Setting up an agent? The [agent guide](/agents/) and the [agent skill](/agents/skill).

</div>
