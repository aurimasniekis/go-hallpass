# Events (Pulse)

HallPass can publish what happens to [Pulse](https://github.com/aurimasniekis/go-pulse), an event bus on NATS
JetStream, so other systems can react to requests, approvals, sign-ins, configuration changes and agent sessions.
Publishing is off by default. Reference:
[events.md](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/operator/events.md).

## What is published

| Subject | Published for |
|---|---|
| `evt.hallpass.<action>` | Every audit event, for example `evt.hallpass.request.created`, `evt.hallpass.request.approved`, `evt.hallpass.grant.revoked`, `evt.hallpass.operator.login`, `evt.hallpass.server.updated`. The action is the one shown on the console's audit page. |
| `evt.hallpass.session.<event>` | Agent and web-terminal sessions: connections opened and closed, channels opened, exited and failed, exec, git and file-transfer summaries, recording failures, and `closed` when the session ends. |

Subscribe to `evt.hallpass.>` for everything. Each event has a stable ID (`Nats-Msg-Id`, also the payload's `id`) that
consumers can deduplicate on, a CloudEvents type such as `hallpass.request.created.v1`, and the source set in
`events.pulse.source`.

- **Audit events** carry the audit record: who did what to which object, the outcome, the source IP address and the
  plaintext details. Details HallPass keeps encrypted, such as request reasons, are never published.
- **Session events** carry the session, grant, agent, server and role, plus what the session timeline shows: channel
  kind, exit status, git repository, transfer totals. Command text, terminal content and file contents are never
  published.

## Delivery

Events are written in the same database transaction as the change they describe, then published by a background relay
that waits for JetStream to acknowledge each one. **Pulse being down never blocks HallPass**: events wait and are sent
when Pulse is back, retrying with backoff for up to 24 hours. Only events recorded while publishing is on are sent;
turning it on does not replay older history.

## Set up

1. In Pulse, create a client for HallPass with the grant `publish:evt.hallpass.>` and download its `.creds` file.
2. Put it on the HallPass host, readable only by the HallPass user, for example `/etc/hallpass/pulse.creds` with mode
   `0400`.
3. Add this to the configuration and restart HallPass:

```yaml
events:
  pulse:
    enabled: true
    url: tls://events.example.com:4222
    creds_file: /etc/hallpass/pulse.creds
```

`events.pulse.ca_file` trusts an extra CA when the NATS certificate is not from a public CA, and `events.pulse.source`
sets the CloudEvents source (default `hallpass`). Production requires a `tls://` URL. HallPass only connects out to
Pulse (TCP 4222 by default) and only publishes.

## Monitoring

`hallpass_events_pending` counts events waiting to be published; if it keeps growing, Pulse is unreachable or refuses
HallPass's credentials. `hallpass_events_dead` counts events given up on, and each one is also logged as
`event dead-lettered`.

Anyone who can read `evt.hallpass.>` in Pulse sees the same information as the audit log, so grant that permission as
carefully as access to the audit log.
