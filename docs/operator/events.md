# Events (Pulse)

HallPass can publish what happens to [Pulse](https://github.com/aurimasniekis/go-pulse), an event bus on NATS
JetStream, so other systems can react to requests, approvals, sign-ins, configuration changes and agent sessions. It
is off by default.

## What is published

| Subject | Published for | Payload |
|---|---|---|
| `evt.hallpass.<action>` | Every audit event, for example `evt.hallpass.request.created`, `evt.hallpass.request.approved`, `evt.hallpass.grant.revoked`, `evt.hallpass.operator.login`, `evt.hallpass.server.updated`, `evt.hallpass.policy.rule.created`. The action is the one shown on the console's audit page. | The audit record |
| `evt.hallpass.session.<event>` | Agent and web-terminal sessions: `connection.opened`, `connection.closed`, `channel.opened`, `channel.exited`, `channel.failed`, `exec.requested`, `git.requested`, `git.push`, `git.push_refused`, `git.transferred`, `file.summary`, `recording.failed`, and `closed` when the session ends. | The session event |

Subscribe to `evt.hallpass.>` for everything. Each event carries CloudEvents headers:

- `Nats-Msg-Id`: the event ID, which is also the payload's `id`. A retry publishes the same ID, so JetStream drops the
  duplicate and consumers can deduplicate on it.
- `ce-type`: `hallpass.<action>.v1`, for example `hallpass.request.created.v1` or `hallpass.session.channel.opened.v1`.
- `ce-source`: `events.pulse.source` (default `hallpass`).
- `ce-time`: when the event happened.

An action with a single word is published as `evt.hallpass.<word>.recorded`.

### Audit record

The same JSON object `log.audit_file` writes. `at` is Unix microseconds.

```json
{
  "id": "aud_01JB6Q…", "seq": 1842, "at": 1793023200123456,
  "actor_type": "operator", "actor_id": "opr_01JB…",
  "action": "request.approved", "target_type": "request", "target_id": "req_01JB…",
  "outcome": "success", "source_ip": "203.0.113.7", "correlation_id": "4bf92f35…",
  "details": {"decision_id": "dec_01JB…", "channel": "web", "duration": "1h0m0s",
              "agent_id": "agt_01JB…", "server_id": "srv_01JB…", "role_id": "rol_01JB…"},
  "has_sensitive": true
}
```

Details that HallPass keeps encrypted (for example request reasons and revocation notes) are **never** published;
`has_sensitive` only says that some exist.

### Session event

```json
{
  "id": "evt_01JB6R…", "type": "channel.exited", "at": 1793023260000000,
  "session_id": "ses_01JB…", "grant_id": "grt_01JB…",
  "agent_id": "agt_01JB…", "server_id": "srv_01JB…", "role_id": "rol_01JB…",
  "connection_id": "con_01JB…", "channel_id": "chn_01JB…",
  "data": {"reason": "exit_status", "exit_status": 0}
}
```

`operator_id` is set for web terminals. `data` is what the session timeline shows: the kind of channel, exit status,
git service and repository, file transfer totals and so on. Command text, terminal content and file contents are never
published (`exec.requested` carries only `has_command` and the command's length). Request and grant events are
published once, from the audit log, not again as session events. Single file operations and records from destination
audit collectors are not published.

## Delivery

- An event is written to an outbox in the same database transaction as the change it describes, so it is published
  if and only if the change happened.
- A background relay publishes events in batches and waits for JetStream to acknowledge each one.
- **Pulse being down never blocks HallPass.** Events wait in the outbox and are published when Pulse is reachable
  again. A failed publish is retried with exponential backoff (1 s doubling to at most 5 minutes). An event is
  dead-lettered after 50 failed attempts or 24 hours; it then stays in the database, unpublished, for 7 days.
- Order is mostly preserved, but after a retry a later event can arrive before an earlier one. Use `at` (and `seq` for
  audit records) to order them.
- Only events recorded while publishing is enabled are published. Turning it on does not replay older history; the
  audit log in HallPass stays the complete record.
- Outbox rows are deleted 7 days after they were written, published or not.

## Setup

1. In Pulse, create a client for HallPass with the grant `publish:evt.hallpass.>` and download its `.creds` file.
2. Put the file on the HallPass host, readable only by the HallPass user, for example
   `/etc/hallpass/pulse.creds` with mode `0400`.
3. Configure HallPass and restart it:

```yaml
events:
  pulse:
    enabled: true
    url: tls://events.example.com:4222
    creds_file: /etc/hallpass/pulse.creds
    # ca_file: /etc/hallpass/pulse-ca.pem   # only if the NATS certificate is not from a public CA
    # source: hallpass.example.com          # CloudEvents source, default "hallpass"
```

| Key | Default | Meaning |
|---|---|---|
| `events.pulse.enabled` | `false` | Publish events to Pulse. |
| `events.pulse.url` | — | Pulse NATS endpoint. Production requires `tls://`; `nats://` is accepted in development mode only. |
| `events.pulse.creds_file` | — | The Pulse client `.creds` file (required when enabled). |
| `events.pulse.ca_file` | — | Extra CA to trust for the NATS TLS certificate. Empty uses the system roots. |
| `events.pulse.source` | `hallpass` | CloudEvents `ce-source` of published events. |

Each key can also be set from the environment, for example `HALLPASS_EVENTS_PULSE_URL`.

HallPass connects out to Pulse (TCP 4222 by default); nothing connects in. If Pulse cannot be reached at startup,
HallPass logs a warning and tries again every 30 seconds.

## Monitoring

| Metric | Meaning |
|---|---|
| `hallpass_events_publish_total{outcome}` | Publish attempts: `published`, `retry`, `dead`. |
| `hallpass_events_pending` | Events waiting to be published. A growing value means Pulse is unreachable or rejects HallPass. |
| `hallpass_events_dead` | Events dead-lettered in the last 7 days. |

Losing the connection to Pulse is logged as a warning (`event relay disconnected from Pulse`) and getting it back at
info level. Dead-lettered events are logged at error level (`event dead-lettered`, with the event ID and type).

## Security

Published events contain the same information as the audit file: identifiers, actions, outcomes, operator and agent
source IP addresses, and the plaintext audit details. Anyone who can subscribe to `evt.hallpass.>` in Pulse sees them,
so restrict that permission as you would access to the audit log. Nothing HallPass stores encrypted is published, and
Pulse cannot change anything in HallPass: the connection only publishes.
