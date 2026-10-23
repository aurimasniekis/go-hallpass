# Approvals and notifications

Agents request access over SSH. Approvers decide in the web UI (`/requests`) or from Slack or Telegram. Every channel
uses the same decision service, so role, approver-rule scope, self-approval, request state, lockdown and duration limits
are checked in the same transaction that creates the grant (HP-NTF-008).

## Web approvals

The request page shows the agent's verified identity, the server and role, the capabilities, the agent's reason (marked
untrusted), the expiry and the allowed durations. Approve and deny accept an `Idempotency-Key`, so a retried click
never decides twice.

## Chat approvals

1. Create an integration (**Settings → Integrations**, administrator, recent authentication):
   - Slack: [slack.md](slack.md).
   - Telegram: [telegram.md](telegram.md).
   Secrets are encrypted at rest and write-only.
2. Add **notification routes**: a destination (Slack channel ID, Telegram chat ID) plus a target selector (all servers,
   servers, groups or labels). An empty selector matches nothing.
3. Each approver links their chat account. In **Me → Chat accounts**, create a link code (single use, 10 minutes) and
   send it to the bot:
   - Slack: `/hallpass link <code>`.
   - Telegram: `/link <code>` in a **private** chat with the bot. A code posted in a group is burned.
   Administrators can also link accounts directly (audited).
4. Chat decisions require MFA by default: the approver has TOTP enrolled in Hallpass, or a linked SSO identity whose IdP
   enforces MFA (R-10). Restrict sensitive roles to web-only approval with the role's `approval_channels`.

For each pending request, each matching route gets one message with up to five approve buttons (allowed durations,
smallest first) and a deny button. Each button carries a single-use action token. Hallpass stores only a keyed hash of
the token, bound to the request, the action and the provider, and the token expires with the request.

Pressing a button still requires a linked, enabled operator who passes every decision check. Possession of a button is
never enough (HP-NTF-007). A repeated press returns the recorded outcome (HP-NTF-009). Once a request is decided,
canceled or expires, the messages are edited to show the outcome.

## Delivery and failures

Messages go through the durable outbox:
- up to 8 attempts with exponential backoff, then a `dead` state;
- delivery history under **Settings → Integrations → Deliveries** (`GET /api/v1/notification-deliveries`);
- dead letters are counted in the `hallpass_outbox_dead` metric.

A failed notification never approves anything. The request stays pending until it is decided, canceled or expires
(HP-NTF-010).

## Security notes

- Webhooks live under `/hooks/{slack|telegram}/<integration_id>` and use no cookies. They are rate limited to 20
  requests/s per integration, and each request is verified (Slack HMAC with timestamp and replay cache; Telegram secret
  token, chat allowlist and `update_id` replay) before anything is parsed.
- Someone holding the Slack signing secret or the Telegram webhook secret can forge callbacks that claim any user ID.
  Treat these secrets like credentials and rotate them if exposed. Use web-only approval for sensitive roles
  (THREAT_MODEL T-05, ADR-0035).
