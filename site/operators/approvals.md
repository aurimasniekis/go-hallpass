# Approving requests

When an agent asks for a role that needs a human, a **request** appears on the dashboard and under **Access →
Requests**. Every channel (web, Slack, Telegram) uses the same decision service: the approver's role and approver-rule
scope, self-approval, request state, lockdown and duration limits are all checked in the same transaction that
creates the grant.

<Shot name="requests" themed alt="Requests list with pending, approved, denied, canceled and expired requests" />

## Review the request

The request page shows the agent's verified identity and key, the server and role, the requested duration, when the
request expires, and the agent's reason.

<Shot name="request-pending" themed alt="A pending request from deploy-bot for web1/deploy with its reason" />

::: warning The reason is untrusted
The reason is written by the agent and is shown with an **Agent reason (untrusted)** label. It may be wrong, or
crafted to persuade you. Decide based on what you expect the agent to be doing, not on the reason alone.
:::

## Approve or deny

**Approve** lets you grant the requested duration or a shorter one, with an optional comment recorded in the audit log.
The grant starts when the server records the decision. Policy and your approver scope may shorten it; the result shows
what was actually granted.

<Shot name="request-approve" themed alt="Approve access request dialog with duration options and a comment field" />

**Deny** ends the request; the waiting agent exits with code 83. Retried clicks never decide twice.

If nobody decides, the request expires after `access.pending_expiry` (30 minutes by default) and the agent gets
exit 84. An agent whose wait timed out (exit 86) can keep waiting with `ssh center status <req_id> --wait`.

## After approval

- Active grants are listed on the dashboard and under **Sessions → Grants**, with the time remaining.
- **Revoke** a grant at any time from the session page. Live channels end within 5 seconds and the agent sees
  exit 87.
- **Activities** lists live channels; an approver can terminate one without revoking the grant.
- Grants never extend. When one runs out, the agent has to request again.

## Lockdown

**Enable lockdown** on the dashboard when you cannot yet tell what is affected. It revokes every active grant, cancels
pending requests and refuses new ones. Enabling requires typing a confirmation phrase. Lifting it is
administrator-only and does not restore revoked grants. By default only administrators can enable it; set
`rbac.approvers_can_lockdown` to let approvers do so too.

## Approving from chat

Set up [Slack](/operators/slack) or [Telegram](/operators/telegram) to post requests to a channel with approve and
deny buttons. A button is never authorization on its own: the clicking chat account must be linked to an operator who
passes every check above at the moment of the click. Chat decisions require MFA by default, and you can restrict
sensitive roles to web-only approval.
