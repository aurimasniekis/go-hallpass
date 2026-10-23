# Slack approvals

Hallpass can post pending access requests to Slack channels. Linked approvers can approve or deny a request with
buttons, and use `/hallpass link <code>` and `/hallpass status <request-id>`. Requirements: HP-NTF-002..005,
HP-NTF-011, PLAN §10.4, ADR-0011.

> **Status.** Implemented and tested end to end against a fake Slack API (`internal/notify` and `internal/notify/slack`
> tests: delivery, escaping, link codes, unlinked users, the chat MFA requirement, approve/deny through the single decision
> service, idempotent redelivery, message updates, signature failures). The webhook path is per integration:
> `<public_url>/hooks/slack/<integration_id>` (shown in the integration settings). Nothing has been **externally verified**
> against a real Slack workspace yet; that evidence is recorded separately (ADR-0035).

## How it works

1. An agent requests access. Hallpass writes one outbox message for each Slack route (channel) that matches the request.
2. The delivery worker posts a Block Kit message with `chat.postMessage`. The message shows the verified agent identity,
   server and role (alias and description), capabilities, the requested duration, the expiry, and the reason. The reason
   is labeled **"Agent-provided reason (untrusted)"** and truncated to 500 characters. The message has one *Approve
   &lt;duration&gt;* button for each allowed duration (up to 5), a *Deny* button, and a *Details* link to the web console.
   It never contains destination addresses, remote usernames or credentials.
3. When someone clicks a button, Slack posts a signed request to Hallpass. Hallpass verifies the request, maps the
   clicking Slack user to a Hallpass operator through a link that operator created earlier, and runs the **same**
   decision checks as the web UI: role, approver scope, self-approval, MFA policy, request state and duration limits.
4. The original message is edited to show the outcome (best effort). The clicking user also gets a short private reply
   that only they can see.

A button click is **never** authorization by itself. Each button carries a single-use, request-bound action token, and
the click counts only if the Slack user is linked to an operator who is allowed to make this decision at the moment of
the click.

## 1. Create the Slack app

Create an app at <https://api.slack.com/apps> → **Create New App** → **From a manifest**, choose your workspace, and
paste the manifest below. Replace `hallpass.example.com` with the host of your `public_url`.

```yaml
display_information:
  name: Hallpass
  description: Access approvals for AI agents
features:
  bot_user:
    display_name: Hallpass
    always_online: false
  slash_commands:
    - command: /hallpass
      url: https://hallpass.example.com/hooks/slack/interactions
      description: Link your Hallpass account or check a request
      usage_hint: "link <code> | status <request-id>"
      should_escape: false
oauth_config:
  scopes:
    bot:
      - chat:write
      - commands
settings:
  interactivity:
    is_enabled: true
    request_url: https://hallpass.example.com/hooks/slack/interactions
  org_deploy_enabled: false
  socket_mode_enabled: false
  token_rotation_enabled: false
```

- **Scopes.** The app needs only `chat:write` (post and edit its own messages) and `commands` (the slash command). Do not
  add other scopes. In particular, Hallpass does not need `chat:write.public`, so the bot can post only to channels it
  has been invited to.
- **One URL.** Interactivity and the slash command use the same endpoint. The handler tells them apart by payload.
- **Single workspace.** Do not distribute the app. Hallpass accepts requests from exactly one team ID and rejects all
  others with `403`.

Then:

1. **Install to Workspace** and copy the **Bot User OAuth Token** (`xoxb-…`).
2. Under **Basic Information → App Credentials**, copy the **Signing Secret**. Do not use the deprecated
   "Verification Token". Hallpass ignores it.
3. Find the **team ID** (`T…`). It appears in the browser URL of the Slack web client
   (`app.slack.com/client/T…/…`) and under *Workspace settings → About this workspace*.

## 2. Prepare approval channels

1. Create a channel for approvals. A private channel is recommended, because every member can read request details,
   including the agent-provided reason.
2. Invite the bot to it: `/invite @Hallpass`.
3. Copy the **channel ID** (`C…`) from *channel details → About* (at the bottom).

Keep channel membership limited to people who should see access requests. Anyone in the channel sees the message, but
only linked, authorized operators can decide.

## 3. Configure Hallpass

Create a Slack integration in the web console (administrator, reauthentication required) with:

| Setting | Value | Notes |
|---|---|---|
| Bot token | `xoxb-…` | Encrypted at rest (AEAD, sealed column). Write-only: it is never shown again or returned by the API. |
| Signing secret | from step 1 | Encrypted at rest. Write-only. |
| Team ID | `T…` | Requests from any other team are rejected. |
| Routes | channel IDs | The channels that receive notifications, optionally filtered by server or role. |

Network requirements:

- **Inbound.** Slack must reach `https://<public_url host>/hooks/slack/interactions` over HTTPS with a publicly trusted
  certificate.
- **Outbound.** Hallpass calls `https://slack.com/api/` and `https://hooks.slack.com/` and must be allowed to reach both.
- **Clock.** The Hallpass host clock must be NTP-synchronized. Requests with timestamps more than 5 minutes away from the
  server clock are rejected with `401`.

## 4. Link approver accounts

A Slack user can decide requests only after the operator links their Slack account (HP-NTF-011):

1. The operator signs in to the web console and creates a **Slack link code** (8 characters, valid for 10 minutes,
   single use, bound to that operator).
2. Within 10 minutes the operator runs `/hallpass link <code>` in Slack. The reply is visible only to them.
3. Hallpass records the team ID and Slack user ID (never the display name) as that operator's Slack identity.

An administrator can also link or unlink accounts manually (audited, reauthentication required). Unlinking takes effect
immediately, and links of disabled operators have no effect. If an unlinked user clicks a button, only they see the reply
"your Slack account is not linked to a Hallpass approver", and nothing is decided.

## 5. What is verified on every request

In this order (PLAN §10.4):

1. The body is at most 64 KiB (`413` otherwise).
2. `X-Slack-Request-Timestamp` is within ±300 s of the server clock (`401` otherwise).
3. `X-Slack-Signature` equals `v0=HMAC-SHA256(signing_secret, "v0:" + timestamp + ":" + body)`, compared in constant
   time (`401` otherwise).
4. The SHA-256 of the decoded signature is stored in the replay cache for 10 minutes. A repeated request is acknowledged
   with `200` and ignored. If the replay cache is unavailable, the request is rejected with `503` (fail closed).
5. The payload must come from the configured team and contain exactly one Hallpass button (`hp1:a:<token>` or
   `hp1:d:<token>`), or must be the `/hallpass` command.

Every rejected request is reported to the audit pipeline (rate limited) and counted in metrics. Rejections never include
request bodies or signatures.

## Message safety

All untrusted text is cleaned and rendered so that it cannot ping, link or format (HP-NTF-003). This covers the reason,
agent, server and role names, descriptions, capabilities and decider names:

- Control characters, bidirectional overrides, zero-width and other invisible characters are removed. Newlines are
  collapsed, so a reason cannot fake extra message lines.
- `&`, `<` and `>` are escaped, so `<!channel>`, `<!here>`, `<@U…>`, `<#C…>` and `<https://…|label>` cannot form.
- Untrusted text is placed only in `plain_text` objects with emoji conversion off. Hallpass never sends untrusted text in
  `mrkdwn` fields. The notification fallback text contains only the request ID.
- Messages are posted with `parse=none`, `link_names=false`, `unfurl_links=false` and `unfurl_media=false`.

## Rotating secrets

- **Signing secret.** *Basic Information → Regenerate*, then update the integration in Hallpass right away. Requests
  signed with the old secret fail with `401` until you do.
- **Bot token.** Reinstall the app or revoke the token (*OAuth & Permissions → Revoke tokens*), then update Hallpass.
  Deliveries fail with `invalid_auth` until the token is updated. They retry with backoff and are then marked **dead**.
  They never approve anything (HP-NTF-010).

Rotate both immediately if you suspect either was exposed.

## What chat approval can and cannot guarantee

**Guaranteed by Hallpass:**

- Only requests signed with your signing secret, fresh, not replayed and from your team are processed.
- A decision is made only for a linked Slack user whose operator passes the full decision check at click time. Possession
  of a button or action token is never enough.
- Each action token is single use, bound to its request, action, duration and provider, and expires with the request.
- Duplicate clicks return the original outcome. Delivery failures never approve.

**Not guaranteed:**

- **Slack account security.** Hallpass trusts Slack to authenticate the person clicking. A compromised Slack account
  that is linked to an approver can approve within that approver's scope. Enforce SSO and 2FA in Slack. For sensitive
  roles, use the per-role `approval_channels` restriction (web only) and the "recent web MFA" requirement (DECISIONS
  R-10).
- **Signing-secret confidentiality.** Anyone who holds the signing secret can forge requests and **claim any Slack user
  ID**, which includes a linked approver's. They still need a valid, unused action token, and the request must still
  pass the decision checks for that operator. Protect and rotate the secret like an approval credential.
- **Confidentiality of notification content.** Every channel member sees the agent identity, server and role aliases,
  and the reason. Addresses, usernames and credentials are never included.
- **Message updates.** Edits that show the outcome are best effort. The web console is authoritative.
- **Rendering on real Slack clients.** This is covered by automated tests against a fake API. It still needs manual
  verification in a real workspace (externally verified evidence, WP17).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Buttons show a warning triangle, and Hallpass logs `bad_signature` or `stale_timestamp` | Wrong signing secret, or clock skew on the Hallpass host. |
| `403` / `wrong_workspace` | The team ID in Hallpass does not match the workspace. |
| Deliveries go **dead** with `channel_not_found` / `not_in_channel` | The bot was not invited, or the route has the wrong channel ID. |
| Deliveries retry with `rate limited` | Slack rate limiting. Hallpass honors `Retry-After` and retries. |
| "not linked to a Hallpass approver" | The user has not completed `/hallpass link`, or the link was removed or the operator disabled. |
