# Telegram approvals

HallPass can post pending access requests to Telegram groups through a bot. Linked approvers decide with inline
buttons.

> **Status.** Implemented and tested end to end against a fake Bot API (`internal/notify` and `internal/notify/telegram`
> tests: secret token, chat allowlist, unlinked users, approve through the single decision service, `update_id` replay,
> link codes burned in group chats). The webhook path is `<public_url>/hooks/telegram/<integration_id>`; saving an enabled
> integration calls `setWebhook`. Nothing has been **externally verified** against a real bot yet.

## How it works

1. For each Telegram route (an allowlisted chat) that matches a pending request, HallPass sends a plain-text message
   (no `parse_mode`) with link previews disabled. The message shows the verified agent identity, server and role,
   capabilities, the requested duration, the expiry, and the reason. The reason is labeled **"Agent-provided reason
   (untrusted)"** and truncated to 500 characters. Under the message are inline buttons: *Approve &lt;duration&gt;*
   (up to 5) and *Deny*. The message never contains destination addresses, remote usernames or credentials.
2. Each button's `callback_data` is only `hp1:<a|d>:<action-token-id>` (28 bytes, at most 64).
3. When someone presses a button, Telegram delivers an update to the HallPass webhook. HallPass checks the secret
   token, the replay cache, and both allowlists. It then maps the Telegram user to an operator and runs the **same**
   decision checks as the web UI.
4. HallPass always answers the button press (a short toast) and edits the message to show the outcome (best effort).

Pressing a button is **never** authorization by itself. See "What chat approval can and cannot guarantee" below.

## 1. Create the bot

In a chat with [@BotFather](https://t.me/BotFather):

1. `/newbot`. Choose a name and a username, then copy the **bot token** (`123456789:AA…`). The number before the colon
   is the **bot ID**. HallPass uses it as the workspace in account links.
2. `/setprivacy` → **Enable**. With privacy mode on, the bot receives only commands and button presses in groups, not
   ordinary chatter.
3. `/setcommands` → `link - Link your Telegram account to HallPass`.
4. After you add the bot to your approval groups (step 2), run `/setjoingroups` → **Disable**. This stops anyone else from
   adding the bot to other groups.

Treat the bot token as an approval credential. Do not paste it into chats, tickets or shell history.

## 2. Prepare approval groups

1. Create a private group for approvals, add the bot, and keep membership limited. Every member can read the request
   details.
2. Find the group's **chat ID**. Supergroup IDs look like `-100…`. Once the integration is configured, the easiest way
   is to send `/start` in the group. HallPass ignores it, but records the rejected update in the audit log together with
   the chat ID. You can also read the ID from the group info screen in Telegram
   clients that display it.

## 3. Configure HallPass

Create a Telegram integration in the web console (administrator, reauthentication required):

| Setting | Value | Notes |
|---|---|---|
| Bot token | from BotFather | Encrypted at rest. Write-only. It appears only in the Bot API URL path and is redacted from errors and logs. |
| Allowed chat IDs | `-100…` | Routes. Button presses from any other chat are ignored and audited. |
| Webhook secret | generated | 32 random bytes, base64url (43 characters). HallPass generates it. Never reuse it. |

When the integration is saved, HallPass registers the webhook with `setWebhook`:

- URL `https://<public_url host>/hooks/telegram/<integration_id>`.
- `secret_token` set to the webhook secret.
- `allowed_updates=["callback_query","message"]`.

Telegram requirements for the webhook: HTTPS with a publicly trusted certificate, on port 443, 80, 88 or 8443.
HallPass must also be able to reach `https://api.telegram.org`. As defense in depth, your reverse proxy may restrict
the webhook path to Telegram's published source ranges (currently `149.154.160.0/20` and `91.108.4.0/22`).

## 4. Link approver accounts

1. The operator creates a **Telegram link code** in the web console. The code is 8 characters, valid for 10 minutes,
   single use, and bound to that operator.
2. The operator opens a **private chat** with the bot and sends `/link <code>`.
3. HallPass records the bot ID and the sender's numeric Telegram user ID (never the username) as that operator's Telegram
   identity.

**Never send a link code in a group.** Other members could see the code and use it to link their own account to your
operator. The adapter forwards a `/link` sent in a group as "non-private", and the core rejects that code and burns it,
so you must create a new one.

`/link` is the only command that a not-yet-linked user may send. The link code itself authenticates the request.
Button presses always require an allowlisted chat **and** a linked user. Unlinking takes effect immediately, and links of
disabled operators have no effect.

## 5. What is verified on every update

1. `X-Telegram-Bot-Api-Secret-Token` matches the webhook secret, compared in constant time (`401` otherwise).
2. The body is at most 64 KiB (`413` otherwise).
3. The `update_id` is new. Replays are acknowledged with `200` and ignored. If the replay cache is unavailable, the
   update is rejected with `503` (fail closed), and Telegram retries it.
4. Button presses must come from an allowlisted chat and a linked, non-bot user. Otherwise they are ignored with
   `200` and audited (rate limited).
5. `callback_data` must be exactly `hp1:<a|d>:<token>`.

Every other message, and every other update type, is ignored with `200` so that Telegram does not redeliver it.

## Message safety

No `parse_mode` is used, so Telegram applies no markup. Untrusted text (reason, names, descriptions, capabilities,
decider names) is cleaned first: control characters, bidirectional overrides, zero-width and other invisible characters
are removed, and newlines are collapsed. The text is then placed inside explicit `code` / `pre` entities, which Telegram
renders literally. As a second layer, `@` and `/` inside untrusted text are followed by an invisible word joiner, so
mentions, bot commands and URLs cannot be auto-detected even if entity isolation failed. Messages stay within
Telegram's 4096-character limit: if needed, descriptions and capabilities are shortened first, then the reason.

## Rotating secrets

- **Webhook secret.** Regenerate it in the integration. HallPass calls `setWebhook` again with the new secret.
- **Bot token.** In @BotFather, `/revoke` the token, then save the new one in HallPass. The bot ID stays the same, so
  existing links remain valid.

Rotate both immediately if you suspect either was exposed.

## What chat approval can and cannot guarantee

**Guaranteed by HallPass:**

- Only updates that carry the webhook secret, are new, come from allowlisted chats and come from linked users are
  processed.
- A decision is made only when the linked operator passes the full decision check at the time of the press. Holding a
  button or action token is never enough.
- Action tokens are single use, bound to their request, action, duration and provider, and expire with the request.
- Duplicate presses return the original outcome. Delivery failures never approve.

**Not guaranteed:**

- **Request authenticity beyond the shared secret.** Telegram does not sign updates. The only proof of origin is the
  secret header over TLS. Anyone who holds the webhook secret can forge updates and **claim any Telegram user ID and
  chat ID**, which includes a linked approver's. They still need a valid, unused action token, and the forged request must
  pass the decision checks for that operator. Every group member's client receives the button data, so treat group
  membership, the bot token and the webhook secret as approval-relevant.
- **Telegram account security.** A hijacked Telegram account that is linked to an approver can approve within that
  approver's scope. Require 2-step verification in Telegram. For sensitive roles, use the per-role `approval_channels`
  restriction (web only) and the "recent web MFA" requirement.
- **Confidentiality of notification content.** Every group member sees agent identity, server and role aliases and the
  reason. Telegram cloud chats are not end-to-end encrypted.
- **Message edits.** Edits that show the outcome are best effort. The web console is authoritative.
- **Rendering on real Telegram clients.** This is covered by automated tests against a fake API. It still needs manual
  verification against real Telegram (externally verified evidence).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `getWebhookInfo` shows `last_error_message: "Wrong response from the webhook: 401"` | The secret token does not match. Re-save the integration to re-register the webhook. |
| Button press spins and nothing happens | The chat is not allowlisted or the user is not linked. Check the audit log for `chat_not_allowed` or `user_not_allowed`. |
| Deliveries go **dead** with `403 Forbidden: bot was kicked` | Add the bot back to the group, or remove the route. |
| Deliveries retry with `rate limited` | Telegram flood control. HallPass honors `retry_after`. |
