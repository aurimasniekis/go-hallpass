# Telegram approvals

HallPass can post pending requests to Telegram groups through a bot, with inline **Approve** and **Deny** buttons.
Linked approvers decide from Telegram; the same checks as in the web console apply at the moment of the press.
Reference: [telegram.md](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/operator/telegram.md).

::: info Status
Implemented and tested end to end against a fake Bot API. Not yet verified against real Telegram.
:::

## What you need

- HallPass reachable from Telegram over HTTPS with a publicly trusted certificate, on port 443, 80, 88 or 8443.
- Outbound access from HallPass to `https://api.telegram.org`.

## 1. Create the bot

In a chat with [@BotFather](https://t.me/BotFather):

1. `/newbot`, choose a name and username, copy the **bot token**.
2. `/setprivacy` → **Enable**, so the bot only receives commands and button presses in groups.
3. `/setcommands` → `link - Link your Telegram account to HallPass`.
4. After adding the bot to your approval groups, `/setjoingroups` → **Disable**.

Treat the bot token as an approval credential.

## 2. Prepare an approval group

Create a private group, add the bot, and keep membership small: every member sees request details. You need the
group's **chat ID** (supergroups look like `-100…`).

## 3. Create the integration

**Administration → Integrations → New integration → Telegram**, as an administrator. Enter the bot token and the
allowed chat IDs. HallPass generates the webhook secret. Saving the integration registers the webhook with Telegram
(`setWebhook` to `https://<public_url host>/hooks/telegram/<integration_id>`).

Add a **route** for each chat under **Integrations → Routes**, with a target selector.

## 4. Link approvers

Each approver creates a link code under **My account → Chat accounts** (single use, 10 minutes) and sends
`/link <code>` to the bot **in a private chat**. A code sent in a group is burned, because other members could see it.

## What to keep in mind

- Telegram does not sign updates. The webhook secret is the only proof of origin, so protect it and rotate it if
  exposed (regenerating it re-registers the webhook).
- A hijacked Telegram account linked to an approver can approve within that approver's scope. Require two-step
  verification in Telegram, and restrict sensitive roles to web-only approval.
- Message edits that show the outcome are best effort. The web console is authoritative.

| Symptom | Likely cause |
|---|---|
| `getWebhookInfo` shows `Wrong response from the webhook: 401` | Secret mismatch. Re-save the integration. |
| A button press spins and nothing happens | Chat not allowlisted or user not linked; check the audit log. |
| Deliveries go **dead** with `403 Forbidden: bot was kicked` | Add the bot back, or remove the route. |
