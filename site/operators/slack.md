# Slack approvals

HallPass can post pending requests to Slack channels with **Approve &lt;duration&gt;** and **Deny** buttons. Linked
approvers decide from Slack; the same checks as in the web console apply at the moment of the click. Reference, with
the exact verification steps and message-safety rules:
[slack.md](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/operator/slack.md).

::: info Status
Implemented and tested end to end against a fake Slack API. Not yet verified against a real Slack workspace.
:::

## What you need

- HallPass reachable from Slack over HTTPS with a publicly trusted certificate.
- Outbound access from HallPass to `https://slack.com/api/` and `https://hooks.slack.com/`.
- An NTP-synchronized clock (requests more than 5 minutes off are rejected).

## 1. Create the Slack app

At <https://api.slack.com/apps>: **Create New App → From a manifest**, pick your workspace and paste this manifest.
Replace the host with yours. `INTEGRATION_ID` is filled in at step 4.

```yaml
display_information:
  name: HallPass
  description: Access approvals for AI agents
features:
  bot_user:
    display_name: HallPass
    always_online: false
  slash_commands:
    - command: /hallpass
      url: https://hallpass.example.com/hooks/slack/INTEGRATION_ID
      description: Link your HallPass account or check a request
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
    request_url: https://hallpass.example.com/hooks/slack/INTEGRATION_ID
  org_deploy_enabled: false
  socket_mode_enabled: false
  token_rotation_enabled: false
```

Only `chat:write` and `commands` are needed. Do not distribute the app: HallPass accepts exactly one workspace.

Then **Install to Workspace** and copy the **Bot User OAuth Token** (`xoxb-…`), the **Signing Secret** (Basic
Information → App Credentials) and your **team ID** (`T…`, visible in the Slack web client URL).

## 2. Prepare an approval channel

Create a private channel for approvals, invite the bot (`/invite @HallPass`) and copy the **channel ID** (`C…`) from
the channel details. Everyone in the channel can read request details, including the agent's reason. Only linked,
authorized operators can decide.

## 3. Create the integration in HallPass

**Administration → Integrations → New integration → Slack**, as an administrator. Enter a name, the team ID, the bot
token and the signing secret. Secrets are encrypted at rest and never shown again.

<Shot name="integration-new" alt="New chat integration drawer with provider, name, workspace ID, slash command, bot token and signing secret" />

## 4. Point Slack at the integration

HallPass shows the integration's webhook URL, `https://<public_url host>/hooks/slack/<integration_id>`. Put it in the
Slack app under **Interactivity & Shortcuts → Request URL** and **Slash Commands → /hallpass → Request URL**.

## 5. Route requests to the channel

Under **Integrations → Routes**, add a route with the channel ID and a target selector (all servers, or specific
servers, groups or labels). An empty selector matches nothing. Each matching request gets one message per route.

## 6. Link approvers

Each approver links their Slack account once: in **My account → Chat accounts**, create a link code (single use,
10 minutes), then run `/hallpass link <code>` in Slack. HallPass stores the team and user ID, never the display name.
Administrators can also link accounts directly.

Chat decisions require MFA by default: the approver must have TOTP enrolled in HallPass, or sign in through an SSO
provider that enforces MFA.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Buttons show a warning, logs say `bad_signature` or `stale_timestamp` | Wrong signing secret, or clock skew on the HallPass host. |
| `403` / `wrong_workspace` | The team ID in HallPass does not match the workspace. |
| Deliveries go **dead** with `channel_not_found` / `not_in_channel` | Bot not invited, or wrong channel ID in the route. |
| "not linked to a HallPass approver" | The user has not run `/hallpass link`, or the link was removed. |

Delivery history is under **Integrations → Deliveries**. A failed notification never approves anything; the request
stays pending and can always be decided in the web console.
