# API tokens

API tokens let Terraform and scripts manage HallPass through its [REST API](/reference/api) without a browser. Create
them under **Administration → API tokens** (administrators).

## What a token can do

A token acts **for you**, with **one role**, until it expires or is revoked. Administrators may give a token any role,
for example **Auditor** for a read-only integration, without holding that role themselves; other operators pick one of
their own roles.

- It reads what that role allows, including the list of operators.
- It changes configuration: agents and their keys, servers, git remotes, roles and access profiles, host keys, login
  keys and certificates, groups, policy and approver rules, single sign-on and chat integrations.
- With the **Administrator** role it also manages operators (create them, set their roles, operator groups and enabled
  state, link single sign-on identities and chat accounts) and issues tokens of its own. It cannot change the roles,
  groups or enabled state of the operator it acts for, which keeps automation from locking you out.
- It never approves, denies or cancels requests, revokes grants, ends live sessions, reads or exports recordings,
  sends invitations or password resets, or uses lockdown. Those stay with people in the console.

It stops working when you revoke it, when it expires, when your account is disabled, and when you no longer hold its
role (unless you are an administrator). Changes made with it appear in the audit log under your name, with
`via: api_token:<id>` in the details.

Operations that need recent sign-in in the console (deleting a server, generating login keys, changing SSO or an
operator's roles) work with a token without signing in again: you signed in and passed MFA when you created it.

::: warning An administrator token can take over approvals
Because it can create operators and link sign-in identities and chat accounts to them, someone holding a leaked
administrator token can give themselves an approver account and approve their own requests. Store it like a root
password, watch its **Last used**, and give everything that only reads a lower role such as Auditor or Viewer.
:::

## Create a token

1. **Administration → API tokens → New token**.
2. Name it after what uses it (`terraform-prod`), pick the role (usually **Administrator** for Terraform, **Auditor**
   or **Viewer** for read-only integrations and reports) and an expiry from 1 to 366 days, or **Never expires**.
3. Copy the token (`hallpass_at_…`). It is shown once; HallPass stores only a keyed hash.

Store it in your secret manager or CI secrets, not in the repository.

**Never expires** is for your own Terraform or break-glass automation, which should not stop working on a date. Such a
token still stops when you revoke it, when your account is disabled and when you lose its role, but otherwise it works
for good. Store it like a root password, check **Last used** now and then, and revoke it as soon as nothing needs it.

## Use a token

Send it as a bearer token. No cookie, CSRF token or `Origin` header is needed:

```sh
curl -H "Authorization: Bearer $HALLPASS_TOKEN" https://hallpass.example.com/api/v1/servers
```

An operation a token may not use answers `403` ("API tokens cannot use this operation"). In the API document these
operations lack `x-token: true`.

## Tokens issued by a token

An administrator token can issue tokens itself, so Terraform can create the read-only token an integration needs and
hand it to your secret manager. Such a token is listed under its parent ("Issued by token …") and:

- acts for the same person as its parent, with the role it was given;
- is revoked together with its parent;
- cannot issue tokens itself.

The parent token can read and revoke only the tokens it issued.

## Terraform

The [HallPass Terraform provider](https://github.com/aurimasniekis/terraform-provider-hallpass) uses an API token to
manage agents and their keys, servers and git remotes, host keys, roles and git access profiles, login keys, policy and
approver rules, single sign-on, chat approvals, destination audit collectors, operators and API tokens:

```hcl
provider "hallpass" {
  endpoint = "https://hallpass.example.com" # or HALLPASS_ENDPOINT
  token    = var.hallpass_token             # or HALLPASS_TOKEN
}

resource "hallpass_agent" "claude_sre" {
  name   = "claude-sre"
  groups = ["sre-agents"]
}
```

Give it an **Administrator** token. Approvals, recordings and invitations stay in the console.

The egress settings (`egress.allow_cidrs`, `egress.source_addresses`) stay in the configuration file: the allow list
protects against a server being pointed at internal addresses, even by an administrator. Set it once to the subnets
your destinations live in. Terraform can read the values (the `hallpass_egress` data source) to build firewall rules.

## Rotate and revoke

Create the new token, switch your automation to it, then **Revoke** the old one. Revoking a token also revokes the
tokens it issued. The list shows when and from where
each token was last used, so unused tokens are easy to spot. Revoking takes effect immediately.
