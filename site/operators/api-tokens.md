# API tokens

API tokens let Terraform and scripts manage HallPass through its [REST API](/reference/api) without a browser. Create
them under **Administration → API tokens** (administrators).

## What a token can do

A token acts **for you**, with **one of your roles**, until it expires or is revoked:

- it reads what that role allows;
- it changes configuration: agents and their keys, servers, git remotes, roles and access profiles, host keys, login
  keys and certificates, groups, policy and approver rules, single sign-on and chat integrations;
- it never approves, denies or cancels requests, revokes grants, ends live sessions, reads or exports recordings,
  manages operators or tokens, or uses lockdown. Those stay with people in the console.

It stops working when you revoke it, when it expires, when your account is disabled, and when you no longer hold its
role. Changes made with it appear in the audit log under your name, with `via: api_token:<id>` in the details.

Operations that need recent sign-in in the console (deleting a server, generating login keys, changing SSO) work with
a token without signing in again: you signed in and passed MFA when you created it. Treat a token like a password for
your account, limited to configuration.

## Create a token

1. **Administration → API tokens → New token**.
2. Name it after what uses it (`terraform-prod`), pick the role (usually **Administrator** for Terraform, **Viewer** for
   read-only reports) and an expiry from 1 to 366 days.
3. Copy the token (`hallpass_at_…`). It is shown once; HallPass stores only a keyed hash.

Store it in your secret manager or CI secrets, not in the repository.

## Use a token

Send it as a bearer token. No cookie, CSRF token or `Origin` header is needed:

```sh
curl -H "Authorization: Bearer $HALLPASS_TOKEN" https://hallpass.example.com/api/v1/servers
```

An operation a token may not use answers `403` ("API tokens cannot use this operation"). In the API document these
operations lack `x-token: true`.

## Rotate and revoke

Create the new token, switch your automation to it, then **Revoke** the old one. The list shows when and from where
each token was last used, so unused tokens are easy to spot. Revoking takes effect immediately.
