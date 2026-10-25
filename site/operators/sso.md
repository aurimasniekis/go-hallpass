# Single sign-on (OIDC)

Operators can sign in through any OpenID Connect provider: Keycloak, Dex, Entra ID, Google, Okta, Authentik and
others. Agents never use SSO; they authenticate with SSH keys. Reference:
[sso.md](https://github.com/aurimasniekis/go-hallpass/blob/main/docs/operator/sso.md).

## How it works

- Authorization Code flow with PKCE (S256) only. ID tokens are verified (signature through JWKS, `iss`, `aud`,
  `azp`, expiry, `nonce`) and then discarded, along with access and refresh tokens.
- An operator is identified by **issuer + subject**. Email addresses are never used to match or merge accounts.
- There is one redirect URI for every provider: `<public_url>/auth/oidc/callback`. Register exactly that value.

## Add a provider

Under **Administration → Authentication**, add a provider:

| Field | Notes |
|---|---|
| Slug, display name | Shown on the login page. |
| Issuer | `https://…`, exactly as in the provider's discovery document. |
| Client ID, client secret | The secret is optional (public clients with PKCE work). It is encrypted and write-only. |
| Scopes | Default `openid profile email`. |
| Groups claim | The claim that carries groups, for example `groups`. Use dots for a nested claim, for example `porch.groups`. |
| Provisioning | `preprovisioned` (default; unknown identities are refused) or `jit` with at least one restriction (email domains, tenants, hosted domains or groups). |
| Step-up fallback | `none` or `local_totp`, for providers that do not send `auth_time`. |

Then run a **test login** from the provider settings. It shows the claims, the mapping result and the roles the user
would get, without creating a session.

## Link operators

- **Admin link:** enter the expected `sub` for an operator.
- **Link invitation:** a single-use invitation (72 hours) that the user completes by signing in at the IdP.
- **Self-link:** a locally signed-in operator starts "link SSO" from their account.

An identity linked to one operator is never moved to another.

## Map groups to roles

Mappings are explicit rows: `group value → role` or `group value → operator group`. At each SSO login, SSO-sourced
roles are replaced with the mapped set. Manually assigned roles are kept separately. SSO sync never removes the last
enabled administrator.

## Recent authentication (step-up)

Sensitive actions need authentication within the last 5 minutes. For SSO sessions, HallPass sends the user back to the
IdP with `prompt=login&max_age=0` and checks `auth_time` (and `acr`, if configured).

## SSO-only mode

Password login can be turned off once a test login succeeded and at least one enabled administrator has a linked
identity on an enabled provider. While SSO-only mode is on, HallPass refuses changes that would lock everyone out.

::: warning Plan for IdP outages
When the provider is down, SSO logins fail and existing sessions continue until they expire. Keep the
[break-glass procedure](/operators/incidents#locked-out-of-administration) in mind.
:::

## Tested providers

Besides an in-process mock covering algorithm confusion, wrong claims, expiry and outages, the integration is tested
against real **Keycloak 26.7** and **Dex 2.46** containers. For Dex, add the `groups` scope
(`scopes: [openid, profile, email, groups]`) to receive the `groups` claim.
