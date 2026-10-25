# Single sign-on (OIDC)

HallPass supports any OpenID Connect provider (Keycloak, Dex, Entra ID, Google, Okta, Authentik, …) for operator sign-in.
Agents never use SSO; they authenticate with SSH keys.

## How it works

- **Flow:** Authorization Code with PKCE (S256) only. `state`, `nonce` and the PKCE verifier are kept server-side
  (hashed or encrypted) for at most 10 minutes. The flow is single-use and bound to the browser by a `__Host-hp_oidc`
  cookie.
- **Redirect URI:** one exact URI for all providers: `<public_url>/auth/oidc/callback`. Register exactly this value at the
  IdP.
- **ID token checks:**
  - signature through the provider's JWKS (RS256, ES256 or EdDSA; never `none` or HMAC);
  - `iss` equal to the configured issuer;
  - `aud` containing the client ID, and `azp` equal to it when several audiences are present;
  - `exp`, `iat` and `nbf` with at most 60 s clock skew;
  - `nonce`.
- **Tokens:** access and refresh tokens are discarded immediately. The ID token is used only to read claims and is
  not stored.
- **Identity:** an operator is identified by `iss` + `sub`. Email addresses are never used to match or merge accounts.

## Configuring a provider

| Field | Notes |
|---|---|
| `slug`, `display_name` | Shown on the login page. |
| `issuer` | Must be `https://` and exactly equal to the `issuer` in the discovery document. `http://localhost` is allowed only in development mode. |
| `client_id`, `client_secret` | The secret is optional (public clients with PKCE work). It is encrypted at rest and write-only: the API never returns it. |
| `scopes` | Default `openid profile email`. `openid` is required. |
| `groups_claim` | The claim that carries group values (a string array or a single string), e.g. `groups`. A dotted path reads a nested claim, e.g. `porch.groups`; a top-level claim with exactly that name is used first. |
| `provisioning` | `preprovisioned` (default): unknown identities are refused. `jit`: unknown identities are created when every configured restriction matches. |
| `jit` restrictions | `email_domains` (needs `email_verified=true`), `tenants` (`tid`), `hosted_domains` (`hd`), `groups`. At least one is required. JIT users get no roles except through group mappings. |
| `ca_bundle_pem` | Extra trust roots for a private CA. TLS verification is never disabled. |
| `allow_private_network` | The IdP may resolve to private, loopback or link-local addresses. Off by default; changes are audited. |
| `allow_cross_origin_endpoints` | Allow endpoints outside the issuer's registrable domain. Off by default. |
| `stepup_fallback` | `none` or `local_totp` (see step-up below). |
| `acr_values` | Requested at login and required in the `acr` claim on step-up. |
| `end_session_enabled` | Offer RP-initiated logout at the provider (see logout below). |

Discovery runs on first use and after every configuration change. Endpoints must be https and, by default, on the
issuer's site. HallPass does not use HTTP proxies or follow redirects for IdP requests.

## Linking operators

There are three ways to link an identity to an operator:

1. **Admin link:** an administrator, with recent authentication, enters the expected `sub` for the operator.
2. **Link invitation:** an administrator issues a single-use invitation (valid 72 h). The user completes an SSO
   login with it, and the identity is linked to that operator.
3. **Self-link:** an operator who is signed in locally starts "link SSO" and logs in at the IdP.

An identity already linked to one operator is never moved to another. Unlinking revokes the operator's sessions.

## Group → role mapping

Mappings are explicit allowlist rows: `group value → role` or `group value → operator group`. At every SSO login, the
operator's SSO-sourced roles and groups are replaced with the mapped set. Manually assigned roles are kept separately
and never changed by SSO.

When a group is removed at the IdP, the role disappears at the next login. Existing sessions keep their roles until
they end; the absolute session timeout is 12 h, and administrators can revoke sessions earlier. SSO sync never removes
the last enabled administrator: the role is kept and the conflict is audited.

## Step-up (recent authentication)

Sensitive actions need authentication within the last 5 minutes. For SSO sessions, HallPass sends the user back to the
IdP with `prompt=login&max_age=0`. It then requires `auth_time` to be at or after the step-up start (minus 60 s skew),
and `acr` to match when `acr_values` are configured.

If the provider does not send `auth_time`, step-up fails. Set `stepup_fallback: local_totp` to require the operator's
HallPass TOTP instead; the operator must have TOTP enrolled.

## Test login and SSO-only mode

Before password login can be disabled, an administrator must complete a **test login** from the provider settings. The
test runs discovery, the IdP login and claim validation, then shows the claims, the mapping result and the roles the user
would get. It creates no session.

Password login can then be disabled when at least one enabled administrator has a linked identity on an enabled provider.
While SSO-only mode is on, HallPass refuses changes that would break that path: disabling or deleting the last such
provider, or unlinking the last SSO administrator. The break-glass recovery login (`hallpass admin recover`) always
keeps working.

## Outages

If discovery, JWKS or the token endpoint is unreachable, SSO login fails with "identity provider unavailable". Existing
sessions continue until they expire, and cached signing keys keep working for callbacks already in flight. Password login
(when enabled) and break-glass recovery stay available.

JWKS is cached and refetched when an unknown key ID appears, at most once every 10 seconds.

## Logout

Logout always revokes the HallPass session. When `end_session_enabled` is set and the provider advertises an
`end_session_endpoint`, HallPass also redirects there with `client_id` and `post_logout_redirect_uri`. No `id_token_hint`
is sent, because ID tokens are not retained. This ends the session at that provider only. It is **not** a global logout
from other applications.

## Interoperability status

Tested against an in-process mock provider covering:
- key rotation;
- `none` and HS256 algorithm confusion;
- wrong `iss`, `aud`, `azp` or `nonce`;
- expired tokens;
- missing `auth_time`;
- outages;
- private-network and cross-origin refusal.

Also tested against real **Keycloak 26.7** and **Dex 2.46** containers (`make test-oidc-interop`, nightly CI):
- unknown identities are refused;
- a linked login works with PKCE;
- group mapping works;
- link invitations work;
- the IdP session is reused;
- step-up re-prompts and `auth_time` is checked;
- logout works.

Provider notes:
- **Dex** sends the `groups` claim only when the `groups` scope is requested. Set `scopes: [openid, profile, email,
  groups]` and `groups_claim: groups`.
- **Dex** honours `post_logout_redirect_uri` only together with `id_token_hint`. HallPass does not keep ID tokens
 , so after RP-initiated logout the user stays on Dex's "logged out" page. The Dex session does end.
- **Keycloak** asks the user to confirm RP-initiated logout, then redirects back to HallPass.
- **Porch** sends groups inside its `porch` claim, only when the `groups` scope is requested and the app may disclose
  groups. Set `scopes: [openid, profile, email, groups]` and `groups_claim: porch.groups`. Porch honours
  `prompt=login` and `max_age=0` and always sends `auth_time`, so step-up needs no fallback.
- Logout offers the end-session endpoint of the provider that created the session (`web_sessions.auth_provider`).
