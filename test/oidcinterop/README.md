# OIDC interoperability tests (Keycloak, Dex)

These tests run HallPass's OIDC SSO against real identity providers in Docker (PLAN WP14 "interop smoke tests",
ADR-0030). The tests use the IdP's real login page. A browser-like HTTP client with a cookie jar parses the HTML login
form, submits the username and password, and follows every redirect back to HallPass's `/auth/oidc/callback`.

HallPass runs in process, wired like `internal/httpapi`'s test harness: `app.New` plus `httpapi.New`, served on a
loopback port. The SSO flow therefore goes through the real `/auth/oidc/{provider}/start` and `/auth/oidc/callback`
handlers, the `hp_oidc` binding cookie, session cookies, `/api/v1/me` and `/api/v1/auth/logout`.

## Running

```sh
go test -tags oidcinterop -count=1 -timeout 20m -v ./test/oidcinterop/
```

- **Requirements:** Docker. On the first run the images are pulled, which takes about 600 MB.
- **Run time:** about 25 s once the images are cached. Keycloak takes about 15 s to start.
- **Skipping:** the tests skip cleanly when `docker` is missing, when the daemon is unreachable, or when
  `HALLPASS_SKIP_OIDC_INTEROP` is set.
- **Build tag:** without `-tags oidcinterop` the package is excluded from builds, so `go test ./...` never starts
  containers.

## Images

The images are pinned by version tag and by multi-arch index digest, so Docker refuses different content. Every run
logs the resolved digest.

| IdP | Image |
|---|---|
| Keycloak 26.7.5 | `quay.io/keycloak/keycloak:26.7.5@sha256:37dbaf6f0722c9ec246335f36e1ef8b2e6cb960f7c27e0d8c615121a3d475a85` |
| Dex v2.46.0 | `ghcr.io/dexidp/dex:v2.46.0@sha256:933fcd3f523338c847b88ef84a7145fb2fcb7b9917f08418612afeaaa2001777` |

To try a newer version, set `HALLPASS_KEYCLOAK_IMAGE` or `HALLPASS_DEX_IMAGE`. To upgrade, update the constants in
`docker_test.go` and this table with the tag and the index digest from `docker buildx imagetools inspect <tag>`.

## Transport: plain HTTP on localhost (no TLS)

- **IdP side:** the IdPs are published on `127.0.0.1` and addressed as `http://localhost:<port>`.
- **HallPass side:** HallPass runs in development mode (`oidc.Options.DevMode`), which accepts `http://` issuers and
  endpoints only on localhost. The provider also has `allow_private_network: true`, because the IdP is on loopback.
- **Production checks not covered:** https-only issuers, the SSRF guard and the cookies' Secure flag are covered by
  `internal/oidc` unit tests.
- **Browser cookies:** like real browsers, Go's cookie jar treats `localhost` as a secure origin.

## IdP configuration

The configuration is rendered per run from `testdata/` templates. Passwords, the client secret and the bcrypt hashes are
generated at test time, and nothing secret is committed.

The `hallpass` client registers exactly:
- the redirect URI `<hallpass>/auth/oidc/callback`;
- the post-logout URI `<hallpass>/login`.

| | Keycloak (`start-dev --import-realm`) | Dex (`dex serve`, `DEX_SESSIONS_ENABLED=true`) |
|---|---|---|
| Client | confidential, PKCE S256 required | static client |
| Users | `alice` (group `hallpass-approvers`), `bob` (`other`), `mallory` (`hallpass-approvers`, never linked) | Same, through the static password DB with `groups`; login is by email |
| Groups claim | group-membership mapper → `groups` in the ID token | `groups` claim, **only when the `groups` scope is requested**. The Dex provider uses scopes `openid profile email groups`. |
| `sub` | the user id (fixed in the realm import) | base64url(protobuf{user id, `local`}), computed by `dexSubject` |
| Sessions | IdP SSO session | experimental auth sessions (SSO, `max_age`, `end_session_endpoint`) |

Files are copied into the container with `docker cp` before it starts, not bind-mounted, so the tests also work with
remote Docker daemons.

## What is asserted

The same scenario runs against each IdP (`runScenario`):

1. **Unknown identity refused (preprovisioned mode):**
   - `mallory` completes the IdP login and lands on `/login?sso_error=forbidden`;
   - there is no session cookie, and `/api/v1/me` returns 401;
   - `operator.login.failed` (denied) is audited;
   - no operator is created.
2. **Linked identity login with group mapping:** `alice` is linked by expected `sub` (admin link).
   - The authorize request has PKCE S256, `nonce`, `state`, the exact `redirect_uri` and no `prompt`.
   - Login lands on `return_to`, and the session method is `oidc`.
   - The `hallpass-approvers → approver` mapping yields `approver` with source `sso`. The manual `viewer` role is kept.
   - The identity row has the expected issuer and subject and a `last_login_at`.
3. **Link invitation, then login:**
   - `bob` is linked through an admin invitation. The authorize request has `prompt=login&max_age=0`, and the linked
     `sub` matches.
   - `bob`'s group `other` has no mapping, so he gets no role.
4. **IdP session reuse:** a second login without `prompt` does not show the IdP login form. This proves the IdP has an
   SSO session, so the step-up re-prompt below is meaningful.
5. **Step-up:**
   - `purpose=stepup` sends `prompt=login&max_age=0`, and the IdP asks for credentials again despite its session.
   - HallPass accepts the IdP's `auth_time`: the session's `auth_at` moves forward, and `RequireRecentAuth` passes.
6. **Step-up with a stale `auth_time` is refused:**
   - HallPass's clock is shifted 2 minutes ahead, so the IdP's honest `auth_time` falls before step-up start − 60 s.
   - The callback is refused (`sso_error=forbidden`) and the session is unchanged.
   - HallPass's logs show the refusal did not come from the code exchange or the ID-token checks.
7. **Logout:**
   - `POST /api/v1/auth/logout` revokes the session and returns `provider_logout_url`.
   - The URL is the discovered `end_session_endpoint` with `client_id` and `post_logout_redirect_uri`, and without
     `id_token_hint`.
   - The test follows the URL, confirms the logout form, and then requires a fresh IdP login.
   - Keycloak must redirect back to `<hallpass>/login`. Dex is described under known differences.

## Known differences observed

- **Dex groups need a scope:** Dex sends the groups claim only when the `groups` scope is requested. HallPass's default
  scopes do not include it, so the provider's `scopes` must be set.
- **Dex logout without `id_token_hint`:**
  - Dex needs `id_token_hint` to honor `post_logout_redirect_uri`, and HallPass never sends it, because it does not
    retain ID tokens (HP-OIDC-008).
  - After confirmation, Dex ends its session but shows its own "Logged out" page instead of redirecting back.
  - The test asserts that the Dex session ended and logs the missing redirect.
- **Keycloak `iss` parameter:** Keycloak adds the RFC 9207 `iss` authorization-response parameter. HallPass ignores
  it, and the provider is bound through the server-side `state` instead.
