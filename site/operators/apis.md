# API targets

Agents can call HTTPS APIs such as GitHub, Cloudflare and Google Cloud with their usual tools (`gh`, `wrangler`,
`gcloud`, `curl`) without ever holding your token. They request access like for a server; once a grant is active,
their requests go through the HallPass **API proxy**, which checks each one against the access profile's rules,
replaces whatever credential the agent sent with the profile's credential, and records the call.

<Shot name="apis" themed alt="The APIs page listing a GitHub API target" />

## How it works

```
ssh -fN -o ClearAllForwardings=no -L 127.0.0.1:18080:hallpass:443 center   # the agent's proxy tunnel
eval "$(ssh center api env)"                       # CA bundle + HTTPS_PROXY and friends
gh pr list --repo acme/api                          # a normal gh call
```

1. The agent forwards a local port to the name `hallpass` over its SSH connection to the gateway. HallPass accepts
   this one forward and refuses every other; the agent is identified by its SSH key as usual.
2. The agent's tool sends `CONNECT api.github.com:443` through the tunnel. HallPass answers only for hosts of API
   targets the agent can see.
3. HallPass terminates TLS with that target's own CA, which the agent trusts (from `ssh center api ca`). The CA is
   name-constrained to the target's hosts, so it cannot be used to intercept anything else.
4. For each request, HallPass picks the agent's access profile whose rules allow it: an active grant first, then an
   auto-approved profile (granted on first use), otherwise it answers **403** with the exact `request` command to run.
   An agent that names a profile (`hallpass-api --role`, or the proxy URL's user name) gets only that one. Grants
   belong to the agent session that asked (see [Agents and keys](/operators/agents#agent-sessions)).
5. It removes the agent's `Authorization`, cookies and the credential header, adds the profile's credential, sends the
   request to the API, streams the answer back, and records the call in the session timeline.

## Add an API target

**APIs → New API target**, then pick a preset or **Custom API**:

| Preset | Hosts | Credential |
|---|---|---|
| GitHub | `api.github.com`, `uploads.github.com`, `results-receiver.actions.githubusercontent.com` | Bearer: a fine-grained personal access token or a GitHub App token |
| Cloudflare | `api.cloudflare.com` | Bearer: an API token |
| Google Cloud | `*.googleapis.com` | Google service account key (JSON) |
| Custom | your hosts | Bearer, a custom header such as `X-Api-Key`, or Basic |

Hosts are exact names or `*.domain` wildcards (which cover every subdomain, not the domain itself). IP addresses are not
allowed, and the port is always 443. Host names must resolve to public addresses: private, shared (100.64.0.0/10) and
special ranges are refused unless you re-allow them in the configuration (below).

**GitHub Actions logs.** `gh run view --log` (and `--log-failed`) and
`GET /repos/{owner}/{repo}/actions/{runs,jobs}/{id}/logs` answer with a redirect to a signed URL on
`results-receiver.actions.githubusercontent.com`. HallPass does not follow redirects; the tool requests that URL
through the proxy itself, which refuses it unless the host belongs to the target ("not an API host you can reach").
The GitHub preset includes it; add it to GitHub targets you created with an older preset. It is GitHub's own host, and
the signed URL still works with the profile's token attached. Do **not** add `*.blob.core.windows.net`, which older
log redirects use: HallPass would send the GitHub token to any Azure storage account.

## Access profiles

<Shot name="api-target" themed alt="An API target with a read profile and a profile that may only comment on issues, each with its rules" />

An access profile is like a server role: agents request it, policy rules decide who may use it and whether it is
approved automatically, and approvals, durations and several-approver settings work the same. Instead of a remote
account it has **rules** and a **credential**.

### Rules

Each rule allows or denies requests by method, host and path. A request is allowed when an allow rule matches and no
deny rule does; anything no rule allows is refused. Matching ignores case.

| Pattern | Matches |
|---|---|
| `/repos/acme/api` | exactly that path |
| `/repos/acme/*/issues` | one path segment for `*` |
| `/repos/acme/**` | anything under `/repos/acme/`, and `/repos/acme` itself |
| `/repos/acme/{api,web}/pulls` | either repository |
| `/zones/*/dns_records/**` | Cloudflare DNS records of any zone |

An escaped slash (`%2F`) stays inside its segment, and paths with `.` or `..` segments are refused. The query string is
not matched.

**GraphQL.** GitHub's CLI uses GraphQL for most commands, all as `POST /graphql`. A rule can match by operation type:

```json
{ "effect": "allow", "methods": ["POST"], "paths": ["/graphql"], "graphql": ["query"] }
```

HallPass reads the request body and classifies every operation in it. A read-only profile allows queries; a mutation
(or a body it cannot classify, such as a persisted query) is refused.

Example: a read-only GitHub profile and a profile that may comment on and label issues:

```json
[
  { "effect": "allow", "methods": ["GET", "HEAD"] },
  { "effect": "allow", "methods": ["POST"], "paths": ["/graphql"], "graphql": ["query"] },
  { "effect": "deny", "paths": ["/user/keys", "/user/keys/**", "/authorizations/**"] }
]
```

```json
[
  { "effect": "allow", "methods": ["POST"], "paths": ["/repos/acme/*/issues/*/comments", "/repos/acme/*/issues/*/labels"] },
  { "effect": "allow", "methods": ["PATCH"], "paths": ["/repos/acme/*/issues/*"] }
]
```

::: warning Rules limit which calls, not what they do
An allowed call does whatever the token permits. Give each profile a token with the least scopes it needs (a
fine-grained GitHub token limited to the repositories, a Cloudflare token limited to the zones, a service account with
narrow IAM roles), and deny endpoints that create credentials.
:::

### Credentials

Expand a profile and **Set credential**. The secret is encrypted, never shown again (only its last four characters,
or a service account's email), and never sent to agents or written to logs or the timeline. **Replace** applies to
the next request; **Remove** makes the profile's requests fail until a new credential is set. Deleting the profile
destroys its credential.

| Type | Sent as |
|---|---|
| Bearer | `Authorization: Bearer <secret>` |
| Header | `<header>: <secret>`, for example `X-Api-Key` |
| Basic | `Authorization: Basic …` from a username and the secret |
| Google service account | HallPass signs in as the service account and sends short-lived access tokens for the scopes you list (default `cloud-platform`) |

## Examples

### GitHub

Target `github`, hosts `api.github.com`, `uploads.github.com` and `results-receiver.actions.githubusercontent.com`.
Each profile gets its own fine-grained token, limited to the repositories it covers and to read access (`github-read`)
or issues and pull requests (`github-issues`). Both deny the endpoints that create credentials, which would outlive the
grant:

```json
[
  { "effect": "allow", "methods": ["GET", "HEAD"] },
  { "effect": "allow", "methods": ["POST"], "paths": ["/graphql"], "graphql": ["query"] },
  { "effect": "deny", "paths": ["/user/keys/**", "/user/gpg_keys/**", "/authorizations/**", "/repos/*/*/keys/**"] }
]
```

```json
[
  { "effect": "allow", "methods": ["GET", "HEAD"] },
  { "effect": "allow", "methods": ["POST"], "paths": ["/graphql"], "graphql": ["query", "mutation"] },
  { "effect": "allow", "methods": ["POST", "PATCH"], "paths": ["/repos/<owner>/*/issues/**", "/repos/<owner>/*/pulls", "/repos/<owner>/*/pulls/**"] },
  { "effect": "deny", "paths": ["/user/keys/**", "/user/gpg_keys/**", "/authorizations/**", "/repos/*/*/keys/**"] }
]
```

A policy rule can approve `github-read` automatically and leave `github-issues` requestable with a reason. Agents run
`gh` through `hallpass-api`:

```sh
hallpass-api --gateway gateway --role github-read --reason "Read the failed CI job for #412" -- \
  gh run view 9876543210 --repo <owner>/<repo> --log-failed
hallpass-api --gateway gateway --role github-issues --reason "Post the root cause on #412" -- \
  gh issue comment 412 --repo <owner>/<repo> --body "Root cause: …"
```

### Cloudflare

Target `cloudflare`, host `api.cloudflare.com`, with an API token limited to the zones and permissions the profile
needs. A DNS profile reads everything the token can see and changes DNS records, and never touches API tokens:

```json
[
  { "effect": "allow", "methods": ["GET", "HEAD"] },
  { "effect": "allow", "methods": ["POST", "PUT", "PATCH", "DELETE"], "paths": ["/client/v4/zones/*/dns_records/**"] },
  { "effect": "deny", "paths": ["/client/v4/user/tokens/**", "/client/v4/accounts/*/tokens/**"] }
]
```

`hallpass-api` sets a placeholder `CLOUDFLARE_API_TOKEN` for `wrangler`, and the proxy replaces any `Authorization`
the tool sends, so `curl` needs no token either:

```sh
hallpass-api --gateway gateway --role cloudflare-dns --reason "Point the status page at the new host" -- \
  curl -s https://api.cloudflare.com/client/v4/zones/<zone-id>/dns_records
```

## What is recorded

Every request made under a grant, allowed or refused, is a timeline entry in the agent's session: method, host, path,
query (values of parameters that look like tokens, keys, signatures or codes are replaced by `[redacted]`), status,
sizes, duration, the profile and rule that allowed it, and for GraphQL the operation types. Headers and bodies are not
recorded. Refusals outside any session (an unknown host, no usable profile) go to the audit log.

<Shot name="api-timeline" themed alt="Session timeline of API calls: method, path, status, profile and the rule that allowed each call, and the command reported by hallpass-api" />

## Configuration

The proxy is on by default and does nothing until an API target exists.

```yaml
api_proxy:
  enabled: true                          # false: refuse the hallpass forward entirely
  allow_cidrs: [0.0.0.0/0, ::/0]         # addresses API hosts may resolve to
  allow_special_cidrs: []                # re-allow private or special ranges (internal APIs)
```

API hosts are dialed under this policy, not `egress.allow_cidrs`, and always verified against the system's trusted
roots.

## Agents

Agents need the tunnel, the CA bundle and the proxy settings; see the [agent guide](/agents/#apis). Agents that run
commands with `hallpass-api` report each command line: when a call needs a profile that requires approval, HallPass
files the request with the agent's reason followed by `Command (reported by the agent): gh issue comment 42 …`, so you
see what the access is for in the console, Slack or Telegram. The command is the agent's claim, not proof: HallPass
still checks every request against the profile's rules, and the timeline records both the reported command and each
actual request. Changing a target's
hosts issues a new CA, so agents must fetch the bundle again.

<Shot name="api-request" themed alt="An approved request filed by hallpass-api, with the agent's reason and the gh command it reported" />
