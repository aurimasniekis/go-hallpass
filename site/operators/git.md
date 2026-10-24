# Git remotes

Agents can clone, fetch and push with plain git through HallPass, with the same requests, approvals and time-bound
grants as for servers. HallPass holds the key that logs in to the git host, decides which repositories and branches
an agent may touch, and records what was pushed. Git remotes live on their own **Git** page, separate from servers.

## How it works

```
git clone center:github/acme/api.git      # "center" is the agent's Host entry for the gateway
```

1. The agent's git connects to HallPass over SSH and asks for `git-upload-pack` (clone, fetch) or `git-receive-pack`
   (push) of `github/acme/api.git`.
2. HallPass reads `github` as the git remote and `acme/api` as the repository, and picks the **access profile** of
   that remote that covers the repository and the operation.
3. It reuses the agent's active grant, or creates a request and waits for approval like `connect` does.
4. It runs the git service on the real host with the profile's login key, which the agent never sees.
5. For a push, it checks every ref update before anything reaches the host (see [Push rules](#push-rules)).

A remote the agent may not see, a repository no profile covers and an operation no profile allows all get the same
answer: `repository not found or not permitted`.

## Add a git remote

**Git → New git remote**, then pick a preset (GitHub, GitLab.com, Bitbucket Cloud) or **Other host** for your own
server. The name you choose (for example `github`) is the first part of every repository path agents use.

1. **Allow the host's addresses.** HallPass only connects inside `egress.allow_cidrs`. Add the git host's published
   SSH address ranges (GitHub, GitLab and Bitbucket publish theirs).
2. **Pin the host key.** Under **Host identities**, **Scan host keys**, compare each fingerprint with the ones the
   provider publishes (linked on the page; keys that match a preset's published fingerprints exactly are marked), and
   confirm. HallPass never trusts a key on first use.
3. **Create access profiles** (below), and install each profile's login key on the host.

## Access profiles

An access profile is like a server role: agents request it, policy rules decide who may use it, and it has its own
login key. Instead of a remote account and shell capabilities it has:

| Setting | Meaning |
|---|---|
| **Repositories** | Patterns for the repositories it covers, matched without `.git` and case-insensitively. |
| **Allow pushing** | Off: clone and fetch only. On: push, limited by the push rules. |
| **Push rules** | Which branches and tags may change; see below. |
| **Approvers needed** | How many distinct approvers each request needs (1–5). |
| **Durations** | Default and maximum grant length. |

### Patterns

| Pattern | Matches |
|---|---|
| `acme/api` | exactly `acme/api` |
| `acme/{api,web}` | `acme/api` and `acme/web` |
| `acme/*` | any repository directly under `acme` |
| `acme/**` | anything under `acme`, including subgroups such as `acme/team/tool` |
| `team-*/infra` | `team-a/infra`, `team-blue/infra`, … |
| `v?.*` | one character for `?`: `v1.2`, `v2.0-rc.1` |

`*` never crosses a `/`; `**` does. Patterns are entered one per tag in the form: press Enter after each.

### Login keys

Expand a profile to generate its key, then install it on the host:

- **GitHub:** add it as a **deploy key** on each repository (tick *Allow write access* for push profiles), or to a
  machine user that has access to the repositories.
- **GitLab:** a deploy key per project (with *Grant write permissions* for push), or a bot user.
- **Bitbucket:** an access key per repository (read-only), or a bot account for pushing.
- **Your own host:** the `authorized_keys` of the account that owns the repositories.

Paste only the key itself (`ssh-ed25519 AAAA… hallpass:…`): git hosts ignore `authorized_keys` options. **Test login**
checks that the host accepts the key before you activate it.

## Push rules

HallPass reads the list of ref updates at the start of every push and refuses the whole push if any update breaks a
rule. A refused push never reaches the host, so nothing changes there.

| Rule | Effect |
|---|---|
| **Branches agents may create and update** | Branch patterns relative to `refs/heads/`, for example `agent/**`. Any other branch is refused. |
| **Protected branches** | Never created, updated or deleted, even when an allowed pattern matches (for example `main`, `release/*`). |
| **Tags agents may create** | Tag patterns, for example `v*-rc.*`. Existing tags are never moved or deleted. Empty: no tags. |
| **Branch deletion** | Off by default. On: allowed branches may be deleted. |
| **Force-push** | Off by default: see below. |

Notes, pull request refs and other refs are always refused. Signed pushes (push certificates) are not supported.

### Force-push

With **Force-push** off, every update of an existing branch must be a fast-forward. HallPass reads the commits in the
pushed pack as they stream to the host and follows their parents from the new branch tip back to the old one. It
holds back the last bytes of the pack until that succeeds; if it does not, it ends the connection, the host rejects
the incomplete pack, and the branch stays where it was.

An update HallPass cannot prove from the pushed commits alone, such as moving a branch to a commit the host already
has, is refused too. The agent sees:

```
hallpass: push refused: refs/heads/agent/fix: cannot prove a fast-forward from the pushed commits; force-push is blocked
```

Branch protection on the host itself remains a good second layer.

## Several approvers

Set **Approvers needed** to 2 or more for sensitive profiles (for example any profile that pushes). Each approver
decides separately in the web console, Slack or Telegram; the request stays pending until enough distinct approvers
have approved, and any one denial ends it. Such profiles are never approved automatically by policy. See
[Approving requests](/operators/approvals#several-approvers).

## What is recorded

Git operations are recorded as metadata, not as byte streams:

- the repository, the operation and the bytes transferred;
- for every push, each ref update with the old and new commit IDs and whether it was a fast-forward;
- every refused push, with the reason.

These appear in the session timeline and the audit log. The pushed code itself is not stored by HallPass: it is in the
repository.

## Agents

Agents need nothing beyond their usual `Host` entry for the gateway; see the
[agent guide](/agents/#git). A profile that requires a reason cannot get one from plain git, so the agent requests
access first and then retries the git command.
