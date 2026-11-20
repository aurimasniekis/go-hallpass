# Thin pushes: proving fast-forwards with delta bases fetched from the host (R-17)

> **Status: proposed design, not implemented.** Security-relevant: needs operator approval before anyone builds it.
> Decision record: [DECISIONS.md ADR-0064](../DECISIONS.md#adr-0064--git-fetch-missing-delta-bases-to-prove-thin-pushes-security-relevant-change)
> (review item R-17). Background: ADR-0047 (force-push rule) and ADR-0063 (root cause and the `--no-thin` hint).

## 1. Problem

When an access profile blocks force-pushes, every update of an existing branch must be proven a fast-forward from the
pushed pack before HallPass releases the pack's final checksum (ADR-0047). After a repack with reachability bitmaps,
git's default thin push can reuse a stored delta of a *new* commit against a commit that only the host has. The
commit arrives as a `REF_DELTA` whose base is outside the pack, `gitproto.ScanPack` cannot rebuild it, the proof is
`Unknown` and `gitPushGate` refuses a real fast-forward. Today the agent is told to push again with
`git push --no-thin` (ADR-0063).

The goal is that the same thin push is proven and lands, without weakening the rule that an update HallPass cannot
prove is refused.

## 2. Proposed behaviour (summary)

After the pack has been read and forwarded **except its checksum**, and only if an update that needs a fast-forward
proof is still `Unknown` because the pack is thin, HallPass:

1. picks the `REF_DELTA` objects whose base is missing and whose delta header says source and result are commit-sized
   (the *candidates*), up to a fixed number;
2. revalidates the grant and checks that the profile also has `git-read` (otherwise it stops here: no fetch);
3. opens a second session **on the same, already verified SSH connection to the git host** (same credential, same
   repository path) and runs `git-upload-pack` with protocol v2: `want` exactly the candidate base IDs, `deepen 1`,
   `filter tree:0`, no `have`, no thin pack, within a time and byte budget;
4. keeps only returned objects whose recomputed object ID equals a requested ID and whose type is commit;
5. applies the candidate deltas to those bases (and resolves pack deltas that chain on them), computes the object IDs
   of the resulting commits from their content, adds the commits to the graph and runs `AncestryOf` again;
6. writes the checksum only if every checked update is now `FastForward`. Anything else (no candidates, no
   `git-read`, disabled, a limit, a timeout, the host refusing, a hash mismatch, a real non-fast-forward) leaves the
   update refused exactly as today, including the `--no-thin` hint.

Fetched base objects are used **only as delta bases**: they never become nodes of the commit graph. The proof is still
"a parent chain of pushed commits leads from the new tip to the old tip", where every pushed commit's ID is computed
by HallPass from its content.

## 3. Threat analysis

Adversaries: AD-1/AD-3 (malicious agent or stolen agent key with a git-write grant) and AD-4 (malicious git host).
Assets: repository content the profile must not read, the integrity of the force-push rule, availability of the
gateway and the host.

| # | Threat | Analysis | Mitigation in this design |
|---|---|---|---|
| 1 | **Reading objects the agent may not read.** The agent chooses the base IDs in its `REF_DELTA` headers, so it chooses what HallPass fetches. | Fetched content never goes to the agent. But the proof result is an oracle: the agent can craft a delta that copies bytes of a base into a "commit" whose parent is the old tip, set the update's new ID to the hash of a guessed result, and learn from "pushed" vs "refused" whether the guess was right, byte by byte. With a write-only profile this would leak content the profile cannot read, and object existence. | Fetch **only if the profile has `git-read`** for the same repository (re-read at fetch time). Such an agent can already `git fetch origin <sha>` the same objects through the same profile, so the oracle reveals nothing new. Without `git-read` the push stays refused with the hint. The host's own rules (reachable SHAs only, see §4.4) bound what can be fetched at all. |
| 2 | **SSRF / reaching another host or repository.** | Only if the fetch target or path were agent-controlled. | No new dial: the upload-pack session is a second channel on the existing SSH client, which was dialed through the egress guard with the pinned host key (G-7, HP-SSH-011). The repository path is the push's already validated path (`GitOp.Forward`, quoted with `gitproto.Quote`). Want lines are hex encodings of binary IDs taken from the pack; nothing else from the agent reaches the request. Only if the host refuses a second session does HallPass dial again, to the same enrolled target with the same verifier and credential (§4.2). |
| 3 | **Poisoning the proof** with a base whose content differs from what the host holds, or a resolved commit that is not what the host will store. | The host resolves the same delta against its object with the same ID. Objects are content-addressed, so if the base HallPass used hashes to the requested ID, HallPass and the host build the same bytes, and the resulting commit ID is computed by HallPass, not taken from the pack. | Every fetched object's ID is recomputed (`<type> <len>\0<content>`, SHA-1 or SHA-256 per the push's object format); a mismatch discards it. Base objects never become graph nodes, so a fetched host commit (for example the update's new or old ID used as a delta base) cannot stand in for a pushed commit. A malicious host (AD-4) can make the proof fail (refusal), not succeed wrongly: a wrong base yields a commit whose ID matches no update. No new SHA-1 collision exposure: both sides hash the same bytes. |
| 4 | **Racing the ref.** The fetch adds seconds between the proof and the update. | The proof is about the *claimed* old ID in the agent's command. receive-pack applies the update only if the ref still equals that old ID (compare-and-swap on the host). | Unchanged: the claimed old ID is proven an ancestor of the new ID; the host's CAS rejects the update if the ref moved meanwhile. Base objects are immutable, so their content cannot change between fetch and index-pack. |
| 5 | **Load amplification on the host.** One push could make HallPass ask for many objects, or for objects that pull large trees. | Without a filter, `want <commit>` + `deepen 1` returns the commit's whole snapshot (measured locally: ~9 MiB for this repository against ~1 KB with `filter tree:0`). | `filter tree:0` and `deepen 1` are **required**; a host that does not advertise both is not asked. At most `max_bases` wants (default 256), one fetch per push, a byte budget (`max_fetch_bytes`, default 8 MiB) and a time budget (`timeout`, default 20 s). Only pushes that need a proof, are still `Unknown` and are thin trigger a fetch. Repeated attempts are bounded by the agent's own push rate and grant. |
| 6 | **Resource exhaustion on the gateway.** Memory for withheld deltas and fetched objects, CPU for delta application, goroutines and sessions held open. | Candidate deltas must be kept until the bases arrive; the scan otherwise discards non-commit deltas. | Candidates only if the delta header declares source and result ≤ `maxCommitBytes` (1 MiB); retained delta bytes and count are capped (16 MiB, 4096) inside the existing 64 MiB commit-data budget; fetched objects larger than 1 MiB are dropped while streaming; a gateway-wide semaphore (`max_concurrent`, default 4) bounds simultaneous fetches; the fetch session is closed on every exit path and covered by goroutine-leak checks (HP-SSH-015). |
| 7 | **Hostile host output** (AD-4): malformed pkt-lines, sideband floods, decompression bombs, a v0 advertisement, `ERR` text aimed at the agent. | New parser on untrusted input. | Bounded pkt-line reader and sideband demultiplexer; the same bounded inflate as `ScanPack`; protocol v2 only (anything else ends the fetch); fuzz targets (§6.3). Host error text is never forwarded to the agent; the event records a fixed result class. |
| 8 | **Revocation, expiry, lockdown during the fetch.** | The checksum is withheld during the fetch, so the update cannot land before the decision. | The grant and the profile's capabilities are revalidated before the upload-pack session opens (HP-SSH-025). The fetch context is the channel's; the enforcer's terminator closes the SSH client, which ends both sessions (HP-GRT-008, 5 s bound). The checksum is written only if the channel has not been terminated. |
| 9 | **Unrecorded host access.** HallPass reads from the host with the profile credential although the agent did not run a fetch. | Operators and host audit logs (for example a hosted service's clone/fetch log) will see a fetch they did not expect. | The fetch is recorded on the push channel (counts, bytes, duration, result) and counted in metrics; docs say that a thin push may cause one fetch under the same profile. Metadata only, like all git channels (ADR-0047). |
| 10 | **Withheld checksum and host timeouts.** receive-pack waits for the last bytes of the pack while HallPass fetches. | git's receive-pack has no read timeout by default; hosted services may close idle connections. | The time budget (20 s default) stays well below common idle limits; if the host gives up, receive-pack fails and the ref is unchanged (fail closed). External verification against a hosted service is part of task T0. |

**Residual risks.** A thin push now causes host traffic and a host-side read under the profile's credential; a
profile with both capabilities can make the gateway perform reads it could perform itself. Hosts that do not allow
fetching by SHA, lack `filter`/`shallow` support, or refuse a second session still need `--no-thin`. The
correctness argument relies on the host resolving the pushed delta against the same object HallPass fetched, which
holds for any host that stores objects by ID.

## 4. Scope of the fetch

### 4.1 When it runs

All of these must hold, otherwise behaviour is exactly as today:

- `git.thin_push_bases.enabled` (global, §5);
- at least one ref update needs a fast-forward proof (`RefPolicy.NeedsFastForward`) and `AncestryOf` is `Unknown`;
- the pack is thin (`CommitGraph.Thin()`) and at least one candidate was retained;
- the grant is still active and the profile (re-read, not the snapshot from registration) has `git-read` and its
  repository rules still cover the repository.

### 4.2 Where it goes and with what

- **Connection:** a new session on the destination `*ssh.Client` of the push channel: same TCP connection, same
  verified host key, same login credential (for certificate credentials, the same certificate). If the host refuses a
  second session channel, HallPass dials once more with the same `destssh.Target` (egress guard, verifier, signers)
  and closes that connection after the fetch.
- **Command:** `git-upload-pack <quoted forward path>` with `GIT_PROTOCOL=version=2` set on the session. If the host
  answers with a protocol v0 reference advertisement, HallPass ends the fetch (result `unsupported`).
- **Request:** `command=fetch`, `object-format` matching the push (`sha1` or `sha256`), `no-progress`,
  `ofs-delta`, `deepen 1`, `filter tree:0`, one `want <id>` per candidate base, `done`. Never `have`,
  `thin-pack`, `include-tag`, `want-ref` or `packfile-uris`. The capability advertisement must list
  `fetch` with `shallow` and `filter`; otherwise no request is sent.
- **Response:** `shallow-info` (ignored beyond syntax), then `packfile` over sideband 1; band 2 (progress) is
  discarded, band 3 or `ERR` ends the fetch (result `host_refused`).

### 4.3 What is kept

Every object in the returned pack is inflated (bounded, ≤ 1 MiB, deltas inside the returned pack resolved against
objects of that pack only), its ID recomputed, and it is kept only if the ID is one of the requested IDs **and** its
type is commit. Everything else is dropped. A base that is a tree or blob (a normal thin-pack delta) simply never
resolves to a commit; locally, `filter tree:0` already omits wanted blobs and returns wanted trees alone.

### 4.4 Hosts that do not allow fetching by SHA

Fetching a base the host considers unadvertised fails with `not our ref`. Stock git with protocol v2 served a
reachable, non-tip commit in a local check (git 2.55); hosted services generally allow reachable SHAs, which bases
are (git chose them from the refs it believes the host has). When the host refuses, the result is `host_refused`
and the push stays refused with the `--no-thin` hint. HallPass never retries with different wants.

## 5. Configuration and limits

New top-level section (names final at implementation; all validated at load):

```yaml
git:
  thin_push_bases:
    enabled: true          # operator decision: see ADR-0064 "Open for the operator"
    max_bases: 256         # wants per fetch (1..4096)
    max_fetch_bytes: 8388608  # 8 MiB, whole upload-pack response (64 KiB..64 MiB)
    timeout: 20s           # whole fetch, from session open to last byte (1s..120s)
    max_concurrent: 4      # simultaneous fetches gateway-wide (1..64); a push that cannot get a slot within the
                           # timeout is refused with the hint
```

Internal constants in `gitproto` (not configurable): candidate delta source and result ≤ `maxCommitBytes`
(1 MiB); retained candidate bytes ≤ 16 MiB and count ≤ 4096, inside the existing `maxTotalCommitData` budget.

## 6. Implementation plan

### 6.1 Touched packages

| Package | Change |
|---|---|
| `internal/gitproto` (`pack.go`) | `ScanPack` retains candidate `REF_DELTA`s (and `OFS_DELTA`s whose base is a retained candidate) within the caps; `CommitGraph.ThinBases() [][]byte` lists the missing base IDs; `CommitGraph.ResolveWith(bases map[string]Object) error` applies retained deltas to verified commit bases, adds the resulting commits (IDs computed from content) and leaves bases out of the graph. |
| `internal/gitproto` (new `fetch.go`) | Protocol v2 fetch client over an `io.ReadWriter`: capability check, request writer, bounded pkt-line/sideband reader, pack reader that returns only verified commit objects among the wanted IDs. No SSH or network code. |
| `internal/sshproxy` (`git.go`, `proxy.go`) | After an `Unknown` + thin result: revalidate, take the semaphore, open the upload-pack session on the push's client (fallback dial), run the fetch under the budget and the channel's context, resolve, re-check, write the trailer only when proven and the channel is live; record `base_fetch` on `git.push`/`git.push_refused` and `bytes_fetched` on `git.transferred`. The terminator also closes the fetch session. |
| `internal/access` | A read-only `RevalidateGit(ctx, reg, capability)` check (grant active, role re-read, capability and repository still allowed) without reserving concurrency: the fetch is part of the registered push channel, not a new agent channel. |
| `internal/config` | `git.thin_push_bases` section, defaults, validation, `HALLPASS_GIT_THIN_PUSH_BASES_*` overrides. |
| `internal/obs/metrics` | `hallpass_git_base_fetch_total{result}`, `hallpass_git_base_fetch_duration_seconds`, `hallpass_git_base_fetch_bytes`. |
| docs | ADR-0064 status, R-17, THREAT_MODEL T-28, `docs/operator/configuration.md`, `site/operators/git.md`, `site/agents/index.md`, `docs/security-guarantees.md`, CHANGELOG. |

`base_fetch` result classes: `proven`, `not_proven` (fetched, still not a fast-forward), `no_read` (profile lacks
`git-read`), `disabled`, `no_candidates`, `limit`, `timeout`, `busy`, `unsupported` (v0, no `filter` or
`shallow`, wrong object format), `host_refused`, `session_refused`, `error`. With requested, received and
resolved counts, bytes and duration. Never object content.

### 6.2 Test plan

The test that fails today: **`TestGatewayGitPushThinPackAfterBitmapRepack`** (`internal/app/git_push_e2e_test.go`)
changes so that the default thin push after `git repack -a -d -f -b` succeeds, `main` on the host equals the merge
commit, and the `git.push` event has `base_fetch.result = proven`. The `--no-thin` push stays as a second case on
another branch. Today it fails because the thin push is refused.

End-to-end (`internal/app`, real `git` and `git-receive-pack`/`git-upload-pack` behind `host.Exec`):

- profile with `git-write` only: the thin push is refused with the hint and the host never runs `git-upload-pack`
  (the test host records every command);
- `enabled: false`: refused with the hint, no upload-pack;
- a real non-fast-forward sent thin (rewritten history after a bitmap repack): refused after the fetch, ref unchanged;
- host upload-pack refuses (`not our ref`), answers v0, lacks `filter`, hangs past `timeout`, or returns more than
  `max_fetch_bytes`: refused with the hint, ref unchanged, matching `base_fetch.result`;
- grant revoked while upload-pack hangs: channel ends within 5 s, ref unchanged, no goroutine leak;
- host refuses a second session (test sshd that allows one session per connection): the fallback dial is used and
  the push is proven.

Unit (`internal/gitproto`, packs built with real git in temporary repositories and hand-built packs):

- candidate retention: commit-sized `REF_DELTA`s kept, large ones not, caps enforced (`complete` false, `Unknown`);
- `ResolveWith`: proven with the right base; a base whose content does not hash to its ID is ignored; a base of the
  wrong type is ignored; a base equal to the update's new or old ID never makes `AncestryOf` return `FastForward` by
  itself; `OFS_DELTA` chained on a resolved candidate; a crafted delta producing a commit with a different ID than
  the update stays `Unknown`;
- fetch client against a scripted upload-pack: request bytes exactly as specified (no `have`, no `thin-pack`), v0
  advertisement, missing capabilities, `ERR`, sideband 3, truncated pkt-lines, extra unwanted objects dropped,
  objects over 1 MiB dropped, byte budget enforced while streaming.

`internal/sshproxy`: revalidation failure skips the fetch; trailer not written after termination; semaphore
exhaustion gives `busy`.

OpenSSH interop (`make test-openssh`): one thin push after a bitmap repack against the git container, through a
real OpenSSH sshd (second session on one connection).

External verification (recorded as such, not as CI): one thin push through the gateway to a hosted git service
(test repository, placeholder names in the evidence).

### 6.3 Fuzz targets

- `FuzzScanPack` (existing): extended corpus with thin packs; asserts caps hold and `ThinBases` is consistent.
- `FuzzResolveWith`: arbitrary pack plus arbitrary base objects; must never return `FastForward` for an update whose
  new ID is not the computed ID of a resolved pack commit, never panic, stay within the caps.
- `FuzzFetchResponse`: arbitrary upload-pack response bytes into the fetch client; no panic, bounded memory, only
  wanted IDs with matching hashes returned.
- `FuzzApplyDelta`: base and delta bytes (the delta code becomes reachable with host-supplied bases).

### 6.4 Task split

| Task | Scope | Writer tier | Depends on |
|---|---|---|---|
| T0 | Spike: verify against a hosted git service and OpenSSH that a second session on one connection works, that `deepen 1` + `filter tree:0` + `want <reachable sha>` returns only commits, and how long receive-pack waits for the checksum. Needs gateway access approved by the operator. Report only, no code. | medium | approval of ADR-0064 |
| T1 | `gitproto` core: candidate retention in `ScanPack`, `ThinBases`, `ResolveWith` with hash verification, unit tests, `FuzzResolveWith`, `FuzzApplyDelta`. The soundness of the proof lives here. | **hard** | — |
| T2 | `gitproto` fetch client (`fetch.go`): v2 request, capability check, bounded pkt-line/sideband/pack reading, unit tests, `FuzzFetchResponse`. Security impact limited to availability because T1 re-verifies everything. | medium | — |
| T3 | `sshproxy` + `access` integration: trigger conditions, `RevalidateGit`, second session and fallback dial, semaphore, budgets, terminator, trailer only when proven and live, events; flip `TestGatewayGitPushThinPackAfterBitmapRepack`. | **hard** | T0, T1, T2, T4 |
| T4 | Config section, validation, env overrides, metrics, `docs/operator/configuration.md`. | light | — |
| T5 | Negative end-to-end tests (§6.2 list) and the OpenSSH interop case. | medium | T3 |
| T6 | Docs and status: ADR-0064 status, R-17 resolved, THREAT_MODEL T-28 status, operator and agent guides, security guarantees, CHANGELOG. | light | T3, T5 |

T1, T2 and T4 can run in parallel. T3 and T1 need an independent security review before merge.
