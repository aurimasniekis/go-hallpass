# AGENTS.md — rules for agents working on Hallpass

Hallpass is a security-sensitive terminating SSH gateway for AI agents. These rules apply to every agent session in this repository.

## Before working

1. Read `docs/GOAL.md` (canonical product contract) and `docs/PLAN.md` (execution plan) before making changes.
2. Check `docs/PLAN.md` §19.2 (work-package status) and `docs/DECISIONS.md` §2 (open review items) to find the next work package
   and any blockers.
3. Consult `docs/THREAT_MODEL.md` and `docs/TEST_STRATEGY.md` for the work package's security and test obligations.

## Contract rules

- `docs/GOAL.md` is the canonical product contract. If PLAN.md or code disagrees with it, GOAL.md wins until a recorded decision changes it.
- **Never silently weaken security requirements.** Any change that relaxes a requirement, guarantee or default must be recorded as an ADR in
  `docs/DECISIONS.md`, labeled **security-relevant change**, and flagged for operator review.
- **Never redefine unfinished features as complete.** Do not mark a requirement or work package done unless it meets the definition of done
  (GOAL.md §7).
- **Record deviations** from PLAN.md or GOAL.md, with their justification, in `docs/DECISIONS.md` in the same commit as the deviation.
- **Distinguish implemented, tested and externally verified behavior** in status tables, checklists, docs and reports. Never upgrade a status
  without evidence.
- Keep `docs/PLAN.md` progress (§19.2 status table, §21 acceptance checklist) and `docs/DECISIONS.md` current as part of every work package.
- Requirement IDs (`HP-<AREA>-NNN`) are stable. Never renumber or reuse them. Withdraw with a DECISIONS.md reference instead of deleting.
- Do not invent cryptography. Use only Go standard library and `golang.org/x/crypto` primitives as specified in PLAN.md §13.
- Never use `ssh.InsecureIgnoreHostKey` or an equivalent permissive host-key callback.
- Never commit secrets, credentials, private production data, private infrastructure details or secret-bearing fixtures. Generate test keys at test time.
- Do not add a LICENSE file or choose a license until the operator decides (DECISIONS.md R-01).

## Git workflow (commit locally, never push)

- Work on the `main` branch.
- Commit completed, coherent work: one or more local commits per completed work package, rather than leaving everything uncommitted.
- Before committing: run `git status`, inspect the diff, and stage **only** the relevant files by explicit path. Do not
  commit unrelated user work.
- Generate the commit message with the `/cc` skill (Conventional Commits). `/cc` only prints a message and never stages,
  commits or pushes. Then run `git commit` yourself with that message. The user has authorized local commits.
- If `/cc` is unavailable, do not invent its output or claim it ran. Leave changes intact and report that the required commit workflow is unavailable.
- **Never run `git push`** or otherwise publish repository changes (no remote creation, no PRs, no pushed tags). Pushing requires a separate,
  explicit user instruction for that specific push.
- Do not discard existing changes, force-switch branches, rewrite history, or amend unrelated commits.
- If safely working on `main` is blocked by existing work, preserve that work and report the blocker instead of forcing a destructive operation.
- Report local commit hashes when commits are actually created.
