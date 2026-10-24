# Releasing HallPass

This is the maintainer procedure for publishing a version. Version numbers follow [VERSIONING.md](VERSIONING.md).
A release is cut from `main` by pushing a `vX.Y.Z` tag; the [release workflow](../.github/workflows/release.yaml)
does the rest and stops at a **draft** GitHub release that a maintainer reviews and publishes.

## One-time setup

| What | Where |
|---|---|
| Docker Hub access token with **Read & Write** scope for `aurimasniekis/hallpass` | Repository secret `DOCKERHUB_TOKEN` (`gh secret set DOCKERHUB_TOKEN`). The Docker Hub user is `DOCKERHUB_USER` in the workflow. Without the secret the publish job fails before pushing anything. |
| Docker Hub repository `aurimasniekis/hallpass` | Created on the first push if it does not exist. Set it public and add a short description linking to the documentation. |
| GHCR package `ghcr.io/aurimasniekis/go-hallpass` | Created on the first push as **private**. Make it public once (package settings → visibility) so the mirror can be pulled anonymously. |
| Private vulnerability reporting | Repository settings → Security → enable "Private vulnerability reporting" ([SECURITY.md](../SECURITY.md) points reporters there). |
| GitHub Actions artifact storage | The release workflow passes binaries and images between jobs as artifacts. Keep the account under its storage quota. |

## Checklist

1. **Gates.** Evaluate RG-1…RG-11 ([GOAL.md](GOAL.md) §8) and write the result to
   `docs/evidence/vX.Y.Z/release-gates.md`, with evidence links. A version below 1.0 may ship with failing gates only
   when they are listed as known limitations; HallPass is never called stable or production-ready unless every gate
   passes. Record any operator decision to release with open gates in [DECISIONS.md](DECISIONS.md).
2. **CI.** `main` is green on GitHub for the commit to be tagged: the `ci` workflow, including the browser E2E job, and
   the OpenSSH interop job. Run the slower local suites as well: `make test-fault`, `scripts/recovery-drill.sh`.
3. **Changelog.** Move the `[Unreleased]` entries into `## [X.Y.Z] - YYYY-MM-DD` in [CHANGELOG.md](../CHANGELOG.md),
   update the comparison links at the bottom, and keep the "Recording format and keyring not externally reviewed"
   label until R-02 is resolved by an external review. The release workflow refuses a tag without this section and
   uses it as the release notes.
4. **Version references.** Install examples name the current version. Find them with the previous version, for
   example `git grep -nF 0.1.0 -- README.md site docs/operator deploy`, and update them, together with the status
   and known limitations in `README.md`, [site/security/index.md](../site/security/index.md) and the FAQ.
5. **Screenshots.** If the UI changed visibly, regenerate them with [`scripts/screenshots.sh`](../scripts/screenshots.sh)
   (fictional data on a throwaway instance) and review every image before committing.
6. **Commit** these changes on `main` (`docs: prepare vX.Y.Z release`) and push. Wait for CI.
7. **Tag** the exact commit CI tested and push the tag:

   ```sh
   git tag -a vX.Y.Z -m "HallPass vX.Y.Z"
   git push origin vX.Y.Z
   ```

8. **Watch the release workflow.** It runs the race tests, builds reproducible archives and SBOMs, builds and scans
   both image architectures with Trivy, runs the container smoke test, pushes one multi-arch manifest to Docker Hub
   and GHCR, attests archives and images, and creates a draft release with the changelog section, image digests and
   all files.
9. **Review and publish the draft.** Check the notes, the attached archives, `SHA256SUMS` and both SBOMs. Release
   candidates (`vX.Y.Z-rc.N`) are marked as pre-releases automatically and do not move the `latest` image tag.
10. **Verify what was published** from a clean machine:

    ```sh
    V=X.Y.Z
    gh release download v$V --repo aurimasniekis/go-hallpass --pattern "hallpass_${V}_linux_amd64.tar.gz" --pattern SHA256SUMS
    sha256sum --check --ignore-missing SHA256SUMS
    gh attestation verify "hallpass_${V}_linux_amd64.tar.gz" --repo aurimasniekis/go-hallpass
    gh attestation verify "oci://docker.io/aurimasniekis/hallpass:$V" --repo aurimasniekis/go-hallpass
    docker run --rm "aurimasniekis/hallpass:$V" version
    ```

11. **After the release**, add an empty `## [Unreleased]` section if it is missing and update the evidence index in
    [PLAN.md](PLAN.md) §19.2.

## If something goes wrong

- **The workflow fails before publishing** (tests, Trivy, smoke test): fix on `main`, delete the tag
  (`git push --delete origin vX.Y.Z && git tag -d vX.Y.Z`) and tag the fixed commit. Nothing was published.
- **A published release is broken:** never move or reuse a published tag or image tag. Publish `vX.Y.(Z+1)` with the
  fix and mark the broken GitHub release as such in its notes. Re-tagging would invalidate checksums and attestations
  that users may already have verified.
