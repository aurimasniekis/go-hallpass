# Container image

The image is built by the root [`Dockerfile`](../../Dockerfile) (PLAN WP24, ADR-0022, HP-OPS-007).

## What is in the image

| Property | Value |
|---|---|
| Base | `gcr.io/distroless/static-debian12:nonroot`, pinned by digest. No shell, no package manager. |
| Binary | `/usr/local/bin/hallpass`, static (`CGO_ENABLED=0`, `-trimpath`), root-owned, mode `0555`. |
| User | `65532:65532` (numeric, so `runAsNonRoot` policies can check it). |
| Entrypoint / command | `hallpass` / `serve`. Any subcommand can be passed instead, e.g. `docker run IMAGE version`. |
| Configuration | `HALLPASS_CONFIG=/etc/hallpass/hallpass.yaml`. Mount the file read-only. |
| Data | `VOLUME /var/lib/hallpass`, created `0700` and owned by `65532:65532`. |
| KEK | Not in the image. Mount it from outside the data volume (below). |
| Ports | `2222/tcp` (agent SSH), `8080/tcp` (web console/API, WP15; nothing listens there yet). |
| Platforms | linux/amd64, linux/arm64. |

Build stages: `web` (Node, `pnpm install --frozen-lockfile && pnpm build` → `web/dist`), `build` (Go, cross-compiled for
the target platform), final (distroless). `web/dist` is placed in the Go build tree for the upcoming `go:embed` of the UI
(HP-UI-016). Until that lands, the binary does not serve the UI.

Build locally (never pushes):

```sh
make image IMAGE=hallpass:local VERSION=v0.0.0-local     # docker buildx build --load
make image-smoke IMAGE=hallpass:local                      # scripts/container-smoke.sh
```

## KEK provisioning

Hallpass refuses a KEK file that is readable by group or others, owned by a UID other than its own (or root), or located
inside `data_dir`. In a container that means:

- The KEK lives **outside the data volume**: a Compose/Swarm secret, a Kubernetes Secret volume, or a separate read-only
  bind mount. A KEK in the data volume would end up in every volume snapshot and backup, defeating the separation of
  data backups and key backups (ADR-0023).
- The file is mode `0400` and owned by UID `65532`. A bind mount shows the host file's owner and mode, so set them on the host:

  ```sh
  hallpass keys init-kek --out /srv/hallpass/hallpass.kek     # release binary on the host
  chown 65532:65532 /srv/hallpass/hallpass.kek               # mode is already 0400
  ```

- Kubernetes is not a documented or tested target yet. Secret volumes are root-owned and `fsGroup` adds group-read bits,
  and Hallpass refuses both a group-readable KEK and one its UID cannot read. A Secret-backed KEK therefore needs an init
  step that copies it into a memory-backed `emptyDir` as `0400 65532:65532`.
- `kek.file` points at the mount, e.g. `/run/secrets/hallpass_kek` (as in
  [`deploy/examples/hallpass.container.yaml`](../../deploy/examples/hallpass.container.yaml)).

Back up the KEK offline before the first start. See [keys.md](keys.md).

## Data volume

- Use a local named volume or a local bind mount. Network filesystems are refused (HP-DB-007). On Docker Desktop,
  bind mounts are FUSE-backed and are refused for the data directory; use a named volume.
- A new named volume inherits `0700 65532:65532` from the image. A bind-mounted directory must be prepared on the host:
  `install -d -m 0700 -o 65532 -g 65532 /srv/hallpass/data`.
- Run exactly one container per volume. A second container fails with `another hallpass process owns this data directory`.

## Hardened `docker run`

```sh
docker volume create hallpass-data
docker run -d --name hallpass \
  --read-only --tmpfs /tmp:size=16m,mode=1777 \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --user 65532:65532 \
  -p 2222:2222 -p 127.0.0.1:8080:8080 \
  -v hallpass-data:/var/lib/hallpass \
  -v /srv/hallpass/hallpass.yaml:/etc/hallpass/hallpass.yaml:ro \
  -v /srv/hallpass/hallpass.kek:/run/secrets/hallpass_kek:ro \
  --stop-timeout 45 \
  ghcr.io/<owner>/<repo>:X.Y.Z serve
```

Offline commands (`migrate`, `keys status`, `hostkey show`, `verify`) take the data-directory lock: stop the serving
container first and run them with the same mounts, e.g. `docker run --rm … IMAGE hostkey show`.

The image has no health-check command and no shell. Once `/readyz` exists (WP22), probe it from the orchestrator or
reverse proxy rather than from inside the container.

## Docker Compose

See [`deploy/compose.yaml`](../../deploy/compose.yaml) and [install.md](install.md#docker-compose). The stop grace period
(45 s) is longer than `shutdown.drain_timeout` (30 s), so draining finishes and recordings are finalized before Docker
sends SIGKILL.

## Smoke test

[`scripts/container-smoke.sh`](../../scripts/container-smoke.sh) checks an image without pushing it: numeric non-root
user, ports, data volume, absence of `/bin/sh`, `version`, KEK provisioning (`0400`, UID 65532), refusal of a KEK inside
the data volume and of a group-readable KEK, `config check`, `migrate` (data volume `0700 65532:65532`), and `serve`
answering with an SSH banner and exiting 0 on SIGTERM, all with a read-only root filesystem and no capabilities.
It does not yet cover `/readyz` (WP22) or an agent running `ssh center list` against a fixture (needs agent bootstrap).

## Supply chain

Base images (Node, Go, distroless) are pinned by digest in the `Dockerfile`. The release workflow
([`.github/workflows/release.yaml`](../../.github/workflows/release.yaml)) scans each platform image with Trivy before
publishing and fails on HIGH/CRITICAL vulnerabilities that have a fix. It pushes to GHCR only for `v*` tags, with BuildKit
SBOM and provenance attestations plus a GitHub build provenance attestation on the image digest.
Verify with `gh attestation verify oci://ghcr.io/<owner>/<repo>:X.Y.Z --repo <owner>/<repo>`.
