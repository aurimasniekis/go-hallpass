# syntax=docker/dockerfile:1.7
#
# Hallpass container image (PLAN WP24, ADR-0022, HP-OPS-007).
#
#   web    : builds the operator UI (web/dist) with the locked pnpm dependency tree.
#   build  : static Go binary (CGO_ENABLED=0, -trimpath), cross-compiled on the build platform (no emulation).
#   final  : distroless static, non-root (UID/GID 65532), no shell, no package manager.
#
# Every base image is pinned by digest. Update a digest with:
#   docker buildx imagetools inspect <image>:<tag>      # use the index "Digest:" line
#
# Runtime layout (see docs/operator/container.md):
#   /usr/local/bin/hallpass          binary (root-owned, read-only)
#   /etc/hallpass/hallpass.yaml      configuration, mount read-only (HALLPASS_CONFIG points here)
#   /var/lib/hallpass                data volume (0700, 65532:65532)
#   KEK                              mount separately (e.g. /run/secrets/hallpass_kek); never inside the data volume
#
# Build:  docker buildx build --build-arg VERSION=v1.2.3 --build-arg COMMIT=$(git rev-parse HEAD) \
#           --build-arg BUILD_DATE=2026-01-02T03:04:05Z -t hallpass:local .

ARG NODE_IMAGE=docker.io/library/node:24.22.0-bookworm-slim@sha256:91acba91b842bec0bf7ea6f5e09c644c7ccad72c4996ed9616d861d1c7cd60d4
ARG GO_IMAGE=docker.io/library/golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

# ---------------------------------------------------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS web
ENV CI=true \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    PNPM_HOME=/pnpm \
    PATH=/pnpm:$PATH
WORKDIR /src/web
# pnpm version comes from "packageManager" in web/package.json (corepack verifies the download signature).
COPY web/package.json web/pnpm-lock.yaml ./
RUN corepack enable && corepack install
RUN --mount=type=cache,id=hallpass-pnpm-store,target=/pnpm/store \
    pnpm config set store-dir /pnpm/store && \
    pnpm install --frozen-lockfile
COPY web/ ./
# `pnpm build` = typecheck + vite build + CSP/dev-code leak check (web/scripts/check-dist.mjs).
RUN pnpm build

# ---------------------------------------------------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=
ARG BUILD_DATE=
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download && go mod verify
COPY cmd/ cmd/
COPY internal/ internal/
COPY api/ api/
# The webui Go package (embed and SPA handler) plus the UI bundle it embeds with -tags embedui (HP-UI-016).
COPY web/*.go web/
COPY --from=web /src/web/dist/ web/dist/
# -buildvcs=false: the build context deliberately excludes .git; version metadata comes from build args instead.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -tags embedui -trimpath -buildvcs=false \
      -ldflags "-s -w -buildid= \
        -X github.com/aurimasniekis/go-hallpass/internal/buildinfo.Version=${VERSION} \
        -X github.com/aurimasniekis/go-hallpass/internal/buildinfo.Commit=${COMMIT} \
        -X github.com/aurimasniekis/go-hallpass/internal/buildinfo.Date=${BUILD_DATE}" \
      -o /out/hallpass ./cmd/hallpass
# Directory skeleton for the final image (it has no shell, so ownership and modes are prepared here).
# A named volume mounted at /var/lib/hallpass inherits this ownership and mode on first use.
RUN install -d -m 0700 -o 65532 -g 65532 /rootfs/var/lib/hallpass && \
    install -d -m 0755 -o 0 -g 0 /rootfs/etc/hallpass

# ---------------------------------------------------------------------------------------------------------------------
FROM ${RUNTIME_IMAGE}
ARG VERSION=dev
ARG COMMIT=
LABEL org.opencontainers.image.title="hallpass" \
      org.opencontainers.image.description="Terminating SSH access gateway for AI agents" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian12:nonroot"
COPY --from=build --chown=0:0 --chmod=0555 /out/hallpass /usr/local/bin/hallpass
COPY --from=build /rootfs/ /
ENV HALLPASS_CONFIG=/etc/hallpass/hallpass.yaml
USER 65532:65532
WORKDIR /var/lib/hallpass
VOLUME ["/var/lib/hallpass"]
# ssh.listen and http.listen defaults (internal/config/defaults.go). The HTTP console/API arrives with WP15.
EXPOSE 2222/tcp 8080/tcp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/hallpass"]
CMD ["serve"]
