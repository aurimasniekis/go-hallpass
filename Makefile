SHELL := /usr/bin/env bash
GO ?= go
BIN := bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/aurimasniekis/go-hallpass/internal/buildinfo.Version=$(VERSION)
FUZZTIME ?= 30s

.PHONY: all build test race lint vet custom-vet fuzz-smoke coverage vuln tools-test generate check clean

all: check build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/hallpass ./cmd/hallpass

test:
	$(GO) test ./...

race:
	$(GO) test -race -count=1 ./...

$(BIN)/hallpass-vet: $(shell find tools -name '*.go' -not -path '*/testdata/*')
	cd tools && $(GO) build -o ../$(BIN)/hallpass-vet ./cmd/hallpass-vet

custom-vet: $(BIN)/hallpass-vet
	$(GO) vet -vettool=$(abspath $(BIN)/hallpass-vet) ./...

vet:
	$(GO) vet ./...

lint:
	golangci-lint run ./...
	golangci-lint run --build-tags openssh ./test/...

tools-test:
	cd tools && $(GO) test ./...

# Runs every Fuzz* target for FUZZTIME (HP-TST-002 smoke; release runs use FUZZTIME=10m).
fuzz-smoke:
	@set -e; for pkg in $$($(GO) list ./...); do \
	  for fz in $$($(GO) test -list '^Fuzz' $$pkg 2>/dev/null | grep '^Fuzz' || true); do \
	    echo "fuzz $$pkg $$fz"; $(GO) test -run '^$$' -fuzz "^$$fz$$" -fuzztime $(FUZZTIME) $$pkg; \
	  done; \
	done

coverage:
	./scripts/coverage-floor.sh

vuln:
	govulncheck ./...

generate:
	$(GO) generate ./...

check: vet custom-vet lint race tools-test coverage

clean:
	rm -rf $(BIN)

.PHONY: sqlc sqlc-check
bin/sqlc:
	./scripts/install-sqlc.sh

# Regenerate typed queries from internal/store/{migrations,queries}.
sqlc: bin/sqlc
	bin/sqlc generate

# CI drift check: generated code must match the committed SQL.
sqlc-check: bin/sqlc
	bin/sqlc diff

.PHONY: api api-check
# HP-API-001: regenerate the operation table / server interface and the UI's TypeScript types from api/openapi.yaml.
api:
	go run ./internal/tools/apigen -spec api/openapi.yaml -out internal/httpapi/gen/operations.gen.go
	cd web && pnpm exec openapi-typescript ../api/openapi.yaml -o src/api/schema.gen.ts

# Fails when generated code drifts from the spec.
api-check: api
	git diff --exit-code -- internal/httpapi/gen web/src/api/schema.gen.ts

.PHONY: test-openssh
# HP-TST-003: real OpenSSH client + in-process gateway + OpenSSH sshd container (requires Docker and ssh).
test-openssh:
	go test -tags openssh -count=1 -timeout 15m -v ./test/openssh/

.PHONY: test-netfs
# HP-DB-007: verify network/FUSE filesystem refusal on Linux (Docker bind mounts are FUSE on Docker Desktop).
test-netfs:
	docker run --rm -v "$(CURDIR)":/src -w /src -e GOTOOLCHAIN=auto -e GOFLAGS=-buildvcs=false \
	  -e HALLPASS_TEST_NETFS_DIR=/src/.netfs-test golang:1.27 \
	  sh -c 'mkdir -p /src/.netfs-test && go test -count=1 -run "Filesystem" -v ./internal/store/; rc=$$?; rm -rf /src/.netfs-test; exit $$rc'

# ---- WP24: packaging and release (appended block; docs/operator/install.md, docs/operator/container.md) ----
IMAGE ?= hallpass:local

.PHONY: release-snapshot image image-smoke

# Static release archives + SHA256SUMS for linux/amd64, linux/arm64, darwin/arm64 in dist/ (scripts/release-build.sh).
release-snapshot:
	VERSION=$(VERSION) ./scripts/release-build.sh -o dist

# Local container image for the build platform (never pushed).
image:
	docker buildx build --load -t $(IMAGE) --build-arg VERSION=$(VERSION) .

# Container smoke test against $(IMAGE): non-root, no shell, KEK checks, migrate, serve + SSH banner, clean SIGTERM.
image-smoke:
	./scripts/container-smoke.sh $(IMAGE)
# ---- end WP24 ----
