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
