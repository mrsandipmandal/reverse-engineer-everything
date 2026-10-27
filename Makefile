GO ?= go
BIN_DIR := bin
GOBIN := $(CURDIR)/$(BIN_DIR)
export GOBIN

GOLANGCI_LINT_VERSION ?= v2.15.0
GOVULNCHECK_VERSION ?= v1.1.4
ACTIONLINT_VERSION ?= v1.7.12

.PHONY: all tools fmt fmt-check vet test race build cross-build lint vuln actionlint check verify-release clean

all: build

tools:
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	$(GO) install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

fmt:
	gofmt -w .

fmt-check:
	@files="$$(gofmt -l .)"; test -z "$$files" || { echo "gofmt needed:"; echo "$$files"; exit 1; }

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

build:
	mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -o $(BIN_DIR)/ree ./cmd/ree

cross-build:
	@mkdir -p $(BIN_DIR)/cross
	@for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do \
		os=$${target%/*}; arch=$${target#*/}; out=$(BIN_DIR)/cross/ree-$$os-$$arch; \
		if [ "$$os" = windows ]; then out="$$out.exe"; fi; \
		echo "building $$out"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -o "$$out" ./cmd/ree || exit 1; \
	done

lint:
	$(GOBIN)/golangci-lint run ./...

vuln:
	$(GOBIN)/govulncheck ./...

actionlint:
	$(GOBIN)/actionlint

verify-release:
	@test -n "$(TAG)" || { echo "usage: make verify-release TAG=v0.0.1"; exit 2; }
	./scripts/verify-release.sh "$(TAG)"

check: fmt-check vet test race lint vuln actionlint

clean:
	rm -rf $(BIN_DIR)/cross $(BIN_DIR)/ree $(BIN_DIR)/ree.exe
