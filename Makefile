# vizra-search — build and verification lanes.
#
# `make ci` is the complete gate. Every lane below is listed in
# .github/required-checks.txt, and a lane that does not run is a failure, never
# a pass (ADR-002 § CI fan-in).

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

BINARY      := vizra-search
PKG         := ./...
GOFMT       := $(shell go env GOROOT)/bin/gofmt

VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
BUILD_TIME  ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
IMAGE       ?= vizra-search:$(VERSION)

LDFLAGS := -s -w \
	-X github.com/yegamble/vizra-search/internal/buildinfo.Version=$(VERSION) \
	-X github.com/yegamble/vizra-search/internal/buildinfo.Commit=$(COMMIT) \
	-X github.com/yegamble/vizra-search/internal/buildinfo.BuildTime=$(BUILD_TIME)

.PHONY: help
help: ## List the targets
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ------------------------------------------------------------------- lanes ---

.PHONY: ci
ci: fmt-check vet echo-containment build contract-drift test test-noskip tidy-check ## Every required lane, in order

.PHONY: fmt-check
fmt-check: ## Fail if any file is not gofmt-clean
	@unformatted="$$($(GOFMT) -l cmd internal)"; \
	if [ -n "$$unformatted" ]; then \
		echo "these files are not gofmt-clean:"; echo "$$unformatted"; exit 1; \
	fi
	@echo "fmt-check: clean"

.PHONY: vet
vet: ## go vet
	go vet $(PKG)

.PHONY: echo-containment
echo-containment: ## ADR-001: Echo types stay inside internal/httpapi
	@offenders="$$(grep -rln 'labstack/echo' --include='*.go' cmd internal | grep -v '^internal/httpapi/' || true)"; \
	if [ -n "$$offenders" ]; then \
		echo "ADR-001 confines Echo to internal/httpapi, but these files import it:"; \
		echo "$$offenders"; exit 1; \
	fi
	@echo "echo-containment: Echo is confined to internal/httpapi"

.PHONY: build
build: ## Build the binary
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/$(BINARY)

# contract-drift selects by PACKAGE, never by test name.
#
# It used to carry a `-run` regex of name fragments. That is a guard tied to a
# naming habit: renaming a test to something the regex does not match silently
# drops it out of the lane, with no failure anywhere to say so. It had already
# happened. The manifest guard was `TestVendoredContractMatchesItsManifest`,
# which the regex's `Contract` fragment matched; it was renamed to
# `TestEveryVendoredFileMatchesItsManifest`, which matches no fragment in the
# regex. From then on, editing a vendored file in place — or zeroing a sha256 in
# api/CONTRACT-SOURCE.json — left this lane GREEN. The mutation died only under
# the broader `make ci`, which is not the lane whose name says it checks drift.
#
# The lane is therefore bracketed by two steps that `go test` cannot deselect,
# because the first attempt at this fix put the rule in a Go test INSIDE the
# lane — and `-run 'TestVerifier'` then deselected the very guard that forbids
# `-run`, leaving `ok … [no tests to run]` and exit 0 with the contract drifted.
#
#   recipe  asks `make --dry-run` what this lane will ACTUALLY run — which
#           resolves variables, includes and duplicate targets that a text
#           parser misses — and refuses any flag, wrapper or environment
#           variable that could deselect a guard, plus any package holding a
#           vendored-file guard that is missing from the list below.
#   ran     reads the report afterwards and refuses a lane that ran zero tests
#           in any listed package, which is what a filter that selects nothing
#           looks like from the outside.
#
# `|| true` on the test line is not swallowing the result: the `ran` step is the
# authority on pass/fail, it prints the real test output, and `recipe` refuses
# the lane if that step is not the last command.
DRIFT_PKGS   := ./internal/httpapi/ ./internal/contract/ ./internal/hmacauth/ ./internal/config/
DRIFT_REPORT := .contract-drift-report.json

.PHONY: contract-drift
contract-drift: ## Compare the handlers and the HMAC scheme against the canonical contract owned by vizra-core
	./scripts/contract-drift-guard.py recipe
	go test -count=1 -json $(DRIFT_PKGS) > $(DRIFT_REPORT) || true
	./scripts/contract-drift-guard.py ran $(DRIFT_REPORT)

.PHONY: test
test: ## Full test suite with the race detector
	go test -race -count=1 $(PKG)

# test-noskip proves the claim "nothing skipped or fake" of Q-001: the lane
# fails if any test reports a skip, and fails if the run collects no tests.
.PHONY: test-noskip
test-noskip: ## Fail if any test was skipped, or if no test ran
	@go test -count=1 -json $(PKG) > .test-report.json || { cat .test-report.json; rm -f .test-report.json; exit 1; }
	@skipped="$$(grep -c '"Action":"skip"' .test-report.json || true)"; \
	passed="$$(grep -c '"Action":"pass"' .test-report.json || true)"; \
	rm -f .test-report.json; \
	if [ "$$skipped" != "0" ]; then echo "test-noskip: $$skipped skipped test(s); Q-001 requires that nothing is skipped"; exit 1; fi; \
	if [ "$$passed" -lt 40 ]; then echo "test-noskip: only $$passed pass events; the suite did not run"; exit 1; fi; \
	echo "test-noskip: $$passed pass events, 0 skips"

.PHONY: tidy-check
tidy-check: ## Fail if go.mod/go.sum are not tidy
	@cp go.mod .go.mod.bak && cp go.sum .go.sum.bak
	@go mod tidy
	@if ! diff -q go.mod .go.mod.bak >/dev/null || ! diff -q go.sum .go.sum.bak >/dev/null; then \
		mv .go.mod.bak go.mod; mv .go.sum.bak go.sum; \
		echo "go.mod or go.sum is not tidy; run 'go mod tidy'"; exit 1; \
	fi
	@rm -f .go.mod.bak .go.sum.bak
	@echo "tidy-check: tidy"

# ------------------------------------------------------------------ extras ---

# The development key is a published constant in this repository, so anyone on
# the developer's network could sign a valid request against a process that
# binds every interface. `run` therefore binds loopback explicitly rather than
# inheriting the container default of ":8081".
.PHONY: run
run: ## Run locally in development mode, on loopback only, with the documented dev key
	VIZRA_SEARCH_MODE=development \
	VIZRA_SEARCH_ADDR=127.0.0.1:8081 \
	SEARCH_HMAC_KEY=dev-insecure-hmac-key-do-not-use-in-production \
	go run ./cmd/$(BINARY)

.PHONY: docker-build
docker-build: ## Build the image natively (no emulation)
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(IMAGE) .

.PHONY: clean
clean: ## Remove build output
	rm -rf bin .test-report.json $(DRIFT_REPORT)
