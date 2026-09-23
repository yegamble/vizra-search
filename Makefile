# vizra-search — build and verification lanes.
#
# `make ci` is the complete gate. Every lane below is listed in
# .github/required-checks.txt, and a lane that does not run is a failure, never
# a pass (ADR-002 § CI fan-in).
#
# CI does not trust this file to be honest about itself. One line here —
# `SHELL := /usr/bin/true`, `MAKEFLAGS += -i` — would no-op every recipe, and no
# check inside a Makefile can stop that. So every `make` step in
# .github/workflows/ci.yml is byte-equal to an entry in .github/pinned-steps.yml
# and is IMMEDIATELY preceded by `./scripts/make-integrity-guard.sh --workflow`,
# which reads this file (and anything it includes) and the step's environment
# from outside make, and refuses a no-op by name. The `test-noskip` lane runs the
# suite WITHOUT make, so a failing test fails a required lane whatever this file
# says. See AGENTS.md § "The make lanes cannot be silenced".
#
# THIS FILE IS PINNED BY ITS BYTES. The anchor refuses to invoke make unless
# this file matches its sha256 in .github/pinned-makefiles.yml, so an edit here
# is mergeable only together with a reviewed edit to that pin:
#   shasum -a 256 Makefile

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
ci: fmt-check vet echo-containment build contract-drift test test-noskip tidy-check vendor-contract-selftest ## Every required lane, in order

.PHONY: fmt-check
fmt-check: ## Fail if any file is not gofmt-clean
	@unformatted="$$($(GOFMT) -l cmd internal scripts)"; \
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
#           vendored-file guard that is missing from the list below. It ALSO
#           reads this file's text, because a `-` prefix on a recipe line makes
#           make ignore that line's exit status and `make --dry-run` prints the
#           command WITHOUT the `-`: the guard would refuse the lane, print its
#           refusal, and the lane would still exit 0.
#   ran     reads the report afterwards and refuses a lane that ran zero tests
#           in any listed package, which is what a filter that selects nothing
#           looks like from the outside.
#
# A recipe step alone is not enough: every check invoked by this recipe dies
# with it, and a duplicate `contract-drift:` target supplying its own recipe
# replaces these two lines outright. So `recipe` also runs as its own step in
# .github/workflows/ci.yml BEFORE `make contract-drift`, where no Makefile edit
# reaches it, and scripts/ci-required-guard.sh asserts that step is there,
# unconditional and able to fail.
#
# A Makefile-level `SHELL := /usr/bin/true` or `MAKEFLAGS += -i` — one line that
# no-ops every recipe here — used to be listed as what none of this stops. It is
# now refused BY NAME before `make contract-drift` runs, by the pinned
# make-integrity-guard anchor step in ci.yml, from outside make; and the
# `test-noskip` lane runs every package, the drift guards included, without make.
#
# `|| true` on the test line is not swallowing the result: the `ran` step is the
# authority on pass/fail, it prints the real test output, and `recipe` refuses
# the lane if that step is not the last command. It is the ONE swallowing suffix
# scripts/make-integrity-guard.py accepts, keyed to this target and these exact
# bytes (SWALLOW_EXEMPT); the same suffix anywhere else in a gate recipe is red.
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

# test-noskip proves the claim "nothing skipped or fake" of Q-001. It is local
# parity for the `test-noskip` CI lane, which runs the SAME `go test -json` and
# the same report DIRECTLY, without make (.github/pinned-steps.yml). The report
# fails on any skipped test and any package with no test files, holds EVERY
# package to its executed-test floor in scripts/test-floors.json, refuses a
# package that has no floor, judges `go test`'s own exit code, and prints the
# counts.
.PHONY: test-noskip
test-noskip: ## Fail on any skip, any package under its executed-test floor, or any package with no floor
	@rc=0; go test -count=1 -json $(PKG) > .test-events.json || rc=$$?; echo "$$rc" > .test-exit.txt; \
	python3 scripts/go-test-report.py --events .test-events.json --suite unit \
		--floors scripts/test-floors.json --go-exit-file .test-exit.txt || exit 1; \
	exit "$$rc"

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

# The two files under api/ that this repository does NOT own are vendored from
# vizra-core. Re-vendoring them by hand is how the manifest and the bytes drift
# apart: PR #1 hand-recorded a commit that a squash-merge then deleted, and a
# hand-typed sha256 is a checksum of someone's attention. scripts/vendor-contract.py
# is therefore the single writer of api/search-internal.openapi.yaml,
# api/search-hmac-testvectors.json and api/CONTRACT-SOURCE.json.
#
# CORE points at a vizra-core checkout, which the script only ever reads
# (remote get-url / rev-parse / for-each-ref / log / merge-base / cat-file / show). It is
# NOT run in CI: CI has no core checkout, and `contract-drift` already fails on
# any drift from the manifest.
#
# vendor-contract-selftest is different: it builds throwaway repositories with
# `git init` and needs no core checkout and no network, so it IS a required CI
# lane (`vendor-contract-selftest` in ci.yml, .github/required-checks.txt and the
# FLOOR_LANES of scripts/ci-required-guard.py) and part of `ci:`. Removing a
# refusal from vendor-contract.py is therefore red in CI, not only locally.
CORE ?= ../vizra-core
CORE_REMOTE ?= origin

.PHONY: vendor-contract
vendor-contract: ## Re-vendor the core contract + HMAC vectors and rewrite api/CONTRACT-SOURCE.json (CORE=<path>)
	./scripts/vendor-contract.py --core '$(CORE)' --remote '$(CORE_REMOTE)'

.PHONY: vendor-contract-check
vendor-contract-check: ## Verify every vendored file still matches api/CONTRACT-SOURCE.json
	./scripts/vendor-contract.py --check

.PHONY: vendor-contract-selftest
vendor-contract-selftest: ## Fire every refusal vendor-contract.py advertises, against throwaway repos (no network)
	./scripts/vendor-contract-selftest.py

# The development key is a published constant in this repository, so anyone on
# the developer's network could sign a valid request against a process that
# binds every interface. `run` therefore binds loopback explicitly rather than
# inheriting the container default of ":8081".
.PHONY: run
run: ## Run locally in development mode, on loopback only, with the documented dev key
	VIZRA_MODE=development \
	VIZRA_SEARCH_ADDR=127.0.0.1:8081 \
	SEARCH_HMAC_KEY=dev-insecure-hmac-key-do-not-use-in-production \
	go run ./cmd/$(BINARY)

# The runtime-mode boot matrix, against the REAL binary: VIZRA_MODE decides the
# mode, VIZRA_SEARCH_MODE is core's topology and is never read as one. Not a CI
# lane — the `test` lane already drives the same refusals through the binary
# (cmd/vizra-search/main_test.go); this is the operator-facing demonstration and
# the home of the three controlled mutations.
.PHONY: boot-matrix
boot-matrix: ## Boot the real binary across the VIZRA_MODE / VIZRA_SEARCH_MODE matrix
	./scripts/boot-matrix.sh

.PHONY: docker-build
docker-build: ## Build the image natively (no emulation)
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(IMAGE) .

.PHONY: clean
clean: ## Remove build output
	rm -rf bin .test-report.json .test-events.json .test-exit.txt $(DRIFT_REPORT)
