#!/usr/bin/env bash
# Thin wrapper around scripts/make-integrity-guard.py (ported from vizra-core at
# eeeea068a20118f7af721f024264603b436a1528), so a workflow step and the Go
# meta-tests invoke the same thing.
#
# It is DELIBERATELY not a make target: the whole point of the program it runs is
# that a neutered Makefile cannot disarm it, which is only true while it runs
# from outside make. .github/workflows/ci.yml invokes it as
# `./scripts/make-integrity-guard.sh --workflow` IMMEDIATELY before every `make`
# step, byte-equal to the `anchor_step` in .github/pinned-steps.yml, and
# scripts/ci-required-guard.py refuses a make step without it.
set -euo pipefail
cd "$(dirname "$0")/.."
if ! command -v python3 >/dev/null 2>&1; then
  echo "make-integrity-guard: python3 is required. This lane is BLOCKED, not passed." >&2
  exit 2
fi
exec python3 scripts/make-integrity-guard.py "$@"
