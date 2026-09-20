#!/usr/bin/env bash
#
# The fan-in guard for vizra-search (ADR-002 § CI fan-in and merge queue).
#
# It is a script rather than an inline workflow step so it can be run and
# demonstrated outside GitHub Actions. CODEOWNERS puts it under owner review.
#
# It enforces three things about .github/required-checks.txt, which the PR
# under test is able to edit:
#   1. a FLOOR of lanes that may never be removed from the manifest;
#   2. every entry is a bare job name, so a lane cannot be neutered in place;
#   3. every entry names a job that actually exists.
# It also rejects continue-on-error anywhere in the workflows.

set -euo pipefail
manifest=".github/required-checks.txt"
test -s "$manifest" || { echo "$manifest is missing or empty"; exit 1; }
required="$(grep -vE '^\s*(#|$)' "$manifest" | tr -d '\r')"
test -n "$required" || { echo "$manifest lists no checks"; exit 1; }
echo "required checks:"; echo "$required" | sed 's/^/  - /'
# ADR-002: the fan-in guard rejects `continue-on-error` on any
# required lane, because a lane that cannot fail is not a gate. The
# pattern matches the YAML key, not the word, so this guard does not
# trip over its own error message.
if grep -rnE '^[[:space:]]*(-[[:space:]]+)?continue-on-error[[:space:]]*:' .github/workflows/; then
  echo "continue-on-error is not allowed on a required lane"
  exit 1
fi
# FLOOR. The manifest is read from the checkout under test, so the
# PR being gated can edit it. Checking only that every name PRESENT
# maps to a real job is not enough: deleting a lane's line would
# leave this check green with that lane no longer required. These
# lanes may not be removed from the manifest by any PR.
#
# The floor lives HERE, in scripts/ci-required-guard.sh — not in the
# workflow and not in the manifest it guards. Being one file away
# from the manifest is a speed bump, not a control: this script is
# also checked out from the PR under test and could be edited in the
# same commit. What actually closes it is the owner ruleset requiring
# CODEOWNERS review on /.github/ and /scripts/, which is an owner
# action after this PR lands (ADR-002 item 9) and is NOT part of it.
# Until that ruleset is applied, "ci-required is the gate" is a
# convention, and this comment says so rather than implying otherwise.
floor="build
test
test-noskip
contract-drift
govulncheck"
absent=0
while IFS= read -r lane; do
  lane="$(printf '%s' "$lane" | tr -d '[:space:]')"
  [ -z "$lane" ] && continue
  if ! printf '%s\n' "$required" | grep -qxF "$lane"; then
    echo "FLOOR VIOLATION: '$lane' is a non-optional lane and must appear in .github/required-checks.txt, but it is absent."
    echo "  A PR may add lanes to the manifest. It may not remove one of the floor lanes,"
    echo "  because that would silently stop gating the thing the lane exists to gate."
    absent=1
  fi
done <<< "$floor"
test "$absent" = "0" || exit 1
echo "floor: every non-optional lane is present in the manifest"
# A manifest entry must be a bare job name. Any annotation — a
# trailing comment, an "optional" marker, a colon-separated field —
# is refused, so a lane cannot be neutered in place instead of being
# deleted.
if printf '%s\n' "$required" | grep -nvE '^[a-z0-9][a-z0-9-]*$'; then
  echo "a required-check entry must be a bare lowercase job name with no annotation"
  exit 1
fi
echo "manifest entries are bare job names"
# Every required check must exist as a job in a workflow, or the
# aggregate would wait forever for something nobody defined.
missing=0
while IFS= read -r check; do
  [ -z "$check" ] && continue
  if ! grep -qE "^  ${check}:\s*$" .github/workflows/*.yml; then
    echo "required check '$check' has no job of that name in .github/workflows/"
    missing=1
  fi
done <<< "$required"
test "$missing" = "0" || exit 1
echo "every required check is defined by a job"

# Every Dockerfile base image that actually resolves to a registry image must
# be pinned by @sha256 digest, so a moved tag cannot change what CI builds and
# what operators run. `scratch` is exempt: it is Docker's reserved empty base,
# not a pullable image, and has no digest.
unpinned=0
while IFS= read -r line; do
  [ -z "$line" ] && continue
  image="$(printf '%s' "$line" | awk '{print $2}')"
  case "$image" in
    scratch) continue ;;
    *@sha256:*) continue ;;
    *)
      echo "UNPINNED BASE IMAGE: '$image' is not pinned by @sha256 digest"
      unpinned=1
      ;;
  esac
done <<< "$(grep -hiE '^FROM[[:space:]]' Dockerfile 2>/dev/null || true)"
test "$unpinned" = "0" || exit 1
echo "every pullable Dockerfile base image is pinned by digest"
