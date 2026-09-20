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
# required lane, because a lane that cannot fail is not a gate.
#
# This PARSES the workflows rather than grepping them. A literal
# grep is evaded by a quoted key, a capitalised key, or a value
# that is a ${{ }} expression, and it also trips over its own error
# message. scripts/check-workflows.py matches the key after
# unquoting and case-folding, ignores the value entirely, and fails
# closed on a workflow it cannot parse. Its negative fixtures live
# in scripts/testdata/.
if ! ./scripts/check-workflows.py; then
  echo "continue-on-error is not allowed on a required lane"
  exit 1
fi
# The contract-drift lane's shape check must also run as its own WORKFLOW step,
# outside make. Every check inside `make contract-drift` is invoked by a line in
# the recipe it guards, so one Makefile edit — a duplicate target supplying its
# own recipe, a `-` prefix, a SHELL override — removes the check along with the
# lane. Asserting the workflow step here means deleting it turns ci-required red.
if ! ./scripts/contract-drift-guard.py workflow; then
  echo "the contract-drift lane has no unconditional out-of-make shape check"
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

# The workflow checker must itself still reject every spelling it exists to
# catch. A checker that silently stopped matching would leave the gate open,
# so its fixtures are exercised on every run rather than only in a
# demonstration.
#
# The fixture set is therefore a FLOOR, checked by name, exactly like the lane
# floor above — and for the same reason. `for fixture in scripts/testdata/*.yml`
# alone is green when the fixtures are gone: with no match bash passes the
# literal glob through, the checker is handed a path that does not exist and
# exits non-zero, and the "must be rejected" branch reads that as a pass. So a
# deleted fixture directory, an empty glob, or a single missing negative fixture
# each have to be a NAMED failure, not a silent one.
#
# A fixture must also be rejected FOR THE REASON IT WAS WRITTEN TO TRIP. The
# first version of this loop read any non-zero exit of the checker as "correctly
# rejected" — and a checker that cannot read, or cannot parse, its input also
# exits non-zero. So `chmod 000` on a reject fixture, or emptying one, left this
# guard at exit 0 still printing a fixture count it had not earned. (The emptied
# case is the one that reaches CI: file modes other than the executable bit do
# not survive a git checkout, but an emptied fixture committed in a PR stays
# emptied.) `test -f` does not test readability either, though its message said
# so.
#
# check-workflows.py therefore answers three ways — 0 clean, 1 VIOLATION,
# 2 UNEVALUABLE — and each reject fixture below DECLARES the rule it must trip.
# The guard requires exit 1 exactly, and requires the reported rule to be the
# declared one. Exit 2 is a named guard failure, never a pass.
fixtures_dir="scripts/testdata"
accept_fixture="wf-clean.yml"
# Every spelling of continue-on-error that a literal grep would miss, each with
# the rule it exists to trip: the key spelling as written, where it sits, and
# the kind of value. Rejection for a DIFFERENT reason than the declared one
# fails this guard — a fixture that has stopped testing what it was written for
# is not a fixture, it is a decoration.
#
#            fixture|at|key spelling|value kind
reject_fixtures="wf-plain.yml|job|continue-on-error|literal-true
wf-quoted-key.yml|job|\"continue-on-error\"|literal-true
wf-capitalised.yml|job|Continue-On-Error|literal-true
wf-expression.yml|step|continue-on-error|expression
wf-false.yml|step|continue-on-error|literal-false"

# The declared set is itself a floor. Without this, deleting a row above would
# lower the fixture floor from 6 to 5 and the guard would still print a tidy
# "N fixtures exercised, floor N" — a count that moved to match whatever was
# left, which is the same class of false green this script exists to remove.
# This number is changed only when a spelling is deliberately added or retired.
expected_reject_fixtures=5
declared_reject_fixtures="$(printf '%s\n' "$reject_fixtures" | grep -c .)"
if [ "$declared_reject_fixtures" != "$expected_reject_fixtures" ]; then
  echo "FIXTURE FLOOR CHANGED: $declared_reject_fixtures reject-fixture rule(s) are declared;"
  echo "  expected_reject_fixtures says $expected_reject_fixtures."
  echo "  A spelling of continue-on-error was added or removed. If that was deliberate, change"
  echo "  expected_reject_fixtures in the same commit so the floor is a decision, not a"
  echo "  consequence of whatever rows happen to be left."
  exit 1
fi

test -d "$fixtures_dir" || {
  echo "MISSING FIXTURES: '$fixtures_dir' does not exist."
  echo "  The workflow checker's negative fixtures are what prove it still catches every"
  echo "  spelling of continue-on-error. With the directory gone there is nothing to prove"
  echo "  it with, and this guard must not pass by default."
  exit 1
}

missing_fixture=0
for entry in "$accept_fixture" $(printf '%s\n' "$reject_fixtures" | cut -d'|' -f1); do
  if [ ! -f "$fixtures_dir/$entry" ]; then
    echo "MISSING FIXTURE: '$fixtures_dir/$entry' is a non-optional fixture and is absent."
    echo "  It is in the floor because the checker must keep proving it handles that spelling."
    missing_fixture=1
  fi
done
test "$missing_fixture" = "0" || exit 1

# Readable and non-empty, checked separately and BEFORE the checker runs, so an
# unusable fixture is never mistaken for a rejected one.
unusable=0
for entry in "$accept_fixture" $(printf '%s\n' "$reject_fixtures" | cut -d'|' -f1); do
  f="$fixtures_dir/$entry"
  if [ ! -r "$f" ]; then
    echo "UNUSABLE FIXTURE: '$f' exists but is not readable."
    echo "  The checker would exit non-zero because it cannot open the file, which must never"
    echo "  be counted as 'the checker rejected it'."
    unusable=1
  elif [ ! -s "$f" ]; then
    echo "UNUSABLE FIXTURE: '$f' is empty."
    echo "  An empty fixture tests nothing; the checker reports UNEVALUABLE, not a rejection."
    unusable=1
  fi
done
test "$unusable" = "0" || exit 1

# Now run every fixture actually present — the floor above is a minimum, not a
# maximum, so a fixture added later is exercised too. An empty glob is refused
# rather than skipped.
shopt -s nullglob
present=("$fixtures_dir"/wf-*.yml)
shopt -u nullglob
if [ "${#present[@]}" -eq 0 ]; then
  echo "NO FIXTURES MATCHED: '$fixtures_dir/wf-*.yml' matched nothing."
  echo "  An empty fixture glob must fail loudly; it previously left this guard green."
  exit 1
fi

# declared_rule <basename> -> "at|key|value", or empty when the fixture carries
# no declaration (a fixture added later, held only to "must be rejected").
declared_rule() {
  printf '%s\n' "$reject_fixtures" | awk -F'|' -v want="$1" \
    '$1 == want { print $2 "|" $3 "|" $4 }'
}

checked=0
for fixture in "${present[@]}"; do
  base="$(basename "$fixture")"
  if [ ! -r "$fixture" ] || [ ! -s "$fixture" ]; then
    echo "UNUSABLE FIXTURE: '$fixture' is unreadable or empty; it cannot be exercised."
    exit 1
  fi
  set +e
  out="$(./scripts/check-workflows.py "$fixture" 2>&1)"
  rc=$?
  set -e
  case "$fixture" in
    *"/$accept_fixture")
      if [ "$rc" != "0" ]; then
        echo "the workflow checker did not accept its own clean fixture: $fixture (exit $rc)"
        printf '%s\n' "$out" | sed 's/^/    /'
        exit 1
      fi
      ;;
    *)
      # Exit 1 EXACTLY. 0 means it accepted a file it must catch; 2 means it
      # could not evaluate the file at all, which is not a rejection.
      if [ "$rc" = "0" ]; then
        echo "the workflow checker ACCEPTED $fixture, which spells continue-on-error in a way it must catch"
        exit 1
      fi
      if [ "$rc" != "1" ]; then
        echo "UNEVALUABLE FIXTURE: the workflow checker could not evaluate $fixture (exit $rc)."
        echo "  Nothing was checked. This is a guard failure, not a rejection."
        printf '%s\n' "$out" | sed 's/^/    /'
        exit 1
      fi
      rule="$(declared_rule "$base")"
      if [ -n "$rule" ]; then
        want_at="$(printf '%s' "$rule" | cut -d'|' -f1)"
        want_key="$(printf '%s' "$rule" | cut -d'|' -f2)"
        want_value="$(printf '%s' "$rule" | cut -d'|' -f3)"
        want_line="VIOLATION $fixture at=$want_at key=$want_key value=$want_value"
        if ! printf '%s\n' "$out" | grep -qF "$want_line"; then
          echo "WRONG RULE TRIPPED: $fixture was rejected, but not for the rule it declares."
          echo "  declared: $want_line"
          echo "  reported:"
          printf '%s\n' "$out" | grep '^VIOLATION ' | sed 's/^/    /' || echo "    (no VIOLATION line at all)"
          exit 1
        fi
      fi
      ;;
  esac
  checked=$((checked + 1))
done

# A count, not a claim. The floor is 1 accept fixture + the reject fixtures
# named above; anything fewer means the loop skipped something.
floor_count=$((expected_reject_fixtures + 1))
if [ "$checked" -lt "$floor_count" ]; then
  echo "only $checked fixture(s) were exercised; the floor is $floor_count"
  exit 1
fi
echo "the workflow checker rejects every continue-on-error spelling in $fixtures_dir/ ($checked fixtures exercised, floor $floor_count)"
