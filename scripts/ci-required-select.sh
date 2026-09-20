#!/usr/bin/env bash
#
# Decide whether every required check succeeded on one SHA.
#
# Reads a TSV of check runs on stdin — name, status, conclusion, started_at —
# and the required-check names as $1 (newline separated). Prints a report and
# exits 0 only when every required check completed with `success`.
#
# It is a script rather than an inline workflow step so it can be run and
# demonstrated outside GitHub Actions. CODEOWNERS puts it under owner review.
#
# Duplicate names. A SHA can carry more than one check-run with the same name —
# a re-run, or two workflows defining the same job name. The previous version
# took whichever row the API listed FIRST, so a stale SUCCESS could mask a
# current FAILURE. Rows are now ordered by started_at and the newest decides;
# when two COMPLETED runs of one name disagree, there is no honest winner and
# the aggregate fails loudly instead of choosing.
#
# Exit codes: 0 all required checks succeeded · 1 at least one did not ·
#             2 at least one is still pending or never ran.

set -uo pipefail

required="${1:?usage: ci-required-select.sh <newline-separated required names> < runs.tsv}"
runs="$(cat)"
tab="$(printf '\t')"

pending=0
failed=0

while IFS= read -r check; do
  [ -z "$check" ] && continue

  # All rows for this name, newest first by started_at.
  rows="$(printf '%s\n' "$runs" | awk -F"$tab" -v n="$check" '$1==n' | sort -t"$tab" -k4,4r)"
  if [ -z "$rows" ]; then
    echo "  $check: NEVER RAN"
    pending=1
    continue
  fi

  count="$(printf '%s\n' "$rows" | grep -c . || true)"
  if [ "$count" -gt 1 ]; then
    distinct="$(printf '%s\n' "$rows" | awk -F"$tab" '$2=="completed" {print $3}' | sort -u | grep -c . || true)"
    if [ "$distinct" -gt 1 ]; then
      echo "  $check: AMBIGUOUS — $count check-runs share this name and their conclusions disagree:"
      printf '%s\n' "$rows" | awk -F"$tab" '{printf "      %s %s %s\n", $2, $3, $4}'
      failed=1
      continue
    fi
    echo "  $check: ($count runs with this name, all agreeing)"
  fi

  line="$(printf '%s\n' "$rows" | head -n 1)"
  status="$(printf '%s' "$line" | cut -f2)"
  conclusion="$(printf '%s' "$line" | cut -f3)"

  if [ "$status" != "completed" ]; then
    echo "  $check: $status"
    pending=1
    continue
  fi
  echo "  $check: $conclusion"
  # Only `success` passes. skipped, cancelled, timed_out, failure, neutral and
  # action_required all fail.
  if [ "$conclusion" != "success" ]; then
    failed=1
  fi
done <<< "$required"

if [ "$failed" = "1" ]; then
  echo "ci-required: at least one required check did not succeed"
  exit 1
fi
if [ "$pending" = "1" ]; then
  exit 2
fi
exit 0
