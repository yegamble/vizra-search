#!/usr/bin/env bash
#
# revendor-demo.sh — the red/green harness for a contract re-vendor.
#
# WHY THIS EXISTS, AND WHY IT IS FUSSY
#
# A re-vendor PR's whole claim is "a drifted vendored file is caught". The way
# that claim goes wrong is not a check that fails to fire — it is a
# demonstration that scores GREEN or RED for a reason unrelated to the mutation
# it says it applied. This repository has already been bitten by exactly that
# twice (a `-run` regex that happened to match the guard's own name; a reject
# fixture that "rejected" because the checker could not parse it). So this
# harness never trusts that a mutation happened:
#
#   * it records the sha256 of the target BEFORE and AFTER writing the mutation
#     and ABORTS (exit 2, "MUTATION DID NOT APPLY") if the digest did not move;
#   * it records the digest again after restoring and ABORTS if the file did not
#     come back byte for byte;
#   * it restores from a pristine copy taken at start, through an EXIT trap, so
#     an interrupted run cannot leave a mutated file behind;
#   * it prints every digest it observed, so a reviewer reads the measurement
#     rather than this script's opinion of it.
#
# A mutation is a single byte, chosen inside a comment (YAML) or a
# non-normative prose string (JSON), so the file stays parseable and the only
# thing that can turn a lane red is the DIGEST check — not a parse error.
#
# USAGE
#   scripts/revendor-demo.sh before <core-main-vectors-file>
#       Run on the tree BEFORE the re-vendor. Drops core main's vectors file in
#       and shows TestEveryVendoredFileMatchesItsManifest going red BY NAME.
#   scripts/revendor-demo.sh after
#       Run on the re-vendored tree. Baseline green, then a one-byte edit of
#       each vendored file against `make contract-drift` AND `make ci`.
#
set -uo pipefail

cd "$(dirname "$0")/.."
REPO="$PWD"

YAML=api/search-internal.openapi.yaml
JSON=api/search-hmac-testvectors.json
MANIFEST=api/CONTRACT-SOURCE.json

PRISTINE=""
FAILURES=0

digest() { shasum -a 256 "$1" | cut -d' ' -f1; }
bytes()  { wc -c < "$1" | tr -d ' '; }

banner() {
	echo
	echo "=============================================================================="
	echo "$*"
	echo "=============================================================================="
}

rule() { echo "------------------------------------------------------------------------------"; }

take_pristine() {
	PRISTINE="$(mktemp -d "${TMPDIR:-/tmp}/revendor-demo-pristine-XXXXXX")"
	mkdir -p "$PRISTINE/api"
	cp "$YAML" "$JSON" "$MANIFEST" "$PRISTINE/api/"
	trap restore_all EXIT
}

# The EXIT trap. Restore FIRST, then drop the pristine copy — in that order, so
# an interrupt between the two leaves the repository correct and only a stray
# temp directory behind, never the reverse. The `case` guard is there because
# this line deletes a directory recursively: if PRISTINE is ever not the path
# mktemp handed us, delete nothing and say so.
restore_all() {
	[ -n "$PRISTINE" ] || return 0
	cp "$PRISTINE/api/$(basename "$YAML")" "$YAML"
	cp "$PRISTINE/api/$(basename "$JSON")" "$JSON"
	cp "$PRISTINE/api/$(basename "$MANIFEST")" "$MANIFEST"
	case "$PRISTINE" in
	*/revendor-demo-pristine-??????)
		rm -rf "$PRISTINE"
		;;
	*)
		echo "not removing unexpected pristine path: $PRISTINE" >&2
		;;
	esac
	PRISTINE=""
}

# mutate_one_byte <file> <needle> <replacement>
# The needle and replacement must be the same length and differ in exactly one
# byte; the function checks both, then checks the file's digest actually moved.
mutate_one_byte() {
	local file="$1" needle="$2" repl="$3"
	local before after
	before="$(digest "$file")"
	python3 - "$file" "$needle" "$repl" <<-'PY'
		import sys
		path, needle, repl = sys.argv[1], sys.argv[2].encode(), sys.argv[3].encode()
		if len(needle) != len(repl):
		    sys.exit("HARNESS BUG: needle and replacement differ in length")
		if sum(a != b for a, b in zip(needle, repl)) != 1:
		    sys.exit("HARNESS BUG: the mutation must change exactly one byte")
		raw = open(path, 'rb').read()
		if raw.count(needle) != 1:
		    sys.exit("HARNESS BUG: anchor %r occurs %d times in %s, want exactly 1"
		             % (needle, raw.count(needle), path))
		open(path, 'wb').write(raw.replace(needle, repl))
	PY
	if [ $? -ne 0 ]; then
		echo "ABORT: the mutation could not be written to $file"
		exit 2
	fi
	after="$(digest "$file")"
	echo "  mutation: one byte in $file"
	echo "    sha256 before mutation: $before"
	echo "    sha256 after  mutation: $after"
	echo "    bytes: $(bytes "$file")  (length preserved)"
	if [ "$before" = "$after" ]; then
		echo "ABORT: MUTATION DID NOT APPLY — $file has the same digest as before."
		echo "       Refusing to score a red/green result for a mutation that never happened."
		exit 2
	fi
}

restore_one() {
	local file="$1" want="$2" got
	cp "$PRISTINE/api/$(basename "$file")" "$file"
	got="$(digest "$file")"
	echo "  restore: $file"
	echo "    sha256 after restore:   $got"
	if [ "$got" != "$want" ]; then
		echo "ABORT: RESTORE DID NOT RESTORE — $file came back as $got, want $want."
		exit 2
	fi
}

# run_lane <label> <expect: PASS|FAIL> <command...>
run_lane() {
	local label="$1" expect="$2"; shift 2
	local out rc
	out="$("$@" 2>&1)"; rc=$?
	echo "  \$ $*"
	echo "$out" | sed 's/^/    | /'
	echo "    exit=$rc  expected=$expect"
	if [ "$expect" = "PASS" ] && [ $rc -ne 0 ]; then
		echo "    *** UNEXPECTED: $label should have passed"; FAILURES=$((FAILURES + 1))
	fi
	if [ "$expect" = "FAIL" ] && [ $rc -eq 0 ]; then
		echo "    *** UNEXPECTED: $label should have failed"; FAILURES=$((FAILURES + 1))
	fi
	LAST_OUT="$out"
	LAST_RC=$rc
}

# assert_names <needle...> — the previous lane's output must name each needle.
# A red exit code alone is not evidence: the lane must go red FOR THE REASON
# claimed. This is the same principle as the fixture-rule checks in PR #2.
assert_names() {
	local n
	for n in "$@"; do
		if printf '%s' "$LAST_OUT" | grep -qF -- "$n"; then
			echo "    names: $n  OK"
		else
			echo "    *** UNEXPECTED: the output does not name '$n'"; FAILURES=$((FAILURES + 1))
		fi
	done
}

# ----------------------------------------------------------------- before ---

demo_before() {
	local new_vectors="$1"
	[ -f "$new_vectors" ] || { echo "usage: $0 before <core-main-vectors-file>"; exit 2; }

	banner "D-A  BEFORE THE RE-VENDOR: core main's vectors file makes the manifest test red"
	echo "Reproduces the observation recorded by the independent verifier of vizra-core"
	echo "PR #6: search's TestEveryVendoredFileMatchesItsManifest goes red on core main's"
	echo "new bytes. That is what makes this re-vendor REQUIRED rather than cosmetic."
	echo
	echo "Host: $(uname -srm)   go: $(go version)   date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "search HEAD: $(git rev-parse HEAD)"
	take_pristine
	local orig; orig="$(digest "$JSON")"

	rule
	echo "state 1 — as vendored on main (the stale pin)"
	echo "  $JSON sha256=$orig bytes=$(bytes "$JSON")"
	echo "  manifest pins: $(python3 -c 'import json,sys; m=json.load(open("api/CONTRACT-SOURCE.json")); print([f["sha256"] for f in m["files"] if f["vendored_path"].endswith("testvectors.json")][0])')"
	echo "  manifest source_commit: $(python3 -c 'import json;print(json.load(open("api/CONTRACT-SOURCE.json"))["source_commit"])')"
	run_lane "manifest test, stale pin" PASS \
		go test -count=1 -run '^TestEveryVendoredFileMatchesItsManifest$' -v ./internal/httpapi/

	rule
	echo "state 2 — core main's bytes dropped in, manifest UNCHANGED"
	cp "$new_vectors" "$JSON"
	local drifted; drifted="$(digest "$JSON")"
	echo "  $JSON sha256=$drifted bytes=$(bytes "$JSON")"
	if [ "$drifted" = "$orig" ]; then
		echo "ABORT: MUTATION DID NOT APPLY — core main's vectors file is byte-identical"
		echo "       to what is vendored, so there would be nothing to re-vendor."
		exit 2
	fi
	run_lane "manifest test, core main bytes" FAIL \
		go test -count=1 -run '^TestEveryVendoredFileMatchesItsManifest$' -v ./internal/httpapi/
	assert_names "TestEveryVendoredFileMatchesItsManifest" \
		"api/search-hmac-testvectors.json does not match its manifest" \
		"$orig" "$drifted" "Re-vendor from yegamble/vizra-core"

	rule
	echo "state 3 — restored"
	restore_one "$JSON" "$orig"
	run_lane "manifest test, restored" PASS \
		go test -count=1 -run '^TestEveryVendoredFileMatchesItsManifest$' ./internal/httpapi/

	finish "D-A"
}

# ------------------------------------------------------------------ after ---

demo_after() {
	banner "D-C  AFTER THE RE-VENDOR: a one-byte edit of a vendored file is caught"
	echo "Each mutation is a single byte inside a comment (YAML) or a non-normative"
	echo "prose string (JSON), so both files stay parseable and the ONLY thing that can"
	echo "turn a lane red is the digest check."
	echo
	echo "Host: $(uname -srm)   go: $(go version)   date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "search HEAD: $(git rev-parse HEAD)"
	take_pristine
	local yaml0 json0
	yaml0="$(digest "$YAML")"; json0="$(digest "$JSON")"

	rule
	echo "state 0 — baseline, re-vendored tree, nothing mutated"
	echo "  $YAML sha256=$yaml0 bytes=$(bytes "$YAML")"
	echo "  $JSON sha256=$json0 bytes=$(bytes "$JSON")"
	echo "  manifest source_commit: $(python3 -c 'import json;print(json.load(open("api/CONTRACT-SOURCE.json"))["source_commit"])')"
	run_lane "vendor-contract --check, baseline" PASS ./scripts/vendor-contract.py --check
	run_lane "contract-drift, baseline" PASS make contract-drift
	run_lane "ci, baseline" PASS make ci

	rule
	echo "state 1 — one byte of $YAML edited in place"
	mutate_one_byte "$YAML" "search INTERNAL contract" "search INTERNAM contract"
	run_lane "contract-drift, YAML drifted" FAIL make contract-drift
	assert_names "TestEveryVendoredFileMatchesItsManifest" \
		"api/search-internal.openapi.yaml does not match its manifest" "$yaml0"
	run_lane "ci, YAML drifted" FAIL make ci
	assert_names "TestEveryVendoredFileMatchesItsManifest" \
		"api/search-internal.openapi.yaml does not match its manifest"
	run_lane "vendor-contract --check, YAML drifted" FAIL ./scripts/vendor-contract.py --check

	rule
	echo "state 2 — $YAML restored"
	restore_one "$YAML" "$yaml0"
	run_lane "contract-drift, restored" PASS make contract-drift

	rule
	echo "state 3 — one byte of $JSON edited in place"
	mutate_one_byte "$JSON" "TEST VECTOR ONLY" "TEST VECTOR ONLZ"
	run_lane "contract-drift, JSON drifted" FAIL make contract-drift
	assert_names "TestEveryVendoredFileMatchesItsManifest" \
		"api/search-hmac-testvectors.json does not match its manifest" "$json0"
	run_lane "ci, JSON drifted" FAIL make ci
	assert_names "TestEveryVendoredFileMatchesItsManifest" \
		"api/search-hmac-testvectors.json does not match its manifest"
	run_lane "vendor-contract --check, JSON drifted" FAIL ./scripts/vendor-contract.py --check

	rule
	echo "state 4 — $JSON restored; both files back to core main's bytes"
	restore_one "$JSON" "$json0"
	echo "  $YAML sha256=$(digest "$YAML")"
	echo "  $JSON sha256=$(digest "$JSON")"
	run_lane "vendor-contract --check, restored" PASS ./scripts/vendor-contract.py --check
	run_lane "contract-drift, restored" PASS make contract-drift
	run_lane "ci, restored" PASS make ci

	finish "D-C"
}

finish() {
	rule
	if [ "$FAILURES" -eq 0 ]; then
		echo "$1: every lane behaved as the demonstration claims. 0 unexpected results."
		exit 0
	fi
	echo "$1: $FAILURES UNEXPECTED RESULT(S) — this demonstration does not support its claim."
	exit 1
}

case "${1:-}" in
before) shift; demo_before "${1:-}" ;;
after)  demo_after ;;
*) echo "usage: $0 before <core-main-vectors-file> | $0 after"; exit 2 ;;
esac
