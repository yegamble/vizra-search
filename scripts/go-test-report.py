#!/usr/bin/env python3
"""go-test-report — make a `go test` lane corroborate what it ran.

Ported from vizra-core `scripts/go-test-report.py` at eeeea068a20118f7af721f024264603b436a1528 and made
STRICTER for this repository: there is no skip allowlist at all, and a package with no test files is a
failure (this repository's `test-noskip` lane always refused one, and Q-001 says nothing is skipped).

WHY THIS EXISTS

`go test ./...` exits 0 when it ran nothing. Move every `*_test.go` aside and it prints `[no test
files]` per package and succeeds (measured in vizra-core, PR#6 VERIFY, FINDING 3). A non-verbose
`go test` prints nothing at all for a skipped test. And a whole-suite floor alone does not notice ONE
package disappearing inside its headroom (core PR#9 VERIFY, FINDING 7).

So the `test-noskip` lane emits `go test -json` and this program judges the events:

  1. the `go test` process's OWN exit code, passed in and judged, never discarded;
  2. every test that FAILED, named, with its output;
  3. every test that SKIPPED, named — always a failure. The floors file may not carry an
     `allowed_skips` entry: a required test that is skipped is not a pass (AGENTS.md);
  4. every package that reported `[no test files]` — a failure: add tests, do not loosen this;
  5. the tests that actually EXECUTED, against the whole-suite floor AND a per-package floor for EVERY
     package; a package that ran tests with no floor recorded is refused, so a new package cannot
     arrive unprotected;
  6. the counts, printed, so the job log carries them.

Exit codes
  0   the suite ran, met every floor, and nothing failed or skipped
  1   anything else — including an empty, unreadable or truncated event stream

Usage
  rc=0; go test -count=1 -json ./... > events.json || rc=$?; echo "$rc" > exit.txt
  go-test-report.py --events events.json --suite unit \
                    --floors scripts/test-floors.json --go-exit-file exit.txt
  go-test-report.py ... --emit-floors      # print floors generated from this run instead of judging
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def fail(*lines: str) -> None:
    print(f"::error::go-test-report: {lines[0]}")
    for extra in lines[1:]:
        print(f"         {extra}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=Path, required=True, help="`go test -json` output")
    ap.add_argument("--suite", required=True, help="the key in the floors file")
    ap.add_argument("--floors", type=Path, required=True)
    ap.add_argument(
        "--emit-floors",
        action="store_true",
        help="print a min_package_tests block generated from this run, with modest headroom, "
        "instead of judging it. This is how the committed floors are produced.",
    )
    ap.add_argument(
        "--go-exit-file",
        type=Path,
        help="a file holding `go test`'s own exit code. Its absence is a FAILURE: a lane "
        "that does not record it cannot judge it.",
    )
    args = ap.parse_args()

    problems = 0

    # --- the floors, which are committed and reviewed ----------------------
    if not args.floors.is_file():
        fail(f"{args.floors} does not exist; there is no floor to hold this suite to.")
        return 1
    try:
        floors_doc = json.loads(args.floors.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"{args.floors} is not valid JSON: {exc}")
        return 1
    suites = floors_doc.get("suites")
    if not isinstance(suites, dict) or args.suite not in suites:
        fail(
            f"{args.floors} has no floor for suite {args.suite!r}.",
            f"Known suites: {sorted(suites) if isinstance(suites, dict) else '(none)'}",
            "A suite with no recorded floor would pass having run nothing.",
        )
        return 1
    floor = suites[args.suite]
    min_tests = floor.get("min_tests")
    if not isinstance(min_tests, int) or min_tests < 1:
        fail(
            f"suite {args.suite!r} has min_tests={min_tests!r} in {args.floors.name}.",
            "A floor of zero or a missing floor is not a floor.",
        )
        return 1
    if floor.get("allowed_skips"):
        fail(
            f"suite {args.suite!r} in {args.floors.name} carries allowed_skips={floor.get('allowed_skips')!r}.",
            "This repository has NO skip allowlist: a required test that is skipped is not a pass",
            "(AGENTS.md, Q-001). Fix or delete the test; do not allowlist it.",
        )
        return 1
    # A whole-suite floor alone does not notice one small package being emptied
    # inside the headroom of a large one. Per-package floors do.
    min_package_tests = floor.get("min_package_tests") or {}
    vacuous = sorted(p for p, n in min_package_tests.items() if not isinstance(n, int) or n < 1)
    if (not min_package_tests or vacuous) and not args.emit_floors:
        fail(
            f"suite {args.suite!r} in {args.floors.name} has "
            + (f"per-package floors below 1 for {vacuous}." if vacuous else "no per-package floors."),
            "Every package carries a floor of at least one executed test, or emptying it is invisible.",
        )
        return 1

    # --- go test's own exit code -------------------------------------------
    go_exit = None
    if args.go_exit_file is None:
        fail(
            "--go-exit-file was not given.",
            "`go test`'s own exit code is an INPUT this program must judge. A lane that",
            "does not record it has a test runner whose failure nothing reads.",
        )
        return 1
    if not args.go_exit_file.is_file():
        fail(f"{args.go_exit_file} does not exist; `go test`'s exit code was not recorded.")
        return 1
    raw = args.go_exit_file.read_text(encoding="utf-8", errors="replace").strip()
    try:
        go_exit = int(raw)
    except ValueError:
        fail(f"{args.go_exit_file} does not contain an integer exit code: {raw!r}")
        return 1

    # --- the event stream ---------------------------------------------------
    if not args.events.is_file():
        fail(f"{args.events} does not exist; the lane produced no test events.")
        return 1

    # (package, test) tuples, never a joined string: a Go import path contains
    # dots, so `f"{pkg}.{test}".split(".")` mangles both halves — it silently
    # made every per-package count 0 and every allowlist lookup miss.
    passed: list[tuple[str, str]] = []
    failed: list[tuple[str, str]] = []
    skipped: list[tuple[str, str]] = []
    pkg_ok: set[str] = set()
    pkg_failed: set[str] = set()
    pkg_no_tests: set[str] = set()
    output: dict[tuple[str, str], list[str]] = {}
    malformed = 0
    events = 0

    with args.events.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                # `go test -json` can interleave a non-JSON line when a test
                # binary crashes before the harness wraps its output. Counted
                # and reported rather than ignored.
                malformed += 1
                continue
            if not isinstance(ev, dict):
                malformed += 1
                continue
            events += 1
            action = ev.get("Action")
            pkg = ev.get("Package") or "(no package)"
            test = ev.get("Test")
            if action == "output" and test:
                output.setdefault((pkg, test), []).append(ev.get("Output") or "")
                continue
            if test:
                if action == "pass":
                    passed.append((pkg, test))
                elif action == "fail":
                    failed.append((pkg, test))
                elif action == "skip":
                    skipped.append((pkg, test))
                continue
            # package-level
            if action == "pass":
                pkg_ok.add(pkg)
            elif action == "fail":
                pkg_failed.add(pkg)
            elif action == "skip":
                # `[no test files]`. Not a skipped test.
                pkg_no_tests.add(pkg)

    if events == 0:
        fail(f"{args.events} contains no `go test -json` events; nothing ran.")
        return 1
    if malformed:
        fail(f"{malformed} line(s) in {args.events} are not JSON events; the stream is truncated or corrupt.")
        problems += 1

    executed = len(passed) + len(failed) + len(skipped)
    every = passed + failed + skipped
    top_level = [(p, t) for p, t in every if "/" not in t]
    per_package: dict[str, int] = {}
    for pkg, _ in every:
        per_package[pkg] = per_package.get(pkg, 0) + 1

    if args.emit_floors:
        # A floor is not an expected count: it exists to catch a package being
        # emptied, not to pin churn. 15% headroom, at least 2 tests of slack, and
        # never below 1.
        print(f'      "min_tests": {max(1, executed - max(5, round(executed * 0.15)))},')
        print('      "min_package_tests": {')
        rows = sorted(per_package.items())
        for n, (pkg, count) in enumerate(rows):
            floor_n = max(1, count - max(2, round(count * 0.15)))
            comma = "" if n == len(rows) - 1 else ","
            print(f'        "{pkg}": {floor_n}{comma}          // measured {count}')
        print("      }")
        return 0

    # --- the report, printed whatever the verdict ---------------------------
    print(f"go-test-report: suite {args.suite!r} from {args.events.name}")
    print(f"  packages ok:              {len(pkg_ok)}")
    print(f"  packages failed:          {len(pkg_failed)}")
    print(f"  packages [no test files]: {len(pkg_no_tests)}")
    print(f"  tests executed:           {executed}  (floor: {min_tests})")
    print(f"    top-level:              {len(top_level)}")
    print(f"    passed:                 {len(passed)}")
    print(f"    failed:                 {len(failed)}")
    print(f"    skipped:                {len(skipped)}")
    print(f"  `go test` exit code:      {go_exit}")
    for pkg in sorted(min_package_tests):
        print(f"  {pkg}: {per_package.get(pkg, 0)} test(s) (floor: {min_package_tests[pkg]})")

    # --- 1. failures --------------------------------------------------------
    for pkg, test in sorted(failed):
        fail(f"FAILED: {pkg}.{test}")
        for chunk in output.get((pkg, test), [])[-40:]:
            print(f"         {chunk.rstrip()}")
    if failed:
        problems += 1
    for pkg in sorted(pkg_failed):
        if not any(p == pkg for p, _ in failed):
            fail(
                f"package {pkg} FAILED with no failing test — a build or a panic before the harness ran.",
            )
            problems += 1

    # --- 2. skips -----------------------------------------------------------
    for pkg, test in sorted(skipped):
        fail(
            f"SKIPPED: {pkg}.{test}",
            "A required test that is skipped is not a pass (AGENTS.md, Q-001), and this repository",
            "has no skip allowlist. Make the test run, or delete it in a reviewed diff.",
        )
        problems += 1
    for pkg in sorted(pkg_no_tests):
        fail(
            f"package {pkg} has NO test files ([no test files]).",
            "Every package in this module carries tests and an executed-test floor. A package with",
            "none is a package whose breakage nothing would notice. Add tests; do not loosen this.",
        )
        problems += 1

    # --- 3. the floor -------------------------------------------------------
    if executed < min_tests:
        fail(
            f"only {executed} test(s) executed; the recorded floor for {args.suite!r} is {min_tests}.",
            "A suite that ran nothing exits 0 on its own: `go test ./...` with every *_test.go",
            "moved aside reports `[no test files]` and succeeds. This floor is what makes that red.",
            f"If the suite legitimately shrank, move the floor in {args.floors.name} in a reviewed diff.",
        )
        problems += 1

    for pkg, want in sorted(min_package_tests.items()):
        got = per_package.get(pkg, 0)
        if got < want:
            fail(
                f"package {pkg} executed {got} test(s); its recorded floor is {want}.",
                "A whole-suite floor does not detect ONE package disappearing inside its headroom",
                "(vizra-core PR#9 VERIFY, FINDING 7). The per-package floor is what makes that red.",
            )
            problems += 1

    # And a package that RAN with no recorded floor is a package whose absence
    # nobody would notice next time. Adding one is a one-line reviewed diff.
    unfloored = sorted(set(per_package) - set(min_package_tests))
    if unfloored:
        fail(
            f"{len(unfloored)} package(s) executed tests with no recorded floor in "
            f"{args.floors.name}: {unfloored}",
            "Every package in a suite carries a floor, so that emptying any one of them is red",
            "rather than absorbed by the whole-suite headroom. Add each with a modest floor:",
            "  python3 scripts/go-test-report.py --events <events.json> --suite <name> \\",
            "    --floors <file> --go-exit-file <file> --emit-floors",
        )
        problems += 1

    # --- 4. go test's own verdict ------------------------------------------
    if go_exit != 0 and not failed and not pkg_failed:
        fail(
            f"`go test` exited {go_exit} but no test or package event reports a failure.",
            "The runner failed for a reason the event stream does not explain — a toolchain",
            "error, a signal, or a truncated stream. It is not a pass.",
        )
        problems += 1
    elif go_exit != 0:
        problems += 1

    if problems:
        print(f"go-test-report: FAILED ({problems} problem(s))")
        return 1
    print(
        f"go-test-report: ok — {executed} test(s) executed across {len(pkg_ok)} package(s), "
        f"0 skips, every package at or above its floor (suite floor {min_tests})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
