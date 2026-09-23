#!/usr/bin/env python3
"""ci-hardening-demo — red/green demonstrations for the CI-hardening slice, against REAL files.

Each row is a controlled mutation of a file in THIS repository, applied to a throwaway copy of the
working tree (never the checkout):

  1. the file's sha256 is recorded;
  2. the edit is applied — and the harness REFUSES the row if the `old` text does not occur EXACTLY
     once, or if the bytes did not change (a mutation that did not apply proves nothing);
  3. the sha256 after is recorded;
  4. the row's command must go RED (non-zero) and its output must contain the row's `want` text —
     red for the declared reason, not for any reason;
  5. the file is restored and must be byte-identical (sha256 equal to step 1);
  6. the same command must go GREEN (exit 0) on the restored tree.

Rows with an `env` and no file are environment demonstrations: no digest, same red/green rule.

Usage:
  scripts/ci-hardening-demo.py [--only PREFIX] [--list]

Exit 0 only if every selected row behaved exactly as declared. It needs python3 + PyYAML, go and git,
and no network. It is a demonstration tool, not a CI lane: scripts/scripts_test.go holds the durable
versions of the guard rows and runs in `test` and `test-noskip`.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

STRIP = {"MAKEFLAGS", "GNUMAKEFLAGS", "MFLAGS", "MAKELEVEL", "MAKE_RESTARTS", "MAKEOVERRIDES",
         "MAKECMDGOALS", "MAKEFILES", "BASH_ENV", "ENV", "GOFLAGS", "VERSION", "COMMIT", "BUILD_TIME",
         "IMAGE", "CORE", "CORE_REMOTE", "GITHUB_ENV", "GITHUB_PATH"}

GUARD_SH = ["bash", "scripts/ci-required-guard.sh"]
ANCHOR = ["python3", "scripts/make-integrity-guard.py", "--workflow"]
SELFTEST = ["python3", "scripts/vendor-contract-selftest.py"]


def gotest(pkg: str, run: str) -> list[str]:
    return ["go", "test", "-count=1", "-run", run, pkg]


# The pinned direct body, run as GitHub runs a `run:` step.
DIRECT = ["bash", "-c",
          "python3 -c 'import yaml,sys; sys.stdout.write(yaml.safe_load(open(\".github/pinned-steps.yml\"))"
          "[\"direct_test_steps\"][0])' > .direct-step.sh && bash --noprofile --norc -eo pipefail .direct-step.sh"]

CI = ".github/workflows/ci.yml"
MAKE_TEST = "        run: make test\n"
ANCHOR_BEFORE_TEST = ("      - name: refuse a neutered Makefile or make environment (anchor)\n"
                      "        run: ./scripts/make-integrity-guard.sh --workflow\n      - name: make test\n")
FLAGS_PIN = ".SHELLFLAGS := -eu -o pipefail -c\n"
# Closing slice: the M-3 check as committed, and the inventory test the planted rows run.
M3_CHECK = '            if body.startswith("$") and not body.startswith("$$"):\n'
INVENTORY = gotest("./scripts/", "TestEveryPlaceThatStartsMakeIsGated")
# Re-plan (one line reader): the inert-string grammar test and the reader-identity test. Neither starts make.
GRAMMAR_STRINGS = gotest("./scripts/", "TestTheGrammarRefusesEveryLineReadersCouldSplitDifferently")
ONE_READER = gotest("./scripts/", "TestEveryMakefileReaderConsumesTheOneLineReader")
PLANTED = gotest("./scripts/", "TestTheOneReaderSourceCheckRefusesAPlantedReader")

ROWS = [
    # ---------------------------------------------------------------- item 1
    dict(id="1a", item=1, name="workflow: make -i test", file=CI, old=MAKE_TEST,
         new="        run: make -i test\n", cmd=GUARD_SH, want="not byte-equal"),
    dict(id="1b", item=1, name="workflow: MAKEFLAGS=-i make test", file=CI, old=MAKE_TEST,
         new="        run: MAKEFLAGS=-i make test\n", cmd=GUARD_SH, want="not byte-equal"),
    dict(id="1c", item=1, name="workflow: M=make; $M -i test", file=CI, old=MAKE_TEST,
         new="        run: M=make; $M -i test\n", cmd=GUARD_SH, want="not byte-equal"),
    dict(id="1d", item=1, name="workflow: a shell function named make", file=CI, old=MAKE_TEST,
         new="        run: make(){ :; }; make test\n", cmd=GUARD_SH, want="not byte-equal"),
    dict(id="1e", item=1, name="workflow: if: always() && false", file=CI, old=MAKE_TEST,
         new=MAKE_TEST + "        if: always() && false\n", cmd=GUARD_SH, want="carries ['if']"),
    dict(id="1f", item=1, name="workflow: working-directory:", file=CI, old=MAKE_TEST,
         new=MAKE_TEST + "        working-directory: internal\n", cmd=GUARD_SH, want="carries ['working-directory']"),
    dict(id="1g", item=1, name="workflow: anchor deleted", file=CI, old=ANCHOR_BEFORE_TEST,
         new="      - name: make test\n", cmd=GUARD_SH, want="not immediately preceded"),
    dict(id="1h", item=1, name="workflow: compound anchor writes $GITHUB_ENV", file=CI,
         old="        run: ./scripts/make-integrity-guard.sh --workflow\n      - name: make test\n",
         new="        run: ./scripts/make-integrity-guard.sh --workflow && echo MAKEFLAGS=-i >> \"$GITHUB_ENV\"\n"
             "      - name: make test\n", cmd=GUARD_SH, want="not byte-equal to the pinned anchor"),
    dict(id="1i", item=1, name="workflow: job env MAKELEVEL", file=CI,
         old="  test:\n    name: test\n    runs-on: ubuntu-24.04\n",
         new="  test:\n    name: test\n    runs-on: ubuntu-24.04\n    env:\n      MAKELEVEL: \"1\"\n",
         cmd=GUARD_SH, want="job-level env sets makelevel"),
    dict(id="1j", item=1, name="workflow: duplicate run key", file=CI, old=MAKE_TEST,
         new="        run: make -i test\n" + MAKE_TEST, cmd=GUARD_SH, want="duplicate key 'run'"),
    dict(id="1k", item=1, name="Makefile: one byte changed (the digest gate)", file="Makefile",
         old="SHELL := /bin/bash\n", new="SHELL := /bin/bash \n", cmd=ANCHOR, want="make was not invoked"),
    dict(id="1l", item=1, name="Makefile: an include line + an unpinned included file", file="Makefile",
         old=FLAGS_PIN, new=FLAGS_PIN + "include inc.mk\n", create={"inc.mk": "X := 1\n"}, cmd=ANCHOR,
         want="make was not invoked"),
    dict(id="1m", item=1, name="Makefile: a .SECONDEXPANSION line (desk review FINDING 1)", file="Makefile",
         old=FLAGS_PIN, new=FLAGS_PIN + ".SECONDEXPANSION:\n", cmd=ANCHOR, want="make was not invoked"),
    dict(id="1m2", item=1, name="Makefile: a .RECIPEPREFIX line (desk review FINDING 2)", file="Makefile",
         old="", new=".RECIPEPREFIX := >\n", cmd=ANCHOR, want="make was not invoked"),
    dict(id="1m3", item=1, name="Makefile: MAKEFLAGS += -i", file="Makefile", old=FLAGS_PIN,
         new=FLAGS_PIN + "MAKEFLAGS += -i\n", cmd=ANCHOR, want="does not match its pin"),
    dict(id="1m4", item=1, name="ci-required: Makefile edited without a pin update", file="Makefile",
         old="SHELL := /bin/bash\n", new="SHELL := /bin/bash \n", cmd=GUARD_SH, want="does not match its pin"),
    dict(id="1n", item=1, name="env: MAKELEVEL=1 MAKEFLAGS=-ki (strictness is not the environment's)",
         env={"MAKELEVEL": "1", "MAKEFLAGS": "-ki"}, cmd=ANCHOR, want="makelevel"),
    dict(id="1o", item=1, name="env: VERSION=x (a Makefile ?= variable)", env={"VERSION": "x"}, cmd=ANCHOR,
         want="version='x'"),
    dict(id="1p", item=1, name="implementation: adjacency check disabled", file="scripts/ci-required-guard.py",
         old="            if i == 0 or trim_one_newline(step_run(steps[i - 1]) or \"\") != pins.anchor:\n",
         new="            if False:\n",
         cmd=gotest("./scripts/", "TestCIRequiredGuardRefusesEveryEvasion/anchor"), want="green (exit 0) after the mutation"),
    dict(id="1q", item=1, name="implementation: the digest comparison disabled in makegate",
         file="scripts/makegate.py",
         old="        if digests[rel] != pins[rel]:\n",
         new="        if False:\n",
         cmd=gotest("./scripts/", "TestTheAnchorRunsMakeOnlyOnPinnedBytes"),
         want="--- fail"),
    dict(id="1r", item=1, name="a newer unpinned Makefile.sh beside the Makefile (round-2 FINDING 2)",
         file="Makefile.sh", old="", new="# sibling bytes nobody pinned\n", future_mtime=True,
         assert_unchanged="Makefile", cmd=ANCHOR, want="would remake a pinned makefile"),
    dict(id="1s", item=1, name="the same sibling, through the contract-drift shape check (runs before the anchor)",
         file="Makefile.sh", old="", new="# sibling bytes nobody pinned\n", future_mtime=True,
         assert_unchanged="Makefile", cmd=["python3", "scripts/contract-drift-guard.py", "recipe"],
         want="only `make -q` ran"),
    dict(id="1t", item=1, name="implementation: the remake probe disabled in makegate",
         file="scripts/makegate.py",
         old="    proc = run_make(make, root, [\"-q\", *files])\n    if proc.returncode != 0:\n",
         new="    proc = run_make(make, root, [\"-q\", *files])\n    if False:\n",
         cmd=gotest("./scripts/", "TestTheAnchorRefusesAPinnedMakefileMakeWouldRemake"),
         want="want the remake refusal"),
    dict(id="1u", item=1, name="env: MAKEFILES set (R-2: no make process may start)", env={"MAKEFILES": "/dev/null"},
         cmd=ANCHOR, want="make was not invoked (0 make process(es) started)"),
    dict(id="1v", item=1, name="a new ungated make call in a script (R-1 inventory)", file="scripts/vendor-contract.py",
         old="def main():\n", new="def _ungated():\n    subprocess.run([\"make\", \"ci\"])\n\n\ndef main():\n",
         cmd=gotest("./scripts/", "TestEveryPlaceThatStartsMakeIsGated"),
         want="starts make outside scripts/makegate.py"),
    # ---------------------------------------------------------------- item 2
    dict(id="2a", item=2, name="a planted t.Skip, through the pinned direct body", file="internal/buildinfo/buildinfo_test.go",
         old="", new="\nfunc TestPlantedSkip(t *testing.T) { t.Skip(\"planted\") }\n",
         cmd=DIRECT, want="skipped: github.com/yegamble/vizra-search/internal/buildinfo.testplantedskip"),
    dict(id="2b", item=2, name="a package emptied, through the pinned direct body",
         file="internal/buildinfo/buildinfo_test.go", remove=True, cmd=DIRECT,
         want="internal/buildinfo has no test files"),
    dict(id="2c", item=2, name="implementation: the skip refusal disabled", file="scripts/go-test-report.py",
         old="    for pkg, test in sorted(skipped):\n", new="    for pkg, test in []:\n",
         cmd=gotest("./scripts/", "TestGoTestReport|TestTheDirectStepCannotSwallowGoTestsExit"),
         want="--- fail"),
    dict(id="2d", item=2, name="implementation: the unfloored-package refusal disabled",
         file="scripts/go-test-report.py", old="    if unfloored:\n", new="    if False:\n",
         cmd=gotest("./scripts/", "TestGoTestReport"), want="a_package_with_no_floor"),
    dict(id="2e", item=2, name="implementation: the per-package floor check disabled",
         file="scripts/go-test-report.py", old="        if got < want:\n", new="        if False:\n",
         cmd=gotest("./scripts/", "TestGoTestReport"), want="one_package_below_its_floor"),
    # ---------------------------------------------------------------- item 3
    dict(id="3a", item=3, name="implementation: the loud manifest read reverted to the silent one",
         file="scripts/ci-required-guard.sh",
         old="required=\"$(grep -vE '^\\s*(#|$)' \"$manifest\" | tr -d '\\r' || true)\"\n",
         new="required=\"$(grep -vE '^\\s*(#|$)' \"$manifest\" | tr -d '\\r')\"\n",
         cmd=gotest("./scripts/", "TestTheShellGuardFailsLoudlyOnAnEmptiedManifest"),
         want="without saying why"),
    # ---------------------------------------------------------------- item 4
    dict(id="4a", item=4, name="manifest: vendor-contract-selftest removed", file=".github/required-checks.txt",
         old="\nvendor-contract-selftest\n", new="\n", cmd=GUARD_SH, want="'vendor-contract-selftest' is missing"),
    dict(id="4b", item=4, name="Makefile: vendor-contract-selftest dropped from ci:", file="Makefile",
         old=" tidy-check vendor-contract-selftest ## Every required lane", new=" tidy-check ## Every required lane",
         cmd=GUARD_SH, want="`ci:` and the required lanes disagree"),
    dict(id="4c", item=4, name="workflow: the vendor-contract-selftest job renamed away", file=CI,
         old="  vendor-contract-selftest:\n    name: vendor-contract-selftest\n",
         new="  vendor-contract-selftest-x:\n    name: vendor-contract-selftest-x\n", cmd=GUARD_SH,
         want="'vendor-contract-selftest' matches no job"),
    dict(id="4d", item=4, name="implementation: the shallow-clone refusal removed (what the lane catches)",
         file="scripts/vendor-contract.py", old="    refuse_shallow(core)\n    full_ref, tip = resolve_ref(core, args.remote, args.ref)\n    commit = choose_commit(core, full_ref, args.commit)\n\n    print(\"core checkout",
         new="    full_ref, tip = resolve_ref(core, args.remote, args.ref)\n    commit = choose_commit(core, full_ref, args.commit)\n\n    print(\"core checkout",
         cmd=["python3", "scripts/makegate.py", "--", "vendor-contract-selftest"], want="shallow clone"),
    # ---------------------------------------------------------------- item 5
    dict(id="5a", item=5, name="implementation: parse_remote_url back to parts[-2:]", file="scripts/vendor-contract.py",
         old="    if len(parts) != 2:\n        return host or None, None\n    return host, \"/\".join(parts)\n",
         new="    if len(parts) < 2:\n        return host or None, None\n    return host, \"/\".join(parts[-2:])\n",
         cmd=SELFTEST, want="foreign origin, 4-segment path: expected a refusal, got exit 0"),
    dict(id="5b", item=5, name="implementation: the source_ref_tip shape check removed", file="scripts/vendor-contract.py",
         old="    if not isinstance(recorded_tip, str) or not re.fullmatch(r\"[0-9a-f]{40}\", recorded_tip) \\\n",
         new="    if False and not isinstance(recorded_tip, str) or False and not re.fullmatch(r\"[0-9a-f]{40}\", recorded_tip) \\\n",
         cmd=SELFTEST, want="forged tip: a refname: --check accepted a forged source_ref_tip"),
    dict(id="5c", item=5, name="implementation: the with-core tip checks removed", file="scripts/vendor-contract.py",
         old="        if isinstance(recorded_tip, str) and re.fullmatch(r\"[0-9a-f]{40}\", recorded_tip):\n",
         new="        if False:\n",
         cmd=SELFTEST, want="forged tip: a commit off the ref: the refusal does not say"),
    # ---------------------------------------------------------------- item 6
    dict(id="6a", item=6, name="a stray os.Getenv in Config.String()", file="internal/config/config.go",
         old="\t\tc.Mode, c.Addr, c.MaxClockSkew, c.MaxBodyBytes, c.RequestTimeout, c.ShutdownGrace,\n\t)\n}\n",
         new="\t\tc.Mode, c.Addr, c.MaxClockSkew, c.MaxBodyBytes, c.RequestTimeout, c.ShutdownGrace,\n\t) + os.Getenv(EnvSearchTopology)\n}\n",
         extra=[("internal/config/config.go", "import (\n", "import (\n\t\"os\"\n")],
         cmd=gotest("./internal/config/", "TestNothingOutsideTheSeamReadsTheProcessEnvironment"),
         want="os.getenv reads the process environment outside the lookup seam"),
    dict(id="6b", item=6, name="os.LookupEnv taken as a value in main.go", file="cmd/vizra-search/main.go",
         old="func main() {\n", new="var _ = os.LookupEnv\n\nfunc main() {\n",
         cmd=gotest("./internal/config/", "TestNothingOutsideTheSeamReadsTheProcessEnvironment"),
         want="cmd/vizra-search/main.go"),
    # ---------------------------------------------------------------- item 7
    dict(id="7a", item=7, name="A2: a refusal via fmt.Errorf that echoes the value", file="internal/config/config.go",
         old="\tv := &validator{lookup: lookup}\n",
         new="\tif raw, ok := lookup(EnvAddr); ok && raw == \"x\" {\n\t\treturn nil, fmt.Errorf(\"%w: bad %s=%s\", ErrInvalidConfig, EnvAddr, raw)\n\t}\n\tv := &validator{lookup: lookup}\n",
         cmd=gotest("./internal/config/", "TestNoRefusalBypassesTheNoEchoTable"),
         want="builds an error in package config outside the no-echo table"),
    dict(id="7b", item=7, name="A3: a new helper that appends its own message", file="internal/config/config.go",
         old="func (v *validator) raw(key string) (string, bool) {\n",
         new="func (v *validator) note(raw string) { v.problems = append(v.problems, \"bad: \"+raw) }\n\nfunc (v *validator) raw(key string) (string, bool) {\n",
         cmd=gotest("./internal/config/", "TestNoRefusalBypassesTheNoEchoTable"),
         want="problem list is touched outside addf/err"),
    dict(id="7c", item=7, name="A4: an addf refusal in a second file, echoing the value", file="internal/config/env.go",
         old="func osLookupEnv(",
         new="func (v *validator) second(raw string) { v.addf(\"%s is refused: %s\", EnvAddr, raw) }\n\nfunc osLookupEnv(",
         cmd=gotest("./internal/config/", "TestEveryRefusalSiteInTheLoaderHasANoEchoRow"),
         want="no row in refusalsites() drives it"),
    dict(id="7d", item=7, name="a custom error type", file="internal/config/env.go",
         old="func osLookupEnv(",
         new="type badValue struct{ raw string }\n\nfunc (b badValue) Error() string { return b.raw }\n\nfunc osLookupEnv(",
         cmd=gotest("./internal/config/", "TestNoRefusalBypassesTheNoEchoTable"),
         want="declares an error() method"),
    # ------------------------------------------------ closing slice (C): M-3, M-4, FINDING 4
    dict(id="C1", item="C", name="M-3: makegate back to refusing only a leading $( / ${ (the $@ row must go red)",
         file="scripts/makegate.py", old=M3_CHECK, new='            if body.startswith(("$(", "${")):\n',
         cmd=gotest("./scripts/", "TestNamedMakefileConstructsAreRefusedBeforeMake"), want="begins_with_$@"),
    dict(id="C2", item="C", name="M-3 control: refusing EVERY leading $ (so $$ too) must go red",
         file="scripts/makegate.py", old=M3_CHECK, new='            if body.startswith("$"):\n',
         cmd=gotest("./scripts/", "TestARecipeBeginningWithAnEscapedDollarIsNotRefused"), want="want green"),
    dict(id="C3", item="C", name="M-4: run_make no longer drops the environment-taken variables",
         file="scripts/makegate.py", old="env=clean_env(drop=taken)", new="env=clean_env()",
         cmd=gotest("./scripts/", "TestEnvironmentTakenVariablesNeverReachMake"),
         want="received a variable the makefile can read from the environment"),
    dict(id="C4", item="C", name="FINDING 4: a planted Go exec.CommandContext(ctx, \"make\", ...) (never run)",
         file="internal/buildinfo/planted_make_call.go", old="",
         new="package buildinfo\n\nimport (\n\t\"context\"\n\t\"os/exec\"\n)\n\n"
             "func plantedMakeCall(ctx context.Context) { _ = exec.CommandContext(ctx, \"make\", \"ci\") }\n",
         cmd=INVENTORY, want="internal/buildinfo/planted_make_call.go:8 starts make outside"),
    dict(id="C5", item="C", name="FINDING 4: a planted Python subprocess.run(\"make ci\", shell=True) (never run)",
         file="scripts/vendor-contract.py", old="def main():\n",
         new="def _planted():\n    subprocess.run(\"make ci\", shell=True)\n\n\ndef main():\n",
         cmd=INVENTORY, want="starts make outside scripts/makegate.py"),
    dict(id="C6", item="C", name="FINDING 4: a planted Python os.system(\"make ci\") (never run)",
         file="scripts/vendor-contract.py", old="def main():\n",
         new="def _planted():\n    os.system(\"make ci\")\n\n\ndef main():\n",
         cmd=INVENTORY, want="starts make outside scripts/makegate.py"),
    dict(id="C7", item="C", name="FINDING 4: a planted Python subprocess.run([\"env\", \"make\", \"ci\"]) (never run)",
         file="scripts/vendor-contract.py", old="def main():\n",
         new="def _planted():\n    subprocess.run([\"env\", \"make\", \"ci\"])\n\n\ndef main():\n",
         cmd=INVENTORY, want="starts make outside scripts/makegate.py"),
    dict(id="C8", item="C", name="FINDING 4: a planted shell line `cd x && make ci` (never run)",
         file="scripts/planted-make-call.sh", old="", new="#!/bin/sh\ncd x && make ci\n",
         cmd=INVENTORY, want="scripts/planted-make-call.sh:2 starts make outside"),
    dict(id="C9", item="C", name="FINDING 4: a planted shell line `if make -q ci; then :; fi` (never run)",
         file="scripts/planted-make-call.sh", old="", new="#!/bin/sh\nif make -q ci; then :; fi\n",
         cmd=INVENTORY, want="scripts/planted-make-call.sh:2 starts make outside"),
    dict(id="C10", item="C", name="FINDING 4: a planted shell line `/usr/local/bin/make ci` (never run)",
         file="scripts/planted-make-call.sh", old="", new="#!/bin/sh\n/usr/local/bin/make ci\n",
         cmd=INVENTORY, want="scripts/planted-make-call.sh:2 starts make outside"),
    # ------------------------------------------ fix round 1 of the closing slice (R): FINDING 5-8
    # R01 and R04: since fix round 2 the grammar ALSO refuses these shapes, with a message holding the same
    # words, so each row removes both layers (the named check and the grammar call) to show the test row
    # still has teeth.
    dict(id="R01", item="R", name="FINDING 5: the inline `;` recipe refusal AND the grammar removed",
         file="scripts/makegate.py", old='    if "=" not in bare_rest and ";" in bare_rest:\n', new="    if False:\n",
         extra=[("scripts/makegate.py", "        problems += grammar_problems(rel, text)\n", "")],
         cmd=gotest("./scripts/", "TestNamedMakefileConstructsAreRefusedBeforeMake"), want="inline_;_recipe"),
    dict(id="R02", item="R", name="FINDING 5: the several-targets refusal removed",
         file="scripts/makegate.py", old="    if len(targets) > 1:\n", new="    if False:\n",
         cmd=gotest("./scripts/", "TestNamedMakefileConstructsAreRefusedBeforeMake"), want="two_targets_on_one_rule_line"),
    dict(id="R03", item="R", name="FINDING 5: the computed-target refusal removed",
         file="scripts/makegate.py", old='    if any("$" in t for t in targets):\n', new="    if False:\n",
         cmd=gotest("./scripts/", "TestNamedMakefileConstructsAreRefusedBeforeMake"), want="a_rule_target_that_is_an_expansion"),
    dict(id="R04", item="R", name="FINDING 5: the indented-rule-line refusal AND the grammar removed",
         file="scripts/makegate.py", old='    if raw[:1] in (" ", "\\t"):\n', new="    if False:\n",
         extra=[("scripts/makegate.py", "        problems += grammar_problems(rel, text)\n", "")],
         cmd=gotest("./scripts/", "TestNamedMakefileConstructsAreRefusedBeforeMake"), want="starts_with_whitespace"),
    dict(id="R05", item="R", name="FINDING 5: the continued-rule-line refusal removed",
         file="scripts/makegate.py", old="    if physical.rstrip().endswith(", new="    if False and physical.rstrip().endswith(",
         cmd=gotest("./scripts/", "TestNamedMakefileConstructsAreRefusedBeforeMake"), want="continued_with_a_backslash"),
    dict(id="R06", item="R", name="M-2: the computed-variable-name refusal removed",
         file="scripts/makegate.py", old='    if name is not None and "$" in name:\n', new="    if False:\n",
         cmd=gotest("./scripts/", "TestNamedMakefileConstructsAreRefusedBeforeMake"), want="a_computed_variable_name"),
    dict(id="R07", item="R", name="$(call eval,...) no longer recognised as an eval",
         file="scripts/makegate.py", old=r'|\$[({]call\s+(?:eval|guile|\$)")', new='")',
         cmd=gotest("./scripts/", "TestNamedMakefileConstructsAreRefusedBeforeMake"), want="call_eval"),
    # R09 re-pinned by the re-plan (one line reader): the closure now reads makegate's LogicalLine records, so the
    # regression is reading a record's RAW text (comment included) instead of its comment-stripped code.
    dict(id="R09", item="R", name="FINDING 5 class: the closure reads the comment again (a comment holding = hides a lane)",
         file="scripts/make-integrity-guard.py", old="            parts = makegate._rule_parts(rec.code.rstrip())\n",
         new="            parts = makegate._rule_parts(rec.raw.rstrip())\n",
         cmd=gotest("./scripts/", "TestMakeIntegrityGuardStillRefusesKnownShapesInReviewedBytes"),
         want="whose_comment_holds"),
    dict(id="R10", item="R", name="FINDING 7: run_make stops dropping every word of the pinned text",
         file="scripts/makegate.py", old="taken = environment_taken(root, pinned) | environment_words(root, pinned)",
         new="taken = environment_taken(root, pinned)",
         cmd=gotest("./scripts/", "TestEnvironmentTakenVariablesNeverReachMake"),
         want="received a variable the makefile can read"),
    dict(id="R11", item="R", name="FINDING 6: a planted shell line `env -u X make ci` (never run)",
         file="scripts/planted-make-call.sh", old="", new="#!/bin/sh\nenv -u X make ci\n",
         cmd=INVENTORY, want="scripts/planted-make-call.sh:2 starts make outside"),
    dict(id="R12", item="R", name="FINDING 6: a planted shell line `sudo -u bob make ci` (never run)",
         file="scripts/planted-make-call.sh", old="", new="#!/bin/sh\nsudo -u bob make ci\n",
         cmd=INVENTORY, want="scripts/planted-make-call.sh:2 starts make outside"),
    dict(id="R13", item="R", name="FINDING 6: a planted Go dot-import `Command(\"make\", ...)` (never run)",
         file="internal/buildinfo/planted_dot_exec.go", old="",
         new="package buildinfo\n\nimport . \"os/exec\"\n\nfunc plantedDotExec() { _ = Command(\"make\", \"ci\") }\n",
         cmd=INVENTORY, want="internal/buildinfo/planted_dot_exec.go:5 starts make outside"),
    dict(id="R14", item="R", name="a planted Python `from subprocess import *` + run([\"make\"]) (never run)",
         file="scripts/planted_make_call.py", old="",
         new="from subprocess import *\n\nrun([\"make\", \"ci\"])\n",
         cmd=INVENTORY, want="scripts/planted_make_call.py:3 starts make outside"),
    dict(id="R15", item="R", name="a planted Python `from os import *` + system(\"make ci\") (never run)",
         file="scripts/planted_make_call.py", old="",
         new="from os import *\n\nsystem(\"make ci\")\n",
         cmd=INVENTORY, want="scripts/planted_make_call.py:3 starts make outside"),
    dict(id="R16", item="R", name="FINDING 8: a planted Python argv list held in a variable (never run)",
         file="scripts/planted_make_call.py", old="",
         new="import subprocess\nARGV = [\"make\", \"ci\"]\nsubprocess.run(ARGV)\n",
         cmd=INVENTORY, want="scripts/planted_make_call.py:2 starts make outside"),
    # ------------------------------------ fix round 2 of the closing slice (G): the grammar allowlist
    dict(id="G1", item="G", name="the grammar allowlist removed from makegate (F9 row must go red)",
         file="scripts/makegate.py", old="        problems += grammar_problems(rel, text)\n", new="",
         cmd=gotest("./scripts/", "TestNamedMakefileConstructsAreRefusedBeforeMake"), want="f9_inline_recipe_holding_="),
    dict(id="G2", item="G", name="the grammar allowlist removed: a pinned include reaches make again",
         file="scripts/makegate.py", old="        problems += grammar_problems(rel, text)\n", new="",
         cmd=gotest("./scripts/", "TestTheRemakeProbeCoversEveryPinnedInclude"), want="want it refused by the grammar before make"),
    dict(id="G3", item="G", name="the grammar's recipe `$` check removed",
         file="scripts/makegate.py", old="            for d in _dollar_problems(line, allow_shell=False):\n",
         new="            for d in []:\n",
         cmd=gotest("./scripts/", "TestNamedMakefileConstructsAreRefusedBeforeMake"), want="in_a_recipe"),
    dict(id="G4", item="G", name="the grammar's assignment-value `$` check removed (F12 row must go red)",
         file="scripts/makegate.py", old="            for d in _dollar_problems(m.group(3), allow_shell=True):\n",
         new="            for d in []:\n",
         cmd=gotest("./scripts/", "TestNamedMakefileConstructsAreRefusedBeforeMake"), want="f12_call_with_a_partly_computed"),
    dict(id="G5", item="G", name="the grammar's TAB-line-outside-a-rule check removed",
         file="scripts/makegate.py", old="            if not in_rule:\n", new="            if False:\n",
         cmd=gotest("./scripts/", "TestNamedMakefileConstructsAreRefusedBeforeMake"), want="a_tab_line_outside_a_rule"),
    dict(id="G6", item="G", name="control: the grammar made too strict (no `?=`), so the real Makefile no longer fits",
         file="scripts/makegate.py", old=r"(:=|\?=|=)(.*)$", new=r"(:=|=)(.*)$",
         cmd=gotest("./scripts/", "TestTheRealMakefileFitsTheGrammar"), want="does not fit the grammar"),
    # ------------------------------ re-plan (C11-C20): ONE line reader; FINDING 14 and 15 refused by name
    dict(id="C11", item="C", name="F14: the continued-comment refusal removed from the grammar",
         file="scripts/makegate.py", old="        if 0 <= rec.comment_at < rec.tail:\n", new="        if False:\n",
         cmd=GRAMMAR_STRINGS, want="f14_a_comment_continued_into_a_rule_line"),
    dict(id="C12", item="C", name="F14: the control/invisible/non-ASCII-whitespace character refusal removed",
         file="scripts/makegate.py", old="        if bad:\n", new="        if False:\n",
         cmd=GRAMMAR_STRINGS, want="f14_a_lone_cr_inside_a_comment"),
    dict(id="C13", item="C", name="F15: the directive-keyword NAME refusal removed",
         file="scripts/makegate.py", old="        if lead and lead.group(1) in DIRECTIVE_KEYWORDS and lead.group(2):\n",
         new="        if False:\n", cmd=GRAMMAR_STRINGS, want="f15_ifdef_as_a_variable_name"),
    dict(id="C14", item="C", name="blank means empty: the spaces/TABs-only line refusal removed",
         file="scripts/makegate.py", old='        if line and not line.strip(" \\t"):\n', new="        if False:\n",
         cmd=GRAMMAR_STRINGS, want="blank_means_empty:_a_line_of_only_spaces"),
    dict(id="C15", item="C", name="one reader: the anchor's check_text decodes the Makefile itself again (read_text)",
         file="scripts/make-integrity-guard.py", old="            lines = makegate.read_makefile_lines(path)\n",
         new="            lines = makegate.makefile_lines(path.read_text())\n",
         cmd=ONE_READER, want="check_text reads makefile text itself"),
    dict(id="C16", item="C", name="one reader: ci-required-guard's parity check reads the Makefile with its own regex again",
         file="scripts/ci-required-guard.py",
         old="    m = next((m for rec in mg.read_makefile_lines(makefile) if not rec.tab for m in [re.match(r\"^ci:(.*)$\", rec.code)]\n              if m), None)\n",
         new="    m = re.search(r\"^ci:([^#\\n]*)\", makefile.read_text(), re.M)\n",
         cmd=ONE_READER, want="poison:_ci-required-guard_check_local_parity"),
    dict(id="C17", item="C", name="one reader: a line continues on ANY trailing backslash (the old anchor rule), not an odd run",
         file="scripts/makegate.py", old='    return (len(physical) - len(physical.rstrip("\\\\"))) % 2 == 1\n',
         new='    return physical.rstrip().endswith("\\\\")\n',
         cmd=gotest("./scripts/", "TestTheAnchorReadsTheRecipeMakeReads"), want="even-backslashes"),
    dict(id="C18", item="C", name="one reader: the reader splits with universal newlines (a lone CR becomes a line break)",
         file="scripts/makegate.py", old='    phys = text.split("\\n")\n', new="    phys = text.splitlines() + ['']\n",
         cmd=GRAMMAR_STRINGS, want="f14_a_lone_cr_inside_a_comment"),
    dict(id="C19", item="C", name="one reader: the per-text cache removed, so readers of one text get different sequences",
         file="scripts/makegate.py", old="@functools.lru_cache(maxsize=64)\n", new="",
         cmd=ONE_READER, want="different line sequences"),
    dict(id="C20", item="C", name="F14 re-pinned rows: the character refusal removed (a lone CR reaches make)",
         file="scripts/makegate.py", old="        if bad:\n", new="        if False:\n",
         cmd=gotest("./scripts/", "TestNamedMakefileConstructsAreRefusedBeforeMake/F14"),
         want="f14_a_lone_cr_inside_a_comment"),
    # FINDING 16 (re-verification at 854a337): the file-level SOURCE check covers every text-reading spelling.
    dict(id="C21", item="C", name="F16: the file-level SOURCE check no longer sees attribute reads (read_text, splitlines, decode…)",
         file="scripts/scripts_test.go",
         old='TEXT_ATTRS = {"splitlines", "readlines", "read_text", "read_bytes", "decode", "open"}\n',
         new="TEXT_ATTRS = set()\n", cmd=PLANTED, want="read_text_+_split_in_the_anchor"),
    dict(id="C22", item="C", name="F16: the file-level SOURCE check reports nothing outside the named reads",
         file="scripts/scripts_test.go", old="    for owner, kind in sorted(got - set(named)):\n",
         new="    for owner, kind in []:\n", cmd=PLANTED, want="splitlines_in_makegate"),
]


def sha(path: str) -> str:
    if not os.path.exists(path):
        return "(absent)"
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def copy_tree(dst: str) -> None:
    files = subprocess.run(["git", "-C", REPO, "ls-files", "-co", "--exclude-standard", "-z"],
                           check=True, capture_output=True).stdout.decode().split("\0")
    for rel in filter(None, files):
        src = os.path.join(REPO, rel)
        if not os.path.isfile(src):
            continue
        out = os.path.join(dst, rel)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        shutil.copy2(src, out)


def env_for(row) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in STRIP}
    env.update(row.get("env") or {})
    return env


def run(cmd, cwd, env):
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def red_line(out: str) -> str:
    for line in out.splitlines():
        s = line.strip()
        low = s.lower()
        if s.startswith(("FAIL", "::error::", "REQUIRED-CHECKS", "vendor-contract-selftest: FAIL", "---")) or \
                "fail" in low[:12]:
            return s[:220]
    return (out.strip().splitlines() or ["(no output)"])[-1][:220]


def apply_edit(path, old, new, remove):
    if not os.path.exists(path) and old == "" and not remove:
        with open(path, "wb") as fh:
            fh.write(new.encode())
        return None
    with open(path, "rb") as fh:
        orig = fh.read()
    if remove:
        os.remove(path)
        return orig
    text = orig.decode()
    if old == "":
        with open(path, "wb") as fh:
            fh.write((text + new).encode())
        return orig
    n = text.count(old)
    if n != 1:
        raise RuntimeError(f"REFUSED: the mutation did not apply — its text occurs {n} time(s), want exactly 1")
    with open(path, "wb") as fh:
        fh.write(text.replace(old, new, 1).encode())
    return orig


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    rows = [r for r in ROWS if r["id"].startswith(args.only)]
    if args.list:
        for r in rows:
            print(r["id"], r["name"])
        return 0
    head = subprocess.run(["git", "-C", REPO, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "-C", REPO, "status", "--porcelain"], capture_output=True, text=True).stdout.strip()
    make_v = subprocess.run(["python3", os.path.join(REPO, "scripts", "makegate.py"), "--", "--version"],
                            capture_output=True, text=True).stdout.splitlines()[:1] or ["make: (gate refused)"]
    make_v = make_v[0]
    go_v = subprocess.run(["go", "version"], capture_output=True, text=True).stdout.strip()
    print(f"ci-hardening-demo: {len(rows)} row(s); tree = HEAD {head}{' + working-tree changes' if dirty else ''}")
    print(f"  {make_v}; {go_v}; python {sys.version.split()[0]}")
    tmp = tempfile.mkdtemp(prefix="ci-hardening-demo-")
    failures = 0
    try:
        copy_tree(tmp)
        for r in rows:
            print(f"\n=== {r['id']} (item {r['item']}) {r['name']}")
            print(f"    command: {' '.join(r['cmd']) if r['cmd'][0] != 'bash' or r['cmd'][1] != '-c' else 'the pinned direct_test_steps body, bash --noprofile --norc -eo pipefail'}")
            env = env_for(r)
            path = os.path.join(tmp, r["file"]) if r.get("file") else None
            orig = None
            extras = []
            try:
                if path:
                    before = sha(path)
                    orig = apply_edit(path, r.get("old", ""), r.get("new", ""), r.get("remove", False))
                    if r.get("future_mtime"):
                        ref = os.stat(os.path.join(tmp, "Makefile")).st_mtime + 86400
                        os.utime(path, (ref, ref))
                    watched = os.path.join(tmp, r["assert_unchanged"]) if r.get("assert_unchanged") else None
                    watched_before = sha(watched) if watched else None
                    for cf, body in (r.get("create") or {}).items():
                        with open(os.path.join(tmp, cf), "w") as fh:
                            fh.write(body)
                    for (xf, xo, xn) in r.get("extra", []):
                        xp = os.path.join(tmp, xf)
                        extras.append((xp, apply_edit(xp, xo, xn, False)))
                    after = sha(path)
                    if after == before:
                        raise RuntimeError("REFUSED: the mutation changed nothing")
                    print(f"    {r['file']} sha256 before {before}")
                    print(f"    {r['file']} sha256 after  {after}")
                else:
                    print(f"    environment: {r['env']}  (no file mutated)")
            except RuntimeError as exc:
                print(f"    {exc}")
                failures += 1
                continue
            rc, out = run(r["cmd"], tmp, env)
            want_ok = r["want"].lower() in out.lower()
            red_ok = rc != 0 and want_ok
            if path and r.get("assert_unchanged"):
                watched_after = sha(watched)
                same = watched_after == watched_before
                print(f"    {r['assert_unchanged']} sha256 after the command {watched_after} "
                      f"({'byte-identical to before' if same else '*** CHANGED by the command'})")
                red_ok = red_ok and same
            print(f"    MUTATED : exit {rc} -> {'RED as declared' if red_ok else '*** NOT RED AS DECLARED'}")
            print(f"              {red_line(out)}")
            if not want_ok:
                print(f"              (declared reason not found: {r['want']!r})")
                for line in out.strip().splitlines()[-25:]:
                    print(f"              | {line}")
            if path:
                for xp, xorig in reversed(extras):
                    with open(xp, "wb") as fh:
                        fh.write(xorig)
                if orig is None:
                    os.remove(path)
                else:
                    with open(path, "wb") as fh:
                        fh.write(orig)
                for cf in (r.get("create") or {}):
                    os.remove(os.path.join(tmp, cf))
                restored = sha(path)
                identical = restored == before
                print(f"    restored  sha256 {restored} ({'byte-identical' if identical else '*** NOT IDENTICAL'})")
                if not identical:
                    failures += 1
            rc2, out2 = run(r["cmd"], tmp, env_for({}))
            print(f"    RESTORED: exit {rc2} -> {'GREEN' if rc2 == 0 else '*** STILL RED'}")
            if rc2 != 0:
                for line in out2.strip().splitlines()[-15:]:
                    print(f"              | {line}")
            if not red_ok or rc2 != 0:
                failures += 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"\nci-hardening-demo: {len(rows) - failures}/{len(rows)} row(s) behaved as declared")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
