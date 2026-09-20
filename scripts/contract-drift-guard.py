#!/usr/bin/env python3
"""Guard the `contract-drift` lane from outside `go test`'s selection space.

Why this is a shell step and not a Go test
------------------------------------------

The `contract-drift` lane exists to make a vendored-file mutation fail in the
lane whose name says it checks drift. Its first version selected tests with a
`-run` regex of name fragments; renaming a guard out of that regex silently
removed it from the lane (finding F7).

The first fix put the "no test-selecting flag" rule in a Go test inside the
lane. That test is selected by the same `go test` invocation it polices, so
`-run 'TestVerifier'` deselects the guard that forbids `-run`, and the lane
prints `ok … [no tests to run]` and exits 0 with a vendored file edited in
place. A juror who can be dismissed by the defendant is not a control.

So this program runs BEFORE `go test`, as its own recipe line, and it:

  `recipe`  asks make what it will actually run and refuses anything that could
            deselect a guard;
  `ran`     reads the test report afterwards and refuses a lane that selected
            nothing, or that ran no tests in a package it claims to cover.

`recipe` scans `make --dry-run contract-drift` rather than the Makefile text.
Asking make resolves, in one move, every indirection a text parser missed:
variables (`$(TESTFLAGS)`), an included makefile, and a duplicate target (make
runs the LAST definition; a text parser reads the first). The environment is
checked too, because `GOFLAGS=-run=…` never appears in the recipe at all.

A recipe step alone was not enough, and the reason is worth stating precisely.
Every check invoked BY the recipe dies with the recipe. Three one-edit
mutations proved it: a `-` prefix on a guard line (make ignores that line's exit
status, and `make --dry-run` prints the command WITHOUT the `-`, so no scan of
the resolved recipe can see it); `|| true` appended to a guard line; and a
duplicate `contract-drift:` target that supplies its own recipe, which replaces
the guard steps outright so nothing in-recipe runs at all.

So there are three readings, and what each can and cannot do:

  1. this program, as a recipe step. It now also reads the Makefile TEXT —
     `check_makefile_text` — because `-` is invisible in the dry-run. It cannot
     run at all when a duplicate target has replaced the recipe;
  2. this program again, as its own step in `.github/workflows/ci.yml`, BEFORE
     `make contract-drift`. Being outside make, no Makefile edit can remove it.
     `scripts/ci-required-guard.sh` and `TestTheLaneGuardIsAnchoredInTheWorkflow`
     both assert that step exists, is unconditional and is not
     continue-on-error, so deleting it turns `ci-required` and the `test` lane
     red;
  3. `TestThisRepositoryPassesItsOwnLaneGuard`, which runs this program against
     the real Makefile from the ordinary suite, so `test` and `test-noskip`
     object to a tampered lane even when the in-recipe step is gone.

What these readings DO stop. Each was measured with a vendored file edited in
place, and each turns a required check red:

  - a `-` prefix on a guard line, and `|| true` appended to one — red at all
    three readings, because `check_makefile_text` sees what the dry-run hides;
  - a duplicate `contract-drift:` target that replaces the recipe — red at
    readings 2 and 3. Reading 1 cannot run at all, so `make contract-drift`
    alone stays green;
  - a test-selecting flag, whether written into the recipe, reached through a
    variable or an included makefile, or carried in `GOFLAGS`/`GOTESTFLAGS`; a
    wrapper script in place of `go test`; a lane defined inside a make
    conditional; a package holding a vendored-file guard dropped from the lane's
    package list, or listed but running zero tests;
  - deleting the workflow anchor, making it conditional, marking it
    continue-on-error, or moving it after `make contract-drift` — red on
    `ci-required` and on the `test` lane, not on `contract-drift` itself.

What they do NOT stop, stated rather than implied:

  - a Makefile-level `SHELL := /usr/bin/true` or `MAKEFLAGS += -i`. Either is
    ONE line, and either makes every recipe in this repository a no-op —
    `contract-drift`, `test` and `test-noskip` alike. Measured at this commit
    with a vendored file edited in place: `make contract-drift`, `make test` and
    `make test-noskip` all exit 0. No check written inside a Makefile can
    prevent that, and no CI lane catches it today, because the workflows invoke
    `make test` and `make test-noskip` rather than `go test`: the only command
    that goes red is a direct `go test ./internal/httpapi/`, which nothing in CI
    runs. (`resolved_recipe` drops a `MAKEFLAGS` inherited from the ENVIRONMENT;
    this is the in-file assignment, which it cannot drop.) The exposure is
    generic to any make-driven gate, is equally true of `main`, and is not new
    here — what is new is that it is written down. Closing it is queued as a
    cross-repo hardening item: an out-of-make check that refuses a `SHELL`,
    `.SHELLFLAGS` or `MAKEFLAGS` override anywhere in the Makefile, plus one
    required lane that runs `go test` without make. Until that lands, the only
    backstop is human review of the Makefile diff;
  - editing `.github/workflows/ci.yml` as well removes reading 2. That is a
    second file and a second diff, and `ci-required` goes red while the step is
    missing — but `ci-required-guard.sh` is itself checked out from the PR under
    test;
  - all of these paths are CODEOWNERS-assigned, and **CODEOWNERS is advisory
    until the owner's ruleset requires that review**, which does not yet exist —
    so the review that backstops the first bullet is not enforced by anything.
"""

import json
import os
import re
import shlex
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANE = "contract-drift"
GUARD = "./scripts/contract-drift-guard.py"
MANIFEST = "api/CONTRACT-SOURCE.json"
MODULE = "github.com/yegamble/vizra-search"

# The only `go test` flags this lane may carry. Everything else is refused by
# name rather than allowed by default, so a flag invented after this was written
# cannot quietly deselect a guard.
ALLOWED_FLAGS = {"-count=1", "-json"}

# Flags that change WHICH tests run. Named separately only to give a precise
# message; they are refused by the allowlist above either way.
SELECTING_FLAGS = ("-run", "-skip", "-short", "-tags", "-bench", "-fuzz", "-args")

# Environment variables `go test` reads as extra flags.
FLAG_ENV = ("GOFLAGS", "GOTESTFLAGS")

MAKEFILE = "Makefile"
WORKFLOW = ".github/workflows/ci.yml"

# Suffixes that discard a guard step's exit status. `make --dry-run` DOES show
# these, but only as trailing text after a command that still starts with the
# guard's path, so a prefix match alone accepts them.
SWALLOWING_SUFFIXES = ("|| true", "|| :", "|| exit 0", "; true", "; :", "|| /bin/true")

# Make's recipe-line prefixes. `-` is the dangerous one: make ignores the line's
# exit status, and `make --dry-run` prints the command WITHOUT the prefix, so no
# amount of dry-run scanning can see it. That is why the Makefile TEXT is read.
RECIPE_PREFIX_CHARS = "@-+"

MAKE_CONDITIONALS = ("ifeq", "ifneq", "ifdef", "ifndef")


class Refused(Exception):
    """A lane-shape violation, with a message a reviewer can act on."""


def fail(msg):
    raise Refused(msg)


# --------------------------------------------------------------- resolution --


def resolved_recipe():
    """Return (commands, stderr) for what make would actually run for the lane.

    `make --dry-run` prints the commands after expanding variables, applying
    includes, and resolving duplicate-target overrides — i.e. what will really
    execute, not what the Makefile text looks like.
    """
    env = {k: v for k, v in os.environ.items() if k not in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL")}
    proc = subprocess.run(
        ["make", "--dry-run", "--no-print-directory", LANE],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        fail(
            "`make --dry-run %s` failed (exit %d), so the lane's real recipe could not be\n"
            "  determined. A lane whose shape cannot be established is not a lane.\n%s"
            % (LANE, proc.returncode, indent(proc.stderr or proc.stdout))
        )

    # Join make's line continuations so a flag split across lines is still seen.
    commands, pending = [], ""
    for raw in proc.stdout.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        commands.append((pending + line).strip())
        pending = ""
    if pending.strip():
        commands.append(pending.strip())
    return commands, proc.stderr


def indent(text, prefix="    "):
    return "\n".join(prefix + ln for ln in (text or "").rstrip().splitlines())


# ------------------------------------------------------- the Makefile TEXT ---
#
# Some ways of disarming a recipe line are invisible to `make --dry-run`, so the
# resolved-recipe scan above cannot be the only reading. The clearest case is a
# leading `-`: make ignores that line's exit status AND prints the command
# without the prefix, so the guard could refuse the lane, print its refusal, and
# the lane would still exit 0. These checks therefore read the file.


def logical_recipe_lines(lines, start):
    """Collect one target's recipe from Makefile text, joining continuations.

    Returns a list of (first_physical_line_number, joined_text_without_tab).
    """
    recipe, i = [], start
    while i < len(lines):
        line = lines[i]
        if line.strip() == "" or line.lstrip().startswith("#"):
            i += 1
            continue
        if not line.startswith("\t"):
            break
        first, body = i, line[1:]
        while body.rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            body = body.rstrip()[:-1] + " " + lines[i].lstrip("\t")
        recipe.append((first + 1, body.strip()))
        i += 1
    return recipe


def check_makefile_text():
    """Refuse lane definitions whose text disarms a guard step."""
    path = os.path.join(REPO_ROOT, MAKEFILE)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as err:
        fail("cannot read %s: %s" % (MAKEFILE, err))
    lines = text.split("\n")

    target_re = re.compile(r"^%s\s*:" % re.escape(LANE))
    targets = [i for i, ln in enumerate(lines) if target_re.match(ln)]
    if not targets:
        fail("%s declares no `%s` target" % (MAKEFILE, LANE))
    if len(targets) > 1:
        fail(
            "%s declares the `%s` target %d times, at lines %s.\n"
            "  make runs the LAST definition, which REPLACES the earlier recipe — guard steps\n"
            "  included — so a duplicate can remove this check before it ever runs. The lane\n"
            "  must have exactly one recipe."
            % (MAKEFILE, LANE, len(targets), ", ".join(str(t + 1) for t in targets))
        )

    # A lane defined inside a make conditional can be swapped out by setting a
    # variable, with the recipe a reader sees never executing.
    depth = 0
    for i, ln in enumerate(lines[: targets[0]]):
        head = ln.strip().split(" ")[0]
        if head in MAKE_CONDITIONALS:
            depth += 1
        elif head == "endif":
            depth = max(0, depth - 1)
    if depth > 0:
        fail(
            "the `%s` target at %s:%d is defined inside a make conditional, so which recipe\n"
            "  runs depends on a variable. The lane must be unconditional."
            % (LANE, MAKEFILE, targets[0] + 1)
        )

    recipe = logical_recipe_lines(lines, targets[0] + 1)
    if not recipe:
        fail("the `%s` target in %s has an empty recipe" % (LANE, MAKEFILE))

    saw_guard = False
    for lineno, body in recipe:
        prefix = ""
        while body and body[0] in RECIPE_PREFIX_CHARS:
            prefix += body[0]
            body = body[1:].lstrip()
        is_guard = body.startswith(GUARD)
        saw_guard = saw_guard or is_guard

        if "-" in prefix:
            fail(
                "%s:%d begins with `-`, so make IGNORES that line's exit status:\n    %s%s\n"
                "  `make --dry-run` prints the command WITHOUT the `-`, so no scan of the\n"
                "  resolved recipe can see it: the guard would refuse the lane, print its\n"
                "  refusal, and the lane would still exit 0. Remove the `-`."
                % (MAKEFILE, lineno, prefix, body)
            )
        if is_guard:
            for suffix in SWALLOWING_SUFFIXES:
                if body.rstrip().endswith(suffix):
                    fail(
                        "%s:%d ends with `%s`, which discards the guard's exit status:\n    %s\n"
                        "  A guard whose failure is swallowed is not a guard."
                        % (MAKEFILE, lineno, suffix, body)
                    )

    if not saw_guard:
        fail(
            "the `%s` recipe in %s contains no `%s` step, so nothing checks the lane's shape:\n%s"
            % (LANE, MAKEFILE, GUARD, indent("\n".join(b for _, b in recipe)))
        )


# ------------------------------------------------------------- recipe checks --


# GNU make 3.81 (the macOS system make) says "overriding commands for target";
# GNU make 4.x (every Linux runner) says "overriding recipe for target". Matching
# only one wording is how this check silently stops working on the platform that
# actually gates merges, so both are matched — and any other warning make emits
# while resolving the lane is refused too, since a clean lane produces none.
DUPLICATE_TARGET_RE = re.compile(r"(overriding|ignoring old)\s+(commands|recipe)\s+for\s+target", re.I)


def check_make_warnings(stderr):
    """A duplicate target means the recipe a reader sees is not the one that runs."""
    if DUPLICATE_TARGET_RE.search(stderr or ""):
        fail(
            "make reports a DUPLICATE `%s` target:\n%s\n"
            "  make runs the LAST definition while a reader — and any text-based check —\n"
            "  sees the first. The lane must have exactly one recipe." % (LANE, indent(stderr))
        )
    for line in (stderr or "").splitlines():
        if "warning:" in line.lower():
            fail(
                "make emitted a warning while resolving the lane, so what it will run is not\n"
                "  unambiguous:\n%s" % indent(stderr)
            )


def check_environment():
    for name in FLAG_ENV:
        value = os.environ.get(name, "")
        for flag in SELECTING_FLAGS:
            if flag in value:
                fail(
                    "%s in the environment carries %s: %r\n"
                    "  `go test` reads that as if it were on the command line, so it can deselect\n"
                    "  a guard without appearing in the recipe at all. Unset it for this lane."
                    % (name, flag, value)
                )


def split_test_command(cmd):
    """Return the tokens of a `go test` command, refusing any other shape.

    The lane's test line may end with `|| true` (the following `ran` step is the
    authority on pass/fail) and may redirect stdout to the report file. Anything
    else — a pipeline, a chained command, a wrapper script, a command
    substitution — is refused, because this program can only reason about a
    `go test` it can see.
    """
    for bad, why in (
        ("$(", "a command substitution"),
        ("`", "a command substitution"),
        ("&&", "a chained command"),
        (";", "a chained command"),
        ("|", "a pipeline"),
    ):
        # `|| true` is the one allowed use of `|`.
        probe = cmd.replace("|| true", "")
        if bad in probe:
            fail(
                "the lane's test command contains %s, which this guard cannot reason about:\n"
                "    %s\n"
                "  Keep the lane a single, visible `go test` invocation." % (why, cmd)
            )

    body = cmd.replace("|| true", "").strip()
    if ">" in body:
        body = body.split(">", 1)[0].strip()

    tokens = shlex.split(body)
    if not tokens:
        fail("the lane contains an empty command")

    # `VAR=value go test …` — an environment prefix hides flags from the tokens.
    if "=" in tokens[0] and not tokens[0].startswith("-"):
        fail(
            "the lane's test command is prefixed with the environment assignment %r:\n"
            "    %s\n"
            "  `go test` reads GOFLAGS as extra flags, so a prefix can deselect a guard while\n"
            "  the recipe still reads as a plain `go test`." % (tokens[0], cmd)
        )

    if tokens[:2] != ["go", "test"]:
        fail(
            "the lane runs %r instead of `go test`:\n"
            "    %s\n"
            "  A wrapper can add flags this guard never sees. The lane must invoke `go test`\n"
            "  directly." % (tokens[0], cmd)
        )
    return tokens


def check_flags(tokens):
    packages = []
    for tok in tokens[2:]:
        if tok.startswith("./"):
            packages.append(tok.rstrip("/").lstrip("./"))
            continue
        if not tok.startswith("-"):
            fail(
                "unexpected argument %r in the lane's `go test` command.\n"
                "  The lane takes only %s and package paths beginning './'."
                % (tok, " and ".join(sorted(ALLOWED_FLAGS)))
            )
        if tok in ALLOWED_FLAGS:
            continue
        name = tok.split("=", 1)[0]
        if name in SELECTING_FLAGS:
            fail(
                "the contract-drift lane carries %s.\n"
                "  The lane must select by PACKAGE, not by test name, tag or duration: a name\n"
                "  filter silently drops a guard out of the lane the day someone renames it,\n"
                "  with nothing to say so. That is finding F7, and it is why this guard exists."
                % name
            )
        fail(
            "the contract-drift lane carries the unexpected flag %r.\n"
            "  Only %s are allowed, so a flag that can change which tests run cannot be added\n"
            "  without this guard being updated deliberately."
            % (tok, " and ".join(sorted(ALLOWED_FLAGS)))
        )
    if not packages:
        fail("the lane's `go test` command names no package to test")
    return packages


# ------------------------------------------------- vendored-guard coverage ---


def vendored_markers():
    """Basenames whose appearance in a _test.go means that test reads a vendored file."""
    with open(os.path.join(REPO_ROOT, MANIFEST), "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    markers = {os.path.basename(MANIFEST)}
    for entry in manifest.get("files", []):
        markers.add(os.path.basename(entry["vendored_path"]))
    if len(markers) < 3:
        fail("%s pins fewer than two vendored files; the coverage check cannot be trusted" % MANIFEST)
    return markers


def packages_guarding_vendored_files():
    markers = vendored_markers()
    found = set()
    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        dirnames[:] = [d for d in dirnames if d not in (".git", "bin", "docs", "node_modules")]
        for name in filenames:
            if not name.endswith("_test.go"):
                continue
            path = os.path.join(dirpath, name)
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                body = handle.read()
            if any(marker in body for marker in markers):
                found.add(os.path.relpath(dirpath, REPO_ROOT))
    if not found:
        fail("no test file reads a vendored file; either this walk is broken or the guards are gone")
    return found


def check_coverage(packages):
    listed = set(packages)
    for pkg in sorted(packages_guarding_vendored_files()):
        if pkg not in listed:
            fail(
                "package %r contains a test that reads a vendored contract file, but the\n"
                "  contract-drift lane does not run it, so a mutation of that file survives the\n"
                "  lane. Add ./%s/ to the contract-drift recipe.\n"
                "  lane packages: %s" % (pkg, pkg, sorted(listed))
            )


def check_structure(commands):
    """The guard steps must bracket the test command.

    First and last are checked before the count, so dropping one of them reports
    which step is missing rather than only that the lane is too short.
    """
    if not commands:
        fail("the contract-drift lane runs no commands at all")
    # Compared as exact token lists, not by prefix: a prefix match accepts
    # `… recipe || true`, which discards the guard's exit status.
    if shlex.split(commands[0]) != [GUARD, "recipe"]:
        fail(
            "the contract-drift lane's FIRST command must be exactly `%s recipe`, so the lane's\n"
            "  shape is checked before any test runs and its failure is not discarded.\n"
            "  It is:\n    %s" % (GUARD, commands[0])
        )
    last = shlex.split(commands[-1])
    if len(last) != 3 or last[0] != GUARD or last[1] != "ran":
        fail(
            "the contract-drift lane's LAST command must be exactly `%s ran <report>`, which is\n"
            "  the authority on whether the lane passed. It is:\n    %s" % (GUARD, commands[-1])
        )
    if len(commands) < 3:
        fail(
            "the contract-drift lane has %d command(s); it must run this guard, then `go test`,\n"
            "  then this guard's `ran` check:\n%s" % (len(commands), indent("\n".join(commands)))
        )


# ----------------------------------------------------- the workflow anchor --


def cmd_workflow():
    """Assert the lane's guard also runs from the WORKFLOW, outside make.

    Every check in `recipe` is invoked by a line in the recipe it guards, so a
    single Makefile edit that replaces or disarms that line — a duplicate target
    supplying its own recipe, `SHELL := /usr/bin/true`, `MAKEFLAGS` — removes the
    check along with the lane. Running the same check as its own workflow step
    means no Makefile edit can remove it: disarming the lane then requires
    editing `.github/workflows/ci.yml` as well, which is a separate file and a
    separate diff.

    This is called by scripts/ci-required-guard.sh, which runs in the
    `ci-required` job, so the anchor step cannot be deleted without that job
    going red.
    """
    try:
        import yaml
    except ImportError:
        fail(
            "PyYAML is required to check the workflow anchor. This parses the workflow rather\n"
            "  than grepping it, for the same reason scripts/check-workflows.py does."
        )

    path = os.path.join(REPO_ROOT, WORKFLOW)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            doc = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as err:
        fail("cannot read or parse %s: %s" % (WORKFLOW, err))

    jobs = doc.get("jobs") if isinstance(doc, dict) else None
    if not isinstance(jobs, dict) or LANE not in jobs:
        fail("%s declares no `%s` job" % (WORKFLOW, LANE))
    job = jobs[LANE] or {}

    for key in ("if", "continue-on-error"):
        if key in job:
            fail(
                "the `%s` job in %s carries `%s`. The lane's anchor must run on every run and\n"
                "  must be able to fail the gate." % (LANE, WORKFLOW, key)
            )

    steps = job.get("steps")
    if not isinstance(steps, list) or not steps:
        fail("the `%s` job in %s declares no steps" % (LANE, WORKFLOW))

    anchor_at = make_at = None
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        run = step.get("run") or ""
        if not isinstance(run, str):
            continue
        if GUARD in run and "recipe" in run:
            if "if" in step:
                fail(
                    "the guard step at %s:jobs.%s.steps[%d] is conditional (`if`), so it can be\n"
                    "  skipped. The anchor must be unconditional." % (WORKFLOW, LANE, i)
                )
            if "continue-on-error" in step:
                fail(
                    "the guard step at %s:jobs.%s.steps[%d] carries `continue-on-error`, so its\n"
                    "  failure cannot fail the lane." % (WORKFLOW, LANE, i)
                )
            if anchor_at is None:
                anchor_at = i
        if re.search(r"\bmake\s+%s\b" % re.escape(LANE), run):
            if make_at is None:
                make_at = i

    if anchor_at is None:
        fail(
            "the `%s` job in %s does not run `%s recipe` as its own step.\n"
            "  Without it, every check on this lane is invoked by the recipe it guards, so one\n"
            "  Makefile edit — a duplicate target that supplies its own recipe, or a SHELL\n"
            "  override — removes the check along with the lane. Add, before `make %s`:\n"
            "      - name: the lane's own shape, checked outside make\n"
            "        run: %s recipe" % (LANE, WORKFLOW, GUARD, LANE, GUARD)
        )
    if make_at is None:
        fail("the `%s` job in %s never runs `make %s`" % (LANE, WORKFLOW, LANE))
    if anchor_at > make_at:
        fail(
            "the guard step (step %d) runs AFTER `make %s` (step %d) in %s. It must run first,\n"
            "  so a disarmed lane is refused before it reports success."
            % (anchor_at, LANE, make_at, WORKFLOW)
        )

    print(
        "workflow anchor: %s:jobs.%s runs `%s recipe` unconditionally at step %d, before "
        "`make %s` at step %d" % (WORKFLOW, LANE, GUARD, anchor_at, LANE, make_at)
    )
    return 0


def cmd_recipe():
    check_makefile_text()
    commands, stderr = resolved_recipe()
    check_make_warnings(stderr)
    check_environment()
    check_structure(commands)

    tested = [c for c in commands if not c.startswith(GUARD)]
    if len(tested) != 1:
        fail(
            "the contract-drift lane runs %d command(s) besides this guard; it must run exactly\n"
            "  one `go test`:\n%s" % (len(tested), indent("\n".join(tested)))
        )
    packages = check_flags(split_test_command(tested[0]))
    check_coverage(packages)
    print(
        "contract-drift lane: %d package(s) selected with no test-selecting flag (%s)"
        % (len(packages), ", ".join(sorted(packages)))
    )
    return 0


# ---------------------------------------------------------------- ran check --


def cmd_ran(report_path):
    """Refuse a lane that selected nothing, ran nothing, or failed."""
    commands, stderr = resolved_recipe()
    check_make_warnings(stderr)
    tested = [c for c in commands if not c.startswith(GUARD)]
    expected = check_flags(split_test_command(tested[0])) if tested else []

    full = os.path.join(REPO_ROOT, report_path)
    if not os.path.exists(full) or os.path.getsize(full) == 0:
        fail(
            "the test report %r is missing or empty, so `go test` produced nothing to judge."
            % report_path
        )

    ran, failed, pkg_result, notes = {}, [], {}, []
    with open(full, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            pkg, action, test = ev.get("Package", ""), ev.get("Action", ""), ev.get("Test")
            out = ev.get("Output", "")
            if "no tests to run" in out or "[no test files]" in out:
                notes.append("%s: %s" % (pkg, out.strip()))
            if test:
                if action in ("pass", "fail"):
                    ran.setdefault(pkg, set()).add(test)
                if action == "fail":
                    failed.append("%s.%s" % (pkg, test))
            elif action in ("pass", "fail", "skip"):
                pkg_result[pkg] = action

    # Surface the real test output on failure; -json alone is unreadable.
    if failed or any(v == "fail" for v in pkg_result.values()):
        sys.stderr.write("contract-drift FAILED\n")
        with open(full, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if ev.get("Action") == "output":
                    sys.stderr.write(ev.get("Output", ""))
        fail("%d test(s) failed: %s" % (len(failed), ", ".join(failed[:10]) or "see above"))

    for pkg in expected:
        matches = [p for p in set(list(ran) + list(pkg_result)) if p.endswith("/" + pkg) or p == MODULE + "/" + pkg]
        if not matches:
            fail(
                "package ./%s/ is in the lane's package list but produced no result at all in the\n"
                "  test report. The lane cannot claim to cover a package it did not run." % pkg
            )
        for match in matches:
            if not ran.get(match):
                fail(
                    "package %s ran ZERO tests.\n"
                    "  `go test` reports `ok … [no tests to run]` and exits 0 when a filter selects\n"
                    "  nothing, which is exactly how a drift mutation survives a green lane.\n%s"
                    % (match, indent("\n".join(notes)) if notes else "")
                )
    if notes:
        fail("the lane reported packages with nothing to run:\n%s" % indent("\n".join(notes)))

    total = sum(len(v) for v in ran.values())
    print(
        "contract-drift: %d tests ran across %d package(s), 0 failures, none deselected"
        % (total, len(ran))
    )
    return 0


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: contract-drift-guard.py recipe | ran <report.json> | workflow\n")
        return 2
    try:
        if argv[1] == "recipe":
            return cmd_recipe()
        if argv[1] == "workflow":
            return cmd_workflow()
        if argv[1] == "ran":
            if len(argv) < 3:
                sys.stderr.write("usage: contract-drift-guard.py ran <report.json>\n")
                return 2
            return cmd_ran(argv[2])
    except Refused as err:
        sys.stderr.write("CONTRACT-DRIFT LANE REFUSED: %s\n" % err)
        return 1
    sys.stderr.write("unknown subcommand %r\n" % argv[1])
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
