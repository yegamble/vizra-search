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

What remains, stated rather than implied: this program is itself a line in the
recipe it guards. Deleting that line removes the control. That takes a
deliberate edit to `/Makefile`, which CODEOWNERS assigns to the owner, and
`TestTheContractDriftLaneSelectsEveryVendoredFileGuard` fails when the recipe
loses either guard step — so escaping needs two edits, not one, and `make ci`,
`test` and `test-noskip` run `./...` unfiltered and still catch the drift.
"""

import json
import os
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


# ------------------------------------------------------------- recipe checks --


def check_make_warnings(stderr):
    """A duplicate target means the recipe a reader sees is not the one that runs."""
    for marker in ("overriding commands for target", "ignoring old commands for target"):
        if marker in stderr:
            fail(
                "make reports a DUPLICATE `%s` target:\n%s\n"
                "  make runs the LAST definition while a reader — and any text-based check —\n"
                "  sees the first. The lane must have exactly one recipe." % (LANE, indent(stderr))
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
    if not commands[0].startswith(GUARD) or " recipe" not in commands[0]:
        fail(
            "the contract-drift lane's FIRST command must be `%s recipe`, so the lane's shape is\n"
            "  checked before any test runs. It is:\n    %s" % (GUARD, commands[0])
        )
    if not commands[-1].startswith(GUARD) or " ran" not in commands[-1]:
        fail(
            "the contract-drift lane's LAST command must be `%s ran <report>`, which is the\n"
            "  authority on whether the lane passed. It is:\n    %s" % (GUARD, commands[-1])
        )
    if len(commands) < 3:
        fail(
            "the contract-drift lane has %d command(s); it must run this guard, then `go test`,\n"
            "  then this guard's `ran` check:\n%s" % (len(commands), indent("\n".join(commands)))
        )


def cmd_recipe():
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
        sys.stderr.write("usage: contract-drift-guard.py recipe | ran <report.json>\n")
        return 2
    try:
        if argv[1] == "recipe":
            return cmd_recipe()
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
