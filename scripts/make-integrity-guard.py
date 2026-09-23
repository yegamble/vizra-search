#!/usr/bin/env python3
"""make-integrity-guard — refuse a Makefile, or an environment, that turns a make lane into a no-op.

Ported from vizra-core `scripts/make-integrity-guard.py` at eeeea068a20118f7af721f024264603b436a1528
(core PR #9, three verifier rounds), adapted to this repository's Makefile: the approved SHELL is
`/bin/bash`, the gate targets are the ones `.github/workflows/ci.yml` invokes, and exactly one recipe
line is allowed a swallowing suffix (see SWALLOW_EXEMPT).

WHY THIS EXISTS
---------------

Every make lane in this repository runs through `make`. A verifier measured, on this repository, that
ONE line in the Makefile makes every one of them exit 0 without running anything:

    SHELL := /usr/bin/true     make contract-drift = 0   make test = 0   make test-noskip = 0
    MAKEFLAGS += -i            (the same)

(docs/evidence/warroom/2026-09-20-vizra-search-pr2-revendor-VERIFY.md, FINDING 8.) Until this program
existed no CI lane caught it. No check written INSIDE a Makefile can prevent it, because the neutering
disarms that check too. So this program runs OUTSIDE make — as its own workflow step, byte-equal to the
`anchor_step` in .github/pinned-steps.yml, IMMEDIATELY before every `make` step of a required lane.

WHAT IT CHECKS
--------------

First, BEFORE make is invoked at all, THE GATE (scripts/makegate.py, the one way this repository starts
make): every file make may read is pinned by sha256 in .github/pinned-makefiles.yml and must be a
regular file matching it; the files the reviewed bytes include must all be pinned; no unpinned
GNUmakefile/makefile may sit beside them; the environment and `make` itself must pass the checks
below; and ONE `make -q <every pinned makefile>` — no ordinary recipe runs under -q; a `+` or
`$(MAKE)` line would, and can only come from the reviewed bytes — must say none would be REMADE (a newer
unpinned `Makefile.sh` would be, by make's built-in `% : %.sh`). ANY failure stops the anchor before
make runs. Every later make names the pinned makefiles as goals, is started by the checked real path,
runs without the variables the makefiles take from the environment, re-hashes them afterwards, and
MAKEFILE_LIST must be exactly the pinned set; the anchor ends with the same `make -q` probe again.
Then three readings of those reviewed bytes, because a reviewer can approve a mistake:

  RESOLVER  `make -pn TARGET`: SHELL, .SHELLFLAGS and MAKEFLAGS as make itself resolved them — through
            variables, includes and duplicate definitions — and MAKEFILE_LIST, every file make read.
            Blind to a `-` recipe prefix: the dry-run prints the command without it.
  TEXT      those same files, read: a `-`/`+` prefix, a `|| true`-family suffix, any SHELL/.SHELLFLAGS/
            MAKEFLAGS/GNUMAKEFLAGS/MFLAGS assignment, `.ONESHELL`, a gate target defined twice or inside a
            make conditional. The recipe prefix/suffix scan covers the EXPLICIT rules of the named
            closure (prerequisite_closure): every TAB recipe line of each one. Every one of these readings
            consumes makegate's ONE logical-line sequence (makegate.read_makefile_lines), the same one
            makegate's grammar judged before make, and decides which rule a TAB line belongs to with the
            grammar's own rule (makegate.recipe_lines: empty and comment lines keep a recipe open, any
            other line closes it). The grammar has already refused every line that is not empty, a
            comment, an assignment, a `.PHONY:` line, a single-target rule line or a TAB recipe line of a
            rule, every comment continued by a backslash, and every CR, NUL, other control, invisible or
            non-ASCII whitespace character. So a rule's recipe is exactly the TAB lines after it, up to
            the next line that is neither empty nor a comment, for the grammar and for this reading
            alike, and no pattern, suffix or `.DEFAULT` rule and no `$`-named prerequisite can be written. NOT scanned: a recipe make supplies from its BUILT-IN
            implicit rules, for a closure target with no explicit rule (printed as a note) or with an
            explicit rule that has no recipe and is not `.PHONY`.
  WARNINGS  `make --dry-run` stderr: a duplicate target ("overriding commands" on GNU Make 3.81,
            "overriding recipe" on 4.x — both matched).

Plus the ENVIRONMENT, because `MAKEFLAGS=-i make ci` never appears in any file. With `--workflow` — the
only form a required lane can use, because ci-required-guard.py pins the anchor byte-for-byte — the
environment check is STRICT, and the mode is chosen by that argument, never by the environment (core
PR#9 re-verification, R-2: MAKELEVEL's mere presence once selected a lenient mode):

  * MAKEFLAGS, GNUMAKEFLAGS and MFLAGS must be UNSET (not merely empty);
  * MAKELEVEL, MAKE_RESTARTS, MAKEOVERRIDES and MAKECMDGOALS must be ABSENT — the anchor is not a make
    recipe, so if one is present something planted it (typically an earlier `$GITHUB_ENV` write);
  * every variable the makefiles take from the environment AS makegate.environment_taken READS THEM —
    assigned with `?=`, or referenced as `$(NAME)`/`${NAME}` and never assigned — must be ABSENT, plus
    GOFLAGS, which the go command reads directly. Today that is
    VERSION, COMMIT, BUILD_TIME, IMAGE, CORE, CORE_REMOTE and GOFLAGS; the anchor prints the list it
    computed in its own log;
  * in both modes MAKEFILES, BASH_ENV and ENV must be unset and SHELL must be a real shell;
  * `make` must resolve to a FILE named make (or gmake) in a system directory — not a function, an alias,
    or a stub a `$GITHUB_PATH` write put earlier on PATH.

Because the anchor is adjacent to make, a `$GITHUB_ENV` or `$GITHUB_PATH` write by any EARLIER step is in
this process when it runs, exactly as it will be in make's.

WHAT IT DOES NOT DO — stated, not implied. This list is not called complete.

  * It never reads the workflow's own `make` step. The step's argv and keys are ci-required-guard.py's
    job: it pins them to byte-equal literals in .github/pinned-steps.yml rather than parsing them.
  * It checks a NAMED set of environment variables, not the whole environment. A `$GITHUB_ENV` write of
    any other variable — Go's own GOTOOLCHAIN, GOENV, GODEBUG, CGO_ENABLED, … — is not refused here. The
    per-package floors in the direct test step turn a suite made to run nothing red; anything subtler is
    review-only.
  * It cannot see what an earlier step did to the MACHINE: a replaced Go toolchain, a rewritten test file,
    a swapped python3. It checks what `make` IS (a file named make in a system directory), not what it
    DOES: a forwarding stub planted in /usr/local/bin by an earlier step passes. Review is the control,
    and CODEOWNERS is advisory until the owner's ruleset exists.
  * It does not judge what a reviewer approved. The digest gate guarantees that make runs only on
    reviewed bytes — and the reviewed bytes run their own `$(shell …)` calls while being read (today
    four: `go env GOROOT`, `git describe`, `git rev-parse HEAD`, `date`). A malicious Makefile approved
    TOGETHER with its pin update runs. BEFORE make, every line of the reviewed bytes must fit
    makegate's grammar (makegate.grammar_problems — an allowlist, default-deny, over makegate's one
    line reader): empty or a comment, `NAME := | ?= | = value` (NAME not a directive keyword) whose
    value uses only `$$`, `$(NAME)`/`${NAME}` and `$(shell …)`, `.PHONY: names`, a single-target rule
    line with literal prerequisites, or a TAB recipe line of a rule using only `$$` and
    `$(NAME)`/`${NAME}`; anything else, and any CR, NUL, other control, invisible or non-ASCII whitespace
    character and any backslash-continued comment, is refused by line number. Within it,
    SHELL/.SHELLFLAGS other than the approved lines, MAKEFLAGS-family assignments, `+` and `$(MAKE)`
    recipe lines and a recipe body beginning with `$` are also refused by name. What the grammar lets a
    reviewer write — the commands a recipe runs, what a `$(shell …)` in a value runs while make reads
    the file, what a referenced variable expands to — runs once approved. The resolver and text
    readings then refuse the known no-op shapes in reviewed bytes (a SHELL/MAKEFLAGS override, a `-`
    prefix, a swallowed exit, a duplicate gate target), after make has read the file; the `-` prefix
    and suffix scan reads every TAB recipe line of the EXPLICIT rules of the named closure, not a
    recipe make supplies from its built-in implicit rules. vizra-core #11 (open, B5b) refuses
    non-explicit and non-.PHONY closure targets, per the vizra-security desk review of this PR. Search
    adopts core's anchor in a follow-up. Review is the control there, and CODEOWNERS is advisory
    until the owner's ruleset exists.
  * Without `--workflow` the ENVIRONMENT check is not a control. That is the local-parity mode the Go
    meta-tests use: make exports MAKEFLAGS to a recipe, so the words are checked against an ALLOWLIST of
    what GNU Make 3.81 and 4.3 export, and variables the makefiles take from the environment are
    reported, not refused. The digest gate applies in BOTH modes. (There is no `make ci-guard` target in
    this repository.)
  * This file, the workflow and the pins — .github/pinned-steps.yml and .github/pinned-makefiles.yml —
    are checked out from the pull request under test. Every edit to them is visible in a reviewed diff;
    none is prevented.

Usage:
    make-integrity-guard.py [--root DIR] [--targets a,b,c] [--workflow]
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# THE GATE TARGETS.
#
# Every make target a CI lane invokes (.github/pinned-steps.yml `make_steps`),
# plus `ci`, the local complete gate, so its prerequisite closure is scanned too.
# The closure is COMPUTED from the literal prerequisites of explicit rules (see
# prerequisite_closure for what it does not follow), so a lane added to `ci` as
# an explicit rule is covered without editing this list.
# ---------------------------------------------------------------------------
GATE_TARGETS = [
    "ci",  # local parity: every lane, in order
    "fmt-check",  # fmt
    "vet",  # vet
    "echo-containment",  # echo-containment
    "build",  # build
    "contract-drift",  # contract-drift
    "test",  # test
    "tidy-check",  # tidy-check
    "vendor-contract-selftest",  # vendor-contract-selftest
]

# The ONLY accepted values. Anything else — including another shell that happens
# to be a real shell — is refused, because this guard cannot know whether an
# unfamiliar shell honours `-e`.
APPROVED_SHELL = "/bin/bash"
APPROVED_SHELLFLAGS = "-eu -o pipefail -c"

# Special variables whose assignment can disarm every recipe at once.
FORBIDDEN_ASSIGNMENTS = ("MAKEFLAGS", "GNUMAKEFLAGS", "MFLAGS")
CONTROLLED_ASSIGNMENTS = ("SHELL", ".SHELLFLAGS")

# Make's recipe-line prefixes. `-` is the dangerous one and is invisible to
# `make --dry-run`; `+` forces execution even under `-n` and is not something a
# gate recipe has any use for.
RECIPE_PREFIX_CHARS = "@-+"

# Suffixes that throw away a command's exit status.
SWALLOWING_SUFFIXES = (
    "|| true", "|| :", "|| exit 0", "|| /bin/true", "|| /usr/bin/true",
    "; true", "; :", "; exit 0",
)

# The ONE recipe line allowed to end with a swallowing suffix, byte-equal, and
# only in this target. contract-drift's `go test` line ends `|| true` because the
# NEXT line, `./scripts/contract-drift-guard.py ran`, is the authority on the
# lane's verdict: it fails on any failed test, any failed package, any listed
# package that ran zero tests, and an empty or missing report — and
# contract-drift-guard.py `recipe` (run both in the recipe and as its own
# workflow step) refuses a lane whose last command is not that `ran`. A default-
# deny exemption, keyed by target AND exact text: the same suffix anywhere else,
# or this line in any other target, is refused.
SWALLOW_EXEMPT = {
    ("contract-drift", "go test -count=1 -json $(DRIFT_PKGS) > $(DRIFT_REPORT) || true"),
}

# GNU make 3.81 says "overriding commands for target"; GNU make 4.x says
# "overriding recipe for target". Matching only one wording is how a check
# silently stops working on the platform that actually gates merges.
DUPLICATE_TARGET_RE = re.compile(r"(overriding|ignoring old)\s+(commands|recipe)\s+for\s+target", re.I)

# Flags that make a failing recipe not fail the build, or make recipes not run
# at all. `n` and `p` are OURS — this guard invokes `make -pn` — so they are
# expected; anything else is refused by name whatever it is.
DANGEROUS_FLAG_WORDS = (
    "--ignore-errors", "--keep-going", "--touch", "--question", "--dry-run",
    "--just-print", "--recon", "--old-file", "--assume-old",
)

MAKE_CONDITIONALS = ("ifeq", "ifneq", "ifdef", "ifndef")


class Guard:
    def __init__(self) -> None:
        self.failures = 0

    @property
    def failed(self) -> bool:
        return self.failures > 0

    def ok(self, msg: str) -> None:
        print(f"  ok    {msg}", flush=True)

    def fail(self, msg: str, *detail: str) -> None:
        print(f"  FAIL  {msg}", file=sys.stderr, flush=True)
        for d in detail:
            print(f"        {d}", file=sys.stderr, flush=True)
        self.failures += 1


# ------------------------------------------------------ the gate (makegate) ---
#
# Every make process this guard starts goes through scripts/makegate.py, the
# ONE digest-gated way this repository starts make (see its docstring): the
# pinned bytes (regular files, sha256), the static read set, a clean
# environment, a checked `make` started by its real path, and the `make -q`
# remake probe, then a re-hash after every run. History, kept because it is
# why this is bytes and not grammar: the port first scanned the Makefile TEXT;
# the vizra-security desk review of PR #5 showed two constructs make evaluates
# that the scanner missed, and the PR #5 re-verification showed a newer
# unpinned `Makefile.sh` sibling rewriting the Makefile during the anchor's own
# `make -pn` through a built-in rule, after a digest had already passed.
import importlib.util as _ilu

_spec = _ilu.spec_from_file_location("makegate", Path(__file__).resolve().parent / "makegate.py")
makegate = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(makegate)

clean_env = makegate.clean_env
PIN_FILE = makegate.PIN_FILE

# Set by main() once the gate has opened; every later make runs through it,
# with the pinned makefiles named as goals so -n applies to them too.
GATE = None


def run_make(root: Path, args: list[str]):
    return GATE.run(args, name_goals=True)


# --------------------------------------------------------------- resolver ---


def resolve_database(g: Guard, root: Path, target: str):
    """Ask make for its resolved variable database.

    `make -pn TARGET` expands variables, applies `include`s and resolves
    duplicate-target overrides before printing, so this is what will REALLY be
    used — not what the file looks like. Returns (variables, makefile_list) or
    (None, None) if make could not resolve the target at all.
    """
    proc = run_make(root, ["-pn", target])
    if proc.returncode != 0:
        g.fail(
            f"`make -pn {target}` failed (exit {proc.returncode}); the lane's real shape could not be established.",
            "A gate whose shape cannot be determined is not a gate.",
            *(proc.stderr or proc.stdout).strip().splitlines()[:8],
        )
        return None, None

    variables: dict[str, str] = {}
    oneshell = False
    for line in proc.stdout.splitlines():
        if line.startswith(".ONESHELL:"):
            oneshell = True
            continue
        m = re.match(r"^([A-Za-z_.][A-Za-z0-9_.-]*)\s*[:+?]?=\s?(.*)$", line)
        if m and m.group(1) not in variables:
            variables[m.group(1)] = m.group(2)
    variables["__ONESHELL__"] = "yes" if oneshell else ""
    files = [f for f in variables.get("MAKEFILE_LIST", "").split() if f]
    return variables, files


def check_resolved(g: Guard, target: str, variables: dict) -> None:
    shell = variables.get("SHELL")
    if shell is None:
        g.fail(f"make reports no SHELL at all while resolving `{target}`")
    elif shell.strip() != APPROVED_SHELL:
        g.fail(
            f"make resolves SHELL to {shell.strip()!r} while resolving `{target}`, not {APPROVED_SHELL!r}.",
            "A SHELL pointed at a no-op (`/usr/bin/true`, `:`, `/bin/echo`) makes EVERY recipe in this",
            "repository exit 0 without running — `make ci` included — while every gate stays green.",
            "This is the single line that turns the whole merge rule into a formality.",
        )
    else:
        g.ok(f"`{target}`: make resolves SHELL to the approved {APPROVED_SHELL}")

    flags = variables.get(".SHELLFLAGS")
    if flags is None:
        g.fail(f"make reports no .SHELLFLAGS while resolving `{target}`")
    elif flags.strip() != APPROVED_SHELLFLAGS:
        g.fail(
            f"make resolves .SHELLFLAGS to {flags.strip()!r} while resolving `{target}`, not {APPROVED_SHELLFLAGS!r}.",
            "Dropping `-e` makes a recipe continue after a failing command and report the exit status of",
            "the LAST one; dropping `-o pipefail` hides a failure on the left of a pipe.",
        )
    else:
        g.ok(f"`{target}`: make resolves .SHELLFLAGS to the approved {APPROVED_SHELLFLAGS!r}")

    if variables.get("__ONESHELL__"):
        g.fail(
            f"`.ONESHELL:` is in effect while resolving `{target}`.",
            "Under .ONESHELL make passes the WHOLE recipe to one shell invocation, and the `@`/`-`",
            "prefixes then apply only to the first line — which changes what every other check here",
            "means. A gate recipe has no use for it.",
        )
    else:
        g.ok(f"`{target}`: `.ONESHELL:` is not in effect")

    # MAKEFLAGS. This guard invoked make as `-pn`, so `p` and `n` are ours.
    # Anything else was added by a file or by the environment.
    raw = variables.get("MAKEFLAGS", "")
    words = raw.split()
    cluster = ""
    rest = []
    for w in words:
        if not cluster and not w.startswith("-") and "=" not in w:
            cluster = w
        else:
            rest.append(w)
    extra = sorted(set(cluster) - set("pn"))
    bad_words = [w for w in rest if w in DANGEROUS_FLAG_WORDS or w in ("-i", "-k", "-t", "-q")]
    if extra or bad_words:
        g.fail(
            f"make resolves MAKEFLAGS to {raw!r} while resolving `{target}`.",
            f"This guard invoked `make -pn`, so 'p' and 'n' are its own; everything else was added: "
            f"{''.join(extra) or ''}{' ' if extra and bad_words else ''}{' '.join(bad_words)}",
            "`-i` / `--ignore-errors` makes make ignore EVERY recipe's exit status, so `make ci` exits 0",
            "with the whole gate failing underneath it. `-k`, `-t` and `-q` are the same class.",
        )
    else:
        g.ok(f"`{target}`: MAKEFLAGS carries nothing beyond this guard's own -pn ({raw!r})")


def check_warnings(g: Guard, root: Path, target: str) -> None:
    """A duplicate target means the recipe a reader sees is not the one that runs."""
    proc = run_make(root, ["--dry-run", "--no-print-directory", target])
    stderr = proc.stderr or ""
    if DUPLICATE_TARGET_RE.search(stderr):
        g.fail(
            f"make reports a DUPLICATE definition while resolving `{target}`:",
            *[ln for ln in stderr.splitlines() if DUPLICATE_TARGET_RE.search(ln)],
            "make runs the LAST definition. A reader — and any text-based check — sees the first, so a",
            "duplicate can replace a whole gate recipe with `@true` and leave the file looking correct.",
        )
        return
    # Other warnings are REPORTED but do not fail: GNU make 4.3 emits a benign
    # "modification time in the future" warning on some mounted filesystems, and
    # a guard that goes red for that is a guard people route around. Saying so
    # here rather than silently ignoring them.
    others = [ln for ln in stderr.splitlines() if "warning:" in ln.lower()]
    if others:
        print(f"  note  make emitted {len(others)} non-duplicate warning(s) resolving `{target}` (not a failure):")
        for ln in others[:5]:
            print(f"        {ln}")
    g.ok(f"`{target}`: make reports no duplicate-definition override")
    check_expanded_commands(g, target, proc.stdout or "")


# The ONE swallowed command CI accepts, as make EXPANDS it (SWALLOW_EXEMPT holds it as written).
_EXPANDED_EXEMPT_RE = re.compile(r"^go test -count=1 -json( \./\S+)+ > \.contract-drift-report\.json \|\| true$")


def check_expanded_commands(g: Guard, target: str, stdout: str) -> None:
    """A swallowed exit that only appears AFTER expansion (`cmd $(SWALLOW)` with SWALLOW := || true).

    The text reading sees `$(SWALLOW)`, not `|| true`; `make --dry-run` prints the command expanded, so
    the suffix is visible here. A `-` or `+` PREFIX produced by expansion is not visible in the dry-run
    (make strips prefixes before printing), which is why makegate refuses, before make, any recipe line
    that BEGINS with an expansion.
    """
    commands, pending = [], ""
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or re.match(r"^make(\[\d+\])?: ", line):
            continue
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        commands.append((pending + line).strip())
        pending = ""
    bad = [c for c in commands
           if any(c.rstrip().endswith(sfx) for sfx in SWALLOWING_SUFFIXES) and not _EXPANDED_EXEMPT_RE.match(c)]
    for c in bad:
        g.fail(f"`{target}` EXPANDS to a command whose exit status is discarded: `{c[:160]}`",
               "The suffix is produced by a variable, so the text reading could not see it; make's own",
               "dry-run shows it. A check whose failure is swallowed is not a check.")
    if not bad:
        g.ok(f"`{target}`: no expanded command discards its exit status (the one contract-drift `ran` line excepted)")


# ------------------------------------------------------------------- text ---


def prerequisite_closure(root: Path, files: list[str], seeds: list[str]) -> list[str]:
    """Expand the named gate targets through the literal prerequisites of EXPLICIT rules.

    `ci` is one word in a workflow and ten lanes in the Makefile. Checking only
    the word would leave `test`'s recipe — the actual test run — outside
    every recipe check here, which is precisely the gap a `-` prefix would use.
    So the closure is COMPUTED from the explicit rules rather than listed, and a
    lane added to `ci` as an explicit rule is covered without editing this file.

    It reads rule lines through makegate's ONE logical-line sequence
    (makegate.read_makefile_lines: continuations joined, each line's comment
    stripped exactly as the grammar stripped it) and its rule/assignment split.
    makegate's grammar has already refused every rule line that is not
    `name: literal prerequisites`,
    so there is no pattern, suffix or `.DEFAULT` rule and no `$`-named
    prerequisite to follow.

    What it does NOT follow, so what check_recipe never scans: a recipe make
    supplies from its BUILT-IN implicit rules — for a closure prerequisite with
    no explicit rule (only printed as a note), or for a target whose explicit
    rule has no recipe and is not `.PHONY`. vizra-core #11 (open, B5b) refuses
    non-explicit and non-.PHONY closure targets, per the vizra-security desk
    review of this PR. Search adopts core's anchor in a follow-up.
    """
    prereqs: dict[str, list[str]] = {}
    for rel in files:
        try:
            lines = makegate.read_makefile_lines(root / rel)
        except OSError:
            continue
        # makegate's ONE reading: continuations joined and comments stripped exactly as the grammar read them
        # (a rule line whose trailing comment held `=` used to fall out of the old RULE_RE, and its
        # prerequisites with it), then the same rule/assignment split makegate refuses non-simple rule lines with.
        for rec in lines:
            if rec.tab or not rec.code.strip():
                continue
            parts = makegate._rule_parts(rec.code.rstrip())
            if parts is None:
                continue
            names = parts[0].split()
            rest = parts[1]
            if "=" in makegate._outside_expansions(rest):
                continue  # a target-specific variable assignment, not prerequisites
            deps = rest.split(";")[0].replace("|", " ").split()
            for n in names:
                if n.startswith(".") or "%" in n:
                    continue  # .PHONY, .SHELLFLAGS, pattern rules
                prereqs.setdefault(n, [])
                prereqs[n].extend(d for d in deps if not d.startswith("$"))

    out: list[str] = []
    queue = list(seeds)
    while queue:
        t = queue.pop(0)
        if t in out:
            continue
        out.append(t)
        for d in prereqs.get(t, []):
            if d not in out:
                queue.append(d)
    return out


def logical_recipe_lines(lines, start: int):
    """One target's recipe: makegate.recipe_lines over makegate's ONE logical-line sequence.

    `lines` is makegate.read_makefile_lines(<file>) and `start` the index of the line after the rule line.
    Every TAB line from there on is the rule's, blank and comment lines keep it open, and any other line
    closes it — the same sequence, and the same decision, as makegate.grammar_problems, which has already
    refused before make every line that is not empty, a comment, an assignment, a `.PHONY:` line, a
    single-target rule line or a TAB recipe line of a rule, and every comment continued by a backslash. So a
    rule's recipe is exactly the TAB lines after it, for make, for the grammar and for this reading.
    """
    return makegate.recipe_lines(lines, start)


# The environment-taken reading lives in makegate (environment_taken), because EVERY make process drops
# those names, not only the anchor's (M-4); ci-required-guard.py calls it there too.


def check_environment_overrides(g: Guard, root: Path, files: list[str], workflow: bool) -> None:
    """In the WORKFLOW invocation, nothing in the environment may change what a recipe runs.

    Found in vizra-core while fixing PR #9 round 2: its Makefile has
    `GO ?= go`, and `?=` means the ENVIRONMENT wins. `GO=true make test-race`
    exited 0 over a planted failing test where `make test-race` exited 2, and
    the anchor passed it. Here `VERSION ?= …` and `COMMIT ?= …` feed `-ldflags`
    and `CORE ?= …` names the checkout `vendor-contract` reads — the same class.
    An earlier step's `$GITHUB_ENV` write reaches make exactly as MAKEFLAGS does.

    So, from every file make read (MAKEFILE_LIST, includes too): a variable
    assigned with `?=`, or referenced as `$(NAME)` without ever being assigned,
    is one the environment can set — and in `--workflow` mode it must be ABSENT.
    `GOFLAGS` is refused as well whether or not a makefile names it, because
    the go command reads it directly. Local mode only reports them: a developer
    may legitimately run `VERSION=v0.0.1 make build`. In BOTH modes, and for
    every other caller of the gate, makegate.run_make starts make without them.
    """
    from_env = makegate.environment_taken(root, files)
    present = sorted(n for n in from_env if n in os.environ)
    if not workflow:
        g.ok(f"[local parity] the makefiles take these from the environment: {sorted(from_env)}"
             + (f"; set now: {present}" if present else "")
             + " — every make the gate starts runs WITHOUT them")
        return
    if present:
        g.fail(
            f"the environment sets {', '.join(f'{n}={os.environ[n]!r}' for n in present)}, and this is "
            f"the WORKFLOW anchor.",
            "The makefiles take these FROM the environment (`?=`, or referenced as $(NAME) and never assigned),",
            "so the environment decides what the recipe runs (vizra-core measured `GO=true make test-race`",
            "exiting 0 over a failing test). In a required lane nothing may set them; the Makefile's own",
            "values must win.",
        )
        return
    g.ok(f"[--workflow] none of the {len(from_env)} variable(s) the makefiles take from the "
         f"environment is set: {sorted(from_env)}")


def check_text(g: Guard, root: Path, files: list[str], targets: list[str], seeds: list[str]) -> None:
    """Read the files make said it read.

    MAKEFILE_LIST comes from make itself, so an `include` cannot hide a file
    from this scan — which matters, because an included makefile carrying
    `MAKEFLAGS += -i` no-ops the whole repository just as well as the root one.
    """
    if not files:
        g.fail("make reported an empty MAKEFILE_LIST; there is nothing to read")
        return
    g.ok(f"make read {len(files)} makefile(s): {', '.join(files)}")

    assignment_re = re.compile(
        r"^\s*(?:export\s+|override\s+)*(" + "|".join(
            re.escape(n) for n in (*CONTROLLED_ASSIGNMENTS, *FORBIDDEN_ASSIGNMENTS)
        ) + r")\s*([:+?!]?=)\s*(.*?)\s*$"
    )

    definitions: dict[str, list[str]] = {t: [] for t in targets}
    seen_shell = seen_shellflags = False

    for rel in files:
        path = root / rel
        try:
            lines = makegate.read_makefile_lines(path)
        except (OSError, UnicodeDecodeError) as err:
            g.fail(f"cannot read {rel}, which make says it read: {err}")
            continue
        is_root = Path(rel).name == "Makefile" and Path(rel).parent in (Path("."), Path(""))

        for idx, rec in enumerate(lines):
            if rec.tab:
                continue  # a recipe line, handled below
            n, line = rec.n, rec.raw
            m = assignment_re.match(line)
            if m:
                name, op, value = m.group(1), m.group(2), m.group(3)
                if name in FORBIDDEN_ASSIGNMENTS:
                    g.fail(
                        f"{rel}:{n} assigns {name}: `{line.strip()}`",
                        "No assignment to MAKEFLAGS/GNUMAKEFLAGS is legitimate here, whatever its value.",
                        "`MAKEFLAGS += -i` is one line and makes EVERY recipe in this repository exit 0",
                        "without its failures counting — measured on GNU Make 3.81 and 4.3.",
                    )
                    continue
                want = APPROVED_SHELL if name == "SHELL" else APPROVED_SHELLFLAGS
                if not is_root:
                    g.fail(
                        f"{rel}:{n} assigns {name}, but only the root Makefile may: `{line.strip()}`",
                        "An included makefile is a second file a reviewer may not open.",
                    )
                elif op != ":=" or value != want:
                    g.fail(
                        f"{rel}:{n} sets {name} to something other than the approved value: `{line.strip()}`",
                        f"Approved: `{name} := {want}`",
                    )
                else:
                    if name == "SHELL":
                        seen_shell = True
                    else:
                        seen_shellflags = True
                continue

            if line.strip().startswith(".ONESHELL"):
                g.fail(f"{rel}:{n} declares `.ONESHELL`: `{line.strip()}`",
                       "It changes what a `-` prefix means, and a gate recipe has no use for it.")
            if line.strip().startswith(".SECONDEXPANSION"):
                g.fail(f"{rel}:{n} declares `.SECONDEXPANSION`: `{line.strip()}`",
                       "Prerequisites are then expanded a second time while make considers targets, which",
                       "happens under `make -n` too. A gate Makefile has no use for it.")
            if re.match(r"^\s*(?:override\s+)?\.RECIPEPREFIX\s*[:+?!]?=", line):
                g.fail(f"{rel}:{n} assigns `.RECIPEPREFIX`: `{line.strip()}`",
                       "Recipes would no longer start with a tab, so every recipe check here would read none",
                       "of them. A gate Makefile has no use for it.")

            for t in targets:
                if re.match(r"^%s\s*:(?!=)" % re.escape(t), line):
                    definitions[t].append(f"{rel}:{n}")
                    # Guard against a gate target hidden inside a conditional:
                    # which recipe runs would then depend on a variable.
                    depth = 0
                    for prev in lines[:idx]:
                        head = prev.raw.strip().split(" ")[0]
                        if head in MAKE_CONDITIONALS:
                            depth += 1
                        elif head == "endif":
                            depth = max(0, depth - 1)
                    if depth > 0:
                        g.fail(
                            f"{rel}:{n} defines the gate target `{t}` inside a make conditional.",
                            "Which recipe runs would depend on a variable, so the recipe a reader sees is",
                            "not necessarily the one that executes. Gate targets must be unconditional.",
                        )
                    check_recipe(g, rel, t, logical_recipe_lines(lines, idx + 1))

    if not seen_shell or not seen_shellflags:
        g.fail(
            "the root Makefile does not carry BOTH approved assignments.",
            f"Required, exactly: `SHELL := {APPROVED_SHELL}` and `.SHELLFLAGS := {APPROVED_SHELLFLAGS}`.",
            "Without them make uses /bin/sh with no -e, and a failing command mid-recipe does not fail the lane.",
        )
    else:
        g.ok("the root Makefile pins SHELL and .SHELLFLAGS to the approved values, and nothing else assigns them")

    undefined = []
    for t in targets:
        where = definitions[t]
        if not where:
            if t in seeds:
                g.fail(
                    f"gate target `{t}` is not defined in any makefile make read.",
                    "A required CI lane invokes it by that name.",
                )
            else:
                # A prerequisite with no rule of its own is an ordinary FILE
                # dependency, not a missing lane. Named rather than silently
                # dropped, so the transcript says what was and was not scanned.
                undefined.append(t)
        elif len(where) > 1:
            g.fail(
                f"gate target `{t}` is defined {len(where)} times: {', '.join(where)}",
                "make runs the LAST definition and REPLACES the earlier recipe. The lane must have one recipe.",
            )
        else:
            g.ok(f"gate target `{t}` is defined exactly once ({where[0]})")
    if undefined:
        print(f"  note  {len(undefined)} prerequisite(s) have no rule and are treated as file dependencies, "
              f"not lanes: {', '.join(sorted(undefined))}")


def check_recipe(g: Guard, rel: str, target: str, recipe) -> None:
    """Refuse recipe lines whose failure would not fail the lane.

    This reading is the only one that can see a `-` prefix: `make --dry-run`
    prints the command WITHOUT it, so the resolved recipe looks identical to a
    correct one.
    """
    if not recipe:
        # Legitimate for an aggregate like `ci:` whose work is its prerequisites.
        return
    for lineno, body in recipe:
        prefix = ""
        while body and body[0] in RECIPE_PREFIX_CHARS:
            prefix += body[0]
            body = body[1:].lstrip()
        if "-" in prefix:
            g.fail(
                f"{rel}:{lineno} — gate target `{target}` has a recipe line prefixed `-`: `{prefix}{body}`",
                "make IGNORES that line's exit status, and `make --dry-run` prints the command WITHOUT the",
                "`-`, so no scan of the resolved recipe can see it: the command can fail, print its failure,",
                "and the lane still exits 0.",
            )
        if "+" in prefix:
            g.fail(
                f"{rel}:{lineno} — gate target `{target}` has a recipe line prefixed `+`: `{prefix}{body}`",
                "`+` forces the line to run even under `-n`, which is how a guard's own dry-run probe can be",
                "made to execute something. A gate recipe has no use for it.",
            )
        stripped = body.rstrip()
        if (target, stripped) in SWALLOW_EXEMPT and not prefix:
            continue
        for suffix in SWALLOWING_SUFFIXES:
            if stripped.endswith(suffix):
                g.fail(
                    f"{rel}:{lineno} — gate target `{target}` has a recipe line ending `{suffix}`: `{stripped}`",
                    "The command's exit status is discarded. A check whose failure is swallowed is not a check.",
                )
                break


# ------------------------------------------------------------ environment ---


# `make` must resolve to a regular file named make/gmake in makegate.APPROVED_MAKE_DIRS.

# Shells that are not shells: a SHELL pointed at one of these makes every recipe
# a no-op on the platforms that honour the environment's SHELL.
NEUTERED_SHELLS = ("/usr/bin/true", "/bin/true", ":", "/bin/echo", "/usr/bin/echo", "/bin/false", "/usr/bin/false")


# Variables make itself exports to a recipe. In the WORKFLOW invocation the
# anchor is not a recipe, so any of these being present means something planted
# it — typically an earlier step writing to $GITHUB_ENV.
MAKE_INTERNAL_VARS = ("MAKELEVEL", "MAKE_RESTARTS", "MAKEOVERRIDES", "MAKECMDGOALS")
FLAG_VARS = ("MAKEFLAGS", "GNUMAKEFLAGS", "MFLAGS")

# LENIENT mode is an ALLOWLIST, not a list of bad letters. These are the words
# GNU make itself puts in MAKEFLAGS/MFLAGS for a recipe such as `make test` (the meta-tests),
# MEASURED on GNU Make 4.3 (ubuntu:24.04, CI's version) and 3.81 (the host):
#   make            MAKEFLAGS=''                            (both)
#   make -j2        ' -j2 --jobserver-auth=3,4'             (4.3)
#                   ' --jobserver-fds=3,4 -j', MFLAGS '- --jobserver-fds=3,4 -j'  (3.81)
#   make -s         's'          make -w  'w'          --no-print-directory
# Anything else — `-ki`, `n`, `--ign`, `e` — is refused, whatever it means.
_ALLOWED_FLAG_WORD = re.compile(
    r"^(?:-|[ws]+|-[ws]|-j\d*|--jobserver-(?:fds|auth)=\S+"
    r"|--print-directory|--no-print-directory|--silent|--quiet)$"
)


def check_environment(g: Guard, workflow: bool) -> None:
    """The anchor's OWN process environment.

    WHICH MODE is chosen by how the anchor is INVOKED, never by the environment.
    Round 2 chose it from `MAKELEVEL is not None`, and an earlier step can put
    `MAKELEVEL=1` (or even an empty `MAKELEVEL=`) in $GITHUB_ENV beside
    `MAKEFLAGS=-ki`. The lenient path then passed `-ki`, `n` and `--ign`, and GNU
    Make 4.3 made a failing recipe exit 0 under each (PR#9 re-verification,
    FINDING R-2). Now:

    --workflow  the invocation pinned byte-for-byte in .github/pinned-steps.yml,
                the ONLY form ci-required-guard accepts as the anchor. STRICT:
                MAKEFLAGS/GNUMAKEFLAGS/MFLAGS must be UNSET (not merely empty or
                free of known flags), and MAKELEVEL/MAKE_RESTARTS/MAKEOVERRIDES/
                MAKECMDGOALS must be ABSENT — the anchor is not a make recipe, so
                if any is present, something planted it.

    (no flag)   local parity: the scripts/scripts_test.go runs, under make or not.
                Make legitimately exports MAKEFLAGS to a recipe, so every word of
                it must be in a measured ALLOWLIST (_ALLOWED_FLAG_WORD). This mode
                is not a control, and no floor lane can select it: a workflow
                anchor without the pinned `--workflow` is not byte-equal to the
                pin and is refused by ci-required-guard.

    In BOTH modes MAKEFILES, BASH_ENV and ENV must be unset and SHELL must be a
    real shell.
    """
    bad = False
    mode = "--workflow (strict)" if workflow else "local parity (allowlist)"

    if workflow:
        for name in MAKE_INTERNAL_VARS:
            if name in os.environ:
                g.fail(
                    f"the environment has {name}={os.environ[name]!r}, and this is the WORKFLOW anchor.",
                    "The anchor is not a make recipe, so make did not put it there: something else did,",
                    "most likely an earlier step writing to $GITHUB_ENV. MAKELEVEL in particular was how",
                    "the round-2 anchor was talked into a lenient mode (PR#9 re-verification, R-2).",
                )
                bad = True
        for name in FLAG_VARS:
            if name in os.environ:
                g.fail(
                    f"the environment sets {name}={os.environ[name]!r}, and this is the WORKFLOW anchor.",
                    "It must be UNSET: make reads it as if it were typed on the command line, so ANY",
                    "value is a command line nobody reviewed — including ones a blacklist would pass.",
                )
                bad = True
    else:
        for name in FLAG_VARS:
            value = os.environ.get(name, "")
            refused = [w for w in value.split() if not _ALLOWED_FLAG_WORD.match(w)]
            if refused:
                g.fail(
                    f"the environment sets {name}={value!r}; {refused} is not a flag make itself",
                    "exports to a recipe (`make test`). This mode is an ALLOWLIST of the words GNU make",
                    "3.81 and 4.3 were measured to export (-jN, --jobserver-*, s, w, --no-print-directory).",
                )
                bad = True
        if os.environ.get("MAKEOVERRIDES", "").strip():
            g.fail(f"the environment sets MAKEOVERRIDES={os.environ['MAKEOVERRIDES']!r}: a command-line "
                   f"variable override reached the recipe.")
            bad = True

    # MAKEFILES makes make read extra makefiles BEFORE the root one, and make
    # never sets it itself, so it is refused in both modes.
    if os.environ.get("MAKEFILES", "").strip():
        g.fail(
            f"the environment sets MAKEFILES={os.environ['MAKEFILES']!r}.",
            "make reads those files before the root Makefile, so they can assign SHELL or MAKEFLAGS",
            "without appearing in anything this guard scans.",
        )
        bad = True

    # A non-interactive bash SOURCES $BASH_ENV, so it can define a `make` shell
    # function before any recipe or any command runs.
    for name in ("BASH_ENV", "ENV"):
        if os.environ.get(name, "").strip():
            g.fail(
                f"the environment sets {name}={os.environ[name]!r}.",
                "A non-interactive shell sources it, so it can define a `make` function or alias that",
                "shadows the real program before a single recipe runs.",
            )
            bad = True

    shell = os.environ.get("SHELL", "").strip()
    if shell and (shell in NEUTERED_SHELLS or not os.path.isfile(shell) or not os.access(shell, os.X_OK)):
        g.fail(
            f"the environment sets SHELL={shell!r}, which is not a usable shell program.",
            "Some platforms let the environment's SHELL reach make. A SHELL pointed at `true` or `:`",
            "makes every recipe a silent no-op.",
        )
        bad = True

    if not bad:
        if workflow:
            g.ok(f"[{mode}] MAKEFLAGS/GNUMAKEFLAGS/MFLAGS unset; MAKELEVEL/MAKE_RESTARTS/MAKEOVERRIDES/"
                 f"MAKECMDGOALS absent; MAKEFILES/BASH_ENV/ENV unset; SHELL is a real shell")
        else:
            g.ok(f"[{mode}] every MAKEFLAGS/GNUMAKEFLAGS/MFLAGS word is one make exports itself; "
                 f"MAKEFILES/BASH_ENV/ENV unset; SHELL is a real shell")


# ------------------------------------------------------------------- main ---


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent,
                    help="directory holding the Makefile (default: the repository root)")
    ap.add_argument("--targets", default=",".join(GATE_TARGETS),
                    help="comma-separated gate targets (default: every target a required CI lane invokes)")
    ap.add_argument("--workflow", action="store_true",
                    help="STRICT environment mode: the invocation pinned in .github/pinned-steps.yml as "
                         "the workflow anchor. Chosen by the invocation, never by the environment.")
    args = ap.parse_args()

    root = args.root.resolve()
    targets = [t.strip() for t in args.targets.split(",") if t.strip()]

    g = Guard()
    print(f"make-integrity-guard: {root}", flush=True)
    print(f"  gate targets: {', '.join(targets)}", flush=True)

    if not (root / "Makefile").exists():
        g.fail(f"{root}/Makefile does not exist")
        print("make-integrity-guard: FAILED", file=sys.stderr)
        return 1

    # EVERYTHING up to the gate runs WITHOUT starting make. Any failure here
    # stops the anchor before make: an unpinned or changed makefile, a planted
    # MAKEFILES / MAKELEVEL / MAKEFLAGS, a `make` that is not the system's, or a
    # variable the reviewed Makefile takes from the environment (R-2: before
    # this, a failed environment check was reported and make was run anyway).
    global GATE
    pinned = None
    try:
        pinned = makegate.check_pinned_bytes(root)
    except makegate.GateRefused as err:
        for p in err.problems:
            g.fail(p)
    check_environment(g, args.workflow)
    make = None
    try:
        make = makegate.resolve_make()
        g.ok(f"`make` resolves to {make} (a regular file named make in an approved system directory), and "
             f"every make this guard starts is started by that path. This does not inspect the program's "
             f"CONTENT: a forwarding stub planted there by an earlier step is outside what this guard can see.")
    except makegate.GateRefused as err:
        for p in err.problems:
            g.fail(p)
    if pinned is not None:
        check_environment_overrides(g, root, pinned[0], args.workflow)
    if g.failed or pinned is None or make is None:
        print(f"make-integrity-guard: FAILED — make was NOT invoked ({makegate.MAKE_INVOCATIONS} make "
              f"process(es) started)", file=sys.stderr)
        return 1
    files, digests, sites = pinned

    # make's first invocation: ONE `make -q <every pinned makefile>` (no ordinary recipe runs).
    try:
        makegate.remake_probe(make, root, files)
    except makegate.GateRefused as err:
        for p in err.problems:
            g.fail(p)
        for p in makegate.recheck(root, digests):
            g.fail(p)
        print(f"make-integrity-guard: FAILED — {err.invoked} ({makegate.MAKE_INVOCATIONS} make process(es))",
              file=sys.stderr)
        return 1
    GATE = makegate.Gate(root, files, digests, sites, make)
    g.ok(GATE.describe())

    # One resolver pass names every file make reads, including everything an
    # `include` pulls in. The text reading then covers all of them.
    try:
        variables, mfiles = resolve_database(g, root, targets[0])
    except makegate.GateRefused as err:
        for p in err.problems:
            g.fail(p)
        print("make-integrity-guard: FAILED", file=sys.stderr)
        return 1
    if variables is None:
        print("make-integrity-guard: FAILED", file=sys.stderr)
        return 1
    # MAKEFILE_LIST must be EXACTLY the pinned set the static reading predicted.
    read = sorted({os.path.normpath(f) for f in mfiles})
    if read != sorted(files):
        g.fail(
            f"make read {read}, but {PIN_FILE} and the static read set say exactly {sorted(files)}.",
            "make read a file nobody pinned, or the static reading of the reviewed bytes is wrong; either",
            "way it fails closed.",
        )
        print("make-integrity-guard: FAILED", file=sys.stderr)
        return 1
    g.ok(f"MAKEFILE_LIST is exactly the pinned set: {read}")
    files = mfiles

    # The named targets are what CI invokes; the CLOSURE is what actually runs.
    # `make ci` is one word in a workflow and ten lanes here, and it is
    # `test`'s recipe — not `ci`'s, which has none — that runs the tests.
    closure = prerequisite_closure(root, files, targets)
    derived = [t for t in closure if t not in targets]
    print(f"  closure: {len(closure)} target(s); {len(derived)} reached through prerequisites"
          + (f" ({', '.join(derived)})" if derived else ""))

    check_text(g, root, files, closure, targets)

    # The resolver checks read make's own variable database, which is global to
    # the invocation, and make reports a duplicate definition at PARSE time — so
    # one pass per NAMED target covers the closure as well, and also proves each
    # name CI invokes is a target make can resolve at all. Every run re-hashes
    # the pinned files (makegate.Gate.run).
    try:
        for t in targets:
            v, _ = resolve_database(g, root, t)
            if v is None:
                continue
            check_resolved(g, t, v)
            check_warnings(g, root, t)
    except makegate.GateRefused as err:
        for p in err.problems:
            g.fail(p)
    for p in makegate.recheck(root, GATE.digests):
        g.fail(p)

    # N-3: the same one-invocation probe again, last, so the pinned `make` step that follows does not
    # depend on nothing having touched a modification time since the first probe.
    try:
        makegate.remake_probe(GATE.make, root, GATE.files)
        g.ok(f"`make -q {' '.join(GATE.files)}` again at the end: still nothing would be remade")
    except makegate.GateRefused as err:
        for p in err.problems:
            g.fail(p)
    for p in makegate.recheck(root, GATE.digests):
        g.fail(p)

    if g.failed:
        print("make-integrity-guard: FAILED", file=sys.stderr)
        print("A make-driven gate that can be turned into a no-op is not a gate. Fix the Makefile.", file=sys.stderr)
        return 1
    print(f"make-integrity-guard: passed ({len(targets)} gate target(s); make ran {makegate.MAKE_INVOCATIONS} "
          f"time(s), by {GATE.make}, only on the pinned bytes of {', '.join(GATE.files)}, which are unchanged)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
