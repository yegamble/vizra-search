#!/usr/bin/env python3
"""makegate — the ONE way this repository starts `make` from a script or a test.

Derived from vizra-core PR #10 (branch chore/m0-anchor-makefile-digest, head 62d16aa), whose
scripts/make-integrity-guard.py carries the same pin shape, static read set, `make -q` remake probe and
re-hash. vizra-core has since gone further (B5b, vizra-core #11: computed-name refusals, a closure of
explicit .PHONY rules); this module refuses its own set of computed and non-simple spellings (step 2)
and does NOT carry core's closure rule. Search
puts the pieces it has in this module so that the known make invocations — the workflow anchor
(make-integrity-guard.py), the contract-drift lane's shape check (contract-drift-guard.py), and the
Go test that reads the lane (internal/httpapi/lane_selection_test.go) — go through the same gate.
TestEveryPlaceThatStartsMakeIsGated (scripts/scripts_test.go) fails on any make call it matches outside
this file; it matches only the literal forms AGENTS.md lists (os/exec Command/CommandContext, strings
passed to subprocess/os calls, a Python argv list or tuple literal starting with make, make in command
position on a .sh line), not make reached through any other variable, a wrapper, another exec API or a
file type it does not read.

WHY. GNU Make EVALUATES a makefile while it reads it — `$(shell …)`, `$(file …)`, `!=`, `+` and
`$(MAKE)` recipe lines, `.SECONDEXPANSION` prerequisites — and it REMAKES an out-of-date makefile
before anything else, even under -n, from a rule or from one of its BUILT-IN implicit rules: a newer
unpinned `Makefile.sh` beside the Makefile is turned into the Makefile by `% : %.sh` (`cat $< > $@`)
with no line in any makefile saying so (PR #5 re-verification, FINDING 2). So a `make --dry-run`
is not a read-only operation, and it may only ever run on reviewed bytes that nothing will rewrite.

WHAT THE GATE DOES, in this order, and it starts make only if every step passes:

  1. PIN. .github/pinned-makefiles.yml (`makefiles:` then `  <path>: <64 lowercase hex>` lines — the
     shape core PR #10 uses) must parse, pin `Makefile`, and every pinned path must be a REGULAR,
     non-symlink file (lstat) whose sha256 matches.
  2. READ SET. From the pinned bytes, without running them: the files make will read are `Makefile`
     plus every literal include/load target, transitively; each must be pinned. (The grammar below
     refuses `include` and `load`, so today the read set is `Makefile` alone.) No GNUmakefile or
     makefile may sit beside it (compared case-folded, so a case-insensitive disk cannot hide one).
     GRAMMAR (grammar_problems, the control for what the reviewed bytes may say): an ALLOWLIST,
     default-deny. Every logical line of every pinned makefile must be exactly one of: blank or a
     comment; `NAME := | ?= | = value` (NAME a literal identifier, `.SHELLFLAGS` or `.DEFAULT_GOAL`)
     whose value uses only `$$`, `$(NAME)`/`${NAME}` references and `$(shell …)`; `.PHONY: names`; a
     rule line `name: prerequisites` with ONE literal target (not starting with `.`) and literal
     prerequisite words; or a TAB recipe line of the rule above it, whose text uses only `$$` and
     `$(NAME)`/`${NAME}` references, not `$(MAKE)`. ANY other line is refused with its line number.
     So no conditional, include, define, export, override, private, vpath, function outside
     `$(shell …)`, computed name, inline `;` recipe, multi-target, special-target, pattern or suffix
     rule can appear. Within that grammar, also refused BY NAME (reviewed_bytes_problems, kept as a
     second and more specific diagnosis): any SHELL / .SHELLFLAGS assignment other than the approved
     line and any MAKEFLAGS / GNUMAKEFLAGS / MFLAGS assignment; `+` recipe lines and `$(MAKE)`, which
     run even under -n and -q; and a recipe line whose body (after any `@`/`-`/`+` prefix) begins with
     `$` other than `$$`, whose prefix cannot be determined without running make. Today's Makefile
     passes both unchanged.
  3. ENVIRONMENT. MAKEFILES must be unset (it adds makefiles nobody pinned). Every process this module
     starts runs with clean_env(): make's flag variables, MAKEFILES, BASH_ENV, ENV and the runner's
     command-file variables (and anything pointing into the runner's command-file directory) removed.
     Every MAKE process additionally runs, whoever opened the gate, without: every environment
     variable whose name appears as a word ANYWHERE in the pinned makefiles' text (environment_words;
     over-matching on purpose, so `$V`, `$(V:a=b)`, `ifdef V`, `$(origin V)`, `$(value V)` and a read
     before a later `:=` are all covered), except a short keep-list (KEEP_ENV: PATH, HOME, …); and
     environment_taken (`?=` names, names referenced as `$(NAME)`/`${NAME}` and never assigned, and
     GOFLAGS — the narrower list the anchor REFUSES in --workflow mode). A variable name make
     assembles from parts, appearing as no single word, is not dropped.
  4. MAKE. `make` must resolve to a regular file named make/gmake in a system directory, and it is
     started by THAT real path, not looked up again.
  5. REMAKE PROBE. `make -q <every pinned makefile>` — each named as a GOAL, so -q applies to it and
     no ordinary recipe runs (a `+` or `$(MAKE)` recipe line still runs under -q; one can come only from the pinned, reviewed bytes) — must exit 0. ONE invocation names EVERY pinned
     file: -q applies during the remake phase only to makefiles named on the command line, so a
     per-file probe would still remake a pinned include from a newer sibling (core #10 verifier). Anything else means make would remake a pinned makefile before
     reading it, and the gate stops.
  6. Only then the requested make command runs; afterwards every pinned file is RE-HASHED and must be
     unchanged.

WHAT IT DOES NOT DO. It does not judge the reviewed bytes: they run their own reviewed `$(shell …)`
calls while being read (today four), and a malicious Makefile approved together with its pin update
runs. Review is the control there, and CODEOWNERS is advisory. Within the grammar (step 2), the
reviewed bytes may still say anything those shapes can: which commands a recipe runs, what a
`$(shell …)` in an assignment value runs while make reads the file (four such calls today), what a
variable referenced from a recipe expands to. Search adopts core's anchor (vizra-core #11) in a
follow-up. It sees only what it reads: a step
that changed the machine before it ran (a forwarding make stub, a replaced toolchain) is outside it.
It does not use `-r`/`--no-builtin-rules`: disabling the built-in rules in the probe would HIDE the
very remake the unmodified pinned `make` step would perform, and on the resolver it would change
MAKEFLAGS and the database it reads. The probe asks make with its rules intact.

CLI (used by the Go tests):  makegate.py [--root DIR] -- <make arguments>
  Exit: make's own exit code when the gate passed and make ran; 3 when the gate refused, with
  "make was NOT invoked" on stderr (or "only `make -q` ran" after a refused remake probe).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

PIN_FILE = Path(".github") / "pinned-makefiles.yml"
PIN_HEADER_RE = re.compile(r"^makefiles:[ \t]*$")
PIN_ENTRY_RE = re.compile(r"^  ([A-Za-z0-9_][A-Za-z0-9._/-]*): ([0-9a-f]{64})[ \t]*$")

# With no -f, GNU make reads the FIRST of these that exists (manual §3.2).
DEFAULT_MAKEFILE_NAMES = ("GNUmakefile", "makefile", "Makefile")

_READ_DIRECTIVE_RE = re.compile(r"^[ \t]*(-include|sinclude|include|-load|load)(?:[ \t]+(.*))?$")
# `$(eval …)`, `$(guile …)`, and `$(call eval,…)` / `$(call guile,…)` / `$(call $(F),…)`: make's `call`
# always invokes a built-in function of that name, so `call eval` IS an eval. A named diagnosis only:
# it misses e.g. `$(call ev$(A)al,…)`; grammar_problems refuses every function other than `$(shell …)`
# in an assignment value, and every function in a recipe or anywhere else, in any spelling.
_MANUFACTURES_DIRECTIVES_RE = re.compile(r"\$[({](?:eval|guile)[\s)}]|\$[({]call\s+(?:eval|guile|\$)")
_COMPUTED_NAME_CHARS = set("$*?[%~`\\")
_PARSE_TIME_EXEC_RE = re.compile(r"\$[({]shell[\s)}]|!=")

APPROVED_MAKE_DIRS = ("/usr/bin", "/bin", "/usr/local/bin", "/opt/homebrew/bin", "/usr/sbin", "/sbin")

RUNNER_COMMAND_FILES = ("GITHUB_ENV", "GITHUB_PATH", "GITHUB_OUTPUT", "GITHUB_STATE", "GITHUB_STEP_SUMMARY")
RUNNER_FILE_COMMANDS_DIR = "_runner_file_commands"
_ALWAYS_DROPPED = ("MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS", "MAKELEVEL", "MAKEFILES", "BASH_ENV", "ENV")

# Every make process this module starts is counted, so "make was NOT invoked" is measured.
MAKE_INVOCATIONS = 0


class GateRefused(Exception):
    """The gate stopped before (or instead of) running the requested make command."""

    def __init__(self, problems: list[str], invoked: str = "make was NOT invoked"):
        super().__init__("\n".join(problems))
        self.problems = problems
        self.invoked = invoked


# ------------------------------------------------------------------- env ---


def _is_runner_command_file(value: str, command_dirs: set[str]) -> bool:
    if not value or os.pathsep in value or "\n" in value:
        return False
    parent = os.path.dirname(os.path.normpath(value))
    return bool(parent) and (os.path.basename(parent) == RUNNER_FILE_COMMANDS_DIR or parent in command_dirs)


def clean_env(environ=None, drop=()) -> dict:
    """The environment for EVERY process started here. Defence in depth, not the control.

    `drop`: further names to remove — run_make passes environment_taken() for every make process.
    """
    env = dict(os.environ if environ is None else environ)
    command_dirs = {os.path.dirname(os.path.normpath(env[n])) for n in RUNNER_COMMAND_FILES if env.get(n)} - {""}
    drop = set(drop) | set(_ALWAYS_DROPPED) | set(RUNNER_COMMAND_FILES)
    drop |= {k for k, v in env.items() if _is_runner_command_file(v, command_dirs)}
    # A name a shell cannot even spell (`.RECIPEPREFIX`, `.SHELLFLAGS`) is one only make would read.
    drop |= {k for k in env if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k)}
    return {k: v for k, v in env.items() if k not in drop}


# ------------------------------------------------------------------- pin ---


def load_pin(root: Path) -> dict[str, str]:
    """Parse the pin file. Every deviation from the one accepted shape is a GateRefused."""
    path = root / PIN_FILE
    try:
        text = path.read_bytes().decode("utf-8")
    except FileNotFoundError:
        raise GateRefused([f"{PIN_FILE} does not exist. It lists the Makefile bytes make may read; without it "
                           f"nothing says which bytes were reviewed."])
    except (OSError, UnicodeDecodeError) as err:
        raise GateRefused([f"{PIN_FILE} cannot be read as UTF-8: {err}"])
    entries: dict[str, str] = {}
    header = False
    for n, line in enumerate(text.split("\n"), 1):
        if not line.strip() or line.startswith("#"):
            continue
        if not header:
            if not PIN_HEADER_RE.match(line):
                raise GateRefused([f"{PIN_FILE}:{n}: expected `makefiles:` as the first entry, found {line!r}"])
            header = True
            continue
        m = PIN_ENTRY_RE.match(line)
        if not m:
            raise GateRefused([f"{PIN_FILE}:{n}: not a `  <path>: <64 lowercase hex sha256>` entry: {line!r}"])
        name, digest = m.group(1), m.group(2)
        if name != os.path.normpath(name) or name.startswith("../") or name == "..":
            raise GateRefused([f"{PIN_FILE}:{n}: {name!r} is not a normalised path inside the repository"])
        if name in entries:
            raise GateRefused([f"{PIN_FILE}:{n}: {name!r} is pinned twice"])
        entries[name] = digest
    if not header or not entries:
        raise GateRefused([f"{PIN_FILE} pins no file. An empty pin would let make read anything."])
    if "Makefile" not in entries:
        raise GateRefused([f"{PIN_FILE} does not pin `Makefile`, the file make reads."])
    return entries


def _logical_lines(text: str):
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        first, line = i + 1, lines[i]
        while line.endswith("\\") and (len(line) - len(line.rstrip("\\"))) % 2 == 1 and i + 1 < len(lines):
            i += 1
            line = line[:-1] + " " + lines[i].lstrip()
        out, j = [], 0
        while j < len(line):
            c = line[j]
            if c == "\\" and j + 1 < len(line):
                out.append(line[j:j + 2])
                j += 2
                continue
            if c == "#":
                break
            out.append(c)
            j += 1
        yield first, "".join(out)
        i += 1


def static_read_set(root: Path, texts: dict[str, str]) -> tuple[list[str], list[str]]:
    """Which files make WILL read, from reviewed bytes, without running them. (order, problems)."""
    problems: list[str] = []
    try:
        present = os.listdir(root)
    except OSError as err:
        return [], [f"cannot list {root}: {err}"]
    for entry in present:
        # Case-folded: on a case-insensitive disk `gnumakefile` IS GNUmakefile to make.
        if entry.lower() in ("gnumakefile", "makefile") and entry != "Makefile":
            problems.append(f"{entry} exists beside the Makefile. With no -f, GNU make reads GNUmakefile and "
                            f"makefile BEFORE Makefile, so the pinned Makefile would not be what runs.")
    order: list[str] = []
    queue = ["Makefile"]
    while queue:
        rel = queue.pop(0)
        if rel in order:
            continue
        order.append(rel)
        text = texts.get(rel)
        if text is None:
            continue
        problems += grammar_problems(rel, text)
        problems += reviewed_bytes_problems(rel, text)
        for n, line in enumerate(text.split("\n"), 1):
            if _MANUFACTURES_DIRECTIVES_RE.search(line):
                problems.append(f"{rel}:{n} calls $(eval …) or $(guile …) (directly or through $(call …)), which can manufacture an include the "
                                f"static reading cannot see: `{line.strip()[:120]}`")
        for n, line in _logical_lines(text):
            m = _READ_DIRECTIVE_RE.match(line)
            if not m:
                continue
            directive, args = m.group(1), (m.group(2) or "").strip()
            for word in args.split():
                if directive.endswith("load"):
                    word = word.split("(", 1)[0]
                if _COMPUTED_NAME_CHARS & set(word):
                    problems.append(f"{rel}:{n} `{directive} {word}` names a file make COMPUTES.")
                    continue
                norm = os.path.normpath(word)
                if os.path.isabs(word) or norm == ".." or norm.startswith("../"):
                    problems.append(f"{rel}:{n} `{directive} {word}` reads a file outside the repository.")
                    continue
                queue.append(norm)
    return order, problems


# ------------------------------------------------------ the Makefile grammar ---
#
# THE CONTROL for what the reviewed bytes may say (chair ruling after PR #5 closing fix round 1): an
# ALLOWLIST of line shapes, default-deny, checked before make. Every round of review found another
# spelling a denylist missed, because make's grammar is unbounded; this repository's Makefile uses a
# tiny part of it, so that part is all a pinned makefile may use. Every LOGICAL line (backslash-newline
# joined) must be exactly one of:
#
#   BLANK/COMMENT  empty, or a comment (`#` outside any `$(…)`/`${…}`; text after it is ignored);
#   ASSIGNMENT     `NAME op value`: NAME a literal `[A-Za-z_][A-Za-z0-9_]*` or one of ASSIGNABLE_SPECIALS,
#                  op one of `:=` `?=` `=`, at the start of the line; the value may use only `$$`,
#                  `$(NAME)`/`${NAME}` references and `$(shell …)` (whose text may use the same
#                  references); every other `$` form — a function, a substitution reference, `$X`,
#                  a computed name — is refused;
#   PHONY          `.PHONY: name …` with literal names;
#   RULE           `name: prerequisite …` at the start of the line: ONE literal target (not starting with
#                  `.`, so no special target, suffix or pattern rule), one `:`, literal prerequisite words;
#                  no `;`, `$`, `%`, `|`, `=`, second `:`, `::` or `&:`;
#   RECIPE         a TAB line (with its backslash-continued lines, read RAW: make hands `#` in a recipe to
#                  the shell) while a RULE is open — blank and comment lines between recipe lines keep it
#                  open, any other line closes it. Its text may use only `$$` and `$(NAME)`/`${NAME}`
#                  references (RECIPE_FUNCTIONS, the functions a recipe may call, is empty: this Makefile
#                  calls none), and not `$(MAKE)`.
#
# Anything else — a conditional, include, define, export, override, private, vpath, undefine, load, an
# inline `;` recipe, several targets, a special target other than .PHONY, `+=`/`!=`/`::=`, leading
# whitespace, a TAB line outside a rule, a `#` inside `$(…)` (so the comment boundary never depends on the make version) — is
# refused by line number. The older by-name refusals below stay as a second, more specific diagnosis.
ASSIGNABLE_SPECIALS = (".SHELLFLAGS", ".DEFAULT_GOAL")
RECIPE_FUNCTIONS: tuple = ()
_G_NAME = r"(?:[A-Za-z_][A-Za-z0-9_]*|\.SHELLFLAGS|\.DEFAULT_GOAL)"
_G_ASSIGN_RE = re.compile(r"^(" + _G_NAME + r")[ \t]*(:=|\?=|=)(.*)$")
_G_WORD = r"[A-Za-z0-9_][A-Za-z0-9_./-]*"
_G_PHONY_RE = re.compile(r"^\.PHONY[ \t]*:((?:[ \t]+" + _G_WORD + r")+)[ \t]*$")
_G_RULE_RE = re.compile(r"^(" + _G_WORD + r")[ \t]*:((?:[ \t]+" + _G_WORD + r")*)[ \t]*$")
_G_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _dollar_problems(text: str, allow_shell: bool) -> list[str]:
    """Every `$` use in `text` that is not `$$`, a literal `$(NAME)`/`${NAME}` reference, or (when
    allow_shell) `$(shell …)` whose own text passes the same check without shell."""
    out, i = [], 0
    while i < len(text):
        if text[i] != "$":
            i += 1
            continue
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if nxt == "$":
            i += 2
            continue
        if nxt not in "({":
            out.append(f"`{text[i:i + 2]}` (only `$$`, `$(NAME)` and `${{NAME}}` are allowed)")
            i += 2
            continue
        close = ")" if nxt == "(" else "}"
        depth, j = 1, i + 2
        while j < len(text) and depth:
            if text[j] == nxt:
                depth += 1
            elif text[j] == close:
                depth -= 1
            j += 1
        if depth:
            out.append(f"`{text[i:i + 30]}` (an unterminated expansion)")
            break
        inner = text[i + 2:j - 1]
        if _G_IDENT_RE.match(inner):
            if inner == "MAKE":
                out.append("`$(MAKE)`")
        elif allow_shell and nxt == "(" and re.match(r"shell[ \t]", inner):
            out += _dollar_problems(inner[6:], allow_shell=False)
        else:
            out.append(f"`{text[i:j][:60]}` (a function, a substitution reference or a computed name)")
        i = j
    return out


def _strip_comment(line: str):
    """(text before an unescaped `#` at expansion depth 0, problem or None)."""
    depth, i = 0, 0
    while i < len(line):
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            i += 2
            continue
        if c == "$" and i + 1 < len(line) and line[i + 1] in "({":
            depth += 1
            i += 2
            continue
        if c in ")}" and depth:
            depth -= 1
        elif c == "#":
            if depth:
                return line[:i], "a `#` inside `$(…)`, where whether it starts a comment is not left to the make version"
            return line[:i], None
        i += 1
    return line, None


def _grammar_lines(text: str):
    """(first physical line number, joined logical text, is_tab) — backslash-newline joined as make does."""
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        first, line = i + 1, lines[i]
        tab = line.startswith("\t")
        while line.endswith("\\") and (len(line) - len(line.rstrip("\\"))) % 2 == 1 and i + 1 < len(lines):
            i += 1
            line = line[:-1] + " " + (lines[i] if tab else lines[i].lstrip())
        yield first, line, tab
        i += 1


def grammar_problems(rel: str, text: str) -> list[str]:
    """Default-deny: every logical line must be one of the shapes in the block comment above."""
    out: list[str] = []
    in_rule = False
    shapes = {"blank/comment": 0, "assignment": 0, "phony": 0, "rule": 0, "recipe": 0}

    def refuse(n: int, line: str, why: str) -> None:
        out.append(f"{rel}:{n} is outside the Makefile grammar this gate allows ({why}): `{line.strip()[:100]}`. "
                   f"Every line must be blank or a comment, `NAME := | ?= | = value`, `.PHONY: names`, a "
                   f"single-target rule `name: prerequisites`, or a TAB recipe line of a rule.")

    for n, line, tab in _grammar_lines(text):
        if tab:
            if not in_rule:
                refuse(n, line, "a TAB line outside a rule")
                continue
            shapes["recipe"] += 1
            for d in _dollar_problems(line, allow_shell=False):
                refuse(n, line, f"a recipe line using {d}")
            continue
        body, why = _strip_comment(line)
        if why:
            refuse(n, line, why)
            in_rule = False
            continue
        if not body.strip():
            shapes["blank/comment"] += 1
            continue
        in_rule = False
        m = _G_ASSIGN_RE.match(body)
        if m:
            shapes["assignment"] += 1
            for d in _dollar_problems(m.group(3), allow_shell=True):
                refuse(n, line, f"an assignment value using {d}")
            continue
        if _G_PHONY_RE.match(body):
            shapes["phony"] += 1
            continue
        if _G_RULE_RE.match(body):
            shapes["rule"] += 1
            in_rule = True
            continue
        first = body.split()[0]
        if first in ("ifeq", "ifneq", "ifdef", "ifndef", "else", "endif"):
            why = "a conditional directive"
        elif first in ("include", "-include", "sinclude", "load", "-load"):
            why = f"the `{first}` directive"
        elif first in ("define", "endef", "undefine", "export", "unexport", "override", "private", "vpath"):
            why = f"the `{first}` directive"
        elif body[:1] in (" ", "\t"):
            why = "a line that starts with whitespace"
        elif ";" in body:
            why = "an inline `;` recipe or a `;` outside a recipe"
        elif "$" in body:
            why = "an expansion outside an assignment value or a recipe"
        else:
            why = "not one of the allowed shapes"
        refuse(n, line, why)
    grammar_problems.last_shapes = shapes
    return out


# ------------------------------------------------ constructs refused by name ---
#
# Refused in REVIEWED bytes, by name, BEFORE make is started — derived from vizra-core PR #10 and its
# re-verification. These are a SECOND, more specific diagnosis kept beside grammar_problems (above), which
# is the control: grammar_problems refuses every line outside its few shapes, whatever the spelling. The
# functions below recognise only the spellings they name — the regexes match a LITERAL name at the start
# of a line, and rule_line_problems / computed_name_problems / _MANUFACTURES_DIRECTIVES_RE have known
# misses (a `;` recipe whose text holds `=`, a `private`/`override` first word, `$(call ev$(A)al,…)`;
# PR #5 closing re-verification at 888a51b) that grammar_problems refuses. Within the grammar, the ones
# that still matter on their own are the SHELL/.SHELLFLAGS/MAKEFLAGS-family assignments, `+` and
# `$(MAKE)` recipe lines, and a recipe body beginning with `$`. The control for what a reviewer approves
# is still review.
APPROVED_SHELL_LINES = {"SHELL := /bin/bash", ".SHELLFLAGS := -eu -o pipefail -c"}
_CONTROLLED_VARS = r"(SHELL|\.SHELLFLAGS|MAKEFLAGS|GNUMAKEFLAGS|MFLAGS|\.RECIPEPREFIX|\.EXTRA_PREREQS)"
_MODIFIERS = r"(?:(?:export|override|private|unexport)\s+)*"
_ASSIGN_CONTROLLED_RE = re.compile(
    r"^\s*(?:[^\s:=#][^:=#]*:\s*)?" + _MODIFIERS + _CONTROLLED_VARS + r"\s*(?:[:+?!]|::|:::)?=")
_DEFINE_CONTROLLED_RE = re.compile(r"^\s*" + _MODIFIERS + r"define\s+" + _CONTROLLED_VARS + r"(?:\s|$)")
_SPECIAL_TARGET_RE = re.compile(r"^\s*(\.ONESHELL|\.IGNORE|\.DEFAULT|\.POSIX|\.SECONDEXPANSION)\s*:")
_MAKE_VAR_RE = re.compile(r"\$[({]MAKE[)}]")
_SPECIAL_WHY = {
    ".ONESHELL": "the whole recipe goes to one shell, so a prefix applies to its first line only",
    ".IGNORE": "every recipe failure of the named targets (or of ALL targets) is ignored — a `-` prefix no "
               "reading can see",
    ".DEFAULT": "its recipe is run for any target or prerequisite with no rule of its own",
    ".POSIX": "it changes how make invokes the shell and what -e means",
    ".SECONDEXPANSION": "prerequisites would be expanded again while make considers targets, which happens "
                        "under -n and -q too",
}


# Directives whose lines are not rule lines even when they contain a `:`.
_DIRECTIVES = {"ifeq", "ifneq", "ifdef", "ifndef", "else", "endif", "include", "-include", "sinclude", "load",
               "-load", "define", "endef", "undefine", "vpath", "export", "unexport", "override", "private"}


def _rule_parts(line: str):
    """(targets, rest) when this non-recipe logical line is a RULE line, else None.

    Scans outside `$(…)`/`${…}`: an assignment operator (`=`, `:=`, `::=`, `:::=`, `?=`, `+=`, `!=`)
    before the first bare `:` makes it an assignment; otherwise the first `:` (or `::`) splits the
    targets from the rest (prerequisites, an inline `;` recipe, or a target-specific assignment).
    """
    depth, i = 0, 0
    while i < len(line):
        c = line[i]
        if c == "$" and i + 1 < len(line):
            if line[i + 1] in "({":
                depth += 1
            i += 2
            continue
        if depth:
            if c in ")}":
                depth -= 1
            i += 1
            continue
        if c == "=":
            return None
        if c == ":":
            j = i
            while j < len(line) and line[j] == ":":
                j += 1
            if j < len(line) and line[j] == "=":
                return None
            return line[:i], line[j:]
        i += 1
    return None


def _outside_expansions(text: str) -> str:
    """`text` with every `$(…)`/`${…}` and `$X` removed, for finding a bare `;` or `=`."""
    out, depth, i = [], 0, 0
    while i < len(text):
        c = text[i]
        if c == "$" and i + 1 < len(text):
            if text[i + 1] in "({":
                depth += 1
            i += 2
            continue
        if depth:
            if c in ")}":
                depth -= 1
        else:
            out.append(c)
        i += 1
    return "".join(out)


_NON_ASSIGNING_DIRECTIVES = {"ifeq", "ifneq", "ifdef", "ifndef", "else", "endif", "include", "-include", "sinclude",
                             "load", "-load", "endef", "vpath"}
_ASSIGN_MODIFIERS = {"export", "override", "private", "unexport"}


def _assigned_name(text: str):
    """The variable name of an assignment `NAME op value` (modifiers dropped), or None if `text` has no
    bare `=` outside expansions."""
    depth, i = 0, 0
    while i < len(text):
        c = text[i]
        if c == "$" and i + 1 < len(text):
            if text[i + 1] in "({":
                depth += 1
            i += 2
            continue
        if depth:
            if c in ")}":
                depth -= 1
        elif c == "=":
            words = [w for w in text[:i].rstrip(":+?! \t").split() if w not in _ASSIGN_MODIFIERS]
            return " ".join(words)
        i += 1
    return None


def computed_name_problems(rel: str, n: int, raw: str) -> list[str]:
    """Named diagnosis for a variable name that is an expansion in an assignment or `define`
    (`$(M)AKEFLAGS += -i`). grammar_problems already refuses every such line, and any spelling this
    function misses."""
    words = raw.split()
    if not words or words[0] in _NON_ASSIGNING_DIRECTIVES:
        return []
    mods = [w for w in words if w not in _ASSIGN_MODIFIERS]
    if mods and mods[0] == "define":
        name = mods[1] if len(mods) > 1 else ""
        return ([f"{rel}:{n} defines a variable whose name is an expansion (`{raw.strip()[:100]}`); the "
                 f"named-construct list reads literal names only."] if "$" in name else [])
    parts = _rule_parts(raw)
    text = parts[1] if parts is not None else raw
    name = _assigned_name(text)
    if name is not None and "$" in name:
        return [f"{rel}:{n} assigns a variable whose name is an expansion (`{raw.strip()[:100]}`); the "
                f"named-construct list reads literal names only, so a computed one is refused outright."]
    return []


def rule_line_problems(rel: str, n: int, raw: str, physical: str) -> list[str]:
    """Named diagnosis for rule-line spellings: an inline `;` recipe, several targets, an expansion as a
    target, a leading-whitespace or backslash-continued rule line. grammar_problems is the control (it
    refuses every rule line that is not `name: prerequisites`); this function misses spellings it does
    not name, e.g. a `;` recipe whose text holds `=` or a rule line starting `private`/`override`.
    """
    first = raw.split(None, 1)[0] if raw.split() else ""
    if first in _DIRECTIVES:
        return []
    parts = _rule_parts(raw)
    if parts is None:
        return []
    targets_text, rest = parts
    targets = targets_text.split()
    out: list[str] = []
    what = f"`{raw.strip()[:100]}`"
    bare_rest = _outside_expansions(rest)
    if "=" not in bare_rest and ";" in bare_rest:
        out.append(f"{rel}:{n} is a rule with an inline `;` recipe ({what}). That recipe is not a TAB line, so "
                   f"no reading here sees its prefix; write it on its own TAB line.")
    if len(targets) > 1:
        out.append(f"{rel}:{n} names more than one target on one rule line ({what}). The anchor reads a "
                   f"target's rule as `<target>:` at the start of a line; give each target its own rule.")
    if any("$" in t for t in targets):
        out.append(f"{rel}:{n} is a rule whose target name is an expansion ({what}); which target it defines "
                   f"cannot be read without running make.")
    if raw[:1] in (" ", "\t"):
        out.append(f"{rel}:{n} is a rule line that starts with whitespace ({what}); the anchor reads rules at "
                   f"the start of a line.")
    if physical.rstrip().endswith("\\") and (len(physical.rstrip()) - len(physical.rstrip().rstrip("\\"))) % 2 == 1:
        out.append(f"{rel}:{n} is a rule line continued with a backslash ({what}); write the rule on one line.")
    return out


def reviewed_bytes_problems(rel: str, text: str) -> list[str]:
    """Named constructs refused in pinned bytes before make starts. See the block comment above."""
    out: list[str] = []
    physical_lines = text.split("\n")
    for n, line in _logical_lines(text):
        raw = line.rstrip()
        if not raw.strip():
            continue
        if raw.startswith("\t"):
            body = raw[1:]
            prefix = ""
            while body[:1] in ("@", "-", "+", " ", "\t") and body:
                prefix += body[0]
                body = body[1:]
            if "+" in prefix:
                out.append(f"{rel}:{n} is a recipe line prefixed `+`, which make runs even under -n and -q: "
                           f"`{raw.strip()[:100]}`")
            if body.startswith("$") and not body.startswith("$$"):
                out.append(f"{rel}:{n} is a recipe line that BEGINS with an expansion (`{body[:40]}`). What it "
                           f"expands to — possibly a `-` or `+` prefix — cannot be determined without running make.")
            if _MAKE_VAR_RE.search(raw):
                out.append(f"{rel}:{n} names $(MAKE) in a recipe; make runs such a line even under -n and -q.")
            continue
        stripped = raw.strip()
        if stripped in APPROVED_SHELL_LINES:
            continue
        out += rule_line_problems(rel, n, raw, physical_lines[n - 1])
        out += computed_name_problems(rel, n, raw)
        m = _ASSIGN_CONTROLLED_RE.match(raw) or _DEFINE_CONTROLLED_RE.match(raw)
        if m:
            out.append(f"{rel}:{n} assigns `{m.group(1)}` (`{stripped[:100]}`). SHELL and .SHELLFLAGS may appear "
                       f"only as {sorted(APPROVED_SHELL_LINES)}; MAKEFLAGS, GNUMAKEFLAGS, MFLAGS, .RECIPEPREFIX "
                       f"and .EXTRA_PREREQS may not be assigned in any literal form this reading matches (global, "
                       f"target- or pattern-specific, define, private, override).")
        t = _SPECIAL_TARGET_RE.match(raw)
        if t:
            out.append(f"{rel}:{n} declares `{t.group(1)}`: {_SPECIAL_WHY[t.group(1)]}.")
        if _MAKE_VAR_RE.search(raw):
            out.append(f"{rel}:{n} names $(MAKE); a recipe using it runs even under -n and -q.")
    return out


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_pinned_bytes(root: Path) -> tuple[list[str], dict[str, str], list[str]]:
    """Steps 1 and 2. Returns (files make will read, their digests, parse-time exec sites)."""
    pins = load_pin(root)
    problems: list[str] = []
    texts: dict[str, str] = {}
    digests: dict[str, str] = {}
    for rel in sorted(pins):
        path = root / rel
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            problems.append(f"{rel} is pinned in {PIN_FILE} but does not exist.")
            continue
        if not stat.S_ISREG(st.st_mode):
            problems.append(f"{rel} is not a regular file (a symlink, FIFO or device is refused): make would read "
                            f"whatever it points at, which is not what was digested.")
            continue
        data = path.read_bytes()
        digests[rel] = _sha256(data)
        if digests[rel] != pins[rel]:
            problems.append(f"{rel}: sha256 {digests[rel]} does not match its pin in {PIN_FILE} ({pins[rel]}). "
                            f"A Makefile edit is mergeable only together with a reviewed pin update "
                            f"(`shasum -a 256 {rel}`).")
            continue
        try:
            texts[rel] = data.decode("utf-8")
        except UnicodeDecodeError:
            problems.append(f"{rel} is not UTF-8 text.")
    order, read_problems = static_read_set(root, texts)
    problems += read_problems
    problems += [f"make would read {f}, which has no entry in {PIN_FILE}." for f in order if f not in pins]
    if not problems:
        stale = sorted(set(pins) - set(order))
        if stale:
            problems.append(f"{PIN_FILE} pins {', '.join(stale)}, which make would NOT read; the pin and the "
                            f"Makefile drifted.")
    if problems:
        raise GateRefused(problems)
    sites = [f"{rel}:{n} `{line.strip()[:80]}`" for rel in order
             for n, line in _logical_lines(texts[rel]) if _PARSE_TIME_EXEC_RE.search(line)]
    return order, {rel: digests[rel] for rel in order}, sites


# ------------------------------------------------------------------ make ---


def resolve_make() -> str:
    """Step 4: the real path of a `make` that is a regular file in a system directory."""
    try:
        proc = subprocess.run(["bash", "--noprofile", "--norc", "-c", "type -t make; command -v make"],
                              capture_output=True, text=True, timeout=30, env=clean_env())
    except (OSError, subprocess.SubprocessError) as exc:
        raise GateRefused([f"could not ask the shell what `make` is: {exc}"])
    lines = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
    if len(lines) < 2:
        raise GateRefused([f"the shell reports no `make` at all ({proc.stdout!r})."])
    kind, path = lines[0], lines[1]
    if kind != "file":
        raise GateRefused([f"`make` is a {kind}, not a program on disk."])
    real = os.path.realpath(path)
    if not (os.path.isfile(real) and os.access(real, os.X_OK)):
        raise GateRefused([f"`make` resolves to {path!r} -> {real!r}, which is not an executable file."])
    if os.path.dirname(real) not in APPROVED_MAKE_DIRS:
        raise GateRefused([f"`make` resolves to {real!r}, which is not in {list(APPROVED_MAKE_DIRS)}: a stub "
                           f"someone put earlier on PATH."])
    if os.path.basename(real) not in ("make", "gmake"):
        raise GateRefused([f"`make` resolves to {path!r}, whose real file is {real!r} — not a program named make."])
    return real


def check_environment() -> None:
    """Step 3 (the part every caller shares; the anchor adds its strict --workflow checks)."""
    if "MAKEFILES" in os.environ:
        raise GateRefused([f"the environment sets MAKEFILES={os.environ['MAKEFILES']!r}; make would read those "
                           f"files before the pinned Makefile."])


# Make's own variables, which a makefile may reference without assigning.
_MAKE_BUILTIN_VARS = {
    "MAKE", "MAKEFILE_LIST", "CURDIR", "MAKEFLAGS", "MAKECMDGOALS", "SHELL", "MAKELEVEL",
    ".SHELLFLAGS", "MAKE_VERSION", "MAKE_HOST", ".DEFAULT_GOAL", "MFLAGS", "MAKEFILES",
    "VPATH", ".RECIPEPREFIX", ".VARIABLES", ".FEATURES", ".INCLUDE_DIRS", "SUFFIXES",
}
_FUNCTIONS = {
    "shell", "wildcard", "eval", "info", "error", "warning", "foreach", "call", "patsubst",
    "subst", "filter", "filter-out", "sort", "dir", "notdir", "strip", "word", "words",
    "firstword", "lastword", "abspath", "realpath", "if", "or", "and", "origin", "value",
    "addprefix", "addsuffix", "basename", "suffix", "join", "findstring", "flavor", "file",
}
_ASSIGN_RE = re.compile(r"^\s*(?:export\s+|override\s+)*([A-Za-z_][A-Za-z0-9_.]*)\s*(\?=|:{1,3}=|\+=|!=|=)", re.M)
# `$(NAME)` / `${NAME}` — but not the shell's `$${NAME}` inside a recipe.
_REF_RE = re.compile(r"(?<!\$)\$[({]([A-Za-z_][A-Za-z0-9_]*)[)}]")


def environment_taken(root: Path, files) -> set[str]:
    """The variables the given makefiles take FROM the environment, as this reading sees them, plus GOFLAGS.

    A name assigned with `?=`, or referenced as `$(NAME)`/`${NAME}` and never assigned, is one the environment
    sets — and make imports an environment variable as a RECURSIVELY expanded variable, so its value is
    evaluated as make text while the Makefile is read (manual §6.10). The anchor refuses these in
    --workflow mode (check_environment_overrides); run_make drops them from EVERY make process this
    module starts, so a caller that opens the gate without the anchor (contract-drift-guard.py, the lane
    test) does not hand them to make either (PR #5 security desk review, M-4). It does NOT see `$V`,
    `$(V:a=b)`, `ifdef V`, `$(origin V)`, `$(value V)` or a read before a later `:=`; run_make therefore
    also drops environment_words(), which does.
    """
    assigned: dict[str, str] = {}
    refs: set[str] = set()
    for rel in files:
        path = Path(rel) if Path(rel).is_absolute() else Path(root) / rel
        try:
            text = path.read_text()
        except OSError:
            continue
        for m in _ASSIGN_RE.finditer(text):
            if m.group(1) not in assigned or m.group(2) == "?=":
                assigned[m.group(1)] = m.group(2)
        refs |= set(_REF_RE.findall(text))
    taken = {n for n, op in assigned.items() if op == "?="}
    taken |= {n for n in refs if n not in assigned} - _MAKE_BUILTIN_VARS - _FUNCTIONS
    taken.add("GOFLAGS")
    return taken


# Environment variables every make process keeps even when the makefiles name them.
KEEP_ENV = frozenset({"PATH", "HOME", "TMPDIR", "USER", "LOGNAME", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE",
                      "TERM", "SHELL", "PWD", "TZ"})
_WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def environment_words(root: Path, files) -> set[str]:
    """EVERY identifier-shaped word in the given makefiles' text, minus KEEP_ENV.

    Deliberately over-matching (PR #5 closing VERIFY, FINDING 7): make can read an environment variable
    as `$(V)`, `${V}`, `$(V:a=b)`, `$V`, `ifdef V`, `$(origin V)`, `$(value V)`, or before a later `:=`,
    and environment_taken's `$(NAME)`/`${NAME}` reading sees only the first two. A word that appears
    anywhere in the text — comments included — is dropped from make's environment instead. Not covered:
    a name make assembles from parts (`$(A)$(B)`), which appears as no single word.
    """
    words: set[str] = set()
    for rel in files:
        path = Path(rel) if Path(rel).is_absolute() else Path(root) / rel
        try:
            words |= set(_WORD_RE.findall(path.read_text()))
        except OSError:
            continue
    return words - KEEP_ENV


def run_make(make: str, root: Path, args: list[str]) -> subprocess.CompletedProcess:
    global MAKE_INVOCATIONS
    # Computed from the PINNED files on every call (a stale or missing pin raises GateRefused here,
    # before make starts), so no caller can forget to pass it.
    pinned = sorted(load_pin(Path(root)))
    taken = environment_taken(root, pinned) | environment_words(root, pinned)
    MAKE_INVOCATIONS += 1
    return subprocess.run([make, *args], cwd=str(root), env=clean_env(drop=taken), capture_output=True,
                          text=True)


def remake_probe(make: str, root: Path, files: list[str]) -> None:
    """Step 5: ONE `make -q <every pinned makefile>`; exit != 0 means make would remake one.

    -q runs no ordinary recipe; a `+` or `$(MAKE)` recipe line still runs under -q, and one can come
    only from the pinned, reviewed bytes.
    """
    proc = run_make(make, root, ["-q", *files])
    if proc.returncode != 0:
        raise GateRefused(
            [f"make would REMAKE a pinned makefile before reading it (`make -q {' '.join(files)}` exit "
             f"{proc.returncode}). make remakes an out-of-date makefile even under -n — from a rule, or from a "
             f"built-in implicit rule such as `% : %.sh` fed by a newer unpinned `Makefile.sh` — and then reads "
             f"the NEW bytes. -q runs no ordinary recipe, so no rule remade it.",
             *[f"  {l}" for l in (proc.stdout + proc.stderr).strip().splitlines()[:4]]],
            invoked="only `make -q` ran")


def recheck(root: Path, digests: dict[str, str]) -> list[str]:
    """Step 6: the pinned bytes are still the pinned bytes."""
    out = []
    for rel, want in digests.items():
        try:
            got = _sha256((root / rel).read_bytes())
        except OSError as err:
            out.append(f"{rel} could not be re-read after make ran: {err}")
            continue
        if got != want:
            out.append(f"{rel} CHANGED while make ran (sha256 {want} -> {got}); the next make would read bytes "
                       f"nobody reviewed.")
    return out


class Gate:
    """A passed gate: the pinned files, their digests, and the checked make. Use .run() for make."""

    def __init__(self, root: Path, files: list[str], digests: dict[str, str], sites: list[str], make: str):
        self.root, self.files, self.digests, self.sites, self.make = root, files, digests, sites, make

    def run(self, args: list[str], *, name_goals: bool = False) -> subprocess.CompletedProcess:
        """Run make; with name_goals the pinned makefiles lead the goals so -n/-q also apply to them."""
        proc = run_make(self.make, self.root, [*(self.files if name_goals else []), *args])
        changed = recheck(self.root, self.digests)
        if changed:
            raise GateRefused(changed, invoked="make ran and CHANGED a pinned file")
        return proc

    def describe(self) -> str:
        return (f"make runs only on REVIEWED bytes: {', '.join(f'{f} sha256 {self.digests[f][:12]}…' for f in self.files)} "
                f"match {PIN_FILE}; `make -q` (one invocation, every pinned file a goal) says none would be remade; make is {self.make}. Those "
                f"bytes run their own reviewed parse-time call(s) while read: "
                + ("; ".join(self.sites) if self.sites else "(none)")
                + ". What a reviewer approves together with a pin update is outside this check.")


def open_gate(root, *, extra_problems: list[str] | None = None) -> Gate:
    """Steps 1–5. Raises GateRefused (make NOT invoked, or only `make -q`) on any failure.

    extra_problems: failures the CALLER found before make (the anchor's strict environment checks); any
    one of them stops the gate before make is started.
    """
    root = Path(root)
    problems = list(extra_problems or [])
    files = digests = sites = None
    make = None
    for step in (lambda: check_pinned_bytes(root), check_environment, resolve_make):
        try:
            result = step()
        except GateRefused as err:
            problems += err.problems
            continue
        if isinstance(result, tuple):
            files, digests, sites = result
        elif isinstance(result, str):
            make = result
    if problems or files is None or make is None:
        raise GateRefused(problems or ["the gate could not establish the pinned files or make"])
    remake_probe(make, root, files)
    changed = recheck(root, digests)
    if changed:
        raise GateRefused(changed, invoked="only `make -q` ran, and a pinned file CHANGED")
    return Gate(root, files, digests, sites, make)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    ap.add_argument("make_args", nargs=argparse.REMAINDER)
    args = ap.parse_args(argv)
    make_args = args.make_args[1:] if args.make_args[:1] == ["--"] else args.make_args
    try:
        gate = open_gate(args.root.resolve())
        proc = gate.run(make_args)
    except GateRefused as err:
        for p in err.problems:
            sys.stderr.write(f"makegate: FAIL  {p}\n")
        sys.stderr.write(f"makegate: REFUSED — {err.invoked} ({MAKE_INVOCATIONS} make process(es) started)\n")
        return 3
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
