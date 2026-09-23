#!/usr/bin/env python3
"""makegate — the ONE way this repository starts `make` from a script or a test.

Aligned with vizra-core PR #10 (branch chore/m0-anchor-makefile-digest, head 62d16aa), whose
scripts/make-integrity-guard.py carries the same pin shape, static read set, `make -q` remake probe and
re-hash. Search puts those pieces in this module so that EVERY make invocation — the workflow anchor
(make-integrity-guard.py), the contract-drift lane's shape check (contract-drift-guard.py), and the
Go test that reads the lane (internal/httpapi/lane_selection_test.go) — goes through the same gate.
scripts/scripts_test.go inventories every place the repository starts make and fails on any other.

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
     plus every literal include/load target, transitively; each must be pinned. No GNUmakefile or
     makefile may sit beside it (compared case-folded, so a case-insensitive disk cannot hide one).
     `$(eval …)`/`$(guile …)` and computed include names are refused: the reading cannot see them.
     Refused BY NAME in the reviewed bytes (reviewed_bytes_problems): `.RECIPEPREFIX`,
     `.SECONDEXPANSION`, `.ONESHELL`, `.IGNORE`, `.DEFAULT`, `.POSIX`, `.EXTRA_PREREQS`; any SHELL /
     .SHELLFLAGS other than the approved line, and any MAKEFLAGS / GNUMAKEFLAGS / MFLAGS, in every
     form (target- or pattern-specific, define, private, override); `$(eval …)`; `+` recipe lines and
     `$(MAKE)`, which run even under -n and -q; and a recipe line that BEGINS with an expansion,
     whose prefix cannot be determined without running make.
  3. ENVIRONMENT. MAKEFILES must be unset (it adds makefiles nobody pinned). Every process this module
     starts runs with clean_env(): make's flag variables, MAKEFILES, BASH_ENV, ENV and the runner's
     command-file variables (and anything pointing into the runner's command-file directory) removed.
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
runs. Review is the control there, and CODEOWNERS is advisory. It sees only what it reads: a step
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
_MANUFACTURES_DIRECTIVES_RE = re.compile(r"\$[({](eval|guile)[\s)}]")
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


def clean_env(environ=None) -> dict:
    """The environment for EVERY process started here. Defence in depth, not the control."""
    env = dict(os.environ if environ is None else environ)
    command_dirs = {os.path.dirname(os.path.normpath(env[n])) for n in RUNNER_COMMAND_FILES if env.get(n)} - {""}
    drop = set(_ALWAYS_DROPPED) | set(RUNNER_COMMAND_FILES)
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
        problems += reviewed_bytes_problems(rel, text)
        for n, line in enumerate(text.split("\n"), 1):
            if _MANUFACTURES_DIRECTIVES_RE.search(line):
                problems.append(f"{rel}:{n} calls $(eval …) or $(guile …), which can manufacture an include the "
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


# ------------------------------------------------ constructs refused by name ---
#
# Refused in REVIEWED bytes, by name, BEFORE make is started — aligned with vizra-core PR #10 and its
# re-verification. Each one either runs something while make reads the file (so the `make -q` probe
# would not be recipe-free), or changes what the anchor's later readings mean, or ignores a gate
# failure without a `-` prefix any reading could see. This is a list of named constructs over reviewed
# text, not a grammar of make; the control for what a reviewer approves is still review.
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


def reviewed_bytes_problems(rel: str, text: str) -> list[str]:
    """Named constructs refused in pinned bytes before make starts. See the block comment above."""
    out: list[str] = []
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
            if body.startswith(("$(", "${")):
                out.append(f"{rel}:{n} is a recipe line that BEGINS with an expansion (`{body[:40]}`). What it "
                           f"expands to — possibly a `-` or `+` prefix — cannot be determined without running make.")
            if _MAKE_VAR_RE.search(raw):
                out.append(f"{rel}:{n} names $(MAKE) in a recipe; make runs such a line even under -n and -q.")
            continue
        stripped = raw.strip()
        if stripped in APPROVED_SHELL_LINES:
            continue
        m = _ASSIGN_CONTROLLED_RE.match(raw) or _DEFINE_CONTROLLED_RE.match(raw)
        if m:
            out.append(f"{rel}:{n} assigns `{m.group(1)}` (`{stripped[:100]}`). SHELL and .SHELLFLAGS may appear "
                       f"only as {sorted(APPROVED_SHELL_LINES)}; MAKEFLAGS, GNUMAKEFLAGS, MFLAGS, .RECIPEPREFIX "
                       f"and .EXTRA_PREREQS may not be assigned at all, in any form (target-specific, "
                       f"pattern-specific, define, private, override).")
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


def run_make(make: str, root: Path, args: list[str]) -> subprocess.CompletedProcess:
    global MAKE_INVOCATIONS
    MAKE_INVOCATIONS += 1
    return subprocess.run([make, *args], cwd=str(root), env=clean_env(), capture_output=True, text=True)


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
