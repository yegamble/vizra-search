#!/usr/bin/env python3
"""ci-required-guard.py — default-deny on the SHAPE of the steps that carry the gate.

Ported from vizra-core `scripts/ci-required-guard.py` at eeeea068a20118f7af721f024264603b436a1528
(core PR #9, which took three verifier rounds) and adapted to this repository. Run by
scripts/ci-required-guard.sh in the `ci-required` job, after the manifest and continue-on-error
checks that script already made.

WHY IT IS DEFAULT-DENY, AND NOT A BLACKLIST
-------------------------------------------
`ci-required` reads .github/required-checks.txt and the workflows from the checkout UNDER TEST, so
the pull request being gated can edit its own gate. And every make lane here runs through `make`,
where one word on the workflow line (`make -i test`) or one line in the Makefile
(`MAKEFLAGS += -i`) makes a failing lane exit 0.

vizra-core first answered that by reading each make step's `run:` as shell and refusing a list of
flags. A verifier then found thirteen spellings that left the guard green — `make -j -i ci`,
`export MAKEFLAGS=-i` on the line above, a `$GITHUB_ENV` write, `M=make; $M -i ci`,
`${MAKE:-make} -i ci`, a shell function named make, a PATH shadow, backticks, a step `if:`,
`working-directory:`, `shell: bash -c '{0} || true'` — and, in round two, a compound or fake
anchor that wrote `$GITHUB_ENV` after the real guard had exited. A blacklist over arbitrary shell
cannot be complete: the shell has unbounded ways to name a command. So the control is inverted,
and this port starts from the inverted design:

  PINNED       A step in a checked lane that mentions `make` at all (a wide classifier; a token in a
               comment counts, and over-matching fails closed) must be BYTE-EQUAL to an entry in
               .github/pinned-steps.yml `make_steps`. A step that mentions `go test` must be
               byte-equal to an entry in `direct_test_steps`. Either may carry no key but
               `name`, `run` and `id`. No flags, no overrides, no chains, no indirection.
  ANCHORED     Each make step is IMMEDIATELY preceded by a step byte-equal to `anchor_step`
               (`./scripts/make-integrity-guard.sh --workflow`), carrying no key but those three.
               Adjacency is what makes the anchor's runtime checks mean anything: a `$GITHUB_ENV` or
               `$GITHUB_PATH` write applies to LATER steps only, so it reaches the anchor's process
               exactly as it reaches make's. A step that NAMES make-integrity-guard without being
               byte-equal to the pin is refused anywhere in a checked lane.
  PRESENT      Each lane runs the invocations `required_invocations` records for it, byte-equal. This
               is the positive half: deleting a gate step, or replacing it with something that
               reaches make through a variable or a function, leaves it missing — whatever replaced it.
  SURROUNDINGS No `defaults.run` (workflow or job), no job-level `container:`, no job-level `if:`,
               no undigested service image, and no job- or workflow-level `env:` naming a variable
               that reaches make or the shell (MAKEFLAGS, GNUMAKEFLAGS, MFLAGS, MAKEFILES, MAKELEVEL,
               MAKE_RESTARTS, MAKEOVERRIDES, MAKECMDGOALS, SHELL, PATH, BASH_ENV, ENV, GOFLAGS) or a
               variable the Makefile takes from the environment (`?=`, or referenced as `$(NAME)`/
               `${NAME}` and never assigned — computed from the Makefile by the same code the anchor uses).
  DIGEST       .github/pinned-makefiles.yml exists, pins Makefile by sha256, and the tree matches it —
               the same checks scripts/makegate.py makes before it will start make.
  STRICT YAML  A duplicate mapping key and a YAML merge key (`<<:`) are refused anywhere in a
               workflow or in the pins file, so this guard never reads a different value than a
               reviewer sees first.
  FLOOR        FLOOR_LANES cannot be removed from the manifest; every manifest name resolves to a job;
               every checked lane runs on pull_request, on ubuntu-24.04, without continue-on-error,
               and every action is pinned to a 40-character commit SHA.

The checks run over `set(FLOOR_LANES) | set(required)`, not the floor alone: a lane added to the
manifest is checked from the day it is added (core PR#6 VERIFY, FINDING 6).

WHAT THIS IS, AND WHAT IT IS NOT
--------------------------------
It is default-deny on the shape and surroundings of make steps and direct test steps in checked
lanes. That is the whole claim, and this list of what it does not cover is not called complete.

  * It does not constrain what any OTHER step does to the machine. A checked lane may contain other
    `run:` steps and `uses:` actions, and through them anything at all before the anchor runs —
    replacing the Go toolchain, rewriting a test file, installing a different python3. The anchor
    sees what its own assertions cover and nothing else. Review is the control, and CODEOWNERS is
    advisory until the owner's ruleset requires it.
  * It names a set of environment variables. Go's own GOTOOLCHAIN, GOENV, GODEBUG, CGO_ENABLED and the
    rest are not refused; the executed-test floors turn a suite that was made to run nothing red, and
    anything subtler is review-only.
  * A wrapper script or composite action that calls make carries no `make` token and is not read.
    PRESENT bounds the damage — the recorded invocations must still run — but a lane may run one in
    addition.
  * A reusable workflow (`jobs.<id>.uses:`) has no `steps:` here, so there is nothing to read.
  * The pins, the floors and this file are committed and checked out from the pull request under test.
    Widening .github/pinned-steps.yml or FLOOR_LANES is a visible, reviewed diff. It is not prevented.

Usage:
    ci-required-guard.py [--workflows DIR] [--manifest FILE] [--makefile FILE] [--pins FILE]
                         [--skip-makefile]

scripts/scripts_test.go drives it against scripts/testdata/guard/, one crafted workflow per evasion.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import shlex
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - the CI image always has it
    print("ci-required-guard: PyYAML is required. This lane is BLOCKED, not passed.", file=sys.stderr)
    raise SystemExit(2)

# scripts/makegate.py, loaded ONCE: its pin parser, its gate checks, and its ONE makefile line reader
# (makefile_lines / read_makefile_lines), which every reading of Makefile text in this program consumes, so this
# guard cannot split the Makefile's lines differently from the grammar or the anchor (PR #5 FINDING 14).
_mg_spec = importlib.util.spec_from_file_location("makegate", Path(__file__).resolve().parent / "makegate.py")
mg = importlib.util.module_from_spec(_mg_spec)
_mg_spec.loader.exec_module(mg)

# ---------------------------------------------------------------------------
# THE FLOOR.
#
# These lanes cannot be removed from .github/required-checks.txt by the pull
# request they gate:
#
#   build                     the binary links and reports its identity.
#   test                      the suite under the race detector.
#   test-noskip               the suite run DIRECTLY, with no make step, with every
#                             package held to an executed-test floor and no skip.
#   contract-drift            the handlers, HMAC scheme and vendored digests
#                             against the contract vizra-core owns.
#   govulncheck               a known-vulnerable dependency set.
#   vendor-contract-selftest  every refusal vendor-contract.py advertises, fired
#                             against throwaway repositories — so removing one is
#                             red in CI, not only on a laptop.
#
# Adding a lane here is a deliberate widening; removing one is an edit to this
# file, visible in review instead of hiding in a one-line manifest diff.
# ---------------------------------------------------------------------------
FLOOR_LANES = ["build", "test", "test-noskip", "contract-drift", "govulncheck", "vendor-contract-selftest"]

RUNNER = "ubuntu-24.04"
SHA_PIN = re.compile(r"^[^@\s]+@[0-9a-f]{40}(\s|$)")
STEP_KEYS_ALLOWED = {"name", "run", "id"}
PIN_KEYS = {"anchor_step", "make_steps", "direct_test_steps", "required_invocations"}
MAKE_INTEGRITY_GUARD = "make-integrity-guard"

# `make` as a command word, not inside another word (`cmake`, `makefile`,
# `make-integrity-guard`). WIDER than any tokeniser on purpose: the leading
# class includes quotes, backticks and `=` (so `M=make` counts), and a `make`
# token inside a comment counts too. Over-matching demands a pin and fails closed.
MAKE_INVOCATION = re.compile(r"""(?:^|[\s;&|("'`=])make(?=\s|$|[;&|)"'`])""", re.M)
# `go test` as a command, with the same wide leading class.
GO_TEST_INVOCATION = re.compile(r"""(?:^|[\s;&|("'`=])go\s+test(?=\s|$|[;&|)"'`])""", re.M)

# Environment names that reach into make, or into the shell that runs it.
# PATH: a stub `make` earlier on PATH is a complete bypass. BASH_ENV/ENV: a
# non-interactive shell sources them and can define a `make` function. MAKELEVEL
# and friends: how core's round-2 anchor was talked into a lenient mode.
# GOFLAGS: the go command reads it as extra flags, so `-run=^$` selects nothing.
DANGEROUS_ENV_NAMES = {
    "MAKEFLAGS", "GNUMAKEFLAGS", "MFLAGS", "MAKEFILES",
    "MAKELEVEL", "MAKE_RESTARTS", "MAKEOVERRIDES", "MAKECMDGOALS",
    "SHELL", "PATH", "BASH_ENV", "ENV", "GOFLAGS",
}


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


# ------------------------------------------------------------ strict YAML ---


class _StrictLoader(yaml.SafeLoader):
    """A SafeLoader that refuses a duplicate mapping key and a merge key.

    PyYAML resolves a duplicate last-wins, so `run: make -i test` followed by
    `run: make test` in one mapping read as `make test` here while a reviewer
    reads the first line (core PR#9 re-verification, FINDING R-4). A merge key
    (`<<: *base`) splices keys in from elsewhere in the file — an `if:` or a
    `shell:` a reviewer of the step does not see beside it. Whatever GitHub's own
    parser does with either, this guard refuses to guess.
    """


def _construct_mapping_strict(loader, node, deep=False):
    seen = {}
    for key_node, _ in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            raise yaml.constructor.ConstructorError(
                None, None,
                "YAML merge key `<<` — it splices keys into this mapping from elsewhere in the file, "
                "so what a reviewer sees beside the step is not all the step carries; refused",
                key_node.start_mark)
        key = loader.construct_object(key_node, deep=deep)
        try:
            hash(key)
        except TypeError:
            continue
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None,
                f"duplicate key {key!r} (first at line {seen[key] + 1}); the guard refuses to guess "
                f"which value a runner would use",
                key_node.start_mark)
        seen[key] = key_node.start_mark.line
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping_strict)


def safe_load_strict(text: str):
    # _construct_mapping_strict inspects the raw key nodes BEFORE the base
    # constructor flattens a merge, so `<<` is seen and refused, not expanded.
    return yaml.load(text, Loader=_StrictLoader)


def load_workflows(g: Guard, d: Path) -> dict[Path, dict]:
    out: dict[Path, dict] = {}
    paths = sorted(list(d.glob("*.yml")) + list(d.glob("*.yaml")))
    if not paths:
        g.fail(f"no workflow files under {d}; there is nothing to gate with")
    for p in paths:
        try:
            doc = safe_load_strict(p.read_text())
        except yaml.YAMLError as e:
            g.fail(f"{p} is refused by the strict YAML reader: {e}")
            continue
        if isinstance(doc, dict):
            out[p] = doc
        else:
            g.fail(f"{p} is not a YAML mapping; it cannot be a workflow")
    return out


def job_display_name(job_key: str, job: dict) -> str:
    """GitHub reports a job's `name:` when set, otherwise its key."""
    if isinstance(job, dict) and isinstance(job.get("name"), str):
        return job["name"]
    return job_key


def triggers(doc: dict) -> set[str]:
    # PyYAML parses the bare key `on:` as the boolean True (YAML 1.1).
    raw = doc.get("on", doc.get(True))
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, list):
        return {str(x) for x in raw}
    if isinstance(raw, dict):
        return {str(k) for k in raw}
    return set()


def is_coe_key(key) -> bool:
    return str(key).strip().strip("\"'").lower().replace("_", "-") == "continue-on-error"


def continue_on_error_sites(job: dict) -> list[str]:
    """Every place `continue-on-error` appears on a job or its steps, whatever the value."""
    sites: list[str] = []
    for key in job:
        if is_coe_key(key):
            sites.append(f"job-level ({key}: {job[key]!r})")
    for i, step in enumerate(job.get("steps") or []):
        if not isinstance(step, dict):
            continue
        for key in step:
            if is_coe_key(key):
                label = step.get("name") or step.get("uses") or f"step {i}"
                sites.append(f"step {label!r} ({key}: {step[key]!r})")
    return sites


def trim_one_newline(text: str) -> str:
    return text[:-1] if text.endswith("\n") else text


def step_run(step: dict) -> str | None:
    run = step.get("run")
    return run if isinstance(run, str) else None


def step_runs_make(step: dict) -> bool:
    run = step_run(step)
    return run is not None and bool(MAKE_INVOCATION.search(run))


def step_runs_go_test(step: dict) -> bool:
    run = step_run(step)
    return run is not None and bool(GO_TEST_INVOCATION.search(run))


def extra_keys(step: dict) -> list[str]:
    return sorted(str(k) for k in step if str(k) not in STEP_KEYS_ALLOWED)


def step_label(step: dict, i: int) -> str:
    return str(step.get("name") or step.get("uses") or f"step {i}")


# ------------------------------------------------------------------- pins ---


class Pins:
    def __init__(self, anchor: str, make_steps: list[str], direct: list[str], required: dict[str, list[str]]):
        self.anchor = anchor
        self.make_steps = make_steps
        self.direct = direct
        self.required = required


def load_pins(path: Path) -> Pins:
    """The committed allowlist. Missing, malformed or empty is a FAILURE, never a pass."""
    if not path.exists():
        raise SystemExit(
            f"ci-required-guard: {path} is missing. It is the allowlist that makes a checked lane's "
            f"make steps and direct test steps default-deny; without it there is no gate.")
    try:
        doc = safe_load_strict(path.read_text())
    except yaml.YAMLError as e:
        raise SystemExit(f"ci-required-guard: {path} is refused by the strict YAML reader: {e}")
    if not isinstance(doc, dict):
        raise SystemExit(f"ci-required-guard: {path} is not a mapping")
    unknown = sorted(str(k) for k in doc if k not in PIN_KEYS)
    if unknown:
        raise SystemExit(f"ci-required-guard: {path} carries unknown key(s) {unknown}; the pins file is "
                         f"default-deny too — only {sorted(PIN_KEYS)} mean anything.")
    anchor = doc.get("anchor_step")
    if not isinstance(anchor, str) or not anchor.strip():
        raise SystemExit(f"ci-required-guard: {path} has no anchor_step. Without a pinned anchor, any step "
                         f"that merely NAMES make-integrity-guard would satisfy adjacency (core PR#9 R-1).")

    def bodies(key: str) -> list[str]:
        raw = doc.get(key)
        if not isinstance(raw, list) or not raw or not all(isinstance(x, str) and x.strip() for x in raw):
            raise SystemExit(f"ci-required-guard: {path} `{key}` must be a non-empty list of `run:` bodies.")
        return [trim_one_newline(x) for x in raw]

    make_steps = bodies("make_steps")
    direct = bodies("direct_test_steps")
    for body in make_steps:
        if not MAKE_INVOCATION.search(body):
            raise SystemExit(f"ci-required-guard: {path} make_steps entry {body!r} does not invoke make.")
    for body in direct:
        if not GO_TEST_INVOCATION.search(body) or MAKE_INVOCATION.search(body):
            raise SystemExit(f"ci-required-guard: {path} direct_test_steps entry must run `go test` and no make.")
    raw_req = doc.get("required_invocations")
    if not isinstance(raw_req, dict) or not raw_req:
        raise SystemExit(f"ci-required-guard: {path} has no required_invocations; nothing would be asserted PRESENT.")
    required: dict[str, list[str]] = {}
    for job, lst in raw_req.items():
        if not isinstance(lst, list) or not lst or not all(isinstance(x, str) for x in lst):
            raise SystemExit(f"ci-required-guard: {path} required_invocations[{job!r}] must be a non-empty list.")
        required[str(job)] = [trim_one_newline(x) for x in lst]
    all_required = {b for lst in required.values() for b in lst}
    unknown_bodies = sorted(all_required - set(make_steps) - set(direct))
    if unknown_bodies:
        raise SystemExit(f"ci-required-guard: {path} requires invocation(s) {unknown_bodies} that are not pinned "
                         f"in make_steps or direct_test_steps, so they could never be run.")
    unrequired = sorted((set(make_steps) | set(direct)) - all_required)
    if unrequired:
        raise SystemExit(f"ci-required-guard: {path} pins body(ies) {unrequired} that no job is required to run. "
                         f"A pin nothing must run is surface with no gate behind it; require it or remove it.")
    return Pins(trim_one_newline(anchor), make_steps, direct, required)


# ------------------------------------------- variables the Makefile reads ---


def makefile_env_names(g: Guard, makefile: Path, skip: bool) -> set[str]:
    """Names the Makefile takes from the environment — computed by the SAME code the anchor uses.

    makegate.environment_taken, over makegate's one line reader: `?=` means the environment wins; a variable
    referenced as `$(NAME)`/`${NAME}` and never assigned is taken from the environment outright (the other
    reference forms are refused by the grammar; every gate make process also drops every word of the pinned
    text, see makegate.environment_words). The anchor refuses them at run time (from every file make read,
    includes too); this refuses them as job/workflow `env:`. GOFLAGS is always included.
    """
    names = {"GOFLAGS"}
    if skip or not makefile.exists():
        return names
    return names | mg.environment_taken(makefile.parent, [makefile.name])


def env_problems(scope: str, env, makefile_names: set[str]) -> list[str]:
    if env is None:
        return []
    if not isinstance(env, dict):
        return [f"{scope} env is not a mapping ({env!r}); it cannot be checked, so it is refused"]
    out = []
    for key, value in env.items():
        name = str(key).strip()
        if name.upper() in DANGEROUS_ENV_NAMES:
            out.append(f"{scope} env sets {key}: {value!r}")
        elif name in makefile_names:
            out.append(f"{scope} env sets {key}: {value!r}, which the Makefile takes from the environment "
                       f"(`?=` or referenced-unassigned) — so the environment decides what the recipe runs")
    return out


# ----------------------------------------------------------------- checks ---


def check_steps(g: Guard, lane: str, path: Path, doc: dict, job: dict, pins: Pins,
                makefile_names: set[str]) -> None:
    """PINNED, ANCHORED and the env of a job that runs make or a direct test step."""
    steps = [s for s in (job.get("steps") or []) if isinstance(s, dict)]
    failures_before = g.failures
    make_count = direct_count = 0

    for i, step in enumerate(steps):
        run = step_run(step)
        label = step_label(step, i)
        body = trim_one_newline(run) if run is not None else None
        is_anchor = body == pins.anchor

        if run is not None and MAKE_INTEGRITY_GUARD in run and not is_anchor:
            g.fail(
                f"checked lane {lane!r} ({path.name}) step {label!r} names {MAKE_INTEGRITY_GUARD} but its "
                f"`run:` is not byte-equal to the pinned anchor {pins.anchor!r}.",
                f"got: {body!r}",
                "A step that runs the guard and THEN writes $GITHUB_ENV / $GITHUB_PATH, or that only names",
                "it (`: make-integrity-guard`), would otherwise pass for the anchor while the write reaches",
                "make and not the guard (core PR#9 re-verification, R-1).",
            )

        if is_anchor:
            extra = extra_keys(step)
            if extra:
                g.fail(
                    f"checked lane {lane!r} ({path.name}) anchor step {label!r} carries {extra}.",
                    "The anchor may carry only name/run/id: `if:` skips it, `env:` or `shell:` changes the",
                    "environment it exists to inspect, `continue-on-error:` discards its verdict.",
                )
            continue

        if step_runs_make(step):
            make_count += 1
            if body not in pins.make_steps:
                detail = []
                try:
                    shlex.split(run, comments=True)
                except ValueError:
                    detail = ["(its `run:` cannot even be tokenised as shell)"]
                g.fail(
                    f"checked lane {lane!r} ({path.name}) step {label!r} mentions `make` but its `run:` is not "
                    f"byte-equal to any entry in .github/pinned-steps.yml make_steps.",
                    f"got: {body!r}",
                    *detail,
                    "A make step is DEFAULT-DENY on its whole body: no flags, no variable overrides, no",
                    "chains, no indirection, one invocation per step. If this invocation is legitimate, add",
                    "it to .github/pinned-steps.yml in a reviewed diff.",
                )
            extra = extra_keys(step)
            if extra:
                g.fail(
                    f"checked lane {lane!r} ({path.name}) make step {label!r} carries {extra}.",
                    "A make step may carry only name/run/id. `if:` skips it while the job stays green;",
                    "`env:` reaches make; `shell:` can discard its exit status; `working-directory:` is",
                    "`-C` by another name; `continue-on-error:` discards the failure; `timeout-minutes`",
                    "is unused surface.",
                )
            if i == 0 or trim_one_newline(step_run(steps[i - 1]) or "") != pins.anchor:
                before = step_label(steps[i - 1], i - 1) if i else "(nothing)"
                g.fail(
                    f"checked lane {lane!r} ({path.name}) make step {label!r} is not IMMEDIATELY preceded by "
                    f"the pinned {MAKE_INTEGRITY_GUARD} anchor; the step before it is {before!r}.",
                    "Any step between the anchor and make can write MAKEFLAGS to $GITHUB_ENV or a stub",
                    "`make` to $GITHUB_PATH, which GitHub applies to LATER steps only — the anchor would",
                    "check a clean environment and make would run in a poisoned one.",
                )
            continue

        if step_runs_go_test(step):
            direct_count += 1
            if body not in pins.direct:
                g.fail(
                    f"checked lane {lane!r} ({path.name}) step {label!r} runs `go test` but its `run:` is not "
                    f"byte-equal to any entry in .github/pinned-steps.yml direct_test_steps.",
                    f"got: {body!r}",
                    "A direct test step is DEFAULT-DENY on its whole body: the exit handling (`|| exit 1`",
                    "on the report, `exit \"$rc\"` last) is what makes a failing test fail the lane, and",
                    "a `-run`, a `|| true` or a dropped report line changes nothing a substring test sees.",
                )
            extra = extra_keys(step)
            if extra:
                g.fail(
                    f"checked lane {lane!r} ({path.name}) direct test step {label!r} carries {extra}.",
                    "A direct test step may carry only name/run/id, for the same reasons a make step may.",
                )

    if make_count or direct_count:
        for scope, holder in (("workflow-level", doc), ("job-level", job)):
            for problem in env_problems(scope, (holder or {}).get("env"), makefile_names):
                g.fail(
                    f"checked lane {lane!r} ({path.name}) {problem}, and this job runs make or `go test`.",
                    "It reaches every step, the anchor, the make steps and the direct test step included.",
                )

    if g.failures == failures_before and (make_count or direct_count):
        g.ok(
            f"checked lane {lane!r}: {make_count} make step(s) and {direct_count} direct test step(s) are "
            f"byte-equal to a pinned body and carry no key but name/run/id; each make step is immediately "
            f"preceded by the pinned anchor"
        )


def check_required_invocations(g: Guard, lane: str, path: Path, job: dict, pins: Pins) -> None:
    """PRESENT: the lane runs what the pins record for it, byte-equal."""
    wanted = pins.required.get(lane)
    if not wanted:
        return
    bodies = {trim_one_newline(s.get("run") or "") for s in (job.get("steps") or [])
              if isinstance(s, dict) and isinstance(s.get("run"), str)}
    missing = [w for w in wanted if w not in bodies]
    if missing:
        g.fail(
            f"checked lane {lane!r} ({path.name}) does not run required invocation(s) {missing}.",
            ".github/pinned-steps.yml lists these as invocations this job MUST contain, byte-equal.",
            "Deleting one, or replacing it with a step that reaches make through a variable, a function",
            "or a PATH edit, leaves the gate uninvoked — and no reading of the replacement could say so.",
        )
    else:
        g.ok(f"checked lane {lane!r} runs all {len(wanted)} required invocation(s)")


def check_surroundings(g: Guard, lane: str, path: Path, doc: dict, job: dict) -> None:
    for scope, holder in (("workflow", doc), ("job", job)):
        defaults = (holder or {}).get("defaults")
        if isinstance(defaults, dict) and defaults.get("run") is not None:
            g.fail(
                f"checked lane {lane!r} ({path.name}) sets a {scope}-level defaults.run: {defaults['run']!r}.",
                "It rewrites how EVERY `run:` step executes — shell, working directory — so it no-ops the",
                "anchor and every pinned step at once: the Actions analogue of `SHELL := /usr/bin/true`.",
            )
        elif defaults is not None and not isinstance(defaults, dict):
            g.fail(f"checked lane {lane!r} ({path.name}) has a {scope}-level `defaults:` that is not a mapping.")
    if job.get("container") is not None:
        g.fail(
            f"checked lane {lane!r} ({path.name}) runs in a job-level `container:` ({job['container']!r}).",
            "The whole lane would execute inside an image nothing here pins or asserts, with its own make,",
            "go and shell. Nothing here needs one.",
        )
    if "if" in job:
        g.fail(
            f"checked lane {lane!r} ({path.name}) carries a job-level `if:` ({job['if']!r}).",
            "A skipped required lane already fails ci-required (only `success` passes), but a lane that can",
            "be switched off by an expression is refused here too, so the reason has a name.",
        )
    if job.get("uses") is not None:
        g.fail(
            f"checked lane {lane!r} ({path.name}) is a reusable-workflow call (`uses: {job['uses']}`).",
            "It has no steps this guard can read, so nothing here could be checked.",
        )
    services = job.get("services") or {}
    if not isinstance(services, dict):
        g.fail(f"checked lane {lane!r} ({path.name}) has `services:` that is not a mapping.")
        services = {}
    for name, svc in services.items():
        image = svc.get("image") if isinstance(svc, dict) else svc
        if not isinstance(image, str) or "@sha256:" not in image:
            g.fail(
                f"checked lane {lane!r} ({path.name}) service {name!r} image {image!r} is not digest-pinned.",
                "A floating tag lets the service this lane tests against change underneath it.",
            )


def check_makefile_selection(g: Guard, makefile: Path) -> None:
    """The `test` lane selects the whole module."""
    if not makefile.exists():
        g.fail(f"{makefile} is missing; the test selection cannot be checked")
        return
    lines = mg.read_makefile_lines(makefile)
    pkg = next((m for rec in lines if not rec.tab for m in [re.match(r"^PKG\s*:?=\s*(.+)$", rec.raw)] if m), None)
    if not pkg or pkg.group(1).strip() != "./...":
        g.fail(f"the Makefile's PKG is {pkg.group(1).strip() if pkg else None!r}, not './...'",
               "The `test` lane would run a subset of the module while every gate stayed green.")
    else:
        g.ok("the `test` lane selects the whole module (PKG = ./...)")
    at = next((i for i, rec in enumerate(lines) if not rec.tab and re.match(r"^test:", rec.raw)), None)
    recipe = "".join(f"\t{body}\n" for _, body in mg.recipe_lines(lines, at + 1)) if at is not None else ""
    if not recipe or "$(PKG)" not in recipe or re.search(r"\s-(run|skip|short)\b", recipe):
        g.fail("the `test` target does not run `$(PKG)` without a test-selecting flag",
               "Its selection is not the one checked above.")
    else:
        g.ok("the `test` target runs $(PKG) with no test-selecting flag")


def check_local_parity(g: Guard, makefile: Path, pins: Pins) -> None:
    """PARITY: `make ci` runs what CI runs, so the local gate and the required lanes agree.

    Every pinned make body names one target; each must be a prerequisite of
    `ci:`, and every prerequisite of `ci:` must be one of those targets or
    `test-noskip` (local parity for the direct lane). A required lane added to CI
    but not to `ci:` — or the reverse — is a disagreement, and it is red.
    """
    if not makefile.exists():
        g.fail(f"{makefile} is missing; local parity cannot be checked")
        return
    m = next((m for rec in mg.read_makefile_lines(makefile) if not rec.tab for m in [re.match(r"^ci:(.*)$", rec.code)]
              if m), None)
    if not m:
        g.fail("the Makefile has no `ci:` target; there is no local complete gate to agree with CI")
        return
    local = m.group(1).split()
    ci_targets = []
    for body in pins.make_steps:
        words = body.split()
        if len(words) == 2 and words[0] == "make":
            ci_targets.append(words[1])
        else:
            g.fail(f"pinned make body {body!r} is not `make <target>`; parity cannot be judged")
    missing = [t for t in ci_targets if t not in local]
    extra = [t for t in local if t not in ci_targets and t != "test-noskip"]
    if "test-noskip" not in local:
        missing.append("test-noskip")
    if missing or extra:
        detail = []
        if missing:
            detail.append(f"run by a required lane but not by `make ci`: {missing}")
        if extra:
            detail.append(f"run by `make ci` but by no required lane: {extra}")
        g.fail(
            "the Makefile's `ci:` and the required lanes disagree.",
            *detail,
            "`make ci` is documented as the complete gate; a lane on one side only means a local",
            "green that CI does not share, or a CI lane nobody can reproduce.",
        )
    else:
        g.ok(f"`make ci` runs exactly the required make lanes plus test-noskip: {local}")


def check_makefile_pins(g: Guard, path: Path, root: Path, verify_bytes: bool) -> None:
    """DIGEST: .github/pinned-makefiles.yml has the one accepted shape, pins Makefile, and matches the tree.

    Read by scripts/makegate.py's own parser (the one the anchor and every other make call use), so the
    readers cannot disagree, and ALSO by the strict YAML loader, so it is valid YAML as well. With the tree:
    each pinned file is a regular non-symlink file whose sha256 matches, the reviewed bytes include only
    pinned files, and no unpinned GNUmakefile/makefile sits beside the Makefile (case-folded) — the same
    refusals the anchor makes, here in `ci-required`, without running make.
    """
    if not path.is_file():
        g.fail(f"{path} is missing. make is gated on pinned Makefile bytes; without the pin there is no gate.")
        return
    try:
        doc = safe_load_strict(path.read_text())
    except yaml.YAMLError as e:
        g.fail(f"{path} is refused by the strict YAML reader: {e}")
        return
    if not isinstance(doc, dict) or set(doc) != {"makefiles"} or not isinstance(doc.get("makefiles"), dict):
        g.fail(f"{path} must be a single `makefiles:` mapping of `path: sha256` (the shape core PR #10 uses).")
        return
    try:
        if verify_bytes:
            files, _, _ = mg.check_pinned_bytes(root)
        else:
            pins = mg.load_pin(root if (root / mg.PIN_FILE) == path else path.parent.parent)
            files = sorted(pins)
    except mg.GateRefused as err:
        g.fail(f"{path.name}: the Makefile pin does not hold:", *err.problems,
               "A Makefile edit is mergeable only together with a reviewed edit to the pin.")
        return
    g.ok(f"{path.name} pins {files} by sha256" + ("; each is a regular file matching its pin, the reviewed "
         "bytes include nothing unpinned, and no unpinned GNUmakefile/makefile sits beside them"
         if verify_bytes else ""))


def main() -> int:
    ap = argparse.ArgumentParser()
    root = Path(__file__).resolve().parent.parent
    ap.add_argument("--workflows", type=Path, default=root / ".github" / "workflows")
    ap.add_argument("--manifest", type=Path, default=root / ".github" / "required-checks.txt")
    ap.add_argument("--makefile", type=Path, default=root / "Makefile")
    ap.add_argument("--pins", type=Path, default=root / ".github" / "pinned-steps.yml")
    ap.add_argument("--makefile-pins", type=Path, default=root / ".github" / "pinned-makefiles.yml")
    ap.add_argument("--skip-makefile", action="store_true", help="for fixture runs that ship no Makefile")
    args = ap.parse_args()

    g = Guard()
    print("ci-required-guard.py:", flush=True)

    if not args.manifest.is_file():
        g.fail(f"{args.manifest} is missing; ci-required has no gate to enforce")
        return 1
    required: list[str] = []
    commented: list[str] = []
    for line in args.manifest.read_text().splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            commented.append(stripped.lstrip("#").strip())
            continue
        required.append(stripped)
    if not required:
        g.fail(f"{args.manifest} lists no checks; ci-required would pass with nothing verified")
        return 1

    pins = load_pins(args.pins)
    g.ok(f"pinned-steps.yml: anchor pinned; {len(pins.make_steps)} make body(ies), {len(pins.direct)} direct "
         f"test body(ies), required invocations for {sorted(pins.required)}")
    makefile_names = makefile_env_names(g, args.makefile, args.skip_makefile)
    g.ok(f"variables refused as job/workflow env besides the make/shell family: {sorted(makefile_names)}")

    workflows = load_workflows(g, args.workflows)
    jobs: dict[str, tuple[Path, dict, dict]] = {}
    for path, doc in workflows.items():
        raw_jobs = doc.get("jobs")
        if not isinstance(raw_jobs, dict):
            continue
        for key, job in raw_jobs.items():
            if isinstance(job, dict):
                name = job_display_name(key, job)
                if name in jobs:
                    g.fail(f"two jobs report the name {name!r} ({jobs[name][0].name} and {path.name}); the "
                           f"fan-in cannot tell which one it read")
                jobs[name] = (path, doc, job)

    # FLOOR
    floor_ok = True
    for lane in FLOOR_LANES:
        if lane in required:
            continue
        floor_ok = False
        if any(lane == c.split()[0] if c else False for c in commented):
            g.fail(f"required lane {lane!r} is COMMENTED OUT in {args.manifest.name}.",
                   "It is a floor lane: the pull request it gates cannot make it optional.")
        else:
            g.fail(f"required lane {lane!r} is MISSING from {args.manifest.name}.",
                   "It is a floor lane (scripts/ci-required-guard.py FLOOR_LANES). Deleting a manifest line does",
                   "not shrink the gate; it turns this lane red.")
    if floor_ok:
        g.ok(f"all {len(FLOOR_LANES)} floor lane(s) are present in the manifest: {FLOOR_LANES}")

    # RESOLVABLE
    for name in required:
        if name not in jobs:
            g.fail(f"required check {name!r} matches no job in {args.workflows}.",
                   "ci-required would wait for a check nothing produces.")
    for job_name in pins.required:
        if job_name not in jobs:
            g.fail(f".github/pinned-steps.yml requires invocations of job {job_name!r}, which no workflow defines.")
        elif job_name not in set(FLOOR_LANES) | set(required):
            g.fail(f".github/pinned-steps.yml requires invocations of job {job_name!r}, which is not a required "
                   f"lane; its invocations would gate nothing.")

    checked = sorted(set(FLOOR_LANES) | set(required))
    for lane in checked:
        entry = jobs.get(lane)
        if entry is None:
            continue
        path, doc, job = entry
        if "pull_request" not in triggers(doc):
            g.fail(f"checked lane {lane!r} ({path.name}) is not triggered on pull_request.")
        sites = continue_on_error_sites(job)
        if sites:
            g.fail(f"checked lane {lane!r} ({path.name}) carries continue-on-error:", *sites,
                   "Present at all is the rule, whatever the value.")
        check_surroundings(g, lane, path, doc, job)
        check_steps(g, lane, path, doc, job, pins, makefile_names)
        check_required_invocations(g, lane, path, job, pins)

    # The direct suite runs from a pinned body in some required lane.
    direct_lanes = [n for n in required if n in jobs and any(
        isinstance(s, dict) and trim_one_newline(s.get("run") or "") in pins.direct
        for s in (jobs[n][2].get("steps") or []))]
    if direct_lanes:
        g.ok(f"the suite runs directly, with no make step, from a pinned body in lane(s) {direct_lanes}")
    else:
        g.fail("no required lane runs the suite directly from a pinned body.",
               "A Makefile turned into a no-op would then make the suite SILENT rather than red.")

    if not args.skip_makefile:
        check_makefile_selection(g, args.makefile)
        check_local_parity(g, args.makefile, pins)
    check_makefile_pins(g, args.makefile_pins, args.makefile.parent, not args.skip_makefile)

    bad_runners: list[str] = []
    unpinned: list[str] = []
    for path, doc in workflows.items():
        for key, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            if job.get("runs-on") != RUNNER:
                bad_runners.append(f"{path.name}:{key} runs-on: {job.get('runs-on')!r}")
            for step in job.get("steps") or []:
                uses = step.get("uses") if isinstance(step, dict) else None
                if isinstance(uses, str) and not uses.startswith("./") and not SHA_PIN.match(uses):
                    unpinned.append(f"{path.name}:{key} uses: {uses}")
    if bad_runners:
        g.fail("job(s) on a runner other than " + RUNNER + ":", *bad_runners)
    else:
        g.ok(f"every job runs on GitHub-hosted {RUNNER}")
    if unpinned:
        g.fail("action(s) not pinned to a 40-character commit SHA:", *unpinned)
    else:
        g.ok("every third-party action is pinned to a commit SHA")

    if g.failed:
        print(f"ci-required-guard.py: FAILED ({g.failures} failure(s))", file=sys.stderr)
        return 1
    print(f"ci-required-guard.py: passed ({len(required)} required check(s), {len(checked)} checked lane(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
