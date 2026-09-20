#!/usr/bin/env python3
"""Reject `continue-on-error` in GitHub workflow definitions, by PARSING them.

A lane that cannot fail is not a gate (ADR-002 § CI fan-in). The previous
version of this check was a literal-string grep, which several spellings evade:

    continue-on-error: true            # caught by a grep
    "continue-on-error": true          # quoted key — not caught
    Continue-On-Error: true            # YAML keys are case-sensitive, so this
                                       # is a DIFFERENT key to a strict parser,
                                       # but Actions is lenient about it
    continue-on-error: ${{ ... }}      # an expression that evaluates to true
    continue-on-error: false           # harmless today, one character from not

So the key is matched after unquoting and case-folding, and its VALUE is not
consulted at all: the key is refused wherever it appears on a job or on a step.
`false` is refused too, because "it is currently false" is not a property CI
can rely on.

Usage:
    check-workflows.py [workflow.yml ...]      (default: .github/workflows/*.yml)

Exit codes are a three-way answer, not a boolean, because "I rejected this" and
"I could not read this" are different facts and the fan-in guard must not
confuse them:

    0  clean        no forbidden key anywhere
    1  VIOLATION    a forbidden key was found; one `VIOLATION …` line per hit
    2  UNEVALUABLE  the file could not be read, is empty, is not parseable, or
                    declares no jobs — nothing was checked

For a real workflow both 1 and 2 are failures and the lane stays closed either
way. The distinction exists for `scripts/ci-required-guard.sh`, which exercises
this checker against negative fixtures: treating *any* non-zero exit as "the
fixture was correctly rejected" let an unreadable or emptied fixture count as a
pass it had not earned. A fixture must be REJECTED, and rejected for the reason
it was written to trip — not merely fail to be read.

Each violation prints a machine-readable line to stderr:

    VIOLATION <path> at=<job|step> key=<raw spelling> value=<kind> where=<path>

`key` is the spelling as it appears in the source text (YAML has already
unquoted and the parser has already case-folded it, so the raw spelling is
recovered from the file for reporting only). `value` is one of `literal-true`,
`literal-false`, `expression`, `other` — reported, never acted on: the key is
refused whatever its value.
"""

import glob
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only on a runner without PyYAML
    sys.stderr.write(
        "PyYAML is required: this check parses the workflows rather than grepping them.\n"
        "Install it with `python3 -m pip install --break-system-packages pyyaml`.\n"
    )
    sys.exit(2)

FORBIDDEN = "continue-on-error"


def normalise(key):
    """Fold a mapping key the way a permissive reader would see it."""
    if not isinstance(key, str):
        return ""
    return key.strip().strip("\"'").strip().lower()


def find_forbidden(node, path):
    """Yield (path, value) for every forbidden key anywhere under node."""
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}"
            if normalise(key) == FORBIDDEN:
                yield here, value
            yield from find_forbidden(value, here)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            yield from find_forbidden(item, f"{path}[{i}]")


def value_kind(value):
    """Classify a forbidden key's value for reporting. Never acted on."""
    if value is True:
        return "literal-true"
    if value is False:
        return "literal-false"
    if isinstance(value, str) and "${{" in value:
        return "expression"
    return "other"


def raw_key_spelling(text):
    """Recover how the forbidden key is written in the source.

    The parser has already unquoted and case-folded it, so `"continue-on-error"`
    and `Continue-On-Error` are indistinguishable by the time a violation is
    reported. The fan-in guard needs to tell them apart to assert that each
    negative fixture still trips the spelling it was written for, so the raw
    spelling is read back out of the file text. This is reporting only: nothing
    here decides whether the key is refused.
    """
    for line in text.splitlines():
        stripped = line.strip()
        if ":" not in stripped or stripped.startswith("#"):
            continue
        written = stripped.split(":", 1)[0].strip()
        if normalise(written) == FORBIDDEN:
            return written
    return "<unlocated>"


def main(argv):
    paths = argv[1:] or sorted(
        glob.glob(".github/workflows/*.yml") + glob.glob(".github/workflows/*.yaml")
    )
    if not paths:
        sys.stderr.write("no workflow files found; this check is not checking anything\n")
        return 2

    violations = 0
    for path in paths:
        # Read and parse as two distinct failures. An unreadable, empty or
        # unparseable file is UNEVALUABLE (exit 2): nothing was checked, and a
        # caller must not read that as "rejected".
        try:
            with open(path, "r", encoding="utf-8") as handle:
                text = handle.read()
        except OSError as err:
            sys.stderr.write(f"UNEVALUABLE {path}: cannot read: {err}\n")
            return 2
        if not text.strip():
            sys.stderr.write(f"UNEVALUABLE {path}: file is empty\n")
            return 2
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as err:
            sys.stderr.write(f"UNEVALUABLE {path}: cannot parse: {err}\n")
            return 2
        if doc is None:
            sys.stderr.write(f"UNEVALUABLE {path}: empty workflow\n")
            return 2

        jobs = doc.get("jobs") if isinstance(doc, dict) else None
        if not isinstance(jobs, dict) or not jobs:
            sys.stderr.write(f"UNEVALUABLE {path}: declares no jobs\n")
            return 2

        spelling = raw_key_spelling(text)
        for job_name, job in jobs.items():
            for where, value in find_forbidden(job, f"{path}:jobs.{job_name}"):
                at = "step" if ".steps[" in where else "job"
                sys.stderr.write(
                    f"VIOLATION {path} at={at} key={spelling} "
                    f"value={value_kind(value)} where={where}\n"
                )
                sys.stderr.write(
                    f"{where}: `continue-on-error` is not allowed on a required lane "
                    f"(found with value {value!r}; the value is irrelevant — the key "
                    f"makes the lane unable to fail the gate)\n"
                )
                violations += 1

    if violations:
        return 1
    print(f"workflows parsed: {len(paths)}; no continue-on-error on any job or step")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
