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

Exit 0 when clean, 1 when a violation is found, 2 when a file cannot be parsed
— an unparseable workflow fails closed rather than being skipped.
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


def main(argv):
    paths = argv[1:] or sorted(
        glob.glob(".github/workflows/*.yml") + glob.glob(".github/workflows/*.yaml")
    )
    if not paths:
        sys.stderr.write("no workflow files found; this check is not checking anything\n")
        return 2

    violations = 0
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                doc = yaml.safe_load(handle)
        except yaml.YAMLError as err:
            sys.stderr.write(f"{path}: cannot parse: {err}\n")
            return 2
        if doc is None:
            sys.stderr.write(f"{path}: empty workflow\n")
            return 2

        jobs = doc.get("jobs")
        if not isinstance(jobs, dict) or not jobs:
            sys.stderr.write(f"{path}: declares no jobs\n")
            return 2

        for job_name, job in jobs.items():
            for where, value in find_forbidden(job, f"{path}:jobs.{job_name}"):
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
