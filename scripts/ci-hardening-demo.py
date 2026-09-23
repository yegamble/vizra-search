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
    dict(id="1k", item=1, name="Makefile: MAKEFLAGS += -i", file="Makefile", old=FLAGS_PIN,
         new=FLAGS_PIN + "MAKEFLAGS += -i\n", cmd=ANCHOR, want="assigns makeflags"),
    dict(id="1l", item=1, name="Makefile: SHELL := /usr/bin/true", file="Makefile", old="SHELL := /bin/bash\n",
         new="SHELL := /usr/bin/true\n", cmd=ANCHOR, want="shell"),
    dict(id="1m", item=1, name="Makefile: $(shell) writes $GITHUB_ENV while being read", file="Makefile",
         old=FLAGS_PIN, new=FLAGS_PIN + "POISON := $(shell echo MAKEFLAGS=-i >> \"$$GITHUB_ENV\")\n",
         cmd=ANCHOR, want="make was not invoked"),
    dict(id="1n", item=1, name="env: MAKELEVEL=1 MAKEFLAGS=-ki (strictness is not the environment's)",
         env={"MAKELEVEL": "1", "MAKEFLAGS": "-ki"}, cmd=ANCHOR, want="makelevel"),
    dict(id="1o", item=1, name="env: VERSION=x (a Makefile ?= variable)", env={"VERSION": "x"}, cmd=ANCHOR,
         want="version='x'"),
    dict(id="1p", item=1, name="implementation: adjacency check disabled", file="scripts/ci-required-guard.py",
         old="            if i == 0 or trim_one_newline(step_run(steps[i - 1]) or \"\") != pins.anchor:\n",
         new="            if False:\n",
         cmd=gotest("./scripts/", "TestCIRequiredGuardRefusesEveryEvasion/anchor"), want="green (exit 0) after the mutation"),
    dict(id="1q", item=1, name="implementation: parse-time pre-flight removed",
         file="scripts/make-integrity-guard.py",
         old="    if not check_parse_time_side_effects(g, root):\n",
         new="    if False and not check_parse_time_side_effects(g, root):\n",
         cmd=gotest("./scripts/", "TestTheAnchorExecutesNothingWhileReadingTheMakefile"),
         want="--- fail"),
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
         cmd=["make", "vendor-contract-selftest"], want="shallow clone"),
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
    make_v = subprocess.run(["make", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
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
                with open(path, "wb") as fh:
                    fh.write(orig)
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
