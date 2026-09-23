#!/usr/bin/env python3
"""Negative fixtures for scripts/vendor-contract.py — every refusal, fired.

WHY
===

`vendor-contract.py` sits in the contract-provenance path, and an independent
verifier got past its first guard twice: the guard was `ref.split("/")[-1] !=
"main"`, a string-suffix test, so a git TAG named `main` and a branch
`fake/main` (not on core's main, with the HMAC key replaced) were both accepted
— and the manifest then recorded `source_ref: "main"` for them. A guard that
does not guard, documented as one, is worse than no guard.

So every refusal the script and AGENTS.md advertise gets a fixture here that
shows it firing, **by name**. A refusal with no fixture is a claim, not a
control.

NO NETWORK. Each fixture is a throwaway repository built with `git init` in a
temp dir, plus a throwaway "search" tree holding a copy of the real
`vendor-contract.py` and a minimal manifest — so the script under test is the
actual shipped bytes, running against a sandbox repository root it computes
from its own location.

The tool knows two manifests. The first 17 fixtures, and `contract: below the
minimum`, drive the contract manifest (`api/CONTRACT-SOURCE.json`); the
`engine:` fixtures drive the make-anchor engine manifest
(`scripts/ANCHOR-SOURCE.json`) with SYNTHETIC bytes shaped like
`scripts/makeanchor/`, which are not the engine and are never run; the last one
shows that any other `--manifest` is refused.

  scripts/vendor-contract-selftest.py [-v]
  make vendor-contract-selftest

Exit 0 if every fixture behaved; 1 otherwise, naming each fixture that did not.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REAL_SCRIPT = os.path.join(REPO, "scripts", "vendor-contract.py")
CANONICAL_URL = "https://github.com/yegamble/vizra-core.git"

YAML_NAME = "api/search-internal.openapi.yaml"
JSON_NAME = "api/search-hmac-testvectors.json"

CONTRACT_MANIFEST = "api/CONTRACT-SOURCE.json"
ANCHOR_MANIFEST = "scripts/ANCHOR-SOURCE.json"
ENGINE_DIR = "scripts/makeanchor/"
# SYNTHETIC bytes shaped like the make-anchor engine directory. They are not the
# engine and are never run; they exist so the engine manifest has files to pin,
# including one in a subdirectory the vendoring must create.
ENGINE_FILES = {
    ENGINE_DIR + "gate.py": "# synthetic fixture bytes: not the make-anchor engine\nGATE = 1\n",
    ENGINE_DIR + "grammar.py": "# synthetic fixture bytes: not the make-anchor engine\nGRAMMAR = 1\n",
    ENGINE_DIR + "corpus/rows.json": '{"synthetic": "fixture rows, not the corpus"}\n',
}
ENGINE_MIN = 3

VERBOSE = "-v" in sys.argv[1:]

FAILURES = []


def run(cmd, cwd=None, env=None):
    proc = subprocess.Popen(
        cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    out, _ = proc.communicate()
    return proc.returncode, out.decode("utf-8", "replace")


def git(repo, *args):
    rc, out = run(["git", "-C", repo] + list(args))
    if rc != 0:
        raise RuntimeError("git %s failed in %s:\n%s" % (" ".join(args), repo, out))
    return out.strip()


# --------------------------------------------------------------- fixtures ---


def make_core(tmp, name, *, remote_url=CANONICAL_URL, poison=False, engine=False, engine_extra=None):
    """A throwaway 'vizra-core': a main branch, api/ files, remote-tracking ref.

    engine=True adds the synthetic scripts/makeanchor/ files (plus
    `engine_extra`, a {path: text} map) in the first commit, then a SECOND
    commit that touches only api/, so the last commit touching the engine
    directory is not the last commit touching api/ or the tip.
    """
    core = os.path.join(tmp, name)
    os.makedirs(os.path.join(core, "api"))
    git_init(core)
    write(os.path.join(core, YAML_NAME), "# canonical contract\nopenapi: 3.0.3\n")
    write(
        os.path.join(core, JSON_NAME),
        json.dumps({"scheme": "v1", "key_utf8": "PLACEHOLDER-NOT-A-REAL-KEY", "vectors": []}, indent=2)
        + "\n",
    )
    if engine:
        for rel, text in sorted(list(ENGINE_FILES.items()) + list((engine_extra or {}).items())):
            os.makedirs(os.path.dirname(os.path.join(core, rel)), exist_ok=True)
            write(os.path.join(core, rel), text)
    git(core, "add", "-A")
    git(core, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "api: initial")
    if engine:
        write(os.path.join(core, YAML_NAME), "# canonical contract\nopenapi: 3.0.3\n# api only\n")
        git(core, "add", "-A")
        git(core, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "api: later, engine untouched")
    head = git(core, "rev-parse", "HEAD")
    # The remote-tracking ref is what the script vendors from.
    git(core, "update-ref", "refs/remotes/origin/main", head)
    git(core, "remote", "add", "origin", remote_url)
    if poison:
        write(
            os.path.join(core, JSON_NAME),
            json.dumps(
                {"scheme": "v1", "key_utf8": "SWAPPED-BY-THE-FIXTURE-NOT-A-KEY", "vectors": []},
                indent=2,
            )
            + "\n",
        )
        git(core, "add", "-A")
        git(core, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "api: poisoned")
    return core


def git_init(path):
    rc, out = run(["git", "init", "-q", "-b", "main", path])
    if rc != 0:  # git < 2.28 has no -b
        rc, out = run(["git", "init", "-q", path])
        if rc != 0:
            raise RuntimeError("git init failed: %s" % out)
        run(["git", "-C", path, "checkout", "-q", "-b", "main"])


def write(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def engine_entry(source, vendored=None):
    return {
        "source_path": source,
        "vendored_path": vendored or source,
        "sha256": "0" * 64,
        "bytes": 0,
        "role": "synthetic engine fixture file",
    }


def make_search(tmp, name, engine_entries=None):
    """A throwaway repository root: scripts/vendor-contract.py + a manifest.

    `engine_entries` also writes scripts/ANCHOR-SOURCE.json with those entries;
    the contract manifest is written either way, so an engine run can be shown
    to leave it alone.
    """
    search = os.path.join(tmp, name)
    os.makedirs(os.path.join(search, "scripts"))
    os.makedirs(os.path.join(search, "api"))
    shutil.copy2(REAL_SCRIPT, os.path.join(search, "scripts", "vendor-contract.py"))
    manifest = {
        "source_repository": "yegamble/vizra-core",
        "source_ref": "refs/remotes/origin/main",
        "source_commit": "0" * 40,
        "files": [
            {
                "source_path": YAML_NAME,
                "vendored_path": YAML_NAME,
                "sha256": "0" * 64,
                "bytes": 0,
                "role": "the canonical OpenAPI contract",
            },
            {
                "source_path": JSON_NAME,
                "vendored_path": JSON_NAME,
                "sha256": "0" * 64,
                "bytes": 0,
                "role": "normative HMAC conformance vectors",
            },
        ],
    }
    with open(os.path.join(search, "api", "CONTRACT-SOURCE.json"), "w", encoding="utf-8") as fh:
        fh.write(json.dumps(manifest, indent=2) + "\n")
    if engine_entries is not None:
        engine = {
            "source_repository": "yegamble/vizra-core",
            "source_ref": "refs/remotes/origin/main",
            "source_commit": "0" * 40,
            "files": engine_entries,
        }
        with open(os.path.join(search, ANCHOR_MANIFEST), "w", encoding="utf-8") as fh:
            fh.write(json.dumps(engine, indent=2) + "\n")
    return search


def vendor(search, *args):
    return run([sys.executable, os.path.join(search, "scripts", "vendor-contract.py")] + list(args))


def manifest_of(search, which=CONTRACT_MANIFEST):
    with open(os.path.join(search, which), encoding="utf-8") as fh:
        return json.load(fh)


def raw_of(search, rel):
    with open(os.path.join(search, rel), "rb") as fh:
        return fh.read()


# ------------------------------------------------------------------ cases ---


def expect_refusal(label, tmp, core_maker, argv, needles):
    """The command must exit non-zero AND say why, naming each needle."""
    search = make_search(tmp, "search-" + label)
    core = core_maker(tmp)
    rc, out = vendor(search, "--core", core, *argv)
    ok = True
    if rc == 0:
        ok = False
        FAILURES.append("%s: expected a refusal, got exit 0" % label)
    for n in needles:
        if n not in out:
            ok = False
            FAILURES.append("%s: the refusal does not say %r" % (label, n))
    # A refusal must not have written provenance into the manifest.
    m = manifest_of(search)
    if m["source_commit"] != "0" * 40:
        ok = False
        FAILURES.append("%s: the manifest was rewritten despite the refusal" % label)
    report(label, ok, rc, out)
    return ok


def report(label, ok, rc, out):
    print("  %-34s %s  (exit %d)" % (label, "OK" if ok else "*** FAILED", rc))
    if VERBOSE or not ok:
        for line in out.strip().splitlines():
            print("      | %s" % line)


def case_tag_named_main(tmp):
    def maker(t):
        core = make_core(t, "core-tag-main")
        # A TAG called `main`, plus a second commit it points at, so a
        # suffix-matching guard would happily vendor from it.
        git(core, "tag", "main", "HEAD")
        return core

    return expect_refusal(
        "tag named 'main'", tmp, maker, ["--ref", "main"],
        ["--ref 'main' resolves to refs/tags/main", "refs/remotes/origin/main"],
    )


def case_tag_shadowing_remote(tmp):
    def maker(t):
        core = make_core(t, "core-tag-shadow")
        # A tag literally named `origin/main`. Git's ref precedence puts
        # refs/tags/<name> BEFORE refs/remotes/<name>, so the short form
        # `origin/main` resolves to the TAG.
        git(core, "tag", "origin/main", "HEAD")
        return core

    return expect_refusal(
        "tag shadowing origin/main", tmp, maker, ["--ref", "origin/main"],
        ["resolves to refs/tags/origin/main", "refs/remotes/origin/main"],
    )


def case_fake_main_branch(tmp):
    def maker(t):
        core = make_core(t, "core-fake-main", poison=True)
        git(core, "branch", "fake/main", "HEAD")
        # refs/remotes/origin/main still points at the FIRST commit, so
        # fake/main is not an ancestor of it.
        return core

    return expect_refusal(
        "branch 'fake/main'", tmp, maker, ["--ref", "fake/main"],
        ["--ref 'fake/main' resolves to refs/heads/fake/main", "refs/remotes/origin/main"],
    )


def case_local_main_branch(tmp):
    def maker(t):
        return make_core(t, "core-local-main")

    # refs/heads/main exists; the remote-tracking ref is the only acceptable one.
    return expect_refusal(
        "local branch refs/heads/main", tmp, maker, ["--ref", "refs/heads/main"],
        ["resolves to refs/heads/main", "refs/remotes/origin/main"],
    )


def case_non_ancestor_commit(tmp):
    def maker(t):
        core = make_core(t, "core-non-ancestor", poison=True)
        return core

    search = make_search(tmp, "search-non-ancestor")
    core = maker(tmp)
    # HEAD is the poisoned second commit; refs/remotes/origin/main is the first.
    off_branch = git(core, "rev-parse", "HEAD")
    rc, out = vendor(search, "--core", core, "--commit", off_branch)
    ok = rc != 0 and "is NOT an ancestor of refs/remotes/origin/main" in out
    if not ok:
        FAILURES.append("non-ancestor --commit: exit %d, output did not name the ancestry refusal" % rc)
    if manifest_of(search)["source_commit"] != "0" * 40:
        ok = False
        FAILURES.append("non-ancestor --commit: the manifest was rewritten despite the refusal")
    report("non-ancestor --commit", ok, rc, out)
    return ok


def case_foreign_origin(tmp):
    def maker(t):
        return make_core(t, "core-foreign", remote_url="https://github.com/attacker/not-vizra-core.git")

    return expect_refusal(
        "foreign origin URL", tmp, maker, [],
        ["attacker/not-vizra-core", "not github.com/yegamble/vizra-core"],
    )


def case_foreign_origin_ssh(tmp):
    def maker(t):
        return make_core(t, "core-foreign-ssh", remote_url="git@github.com:attacker/vizra-core.git")

    return expect_refusal(
        "foreign origin (scp-like ssh)", tmp, maker, [],
        ["attacker/vizra-core", "not github.com/yegamble/vizra-core"],
    )


def case_foreign_origin_deep_path(tmp):
    # PR#3 VERIFY, FINDING 6: parse_remote_url took the LAST two path segments,
    # so this URL was read as yegamble/vizra-core and accepted.
    def maker(t):
        return make_core(
            t, "core-foreign-deep", remote_url="https://github.com/attacker/x/yegamble/vizra-core"
        )

    return expect_refusal(
        "foreign origin, 4-segment path", tmp, maker, [],
        ["attacker/x/yegamble/vizra-core", "not a recognised repository URL",
         "not github.com/yegamble/vizra-core"],
    )


# ------------------------------------------------ source_ref_tip is checked ---
#
# PR#3 VERIFY, FINDING 4: source_ref_tip was written by `vendor` and read by
# nothing — hand-edited to `refs/remotes/origin/evil`, to `main` or to 40 zeros,
# `--check`, `--check --core` and `make contract-drift` all stayed at exit 0.
# Each case vendors a clean tree, forges the field, and requires the named
# check to go red naming the field. The manifest's other fields are untouched,
# so nothing else can be what turned it red.


def forge_tip(search, value):
    path = os.path.join(search, "api", "CONTRACT-SOURCE.json")
    m = manifest_of(search)
    m["source_ref_tip"] = value
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(m, indent=2) + "\n")


def expect_forged_tip_red(label, tmp, core, forged, with_core, needles):
    search = make_search(tmp, "search-" + label.replace(" ", "-"))
    rc0, out0 = vendor(search, "--core", core)
    problems = []
    if rc0 != 0:
        problems.append("the clean vendor step itself failed (exit %d)" % rc0)
    # Control: the untouched manifest passes the same check that must go red.
    args = ["--check"] + (["--core", core] if with_core else [])
    rc1, out1 = vendor(search, *args)
    if rc1 != 0:
        problems.append("CONTROL: %s on the clean manifest exited %d" % (" ".join(args), rc1))
    forge_tip(search, forged)
    if manifest_of(search).get("source_ref_tip") != forged:
        problems.append("the forgery did not apply")
    rc2, out2 = vendor(search, *args)
    if rc2 == 0:
        problems.append("%s ACCEPTED a forged source_ref_tip %r" % (" ".join(args), forged))
    for n in needles:
        if n not in out2:
            problems.append("the refusal does not say %r" % n)
    ok = not problems
    FAILURES.extend("%s: %s" % (label, p) for p in problems)
    report(label, ok, rc2, "--- control ---\n" + out1 + "\n--- forged ---\n" + out2)
    return ok


def case_tip_not_a_sha(tmp):
    core = make_core(tmp, "core-tip-ref")
    return expect_forged_tip_red(
        "forged tip: a refname", tmp, core, "refs/remotes/origin/evil", False,
        ["source_ref_tip is 'refs/remotes/origin/evil'"],
    )


def case_tip_null_oid(tmp):
    core = make_core(tmp, "core-tip-null")
    return expect_forged_tip_red(
        "forged tip: 40 zeros", tmp, core, "0" * 40, False,
        ["source_ref_tip is '%s'" % ("0" * 40), "null object id"],
    )


def case_tip_not_a_commit(tmp):
    core = make_core(tmp, "core-tip-absent")
    forged = "deadbeef" * 5
    return expect_forged_tip_red(
        "forged tip: no such commit", tmp, core, forged, True,
        ["source_ref_tip %s is not a commit" % forged],
    )


def case_tip_off_the_ref(tmp):
    # poison=True leaves a second commit at HEAD that is NOT on origin/main.
    core = make_core(tmp, "core-tip-off-ref", poison=True)
    off = git(core, "rev-parse", "HEAD")
    return expect_forged_tip_red(
        "forged tip: a commit off the ref", tmp, core, off, True,
        ["source_ref_tip %s is NOT on refs/remotes/origin/main" % off],
    )


def case_tip_before_commit(tmp):
    core = make_core(tmp, "core-tip-before")
    first = git(core, "rev-parse", "HEAD")
    write(os.path.join(core, YAML_NAME), "# canonical contract\nopenapi: 3.0.3\n# second\n")
    git(core, "add", "-A")
    git(core, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "api: second")
    git(core, "update-ref", "refs/remotes/origin/main", git(core, "rev-parse", "HEAD"))
    # source_commit will be the SECOND commit; a tip at the first cannot contain it.
    return expect_forged_tip_red(
        "forged tip: older than the commit", tmp, core, first, True,
        ["is not contained in source_ref_tip %s" % first],
    )


def case_credential_in_url_is_redacted(tmp):
    """A remote URL can carry a token. It must never be echoed."""
    secret = "TOKENVALUE" + "1234567890"
    url = "https://x-access-token:%s@github.com/attacker/not-vizra-core.git" % secret
    search = make_search(tmp, "search-redact")
    core = make_core(tmp, "core-redact", remote_url=url)
    rc, out = vendor(search, "--core", core)
    ok = rc != 0 and secret not in out and "***@github.com" in out
    if not ok:
        FAILURES.append(
            "credential redaction: exit %d, secret present=%s" % (rc, secret in out)
        )
    report("userinfo redacted in output", ok, rc, out)
    return ok


def case_no_remote_tracking_ref(tmp):
    def maker(t):
        core = make_core(t, "core-no-remote-ref")
        git(core, "update-ref", "-d", "refs/remotes/origin/main")
        return core

    return expect_refusal(
        "no refs/remotes/origin/main", tmp, maker, [],
        ["refs/remotes/origin/main does not exist"],
    )


def case_shallow_clone(tmp):
    def maker(t):
        src = make_core(t, "core-shallow-src")
        # A second commit so there is history to truncate.
        write(os.path.join(src, YAML_NAME), "# canonical contract\nopenapi: 3.0.3\n# more\n")
        git(src, "add", "-A")
        git(src, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "api: second")
        git(src, "update-ref", "refs/remotes/origin/main", git(src, "rev-parse", "HEAD"))
        dst = os.path.join(t, "core-shallow")
        # file:// keeps this offline while still producing a real shallow clone.
        rc, out = run(["git", "clone", "-q", "--depth=1", "file://" + src, dst])
        if rc != 0:
            raise RuntimeError("could not build a shallow clone: %s" % out)
        git(dst, "remote", "set-url", "origin", CANONICAL_URL)
        git(dst, "update-ref", "refs/remotes/origin/main", git(dst, "rev-parse", "HEAD"))
        return dst

    return expect_refusal(
        "shallow clone", tmp, maker, [],
        ["is a SHALLOW clone", "fetch --unshallow"],
    )


def case_happy_path(tmp):
    search = make_search(tmp, "search-happy")
    core = make_core(tmp, "core-happy")
    want_commit = git(core, "rev-parse", "refs/remotes/origin/main")
    rc, out = vendor(search, "--core", core)
    m = manifest_of(search)
    problems = []
    if rc != 0:
        problems.append("exit %d" % rc)
    if m.get("source_ref") != "refs/remotes/origin/main":
        problems.append("source_ref = %r, want the FULL refname" % m.get("source_ref"))
    if m.get("source_ref_tip") != want_commit:
        problems.append("source_ref_tip = %r, want %r" % (m.get("source_ref_tip"), want_commit))
    if m.get("source_commit") != want_commit:
        problems.append("source_commit = %r, want %r" % (m.get("source_commit"), want_commit))
    if m.get("source_repository") != "yegamble/vizra-core":
        problems.append("source_repository = %r" % m.get("source_repository"))
    # The bytes must actually be core's, and the digests must describe them.
    for entry in m["files"]:
        path = os.path.join(search, entry["vendored_path"])
        if not os.path.exists(path):
            problems.append("%s not written" % entry["vendored_path"])
            continue
        import hashlib

        with open(path, "rb") as fh:
            raw = fh.read()
        if hashlib.sha256(raw).hexdigest() != entry["sha256"] or len(raw) != entry["bytes"]:
            problems.append("%s: manifest does not describe the bytes written" % entry["vendored_path"])
    # And --check must agree afterwards, with and without the core checkout —
    # so the source_ref_tip checks are shown NOT to fire on an honest manifest.
    rc2, out2 = vendor(search, "--check")
    if rc2 != 0:
        problems.append("--check on the freshly vendored tree exited %d" % rc2)
    rc3, out3 = vendor(search, "--check", "--core", core)
    if rc3 != 0:
        problems.append("--check --core on the freshly vendored tree exited %d" % rc3)
    out2 = out2 + "\n--- --check --core ---\n" + out3
    ok = not problems
    if not ok:
        FAILURES.extend("happy path: " + p for p in problems)
    report("happy path accepted", ok, rc, out + "\n--- --check ---\n" + out2)
    return ok


# ------------------------------------------- the second manifest: the engine ---
#
# Queue 2o (chair ruling 2026-09-23): the make-anchor engine is owned by core in
# scripts/makeanchor/ and will be vendored here with its own manifest,
# scripts/ANCHOR-SOURCE.json. These fixtures drive that manifest with SYNTHETIC
# bytes (ENGINE_FILES), so each refusal the engine manifest adds, and each one
# it shares with the contract, is shown firing for it by name.

ENGINE = ["--manifest", ANCHOR_MANIFEST]


def all_engine_entries():
    return [engine_entry(p) for p in sorted(ENGINE_FILES)]


def slug(label):
    return "".join(c if c.isalnum() else "-" for c in label)


def expect_engine_refusal(label, tmp, core, entries, needles):
    """Vendoring with the engine manifest must exit non-zero, name each needle,
    and write nothing: not the engine manifest, not the contract manifest, and
    no file under the engine directory."""
    search = make_search(tmp, "search-" + slug(label), entries)
    engine_before = raw_of(search, ANCHOR_MANIFEST)
    contract_before = raw_of(search, CONTRACT_MANIFEST)
    rc, out = vendor(search, *(ENGINE + ["--core", core]))
    problems = []
    if rc == 0:
        problems.append("expected a refusal, got exit 0")
    for n in needles:
        if n not in out:
            problems.append("the refusal does not say %r" % n)
    if raw_of(search, ANCHOR_MANIFEST) != engine_before:
        problems.append("the engine manifest was rewritten despite the refusal")
    if raw_of(search, CONTRACT_MANIFEST) != contract_before:
        problems.append("the contract manifest was touched by an engine run")
    if os.path.exists(os.path.join(search, ENGINE_DIR)):
        problems.append("files were written under %s despite the refusal" % ENGINE_DIR)
    ok = not problems
    FAILURES.extend("%s: %s" % (label, p) for p in problems)
    report(label, ok, rc, out)
    return ok


def vendored_engine(tmp, label, core):
    """A search tree whose engine manifest was vendored cleanly from `core`."""
    search = make_search(tmp, "search-" + slug(label), all_engine_entries())
    rc, out = vendor(search, *(ENGINE + ["--core", core]))
    if rc != 0:
        raise RuntimeError("the clean engine vendor step failed (exit %d):\n%s" % (rc, out))
    return search


def expect_check_red(label, search, args, mutate, needles):
    """`args` is green on the untouched tree, `mutate(search)` is applied, and
    the same command must then go red naming each needle."""
    problems = []
    rc1, out1 = vendor(search, *args)
    if rc1 != 0:
        problems.append("CONTROL: %s on the clean tree exited %d" % (" ".join(args), rc1))
    mutate(search)
    rc2, out2 = vendor(search, *args)
    if rc2 == 0:
        problems.append("%s accepted the %s" % (" ".join(args), label))
    for n in needles:
        if n not in out2:
            problems.append("the refusal does not say %r" % n)
    ok = not problems
    FAILURES.extend("%s: %s" % (label, p) for p in problems)
    report(label, ok, rc2, "--- control ---\n" + out1 + "\n--- mutated ---\n" + out2)
    return ok


def case_engine_happy_path(tmp):
    label = "engine: happy path"
    core = make_core(tmp, "core-engine-happy", engine=True)
    engine_commit = git(core, "rev-parse", "HEAD~1")  # the commit that wrote the engine files
    tip = git(core, "rev-parse", "refs/remotes/origin/main")  # a later commit touching api/ only
    search = make_search(tmp, "search-engine-happy", all_engine_entries())
    contract_before = raw_of(search, CONTRACT_MANIFEST)
    rc, out = vendor(search, *(ENGINE + ["--core", core]))
    problems = []
    if rc != 0:
        problems.append("exit %d" % rc)
    m = manifest_of(search, ANCHOR_MANIFEST)
    if m.get("source_commit") != engine_commit:
        problems.append("source_commit = %r, want %r: the last commit touching %s, not the last "
                        "commit touching api/ (%s)" % (m.get("source_commit"), engine_commit, ENGINE_DIR, tip))
    if m.get("source_ref_tip") != tip:
        problems.append("source_ref_tip = %r, want %r" % (m.get("source_ref_tip"), tip))
    if m.get("source_ref") != "refs/remotes/origin/main":
        problems.append("source_ref = %r, want the FULL refname" % m.get("source_ref"))
    import hashlib

    for entry in m.get("files", []):
        rel = entry["vendored_path"]
        if not os.path.isfile(os.path.join(search, rel)):
            problems.append("%s not written" % rel)
            continue
        raw = raw_of(search, rel)
        if raw != ENGINE_FILES[rel].encode("utf-8"):
            problems.append("%s: the bytes written are not core's" % rel)
        if hashlib.sha256(raw).hexdigest() != entry.get("sha256") or len(raw) != entry.get("bytes"):
            problems.append("%s: manifest does not describe the bytes written" % rel)
    if raw_of(search, CONTRACT_MANIFEST) != contract_before:
        problems.append("the contract manifest was touched by an engine run")
    for n in ("(last commit on that ref touching %s)" % ENGINE_DIR, "manifest          : %s" % ANCHOR_MANIFEST,
              "re-vendored %d file(s)" % len(ENGINE_FILES)):
        if n not in out:
            problems.append("the vendor transcript does not say %r" % n)
    rc2, out2 = vendor(search, *(ENGINE + ["--check"]))
    if rc2 != 0:
        problems.append("--check on the freshly vendored engine exited %d" % rc2)
    rc3, out3 = vendor(search, *(ENGINE + ["--check", "--core", core]))
    if rc3 != 0:
        problems.append("--check --core on the freshly vendored engine exited %d" % rc3)
    ok = not problems
    FAILURES.extend("%s: %s" % (label, p) for p in problems)
    report(label, ok, rc, out + "\n--- --check ---\n" + out2 + "\n--- --check --core ---\n" + out3)
    return ok


def case_engine_wrong_pathspec(tmp):
    # The api/-only commit on top of the engine commit carries the SAME engine
    # bytes, so only the pathspec rule can tell it is not the commit to pin.
    core = make_core(tmp, "core-engine-pathspec", engine=True)
    engine_commit = git(core, "rev-parse", "HEAD~1")
    api_commit = git(core, "rev-parse", "refs/remotes/origin/main")
    search = vendored_engine(tmp, "engine wrong pathspec", core)

    def forge(s):
        path = os.path.join(s, ANCHOR_MANIFEST)
        m = manifest_of(s, ANCHOR_MANIFEST)
        m["source_commit"] = api_commit
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(m, indent=2) + "\n")

    return expect_check_red(
        "engine: wrong pathspec", search, ENGINE + ["--check", "--core", core], forge,
        ["the manifest pins %s, but the current last %s commit on refs/remotes/origin/main is %s"
         % (api_commit, ENGINE_DIR, engine_commit)],
    )


def case_engine_file_outside_directory(tmp):
    core = make_core(tmp, "core-engine-outside", engine=True)
    return expect_engine_refusal(
        "engine: file outside the directory", tmp, core,
        all_engine_entries() + [engine_entry("scripts/other.py")],
        ["'scripts/other.py' is not inside %s" % ENGINE_DIR],
    )


def case_engine_digest_mismatch(tmp):
    core = make_core(tmp, "core-engine-digest", engine=True)
    search = vendored_engine(tmp, "engine digest mismatch", core)
    target = ENGINE_DIR + "gate.py"

    def edit(s):
        raw = raw_of(s, target)
        edited = raw.replace(b"GATE = 1", b"GATE = 2")
        if edited == raw:
            raise RuntimeError("the one-byte edit did not apply")
        with open(os.path.join(s, target), "wb") as fh:
            fh.write(edited)

    return expect_check_red(
        "engine: digest mismatch", search, ENGINE + ["--check"], edit,
        ["%s does not match its manifest" % target],
    )


def case_engine_below_minimum(tmp):
    core = make_core(tmp, "core-engine-minimum", engine=True)
    return expect_engine_refusal(
        "engine: below the minimum", tmp, core, all_engine_entries()[:ENGINE_MIN - 1],
        ["the manifest pins %d file(s); it must pin at least %d" % (ENGINE_MIN - 1, ENGINE_MIN)],
    )


def case_engine_duplicate_entry(tmp):
    core = make_core(tmp, "core-engine-duplicate", engine=True)
    entries = all_engine_entries()
    # As many entries as the minimum, but only two distinct files.
    entries = entries[:ENGINE_MIN - 1] + [engine_entry(entries[0]["source_path"])]
    return expect_engine_refusal(
        "engine: duplicate entry", tmp, core, entries,
        ["the manifest pins %r twice" % entries[0]["vendored_path"]],
    )


def case_engine_source_differs(tmp):
    core = make_core(tmp, "core-engine-differs", engine=True)
    entries = [e for e in all_engine_entries() if e["source_path"] != ENGINE_DIR + "gate.py"]
    entries.append(engine_entry(ENGINE_DIR + "gate.py", ENGINE_DIR + "gate2.py"))
    return expect_engine_refusal(
        "engine: source path differs", tmp, core, entries,
        ["source_path '%sgate.py' differs from vendored_path '%sgate2.py'" % (ENGINE_DIR, ENGINE_DIR)],
    )


def case_engine_shallow_clone(tmp):
    src = make_core(tmp, "core-engine-shallow-src", engine=True)
    dst = os.path.join(tmp, "core-engine-shallow")
    rc, out = run(["git", "clone", "-q", "--depth=1", "file://" + src, dst])
    if rc != 0:
        raise RuntimeError("could not build a shallow clone: %s" % out)
    git(dst, "remote", "set-url", "origin", CANONICAL_URL)
    git(dst, "update-ref", "refs/remotes/origin/main", git(dst, "rev-parse", "HEAD"))
    return expect_engine_refusal(
        "engine: shallow clone", tmp, dst, all_engine_entries(),
        ["is a SHALLOW clone", "fetch --unshallow"],
    )


def case_engine_unpinned_in_core(tmp):
    extra = ENGINE_DIR + "extra.py"
    core = make_core(tmp, "core-engine-unpinned", engine=True,
                     engine_extra={extra: "# synthetic fixture bytes: a file the manifest does not pin\n"})
    return expect_engine_refusal(
        "engine: core file not pinned", tmp, core, all_engine_entries(),
        ["holds %s, which the manifest does not pin" % extra],
    )


def case_engine_pinned_absent_in_core(tmp):
    core = make_core(tmp, "core-engine-absent", engine=True)
    absent = ENGINE_DIR + "absent.py"
    return expect_engine_refusal(
        "engine: pinned file absent in core", tmp, core,
        all_engine_entries() + [engine_entry(absent)],
        ["the manifest pins %s, which core does not hold" % absent],
    )


def case_engine_symlink_in_core(tmp):
    core = make_core(tmp, "core-engine-symlink", engine=True)
    link = ENGINE_DIR + "link.py"
    os.symlink("gate.py", os.path.join(core, link))
    git(core, "add", "-A")
    git(core, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "engine: a symlink")
    git(core, "update-ref", "refs/remotes/origin/main", git(core, "rev-parse", "HEAD"))
    return expect_engine_refusal(
        "engine: symlink in core", tmp, core, all_engine_entries() + [engine_entry(link)],
        ["%s at " % link, "is a blob with mode 120000, not a regular file"],
    )


def case_engine_unpinned_on_disk(tmp):
    core = make_core(tmp, "core-engine-disk", engine=True)
    search = vendored_engine(tmp, "engine unpinned on disk", core)
    # Python writes __pycache__ beside any module it imports; the control run
    # has one, and it must not be what turns the check red.
    cache = os.path.join(search, ENGINE_DIR, "__pycache__")
    os.makedirs(cache)
    write(os.path.join(cache, "gate.cpython-39.pyc"), "not really bytecode\n")
    planted = ENGINE_DIR + "planted.py"

    def plant(s):
        write(os.path.join(s, planted), "# an unpinned file planted in the vendored directory\n")

    return expect_check_red(
        "engine: unpinned file on disk", search, ENGINE + ["--check"], plant,
        ["%s is inside %s but the manifest does not pin it" % (planted, ENGINE_DIR)],
    )


def case_engine_symlink_on_disk(tmp):
    core = make_core(tmp, "core-engine-disk-link", engine=True)
    search = vendored_engine(tmp, "engine symlink on disk", core)
    link = ENGINE_DIR + "corpus/rows-link.json"

    def plant(s):
        os.symlink("rows.json", os.path.join(s, link))

    return expect_check_red(
        "engine: symlink on disk", search, ENGINE + ["--check"], plant,
        ["%s is a symlink inside %s" % (link, ENGINE_DIR)],
    )


def case_engine_symlinked_directory(tmp):
    core = make_core(tmp, "core-engine-disk-dirlink", engine=True)
    search = vendored_engine(tmp, "engine symlinked directory", core)

    def relink(s):
        real = os.path.join(s, ENGINE_DIR.rstrip("/"))
        moved = os.path.join(s, "elsewhere")
        os.rename(real, moved)
        os.symlink(moved, real)

    return expect_check_red(
        "engine: symlinked directory", search, ENGINE + ["--check"], relink,
        ["%s is a symlink" % ENGINE_DIR.rstrip("/")],
    )


def case_contract_below_minimum(tmp):
    # The minimum is per manifest: the contract's is 2, so ONE pinned file is
    # refused here while the engine manifest refuses two.
    label = "contract: below the minimum"
    search = make_search(tmp, "search-contract-minimum")
    m = manifest_of(search)
    m["files"] = m["files"][:1]
    with open(os.path.join(search, CONTRACT_MANIFEST), "w", encoding="utf-8") as fh:
        fh.write(json.dumps(m, indent=2) + "\n")
    before = raw_of(search, CONTRACT_MANIFEST)
    core = make_core(tmp, "core-contract-minimum")
    rc, out = vendor(search, "--core", core)
    problems = []
    if rc == 0:
        problems.append("expected a refusal, got exit 0")
    if "the manifest pins 1 file(s); it must pin at least 2" not in out:
        problems.append("the refusal does not name the contract's minimum of 2")
    if raw_of(search, CONTRACT_MANIFEST) != before:
        problems.append("the manifest was rewritten despite the refusal")
    ok = not problems
    FAILURES.extend("%s: %s" % (label, p) for p in problems)
    report(label, ok, rc, out)
    return ok


def case_unknown_manifest(tmp):
    label = "unknown --manifest"
    search = make_search(tmp, "search-unknown-manifest", all_engine_entries())
    before = {w: raw_of(search, w) for w in (CONTRACT_MANIFEST, ANCHOR_MANIFEST)}
    problems = []
    outs = []
    for bad in ("scripts/OTHER-SOURCE.json", "./" + CONTRACT_MANIFEST):
        rc, out = vendor(search, "--manifest", bad, "--check")
        outs.append(out)
        if rc == 0:
            problems.append("--manifest %s was accepted" % bad)
        if "invalid choice: %r" % bad not in out:
            problems.append("the refusal of --manifest %s does not say it is not a known manifest" % bad)
    for w, raw in before.items():
        if raw_of(search, w) != raw:
            problems.append("%s changed" % w)
    ok = not problems
    FAILURES.extend("%s: %s" % (label, p) for p in problems)
    report(label, ok, rc, "\n".join(outs))
    return ok


CASES = [
    case_tag_named_main,
    case_tag_shadowing_remote,
    case_fake_main_branch,
    case_local_main_branch,
    case_non_ancestor_commit,
    case_foreign_origin,
    case_foreign_origin_ssh,
    case_foreign_origin_deep_path,
    case_credential_in_url_is_redacted,
    case_no_remote_tracking_ref,
    case_shallow_clone,
    case_tip_not_a_sha,
    case_tip_null_oid,
    case_tip_not_a_commit,
    case_tip_off_the_ref,
    case_tip_before_commit,
    case_happy_path,
    case_engine_happy_path,
    case_engine_wrong_pathspec,
    case_engine_file_outside_directory,
    case_engine_digest_mismatch,
    case_engine_below_minimum,
    case_engine_duplicate_entry,
    case_engine_source_differs,
    case_engine_shallow_clone,
    case_engine_unpinned_in_core,
    case_engine_pinned_absent_in_core,
    case_engine_symlink_in_core,
    case_engine_unpinned_on_disk,
    case_engine_symlink_on_disk,
    case_engine_symlinked_directory,
    case_contract_below_minimum,
    case_unknown_manifest,
]

# A floor, in the idiom scripts/ci-required-guard.sh already uses: deleting a
# case from the list above must be a named failure, not a quietly shorter run.
EXPECTED_CASES = 33


def main():
    if len(CASES) != EXPECTED_CASES:
        sys.stderr.write(
            "vendor-contract-selftest: %d case(s) registered, the floor is %d. A refusal "
            "lost its fixture.\n" % (len(CASES), EXPECTED_CASES)
        )
        return 1
    print("vendor-contract-selftest: %d fixtures, no network" % len(CASES))
    tmp = tempfile.mkdtemp(prefix="vendor-contract-selftest-")
    try:
        for case in CASES:
            try:
                case(tmp)
            except Exception as exc:  # a fixture that cannot be built is a failure
                FAILURES.append("%s raised %s: %s" % (case.__name__, type(exc).__name__, exc))
                print("  %-34s *** ERROR %s" % (case.__name__, exc))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("")
    if FAILURES:
        for f in FAILURES:
            sys.stderr.write("vendor-contract-selftest: FAIL: %s\n" % f)
        sys.stderr.write("vendor-contract-selftest: %d failure(s)\n" % len(FAILURES))
        return 1
    print("vendor-contract-selftest: all %d fixtures behaved as documented" % len(CASES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
