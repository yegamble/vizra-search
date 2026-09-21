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


def make_core(tmp, name, *, remote_url=CANONICAL_URL, poison=False):
    """A throwaway 'vizra-core': a main branch, api/ files, remote-tracking ref."""
    core = os.path.join(tmp, name)
    os.makedirs(os.path.join(core, "api"))
    git_init(core)
    write(os.path.join(core, YAML_NAME), "# canonical contract\nopenapi: 3.0.3\n")
    write(
        os.path.join(core, JSON_NAME),
        json.dumps({"scheme": "v1", "key_utf8": "PLACEHOLDER-NOT-A-REAL-KEY", "vectors": []}, indent=2)
        + "\n",
    )
    git(core, "add", "-A")
    git(core, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "api: initial")
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


def make_search(tmp, name):
    """A throwaway repository root: scripts/vendor-contract.py + a manifest."""
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
    return search


def vendor(search, *args):
    return run([sys.executable, os.path.join(search, "scripts", "vendor-contract.py")] + list(args))


def manifest_of(search):
    with open(os.path.join(search, "api", "CONTRACT-SOURCE.json"), encoding="utf-8") as fh:
        return json.load(fh)


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
    # And --check must agree afterwards.
    rc2, out2 = vendor(search, "--check")
    if rc2 != 0:
        problems.append("--check on the freshly vendored tree exited %d" % rc2)
    ok = not problems
    if not ok:
        FAILURES.extend("happy path: " + p for p in problems)
    report("happy path accepted", ok, rc, out + "\n--- --check ---\n" + out2)
    return ok


CASES = [
    case_tag_named_main,
    case_tag_shadowing_remote,
    case_fake_main_branch,
    case_local_main_branch,
    case_non_ancestor_commit,
    case_foreign_origin,
    case_foreign_origin_ssh,
    case_credential_in_url_is_redacted,
    case_no_remote_tracking_ref,
    case_shallow_clone,
    case_happy_path,
]

# A floor, in the idiom scripts/ci-required-guard.sh already uses: deleting a
# case from the list above must be a named failure, not a quietly shorter run.
EXPECTED_CASES = 11


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
