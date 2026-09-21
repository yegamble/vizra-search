#!/usr/bin/env python3
"""Vendor the canonical core<->search contract from vizra-core, and its manifest.

WHY THIS SCRIPT EXISTS
======================

`vizra-search` does not own `api/search-internal.openapi.yaml` or
`api/search-hmac-testvectors.json`. They are byte-identical copies of files in
`yegamble/vizra-core`, and `api/CONTRACT-SOURCE.json` records which commit they
came from plus a sha256 and byte count for each.

Until now there was no command to do that. PR #1 and PR #2 both vendored by
hand — `git show <sha>:api/<file> > api/<file>`, then a human edited the digests
into the manifest. Two things went wrong that way, and both are on the record:

  * PR #1 recorded a commit on core's FEATURE BRANCH. Core squash-merged and
    deleted the branch, so the recorded provenance pointed at an object no
    reviewer could fetch.
  * The manifest is only as good as the hand-typed digest in it. A manifest
    whose digests were transcribed rather than computed from the bytes just
    written is a checksum of someone's attention.

So: this script is the only writer of the three files. It resolves the source
commit itself, refuses one that is not on core's default branch, reads the bytes
out of git (never out of core's working tree, which may be dirty or mid-edit by
another author), and computes every digest FROM THE BYTES IT JUST WROTE.

USAGE
=====

  scripts/vendor-contract.py --core <path-to-a-vizra-core-checkout> [--ref origin/main]
      Re-vendor. Writes the two contract files and rewrites the manifest.

  scripts/vendor-contract.py --check
      Self-check, needs no core checkout: every vendored file must match the
      digest and byte count the manifest pins, and the manifest must be
      well-formed. Non-zero exit on any mismatch.

  scripts/vendor-contract.py --check --core <path> [--ref origin/main]
      The same, plus: the manifest's source_commit must still be the commit
      this script would choose, and the vendored bytes must equal core's bytes
      at that commit.

  make vendor-contract CORE=<path>      # the same thing, as a lane
  make vendor-contract-check

WHAT IT REFUSES
===============

  * a source commit that is not an ancestor of the named branch tip — the
    failure mode PR #1 shipped;
  * a `--ref` that is not a `main` branch, unless `--allow-any-ref` is given,
    because the manifest declares `source_ref: main` and a pin on anything a
    merge can delete is not provenance;
  * a manifest that pins fewer than two files, or pins a path that differs
    between `source_path` and `vendored_path`;
  * a file that is empty, or whose written bytes do not read back identically.

It never runs a command in the core checkout that could modify it: only
`git rev-parse`, `git log`, `git merge-base` and `git show`, all read-only.
"""

import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(REPO, "api", "CONTRACT-SOURCE.json")
EXPECTED_SOURCE_REPOSITORY = "yegamble/vizra-core"
MIN_VENDORED_FILES = 2


def die(msg):
    sys.stderr.write("vendor-contract: %s\n" % msg)
    sys.exit(1)


def git(repo, *args):
    """Run a read-only git command in `repo` and return stdout as bytes."""
    proc = subprocess.Popen(
        ["git", "-C", repo] + list(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out, err = proc.communicate()
    if proc.returncode != 0:
        die(
            "git %s failed in %s (exit %d)\n%s"
            % (" ".join(args), repo, proc.returncode, err.decode("utf-8", "replace").strip())
        )
    return out


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def load_manifest():
    with open(MANIFEST, "rb") as fh:
        raw = fh.read()
    try:
        m = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        die("%s is not valid JSON: %s" % (MANIFEST, exc))
    if m.get("source_repository") != EXPECTED_SOURCE_REPOSITORY:
        die(
            "the manifest names source_repository %r; vizra-core owns this contract "
            "(ADR-002, Q-001)" % m.get("source_repository")
        )
    files = m.get("files") or []
    if len(files) < MIN_VENDORED_FILES:
        die(
            "the manifest pins %d file(s); it must pin at least %d, or an unpinned file "
            "could be edited in place with CI green" % (len(files), MIN_VENDORED_FILES)
        )
    for entry in files:
        for key in ("source_path", "vendored_path", "role"):
            if not str(entry.get(key) or "").strip():
                die("a manifest entry is missing %s: %r" % (key, entry))
        if entry["source_path"] != entry["vendored_path"]:
            die(
                "manifest entry %r: source_path %r differs from vendored_path %r; a "
                "vendored copy must sit at the same path as in core"
                % (entry["vendored_path"], entry["source_path"], entry["vendored_path"])
            )
    return m


def write_manifest(m):
    text = json.dumps(m, indent=2, ensure_ascii=False) + "\n"
    with open(MANIFEST, "w", encoding="utf-8") as fh:
        fh.write(text)


def resolve_ref(core, ref, allow_any_ref):
    """Return (branch_tip, api_commit) — both full 40-char SHAs."""
    short = ref.split("/")[-1]
    if short != "main" and not allow_any_ref:
        die(
            "--ref %r is not a main branch. The manifest declares source_ref 'main', and a "
            "commit reachable only from a branch that a squash-merge deletes is not "
            "provenance — that is the defect PR #1 shipped. Pass --allow-any-ref only if "
            "you also change source_ref, and expect a reviewer to ask why." % ref
        )
    tip = git(core, "rev-parse", "%s^{commit}" % ref).decode().strip()

    # The commit to pin is the last one ON THAT BRANCH that touched api/. Pinning
    # the branch tip instead would churn the manifest on every unrelated core
    # commit, and pinning anything else risks pinning a commit off the branch.
    api_commit = git(core, "log", "-1", "--format=%H", ref, "--", "api/").decode().strip()
    if len(api_commit) != 40:
        die("could not find a commit on %s that touches api/ in %s" % (ref, core))

    # Belt and braces: the chosen commit must be an ancestor of (or equal to) the
    # branch tip. `git log <ref>` already guarantees it; this check is what makes
    # the guarantee visible in a transcript, and it also covers --commit.
    proc = subprocess.Popen(
        ["git", "-C", core, "merge-base", "--is-ancestor", api_commit, tip],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    proc.communicate()
    if proc.returncode != 0:
        die(
            "commit %s is NOT an ancestor of %s (%s). A manifest must pin a commit that "
            "is on core's default branch." % (api_commit, ref, tip)
        )
    return tip, api_commit


def read_from_core(core, commit, path):
    raw = git(core, "show", "%s:%s" % (commit, path))
    if not raw:
        die("%s is empty at %s in %s" % (path, commit, core))
    return raw


def vendor(args):
    m = load_manifest()
    core = os.path.abspath(args.core)
    if not os.path.isdir(os.path.join(core, ".git")):
        die("%s is not a git checkout" % core)

    tip, commit = resolve_ref(core, args.ref, args.allow_any_ref)
    print("source repository : %s" % m["source_repository"])
    print("source ref        : %s (tip %s)" % (args.ref, tip))
    print("source commit     : %s   <- pinned (last commit on %s touching api/)" % (commit, args.ref))
    print("subject           : %s" % git(core, "log", "-1", "--format=%s", commit).decode().strip())
    print("")

    changed = []
    for entry in m["files"]:
        path = entry["vendored_path"]
        dest = os.path.join(REPO, path)
        before = None
        if os.path.exists(dest):
            with open(dest, "rb") as fh:
                before = fh.read()

        raw = read_from_core(core, commit, entry["source_path"])
        with open(dest, "wb") as fh:
            fh.write(raw)

        # Read it BACK and digest what is on disk, not what we think we wrote.
        with open(dest, "rb") as fh:
            written = fh.read()
        if written != raw:
            die("%s did not read back as written" % path)

        entry["sha256"] = sha256(written)
        entry["bytes"] = len(written)

        state = "unchanged"
        if before is None:
            state = "NEW"
        elif before != written:
            state = "UPDATED  (was %s, %d bytes)" % (sha256(before), len(before))
            changed.append(path)
        print("%-34s sha256=%s bytes=%-6d %s" % (path, entry["sha256"], entry["bytes"], state))

    m["source_commit"] = commit
    m["source_ref"] = args.ref.split("/")[-1]
    m["vendored_at"] = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    if args.note:
        m["$provenance_note"] = list(args.note)
    write_manifest(m)

    print("")
    print("manifest          : %s" % os.path.relpath(MANIFEST, REPO))
    print("  source_commit   : %s" % m["source_commit"])
    print("  source_ref      : %s" % m["source_ref"])
    print("  vendored_at     : %s" % m["vendored_at"])
    print("")
    if changed:
        print("re-vendored %d file(s): %s" % (len(changed), ", ".join(changed)))
    else:
        print("no vendored file changed; only the manifest's pin was refreshed")
    return 0


def check(args):
    m = load_manifest()
    problems = []

    if len(m.get("source_commit") or "") != 40:
        problems.append(
            "source_commit is %r; a full 40-character SHA is required so the consumed "
            "version is unambiguous" % m.get("source_commit")
        )

    print("manifest source_repository : %s" % m.get("source_repository"))
    print("manifest source_ref        : %s" % m.get("source_ref"))
    print("manifest source_commit     : %s" % m.get("source_commit"))
    print("")

    for entry in m["files"]:
        path = entry["vendored_path"]
        dest = os.path.join(REPO, path)
        if not os.path.exists(dest):
            problems.append("%s is pinned by the manifest but does not exist" % path)
            continue
        with open(dest, "rb") as fh:
            raw = fh.read()
        got, want = sha256(raw), entry.get("sha256")
        ok = got == want and len(raw) == entry.get("bytes")
        print("%-34s sha256=%s bytes=%-6d %s" % (path, got, len(raw), "OK" if ok else "MISMATCH"))
        if got != want:
            problems.append(
                "%s does not match its manifest\n  manifest sha256: %s\n  file sha256:     %s"
                % (path, want, got)
            )
        if len(raw) != entry.get("bytes"):
            problems.append(
                "%s is %d bytes, the manifest says %s" % (path, len(raw), entry.get("bytes"))
            )

    if args.core:
        core = os.path.abspath(args.core)
        if not os.path.isdir(os.path.join(core, ".git")):
            die("%s is not a git checkout" % core)
        tip, commit = resolve_ref(core, args.ref, args.allow_any_ref)
        print("")
        print("core %s tip              : %s" % (args.ref, tip))
        print("core commit this script would pin : %s" % commit)
        if commit != m.get("source_commit"):
            problems.append(
                "the manifest pins %s, but the current last api/ commit on %s is %s — "
                "re-vendor" % (m.get("source_commit"), args.ref, commit)
            )
        for entry in m["files"]:
            raw = read_from_core(core, m["source_commit"], entry["source_path"])
            if sha256(raw) != entry.get("sha256"):
                problems.append(
                    "%s: core@%s has sha256 %s, the manifest pins %s"
                    % (entry["source_path"], m["source_commit"][:7], sha256(raw), entry.get("sha256"))
                )

    print("")
    if problems:
        for p in problems:
            sys.stderr.write("vendor-contract: FAIL: %s\n" % p)
        sys.stderr.write(
            "vendor-contract: %d problem(s). This repository does not own these files; "
            "re-vendor with `make vendor-contract CORE=<path>` instead of editing them.\n"
            % len(problems)
        )
        return 1
    print("vendor-contract: OK — every vendored file matches the manifest%s."
          % (" and core's bytes" if args.core else ""))
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Vendor the canonical core<->search contract from vizra-core.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--core",
        default=os.environ.get("VIZRA_CORE"),
        help="path to a vizra-core checkout (or set VIZRA_CORE). Read-only.",
    )
    ap.add_argument("--ref", default="origin/main", help="branch to vendor from (default origin/main)")
    ap.add_argument(
        "--allow-any-ref",
        action="store_true",
        help="permit a --ref that is not a main branch (you must also justify source_ref)",
    )
    ap.add_argument(
        "--note",
        action="append",
        help="replace the manifest's $provenance_note with these lines (repeatable)",
    )
    ap.add_argument("--check", action="store_true", help="verify instead of writing")
    args = ap.parse_args()

    if args.check:
        return check(args)
    if not args.core:
        ap.error("--core <path-to-vizra-core> is required to vendor (or set VIZRA_CORE)")
    return vendor(args)


if __name__ == "__main__":
    sys.exit(main())
