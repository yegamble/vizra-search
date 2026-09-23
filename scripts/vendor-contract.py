#!/usr/bin/env python3
"""Vendor the canonical core<->search contract from vizra-core, and its manifest.

WHY THIS SCRIPT EXISTS
======================

`vizra-search` does not own `api/search-internal.openapi.yaml` or
`api/search-hmac-testvectors.json`. They are byte-identical copies of files in
`yegamble/vizra-core`, and `api/CONTRACT-SOURCE.json` records which ref and
commit they came from plus a sha256 and byte count for each.

PR #1 vendored by hand and recorded a commit that lived only on core's feature
branch; core squash-merged, deleted the branch, and the recorded provenance
pointed at an object no reviewer could fetch. This script exists so that cannot
happen again, and so a hand-typed digest — a checksum of someone's attention
rather than of the bytes — cannot happen either.

WHAT IT ACTUALLY ENFORCES
=========================

Each of these is a refusal with a negative fixture in
`scripts/vendor-contract-selftest.py` that shows it firing:

  * **The remote is the canonical repository.** `git remote get-url <remote>` is
    read from the checkout and normalised (https, ssh, scp-like and userinfo
    forms all reduce to `owner/repo`); anything that is not
    `github.com/yegamble/vizra-core` is refused. The transcript prints the URL
    that was **measured**, with any userinfo redacted — never a string copied
    out of the manifest this script is about to rewrite.
  * **The ref is the remote-tracking main of that remote, exactly.** The ref the
    caller names is resolved by git to a FULL refname
    (`rev-parse --symbolic-full-name --verify`) and must equal
    `refs/remotes/<remote>/main` character for character. A tag named `main`, a
    tag named `origin/main` shadowing the remote-tracking ref, a local
    `refs/heads/main`, and a branch `anything/main` all resolve to a different
    full refname and are refused, each named in the refusal. There is no
    suffix match and no escape hatch.
  * **The pinned commit is on that ref.** By default it is
    `git log -1 <full refname> -- api/`, which is an ancestor by construction;
    `--commit` lets a caller pin a different one, and that is checked with
    `merge-base --is-ancestor <commit> <full refname>` against the resolved ref
    rather than against anything the caller passed.
  * **The history is complete enough to decide that.** A shallow clone is
    refused, because `merge-base --is-ancestor` can answer "no" merely because
    the history was truncated.
  * **The manifest records what was resolved, not what was asked for.** It
    stores the full refname and the tip that refname pointed at. No string
    derived from the `--ref` argument is ever written; the previous version
    wrote `args.ref.split("/")[-1]`, which laundered `fake/main` into `main`.

WHAT IT CANNOT PROVE — read this before trusting it
===================================================

A local clone's remote URL and its refs are whatever the owner of that checkout
set them to. `git remote set-url` and `git update-ref refs/remotes/origin/main`
are one command each, and this script never fetches, so `refs/remotes/origin/main`
is only as fresh and as honest as the caller's clone. **This tool defends
against a mistake, not against someone who controls the checkout it is pointed
at.** It cannot and does not authenticate core's bytes.

The control for poisoned normative bytes is elsewhere and is real: the HMAC
vectors are *consumed* by this repository's suite — 5 ACCEPT and 24 REJECT
cases — so `make contract-drift` goes red on a tampered key, window or vector.
A poisoned **non-normative** field would not be caught by those tests. The
end-to-end answer remains a reviewer comparing the recorded commit against
`github.com/yegamble/vizra-core` themselves; this script makes that comparison
possible by recording an unambiguous, fetchable ref and commit.

USAGE
=====

  scripts/vendor-contract.py --core <path-to-a-vizra-core-checkout>
      Re-vendor from refs/remotes/origin/main. Writes both contract files and
      rewrites the manifest.

  scripts/vendor-contract.py --check
      Self-check, needs no core checkout: every vendored file must match the
      digest and byte count the manifest pins.

  scripts/vendor-contract.py --check --core <path>
      The same, plus: the manifest's source_commit must still be the commit this
      script would choose, and the vendored bytes must equal core's bytes.

  make vendor-contract CORE=<path>     make vendor-contract-check
  make vendor-contract-selftest        # the negative fixtures, no network

Options: --remote (default origin), --ref (default <remote>/main; must resolve
to refs/remotes/<remote>/main), --commit (pin a specific ancestor), --note
(replace the manifest's $provenance_note).

It never runs a command that could modify the core checkout: only `remote
get-url`, `rev-parse`, `for-each-ref`, `log`, `merge-base`, `cat-file` and `show`.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(REPO, "api", "CONTRACT-SOURCE.json")

# The one repository this contract may come from. `source_repository` in the
# manifest is asserted against this by internal/httpapi's manifest test too.
CANONICAL_HOST = "github.com"
CANONICAL_OWNER_REPO = "yegamble/vizra-core"
MIN_VENDORED_FILES = 2


def die(msg):
    sys.stderr.write("vendor-contract: %s\n" % msg)
    sys.exit(1)


def git(repo, *args):
    """Run a read-only git command in `repo`; die on failure. Returns bytes."""
    out, err, rc = git_raw(repo, *args)
    if rc != 0:
        die(
            "git %s failed in %s (exit %d)\n%s"
            % (" ".join(args), repo, rc, err.decode("utf-8", "replace").strip())
        )
    return out


def git_raw(repo, *args):
    """Run a read-only git command; return (stdout, stderr, returncode)."""
    proc = subprocess.Popen(
        ["git", "-C", repo] + list(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out, err = proc.communicate()
    return out, err, proc.returncode


def gits(repo, *args):
    """git(), decoded and stripped."""
    return git(repo, *args).decode("utf-8", "replace").strip()


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


# ------------------------------------------------------------ remote URLs ---

_SCP_LIKE = re.compile(r"^(?P<userinfo>[^/@]+@)?(?P<host>[^/:]+):(?P<path>.+)$")
_URL_LIKE = re.compile(
    r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://(?P<userinfo>[^/@]*@)?(?P<host>[^/:]*)(?::\d+)?/(?P<path>.*)$"
)


def redact_url(url):
    """Hide any userinfo before printing. A remote URL can carry a token."""
    return re.sub(r"(://)[^/@]*@", r"\1***@", re.sub(r"^[^/@]+@(?=[^/:]+:)", "***@", url))


def parse_remote_url(url):
    """Return (host, 'owner/repo') or (None, None) if it is not a hosted repo URL."""
    url = url.strip()
    m = _URL_LIKE.match(url)
    if m is None:
        m = _SCP_LIKE.match(url)
        if m is None or "://" in url:
            return None, None
    host = (m.group("host") or "").lower()
    path = m.group("path").strip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    parts = [p for p in path.split("/") if p]
    # EXACTLY two path segments. `parts[-2:]` accepted
    # https://github.com/attacker/x/yegamble/vizra-core as yegamble/vizra-core
    # (PR#3 VERIFY, FINDING 6). github.com serves a repository at owner/repo and
    # nowhere deeper, so anything else is not the canonical repository.
    if len(parts) != 2:
        return host or None, None
    return host, "/".join(parts)


def check_remote_is_canonical(core, remote):
    """Measure the checkout's remote URL and refuse a foreign repository."""
    out, err, rc = git_raw(core, "remote", "get-url", remote)
    if rc != 0:
        die(
            "the checkout %s has no remote %r (git remote get-url exit %d).\n"
            "  The source repository must be measured from the checkout, not assumed."
            % (core, remote, rc)
        )
    url = out.decode("utf-8", "replace").strip()
    shown = redact_url(url)
    host, owner_repo = parse_remote_url(url)
    if host != CANONICAL_HOST or (owner_repo or "").lower() != CANONICAL_OWNER_REPO:
        die(
            "remote %r of %s is %s\n"
            "  which is %s, not %s/%s.\n"
            "  This contract may only be vendored from the canonical repository."
            % (
                remote,
                core,
                shown,
                ("%s/%s" % (host, owner_repo)) if owner_repo else "not a recognised repository URL",
                CANONICAL_HOST,
                CANONICAL_OWNER_REPO,
            )
        )
    return shown, owner_repo


# -------------------------------------------------------------------- refs ---


def all_refs(core):
    """Every ref in the checkout: {full refname: (objecttype, objectname)}."""
    out = gits(core, "for-each-ref", "--format=%(refname)%09%(objecttype)%09%(objectname)")
    refs = {}
    for line in out.splitlines():
        fields = line.split("\t")
        if len(fields) == 3:
            refs[fields[0]] = (fields[1], fields[2])
    return refs


def candidates_for(ref):
    """git's documented short-name precedence (gitrevisions), in order.

    `rev-parse --symbolic-full-name` is not used for this: when a short name is
    ambiguous it reports an error instead of the ref it would have picked, which
    leaves a refusal unable to say WHAT it refused. Resolving the candidates
    here is deterministic, needs no network, and lets the refusal name both the
    winner and every other ref that matched.
    """
    if ref.startswith("refs/"):
        return [ref]
    return [
        "refs/%s" % ref,
        "refs/tags/%s" % ref,
        "refs/heads/%s" % ref,
        "refs/remotes/%s" % ref,
        "refs/remotes/%s/HEAD" % ref,
    ]


def resolve_ref(core, remote, ref):
    """Return (full_refname, tip). Accept ONLY refs/remotes/<remote>/main.

    A suffix test — what this script used to do — accepts a tag named `main`, a
    tag named `origin/main` shadowing the remote-tracking ref, and any branch
    `x/main`. This resolves to a full refname and compares character for
    character instead.
    """
    want = "refs/remotes/%s/main" % remote
    refs = all_refs(core)

    if want not in refs:
        die(
            "%s does not exist in %s.\n"
            "  This is the only ref this contract may be vendored from. If that checkout has\n"
            "  no remote-tracking refs, fetch %s in it first."
            % (want, core, remote)
        )
    kind, tip = refs[want]
    if kind != "commit":
        die("%s is a %s object, not a commit" % (want, kind))

    matches = [c for c in candidates_for(ref) if c in refs]
    if not matches:
        die("--ref %r does not name any ref in %s" % (ref, core))
    resolved = matches[0]
    if resolved != want:
        also = ""
        if len(matches) > 1:
            also = "\n  (%r is ambiguous; it also matches %s)" % (ref, ", ".join(matches[1:]))
        die(
            "--ref %r resolves to %s, not %s.%s\n"
            "  The contract is vendored from the canonical remote-tracking branch and nothing\n"
            "  else: not a tag, not a local branch, not a branch whose name merely ends in\n"
            "  'main'. A ref that a squash-merge — or its owner — can delete is not provenance."
            % (ref, resolved, want, also)
        )
    return want, tip


def refuse_shallow(core):
    """A truncated history makes --is-ancestor answer 'no' for the wrong reason."""
    out, _, rc = git_raw(core, "rev-parse", "--is-shallow-repository")
    if rc == 0 and out.decode().strip() == "true":
        die(
            "%s is a SHALLOW clone.\n"
            "  Ancestry cannot be decided against a truncated history: merge-base\n"
            "  --is-ancestor would answer 'no' for commits that really are on the branch.\n"
            "  Run `git fetch --unshallow` in that checkout." % core
        )


def choose_commit(core, full_ref, explicit):
    """Return the commit to pin, having proved it is on `full_ref`."""
    if explicit:
        out, err, rc = git_raw(core, "rev-parse", "--verify", "%s^{commit}" % explicit)
        if rc != 0:
            die("--commit %r is not a commit in %s" % (explicit, core))
        commit = out.decode().strip()
    else:
        commit = gits(core, "log", "-1", "--format=%H", full_ref, "--", "api/")
        if len(commit) != 40:
            die("could not find a commit on %s that touches api/ in %s" % (full_ref, core))

    # Checked against the RESOLVED ref, not against anything the caller passed.
    _, _, rc = git_raw(core, "merge-base", "--is-ancestor", commit, full_ref)
    if rc != 0:
        die(
            "commit %s is NOT an ancestor of %s.\n"
            "  A manifest must pin a commit that is actually on core's default branch;\n"
            "  pinning one that is not is the PR #1 defect this script exists to prevent."
            % (commit, full_ref)
        )
    return commit


# ---------------------------------------------------------------- manifest ---


def load_manifest():
    with open(MANIFEST, "rb") as fh:
        raw = fh.read()
    try:
        m = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        die("%s is not valid JSON: %s" % (MANIFEST, exc))
    if m.get("source_repository") != CANONICAL_OWNER_REPO:
        die(
            "the manifest names source_repository %r; %s owns this contract "
            "(ADR-002, Q-001)" % (m.get("source_repository"), CANONICAL_OWNER_REPO)
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
        vendored = entry["vendored_path"]
        if os.path.isabs(vendored) or os.path.normpath(vendored) != vendored or vendored.startswith(".."):
            die("manifest entry %r is not a plain relative path inside the repository" % vendored)
    return m


def insert_after(mapping, anchor, key, value):
    """Return a copy of `mapping` with `key` placed immediately after `anchor`."""
    out = {}
    placed = False
    for k, v in mapping.items():
        if k == key:
            continue
        out[k] = v
        if k == anchor:
            out[key] = value
            placed = True
    if not placed:
        out[key] = value
    return out


def write_manifest(m):
    with open(MANIFEST, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(m, indent=2, ensure_ascii=False) + "\n")


def read_from_core(core, commit, path):
    raw = git(core, "show", "%s:%s" % (commit, path))
    if not raw:
        die("%s is empty at %s in %s" % (path, commit, core))
    return raw


# ------------------------------------------------------------------ vendor ---


def vendor(args):
    m = load_manifest()
    core = os.path.abspath(args.core)
    if not os.path.isdir(os.path.join(core, ".git")) and not os.path.isfile(os.path.join(core, ".git")):
        die("%s is not a git checkout" % core)

    url_shown, owner_repo = check_remote_is_canonical(core, args.remote)
    refuse_shallow(core)
    full_ref, tip = resolve_ref(core, args.remote, args.ref)
    commit = choose_commit(core, full_ref, args.commit)

    print("core checkout     : %s" % core)
    print("remote %-11s: %s   [measured: git remote get-url]" % (args.remote, url_shown))
    print("  -> repository   : %s" % owner_repo)
    print("resolved ref      : %s   [--ref %s]" % (full_ref, args.ref))
    print("  -> tip          : %s" % tip)
    print("pinned commit     : %s%s" % (commit, "" if args.commit else "   (last commit on that ref touching api/)"))
    print("subject           : %s" % gits(core, "log", "-1", "--format=%s", commit))
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

    # What was RESOLVED, never a string derived from the argument.
    m["source_repository"] = owner_repo
    m["source_ref"] = full_ref
    m["source_commit"] = commit
    m["vendored_at"] = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    if args.note:
        m["$provenance_note"] = list(args.note)
    # Keep the tip beside the ref it belongs to rather than appended at the end,
    # so the provenance block reads as one thing.
    m = insert_after(m, "source_ref", "source_ref_tip", tip)
    write_manifest(m)

    print("")
    print("manifest          : %s" % os.path.relpath(MANIFEST, REPO))
    print("  source_repository : %s" % m["source_repository"])
    print("  source_ref        : %s" % m["source_ref"])
    print("  source_ref_tip    : %s" % m["source_ref_tip"])
    print("  source_commit     : %s" % m["source_commit"])
    print("  vendored_at       : %s" % m["vendored_at"])
    print("")
    if changed:
        print("re-vendored %d file(s): %s" % (len(changed), ", ".join(changed)))
    else:
        print("no vendored file changed; only the manifest's provenance was refreshed")
    return 0


# ------------------------------------------------------------------- check ---


def check(args):
    m = load_manifest()
    problems = []

    if len(m.get("source_commit") or "") != 40:
        problems.append(
            "source_commit is %r; a full 40-character SHA is required so the consumed "
            "version is unambiguous" % m.get("source_commit")
        )
    # source_ref_tip: the tip the resolved ref pointed at when this was vendored.
    # It was written and never read, so a hand-edit to anything at all left
    # every check green (PR#3 VERIFY, FINDING 4). Without a core checkout it
    # can still be held to its SHAPE: a full 40-character lowercase SHA that is
    # not the null object id.
    recorded_tip = m.get("source_ref_tip")
    if not isinstance(recorded_tip, str) or not re.fullmatch(r"[0-9a-f]{40}", recorded_tip) \
            or recorded_tip == "0" * 40:
        problems.append(
            "source_ref_tip is %r; it must be the full 40-character lowercase SHA the resolved ref "
            "pointed at when the files were vendored (and never the null object id)" % (recorded_tip,)
        )
    recorded_ref = m.get("source_ref") or ""
    if not recorded_ref.startswith("refs/remotes/"):
        problems.append(
            "source_ref is %r; it must be the FULL refname that was resolved "
            "(refs/remotes/<remote>/main), not a short name a caller could have laundered"
            % recorded_ref
        )

    print("manifest source_repository : %s" % m.get("source_repository"))
    print("manifest source_ref        : %s" % m.get("source_ref"))
    print("manifest source_ref_tip    : %s" % m.get("source_ref_tip"))
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
        if not os.path.isdir(os.path.join(core, ".git")) and not os.path.isfile(os.path.join(core, ".git")):
            die("%s is not a git checkout" % core)
        url_shown, owner_repo = check_remote_is_canonical(core, args.remote)
        refuse_shallow(core)
        full_ref, tip = resolve_ref(core, args.remote, args.ref)
        commit = choose_commit(core, full_ref, args.commit)
        print("")
        print("core remote %-7s: %s   [measured]" % (args.remote, url_shown))
        print("resolved ref       : %s (tip %s)" % (full_ref, tip))
        print("commit this script would pin : %s" % commit)
        if full_ref != recorded_ref:
            problems.append(
                "the manifest records source_ref %r, but this checkout resolves %r"
                % (recorded_ref, full_ref)
            )
        # With the checkout in hand the recorded tip is checked against what it
        # CLAIMS to be — a commit that was the tip of this ref at vendoring
        # time: it must exist, be on the ref today (a remote-tracking main only
        # moves forward), and contain the pinned source_commit. A tip that has
        # merely moved on since is NOT a failure here — that is staleness, and
        # the api/-commit comparison below is what says "re-vendor".
        if isinstance(recorded_tip, str) and re.fullmatch(r"[0-9a-f]{40}", recorded_tip):
            _, _, rc_obj = git_raw(core, "cat-file", "-e", recorded_tip + "^{commit}")
            if rc_obj != 0:
                problems.append(
                    "source_ref_tip %s is not a commit in %s at all — the manifest names a tip "
                    "that never existed there" % (recorded_tip, core)
                )
            else:
                _, _, rc_on = git_raw(core, "merge-base", "--is-ancestor", recorded_tip, full_ref)
                if rc_on != 0:
                    problems.append(
                        "source_ref_tip %s is NOT on %s (current tip %s): it was never the tip of the "
                        "ref this manifest records" % (recorded_tip, full_ref, tip)
                    )
                sc = m.get("source_commit") or ""
                _, _, rc_sc = git_raw(core, "merge-base", "--is-ancestor", sc, recorded_tip)
                if rc_sc != 0:
                    problems.append(
                        "source_commit %s is not contained in source_ref_tip %s: the pinned commit "
                        "could not have been reached from the tip the manifest says it came from"
                        % (sc, recorded_tip)
                    )
            if recorded_tip != tip:
                print("note: source_ref_tip %s is behind the current tip %s of %s (staleness, "
                      "not forgery — see the api/ commit check)" % (recorded_tip[:12], tip[:12], full_ref))
        if commit != m.get("source_commit"):
            problems.append(
                "the manifest pins %s, but the current last api/ commit on %s is %s — re-vendor"
                % (m.get("source_commit"), full_ref, commit)
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
    ap.add_argument("--remote", default="origin", help="remote of that checkout (default origin)")
    ap.add_argument(
        "--ref",
        default=None,
        help="ref to vendor from; must resolve to refs/remotes/<remote>/main (default <remote>/main)",
    )
    ap.add_argument(
        "--commit",
        default=None,
        help="pin this commit instead of the last api/ commit; must be an ancestor of that ref",
    )
    ap.add_argument(
        "--note",
        action="append",
        help="replace the manifest's $provenance_note with these lines (repeatable)",
    )
    ap.add_argument("--check", action="store_true", help="verify instead of writing")
    args = ap.parse_args()
    if args.ref is None:
        args.ref = "%s/main" % args.remote

    if args.check:
        return check(args)
    if not args.core:
        ap.error("--core <path-to-vizra-core> is required to vendor (or set VIZRA_CORE)")
    return vendor(args)


if __name__ == "__main__":
    sys.exit(main())
