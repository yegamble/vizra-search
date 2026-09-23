# Evidence — CI gates cannot be silenced or pass vacuously (war-room queue 2g)

## Fix round 1 (on top of 4476ad5): the control moved from grammar to digest

The chair's ruling on the vizra-security desk review retired the parse-time text scanner. make is now invoked
only on the bytes pinned in `.github/pinned-makefiles.yml`.

| File | What it shows |
|---|---|
| `demo-red-green-round1.txt` | `scripts/ci-hardening-demo.py` on the round-1 tree, all rows. The chair's demonstrations are 1k (one byte changed: make NOT invoked), 1l (an `include` line with an included file), 1m and 1m2 (the review's `.SECONDEXPANSION` and `.RECIPEPREFIX`, as plain directive lines: red because the bytes changed), 1m4 (`ci-required` is red on a Makefile edit without a pin update) and 1q (the digest gate disabled, so its meta-test goes red). The clean Makefile is the GREEN after every restore. |
| `make43-digest-gate-round1.txt` / `.sh` | GNU Make 4.3 (`ubuntu:24.04`): rows d1–d6 red with make NOT invoked, except d3. d3 is an included file with the Makefile re-pinned, so make runs and MAKEFILE_LIST is red. c0 and c1 are the clean Makefile, green. r1–r4 are reviewed-and-re-pinned bytes: make runs and the later readings refuse the known shapes. The runner env file stays empty in every row. |
| `demo-red-green-round1-first-attempt.txt` | The first round-1 run: 38/39. Row 1g went red, restored byte-identically, and was still red. The cause is a latent pre-existing flake in `ci-required-guard.sh`: `printf \| grep -q` under `set -o pipefail` fails when grep exits early and printf dies of SIGPIPE. It is fixed with a here-string. `pipefail-sigpipe-measurement.txt` measures the mechanism: exit 141, versus 0 with the here-string. |
| `go-meta-tests-verbose-round1.txt` | `go test -v ./scripts/ ./internal/config/` on the round-1 tree. |
| `make-ci-local-round1.txt` | `make ci` on the round-1 tree. |

No new exploit payloads were built for round 1. The only Makefile mutations are byte changes: a trailing space, a comment, an `include` line, and the two directive lines named in the review. The one pre-existing line from round 0 is kept only to show that the digest refuses it before make runs.

## Round 0 (4476ad5)

Produced by the builder before the first push, on darwin/arm64 (GNU Make 3.81, go1.26.2, Python 3.9.6 + PyYAML
6.0.3) and in an `ubuntu:24.04` container (GNU Make 4.3, Python 3.12.3). Host load averaged 150–450 (other
agents), so timings here are not CI timings. **None of this is CI evidence**; see the PR body for what CI did.

| File | What it shows |
|---|---|
| `demo-red-green.txt` | `scripts/ci-hardening-demo.py`, all 36 rows over items 1–7: for each, the real file's sha256 before and after the mutation, the command RED for the declared reason, a byte-identical restore, and GREEN again. **35/36 as declared.** Row 5c was red for the right reason (all three with-core `source_ref_tip` fixtures fired) but its declared `want` text was mis-quoted by the builder, so the harness refused to count it. |
| `demo-red-green-item5-rerun.txt` | item 5 re-run after correcting row 5c's `want` text only: 3/3. |
| `go-meta-tests-verbose.txt` | `go test -count=1 -v ./scripts/ ./internal/config/`: every evasion row of `scripts/scripts_test.go` with its digests and the first FAIL line of its red, the anchor's environment rows, the report rows, and the pinned direct body run against a planted failing and skipped test. |
| `make43-anchor-rows.txt` / `.sh` | GNU Make 4.3: the anchor's strict environment rows, the Makefile mutation rows (digest before/after, restored byte-identical, runner env file untouched), the parse-time side-effect hole REPRODUCED against the anchor as ported from vizra-core (rows p10/p11: exit 0 with `MAKEFLAGS=-i` written to the runner's env file; g10: a glob defeats variable stripping), the same refused with the pre-flight (m10–m13, h10), and what Make 4.3 does with the workflow-line evasions. |
| `make381-anchor-parse-side-effects-before.txt` | the same hole first measured on the host (3.81), before the pre-flight existed. |
| `make-ci-local.txt` | `make ci` on the branch tree, exit 0: 553 tests executed across 7 packages, 0 skips, every package at or above its floor; 17/17 vendoring fixtures. |
