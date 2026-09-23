# Evidence — CI gates cannot be silenced or pass vacuously (war-room queue 2g)

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
