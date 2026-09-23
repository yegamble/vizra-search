# Evidence — CI gates cannot be silenced or pass vacuously (war-room queue 2g)

## Closing slice, fix round 2 (on top of 888a51b): the Makefile grammar is an allowlist

Input: the re-verification at 888a51b, which returned FAIL with FINDINGs 9–11 REQUIRED and 12–13 SHOULD. Every
one of them came from calling the committed functions on inert strings. The chair's ruling was to stop denylisting
make's grammar and allowlist it, default-deny per line, which is how the pinned workflow steps already work.
`makegate.grammar_problems` now runs before make, for every caller and in ci-required-guard. Every logical line of
every pinned makefile must be exactly one of:
- blank, or a comment;
- `NAME := | ?= | = value`, where the value uses only `$$`, `$(NAME)`/`${NAME}` and `$(shell …)`;
- `.PHONY: names`;
- a single-target rule line with literal prerequisites;
- a TAB recipe line of a rule, using only `$$` and `$(NAME)`/`${NAME}`, with `RECIPE_FUNCTIONS` empty.

Anything else is refused with its line number. The real Makefile passes unchanged: 133 blank or comment lines,
15 assignments, 17 `.PHONY`, 17 rules and 24 recipe lines. The older by-name checks stay, as a more specific
second diagnosis.

Consequences, all stated in AGENTS.md:
- **Includes.** The grammar refuses `include`. `TestTheRemakeProbeCoversEveryPinnedInclude` now asserts that a
  pinned include is refused before make and stays byte-identical beside a newer `inc.mk.sh`. Its old control,
  that a pinned include passes, is intentionally red now.
- **Conditionals.** Conditionals cannot be written, so the round-1 conditional stepping in the anchor's recipe
  reader was removed, together with demo row R08 that mutated it. The reading row it served, "- prefix inside a
  conditional within the test recipe", moved to the before-make rows, where it is refused with 0 make processes.
  The round-1 README line "the recipe reader steps over conditional directives" is superseded.
- **M-4 test.** It now plants the reference forms the grammar allows: `$(V)`, `${V}`, and a read before a later
  `:=`. `$V`, `$(V:a=b)`, `$(origin V)`, `$(value V)` and `ifdef V` are before-make grammar rows instead.
- **Lane test.** `internal/httpapi/lane_selection_test.go`'s `TestTheLaneGuardRefusesAFlagFromAnIncludedMakefile`
  used `include drift.mk` to carry `-run`. It now asserts that the include is refused by the grammar before make
  ("the `include` directive", "make was NOT invoked"), no longer "carries -run". A `-run` carried by a variable in
  the Makefile itself is still a "carries -run" row in `TestTheLaneGuardRefusesEveryKnownBypass`.
- **FINDING 13.** The sentence now says what holds: the grammar leaves one environment read the anchor does not
  refuse, an immediate `:=` value referencing a name assigned only later. The lane's own pinned `make` step is
  not a gate process and would receive such a name. Today's Makefile has no such read.

| File | What it shows |
|---|---|
| `closing/round2/new-tests-at-888a51b-BEFORE.txt` | This round's tests against 888a51b's UNMODIFIED `makegate.py` and `make-integrity-guard.py`. All 31 new grammar rows FAIL. **24 were accepted outright** (exit 0): F9 ×3, F10, F11 private/override/undefine, the conditional within a recipe, `$V`, `$(V:a=b)`, `$(origin)`, `$(value)`, `ifdef`, a function in a value, `$X` and `$(shell)` in a recipe, `+=`, a conditional, `::`, a pattern rule, `define`, `export` and `vpath`. **7 were red, but under another check.** `include` and `load` were refused before make by the read-set check. `#` inside `$(shell)`, F12, a TAB line outside a rule and a second colon were caught only because `make -q` itself failed, so one make process had started. `.SILENT` was caught only after make ran, by the resolver. The include test and the real-Makefile grammar test also FAIL. |
| `closing/round2/demo-red-green-round2.txt` | `scripts/ci-hardening-demo.py`, every row: exit 0, **75/75**. The first full run (`demo-red-green-round2-first-attempt.txt`, 73/75) had R01 and R04 NOT red: the grammar now also refuses those shapes, with messages holding the same words, so removing only the named check was masked. Both rows were redefined to remove both layers and are red again. R08 was removed with the conditional-stepping code it mutated. G1–G6 are this round's rows. G1: the grammar check removed, so the F9 row goes red. G2: the same removal, so a pinned include reaches make again. G3: the recipe `$` check removed. G4: the value `$` check removed, so F12 goes red. G5: the TAB-outside-a-rule check removed. G6 is a control: with `?=` removed from the grammar, the real Makefile no longer fits. Each goes red for its declared reason and green on a byte-identical restore. |
| `closing/round2/go-meta-tests-verbose-round2.txt` | `go test -count=1 -v ./scripts/ ./internal/httpapi/`: exit 0, 479 `--- PASS`, 0 FAIL, 0 SKIP. |
| `closing/round2/make-ci-local-round2.txt` | `make ci`: exit 0, 720 tests across 7 packages, 0 skips, every package at or above its floor; contract-drift 365; vendor selftest 17/17. |
| `closing/round2/guards-round2.txt` | `ci-required-guard.sh`, `make-integrity-guard.sh --workflow` and `vendor-contract.py --check`: all exit 0 (make ran 21 times in the anchor). |

Host: darwin/arm64, go1.27.1 (printed from inside each worktree), GNU Make 3.81, Python 3.9.6. Nothing ran on GNU
Make 4.3. Live make behaviour of the refused lines was not measured, because no hostile Makefile was built or run.

## Closing slice, fix round 1 (on top of 617c6d9): refuse the spellings the readers miss

Input: the closing re-verification at 617c6d9 (FINDING 5 to 8 and 3 NITs), and the chair's ruling: where a
construct is cheap to refuse, refuse it; narrow a sentence only where refusing is not practical.

**Refused before make, with 0 make processes (makegate):**
- a rule with an inline `;` recipe (FINDING 5);
- several targets on one rule line, including a special target that is not first, and grouped `&:` (FINDING 5);
- a rule target that is an expansion (`$(I)ORE:`);
- a rule line that starts with whitespace, or is continued with a backslash;
- a variable name that is an expansion, in any assignment or `define` (M-2, refused rather than narrowed);
- `$(call eval,…)`, `$(call guile,…)` and `$(call $(F),…)`, because `call` runs the built-in of that name.

Of these, FINDING 5 named the first two. I found the others while fixing it. Each is a way to write a rule, or to
name something computed, that the anchor's `<target>:` reading or the literal-name list would miss. Today's Makefile
uses none of them, and its pin is unchanged.

**The anchor's readings:**
- the recipe reader steps over conditional directives, as make does;
- the closure reads rule lines with comments stripped. A rule line whose comment held `=` used to drop its
  prerequisites from the closure.

**FINDING 7:** every gate make process now also runs without any environment variable whose name appears as a word
in the pinned text, minus a keep-list.

**The inventory:**
- `env`/`nohup`/`sudo` flags may take one argument (FINDING 6);
- a Go dot-import of `os/exec` is matched (FINDING 6);
- Python `from subprocess|os import *` is matched;
- a Python argv list or tuple literal anywhere is matched, which restores the form e068e07 matched (FINDING 8).

All files are in `closing/round1/` except the demo, which now has 70 rows.

| File | What it shows |
|---|---|
| `closing/round1/new-tests-at-617c6d9-BEFORE.txt` | This round's committed tests against 617c6d9's UNMODIFIED `makegate.py` and `make-integrity-guard.py`. The 13 new pre-make rows FAIL and both new reading rows FAIL. Both M-4 callers FAIL: their make processes received `VZ_M4_SUBST,Q,VZ_M4_ORIGIN,VZ_M4_VALUE,VZ_M4_EARLY,VZ_M4_IFDEF`, the six forms other than `$(V)`/`${V}`. |
| `closing/round1/inventory-planted-forms-at-617c6d9-BEFORE.txt` | Demo rows R11–R16 (shell `env -u X make`, `sudo -u bob make`; a Go dot-import; Python star-imports of subprocess and os; a Python argv list in a variable) against 617c6d9's inventory. Every one exits 0 and is NOT red. |
| `closing/round1/demo-red-green-round1.txt` | `scripts/ci-hardening-demo.py`, every row: exit 0, **70/70** rows as declared. The first full run (`demo-red-green-round1-first-attempt.txt`, 69/70) had row C3 red for the right reason (planted names reached make) but with a declared text this round had made stale; only that text was changed before the second run. R01–R10 remove one new check each: the inline `;`, multi-target, computed-target, indented and continued rule-line refusals, the computed-variable-name refusal, `$(call eval,…)`, the recipe reader's conditional step, the closure's comment stripping, and the word-level environment drop. Each makes its test red, and each is green again after a byte-identical restore. R11–R16 plant the forms above, and the inventory goes red naming the planted file. |
| `closing/round1/go-meta-tests-verbose-round1.txt` | `go test -count=1 -v ./scripts/ ./internal/httpapi/`: exit 0, 448 `--- PASS`, 0 FAIL, 0 SKIP. |
| `closing/round1/make-ci-local-round1.txt` | `make ci`: exit 0, 689 tests across 7 packages, 0 skips, every package at or above its floor; contract-drift 365; vendor selftest 17/17. |
| `closing/round1/guards-round1.txt` | `ci-required-guard.sh`, `make-integrity-guard.sh --workflow` and `vendor-contract.py --check`: all exit 0 (make ran 21 times in the anchor). |

Host: darwin/arm64, go1.27.1 (printed from inside each worktree), GNU Make 3.81, Python 3.9.6. Nothing ran on GNU
Make 4.3.

## Closing slice (on top of e068e07): every sentence claims no more than its control

Inputs: the vizra-security desk review at e068e07 (M-1…M-5, N-1…N-3) and the re-verification's FINDING 4. The
sentences that overclaimed are narrowed to the code (M-1: the recipe scan reads the EXPLICIT rules of the named
closure only; M-2: named constructs are refused in their LITERAL spelling only), and three controls are widened:
M-3 (a recipe body starting with any `$` but `$$` is refused), M-4 (every make process the gate starts, for every
caller, runs without the variables the Makefile takes from the environment) and FINDING 4 (the make-launch
inventory reads Go with `go/ast`, Python with `ast`, and shell command positions). N-3: the anchor ends with the
`make -q` probe again. Nothing under `api/` and nothing in the Makefile changed (its pin is unchanged). All files
are in `closing/`.

| File | What it shows |
|---|---|
| `closing/m3-m4-new-tests-at-e068e07-BEFORE.txt` | The closing slice's committed tests run against e068e07's UNMODIFIED gate: the `$@`, `$<` and `$X` rows FAIL (the anchor passed them), and both M-4 callers FAIL — the make processes of `contract-drift-guard.py recipe` and of `makegate.py -- --dry-run` received `VERSION,COMMIT,CORE,GOFLAGS`. |
| `closing/finding4-planted-forms-at-e068e07-BEFORE.txt` | Demo rows C4–C10 (a planted Go `exec.CommandContext(ctx, "make", …)`, Python `shell=True`, `os.system`, `["env", "make", …]`, shell `&& make`, `if make`, `/usr/local/bin/make`) against e068e07's inventory: every one exit 0, NOT red — FINDING 4 reproduced. |
| `closing/demo-red-green-closing.txt` | `scripts/ci-hardening-demo.py`, every row, on the closing tree: exit 0, **54/54** rows as declared. Closing rows: C1 (makegate back to `$(`/`${` only: the `$@` row goes red); C2 (refusing every leading `$`, `$$` included: the `$$` control goes red); C3 (run_make no longer drops the environment-taken variables: the M-4 test goes red); C4–C10 (the planted forms above: the inventory goes red, naming the planted file). Each is green after a byte-identical restore. |
| `closing/go-meta-tests-verbose-closing.txt` | `go test -count=1 -v ./scripts/ ./internal/httpapi/`: exit 0, 423 `--- PASS`, 0 FAIL, 0 SKIP. |
| `closing/make-ci-local-closing.txt` | `make ci`: exit 0, 664 tests across 7 packages, 0 skips, every package at or above its floor; contract-drift 365; vendor selftest 17/17. |
| `closing/guards-closing.txt` | `ci-required-guard.sh` exit 0; `make-integrity-guard.sh --workflow` exit 0 (make ran 21 times, the last one the closing `make -q`). |

Host for all of these: darwin/arm64, go1.27.1, GNU Make 3.81, Python 3.9.6. The header line of each of the two
e068e07 BEFORE transcripts prints `go1.26.2`. That header ran `go version` in the meta-repository directory, which
selects go1.26.2, not in the worktree where the tests ran. That worktree has the same `go.mod` as this tree, where
`go version` reports go1.27.1. The fix-round-1 BEFORE transcripts print it from inside the worktree. **Nothing in
the closing slice was run on GNU Make 4.3**; its changes are to Python and Go readers and to the environment make
receives, not to how make treats the Makefile.

**Superseded by fix round 1 (above):**
- "M-2: named constructs are refused in their LITERAL spelling only": the computed spellings are now refused
  outright.
- At 617c6d9 the inventory was narrower than e068e07's in one form (FINDING 8): an argv list held in a variable,
  `ARGV = ["make", "ci"]` then `subprocess.run(ARGV)`. e068e07's regex matched it; 617c6d9's Python `ast` half did
  not. Fix round 1 restores it.

## Fix round 2 (on top of c3b2021): one digest-gated way to start make, and a remake probe

Round 1 moved the control from grammar to digest. The re-verification then showed that a newer unpinned
`Makefile.sh` rewrote the Makefile during the anchor's own `make -pn`, through make's built-in `% : %.sh`,
after the digest had passed. The security re-review showed two make calls outside the gate.

Round 2 adopts vizra-core PR #10's design, with the chair's correction: ONE `make -q` names every pinned
file. All of it lives in `scripts/makegate.py`, and every script or test that starts make goes through it — as far as
`TestEveryPlaceThatStartsMakeIsGated` can tell: it matches only the literal forms AGENTS.md lists (see the closing slice
above for what those are now), and make started through a variable, a wrapper or a form it does not match is review-only.

| File | What it shows |
|---|---|
| `demo-red-green-round2.txt` | `scripts/ci-hardening-demo.py` on the final round-2 tree, 44 rows, **44/44**. The round-2 rows are: 1r (a newer `Makefile.sh`: anchor red, Makefile byte-identical); 1s (the same through `contract-drift-guard.py recipe`, which runs before the anchor); 1t (the remake probe disabled, so its test goes red); 1u (`MAKEFILES`: red, 0 make processes); 1v (a new ungated make call, so the inventory test goes red). |
| `make43-round2.txt` / `.sh` | GNU Make 4.3 (`ubuntu:24.04`). The siblings `.sh .c .o .y .l SCCS/s. s.` are refused by the anchor AND by the contract-drift shape check, and the Makefile is unchanged in every row. RCS `,v`/`RCS/` are measured: make would not remake an existing Makefile from them, so the anchor is green with unchanged bytes. The drift check is red there only because the future-dated sibling makes make warn. R-2/R-3 rows: `MAKEFILES`, a stub make, a symlinked Makefile, `GNUmakefile`/`makefile`, and a pin for a missing file are red in both readers; `BASH_ENV` starts 0 make processes. A pinned include with a newer `inc.mk.sh` is refused by the ONE-invocation probe (`make -q Makefile inc.mk`), with inc.mk unchanged. **Measured for contrast:** a per-file `make -q Makefile` alone did NOT stay recipe-free. It was still running after 60 s (exit 124), and inc.mk was then gone (make deletes an interrupted target). That is the chair's correction, observed. Re-pinned `.RECIPEPREFIX`, `.SECONDEXPANSION`, `.IGNORE`, `.DEFAULT`, `.EXTRA_PREREQS`, target-specific `MAKEFLAGS` and a `+` line are each refused with "0 make process(es) started". ONE row, the pattern-specific `%: SHELL := …`, was lost to a harness bug: printf read the `%` as a format, so no mutation was applied and the anchor was correctly green on the unmutated bytes. It is re-run in `make43-round2-pattern-row.txt`: red, 0 make processes. |
| `go-meta-tests-verbose-round2.txt` | `go test -count=1 -v ./scripts/ ./internal/config/ ./internal/httpapi/`: all ok, 456 PASS, 0 FAIL. |
| `make-ci-local-round2.txt` | `make ci` on the round-2 tree, exit 0: 613 tests, 0 skips, every package at or above its floor; vendor selftest 17/17. |

A first round-2 container attempt hung for about an hour on a measured row, which ran the remake probe disabled against a +1-day sibling. The inferred cause is make remaking and re-executing in a loop; that is not verified. It was killed, and its partial output is not used.

Not used: `-r`/`--no-builtin-rules`. In the probe it would hide the very built-in remake the unmodified
pinned `make` step would perform. On the resolver it would change MAKEFLAGS and the database the checks read.


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
