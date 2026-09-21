# PR #4 — the runtime mode is `VIZRA_MODE`

One operator-facing name per concept. `VIZRA_MODE` is this process's runtime
mode (`development | production`, production by default). `VIZRA_SEARCH_MODE` is
`vizra-core`'s search **topology**, owned and read by core alone: this service
refuses it **only** when it carries this service's own retired runtime
vocabulary, and **ignores every other value in silence**. The rule and its
reasoning live in `AGENTS.md` § "One operator-facing name per concept
(2026-09-21)".

The policy in this round's second column is the chair's ruling of 2026-09-21,
which reversed the slice brief's original recommendation. The first round
refused any value in neither vocabulary and kept a list of core's topology
values to do it. That list could not be pinned to anything — the verifier
imagined core adding a value, changed nothing here, and no test went red while
the binary would have refused to boot on it. Validating another repository's
vocabulary bought no safety, because production is the DEFAULT and the only
dangerous direction (running development without asking) requires an explicit
`VIZRA_MODE=development`. The list, the test and every sentence claiming a
cross-repo pin are gone.

## The demonstration

`./scripts/boot-matrix.sh` boots the **real binary** once per case — 20 boot
cases plus the focused suite (`internal/config`, `cmd/vizra-search`) as a
twenty-first check. Every case that must boot is proved healthy over real TCP
and then drained with SIGTERM; every case that must refuse is proved to exit
non-zero with the offending variable named on stderr. The key is minted with
`openssl rand -hex 32` per run, never a literal, because production refuses
every key this repository publishes.

Two assertions run on every case:

- **No refusal echoes the value the operator supplied.** Each refusal row greps
  the process output for the exact value it set. The unit-level counterpart
  covers every `v.addf` site in the loader (17 as of 2026-09-21), with
  `TestEveryRefusalSiteInTheLoaderHasANoEchoRow` parsing `config.go` so a
  refusal added without a table row is red. The two runtime-vocabulary
  words are exempt *exactly as spelled*, because the message prints them as the
  vocabulary — which is why one row supplies `  DeVeLoPmEnT  `: that spelling is
  the operator's, and the message must not reproduce it.
- **No ignored value reaches a log.** Each boot row whose `VIZRA_SEARCH_MODE`
  value is long enough not to collide with ordinary log text greps the output
  for it.

A refusal case that instead serves is caught by a watchdog after 10 s and
reported as having booted — without it, a mutation that removes a refusal makes
the harness hang rather than go red, which is a harness that cannot fail.

| Transcript | Result |
|---|---|
| `boot-matrix-green.txt` | 21 passed, 0 failed — RESULT: pass |
| `boot-matrix-mutation-fallback-to-the-old-name.txt` | red, as required |
| `boot-matrix-mutation-drop-the-refusal.txt` | red, as required |
| `boot-matrix-mutation-default-to-development.txt` | red, as required |
| `boot-matrix-mutation-unknown-value-as-development.txt` | red, as required |
| `boot-matrix-mutation-echo-the-value.txt` | red, as required |
| `boot-matrix-mutation-add-an-unrowed-refusal.txt` | red, as required |

(The per-run counts are in each transcript's last two lines.)

## The mutations

Each is an exact, single-occurrence edit of `internal/config/config.go`, applied
by the harness itself. The harness records the file's sha256 **before and
after** and **refuses to run** if the patch left the file byte-identical or if
its anchor text did not occur exactly once — a demonstration that did not happen
is not reported as one. The original is restored on exit, and each transcript
ends with the restored digest.

1. **`fallback-to-the-old-name`** — the refusal becomes a compatibility alias:
   the old name is read as the mode when `VIZRA_MODE` is unset. This is what
   `vizra-core`'s `RetiredKeys` comment says must not exist.
2. **`drop-the-refusal`** — the old name is ignored whatever it carries,
   including the one class that must be refused.
3. **`default-to-development`** — production is no longer the default.
4. **`unknown-value-as-development`** — an unknown `VIZRA_SEARCH_MODE` value
   selects development instead of being ignored: the exact inversion of the
   fail-safe direction the ignore policy rests on. This is the mutation that
   makes "a typo can never hand you development" a claim with a control behind
   it rather than a sentence.
5. **`echo-the-value`** — the refusal prints the operator's value verbatim. It
   exists because a verifier applied exactly this change to the first round and
   `go test` exited 0 with the matrix at 14/0: the no-echo sentence in
   `AGENTS.md` was stronger than anything enforcing it.
6. **`add-an-unrowed-refusal`** — a new `v.addf` refusal path is added to the
   loader, firing only for a sentinel no case supplies, so **no behaviour
   changes at all**: every boot row behaves exactly as it does unmutated. The
   only thing that can object is
   `TestEveryRefusalSiteInTheLoaderHasANoEchoRow`, and it does. That is round
   2's finding in one mutation — the no-echo table claimed to reach every
   refusal while reaching 6 of 17, so the reach is now itself a test.

Each transcript lists the boot cases and the named Go tests that go red.

## What these transcripts do not cover

- They run on **darwin/arm64**, which is a development platform and carries no
  support claim. ADR-009 / Q-027 make Ubuntu 24.04 on native amd64 the only
  qualified acceptance target; the equivalent proof there is the `test`,
  `test-noskip` and `docker-build` lanes on `ci-required`, including the
  `docker-build` step that boots the image with `VIZRA_SEARCH_MODE=development`
  and requires a non-zero exit **whose output names both variables**.
- The matrix is **not a CI lane**. The refusals it drives are already driven
  through the real binary by `cmd/vizra-search/main_test.go` inside the `test`
  lane; the matrix is the operator-facing demonstration and the home of the
  mutations.
