# PR #4 — the runtime mode is `VIZRA_MODE`

One operator-facing name per concept. `VIZRA_MODE` is this process's runtime
mode (`development | production`, production by default). `VIZRA_SEARCH_MODE` is
`vizra-core`'s search **topology** (`off | managed | external`), owned by core,
and is never read here as a mode — it is refused when it carries this service's
old runtime vocabulary. The rule and its reasoning live in `AGENTS.md` §
"One operator-facing name per concept (2026-09-21)".

## The demonstration

`./scripts/boot-matrix.sh` boots the **real binary** once per case — 13 boot
cases plus the focused suite (`internal/config`, `cmd/vizra-search`) as a
fourteenth check. Every case that must boot is proved healthy over real TCP and
then drained with SIGTERM; every case that must refuse is proved to exit
non-zero with the offending variable named on stderr and the shared secret
absent from the output. The key is minted with `openssl rand -hex 32` per run,
never a literal, because production refuses every key this repository publishes.

A refusal case that instead serves is caught by a watchdog after 10 s and
reported as having booted — without it, a mutation that removes a refusal makes
the harness hang rather than go red, which is a harness that cannot fail.

| Transcript | Result |
|---|---|
| `boot-matrix-green.txt` | 14 passed, 0 failed — RESULT: pass |
| `boot-matrix-mutation-fallback-to-the-old-name.txt` | 11 passed, **3 failed** — red, as required |
| `boot-matrix-mutation-drop-the-refusal.txt` | 7 passed, **7 failed** — red, as required |
| `boot-matrix-mutation-default-to-development.txt` | 11 passed, **3 failed** — red, as required |

## The mutations

Each is an exact, single-occurrence edit of `internal/config/config.go`, applied
by the harness itself. The harness records the file's sha256 **before and
after** and **refuses to run** if the patch left the file byte-identical or if
its anchor text did not occur exactly once — a demonstration that did not happen
is not reported as one. The original is restored on exit, and each transcript
ends with the restored digest, which equals the pre-mutation digest
`538ba2729e53b66fcc83e9e5416dfa49637a0a92f37182ceb410d98c935b631d`.

### 1. `fallback-to-the-old-name` — the compatibility alias grows back

The refusal becomes a fallback: the old name is read as the mode when
`VIZRA_MODE` is unset. This is precisely what `vizra-core`'s `RetiredKeys`
comment says must not exist.

Red on: boot cases `old-name-old-vocabulary-alone`,
`old-name-old-vocabulary-production-alone` (both booted where a refusal was
required), and the suite — `TestTheOldRuntimeModeNameIsRefusedByName` (5
subtests), `TestTheOldNameAloneNeverSilentlySelectsAMode`, and on the real
binary `TestBootRefusesTheRetiredRuntimeModeName`.

### 2. `drop-the-refusal` — the old name is ignored instead of refused

Red on six boot cases and the suite:
`TestTheOldRuntimeModeNameIsRefusedByName`,
`TestTheOldNameAloneNeverSilentlySelectsAMode`,
`TestTheOldRuntimeModeNameIsRefusedInDevelopmentToo`,
`TestANonVocabularyValueInTheOldNameIsRefused`,
`TestTheOldNameIsConsultedOnlyByTheRefusal`,
`TestBootRefusesTheRetiredRuntimeModeName`.

### 3. `default-to-development` — production is no longer the default

Red on `unset-unset` and `old-name-topology-alone` ("booted in DEVELOPMENT mode;
production is the default") and on
`TestLoadFromDefaultsToProductionWhenModeIsOmitted`,
`TestATopologyValueInTheOldNameIsIgnored`,
`TestAnEmptyOldNameIsToleratedAsATombstone`,
`TestBootRefusesTheDevKeyWhenTheModeIsOmitted`.

## What these transcripts do not cover

- They run on **darwin/arm64**, which is a development platform and carries no
  support claim. ADR-009 / Q-027 make Ubuntu 24.04 on native amd64 the only
  qualified acceptance target; the equivalent proof there is the `test`,
  `test-noskip` and `docker-build` lanes on `ci-required`, including the new
  `docker-build` step that boots the image with `VIZRA_SEARCH_MODE=development`
  and requires it to refuse.
- The matrix is **not a CI lane**. The refusals it drives are already driven
  through the real binary by `cmd/vizra-search/main_test.go` inside the `test`
  lane; the matrix is the operator-facing demonstration and the home of the
  mutations.
