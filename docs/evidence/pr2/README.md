# PR2 evidence — re-vendor from core `main`, verifier findings F7 and F8

Environment for every transcript in this directory:

| | |
|---|---|
| host | `Darwin 25.5.0 arm64` (Apple Silicon) |
| Go | `go1.27.1 darwin/arm64` (module toolchain; `go` on PATH is go1.26.2) |
| `govulncheck` | `v1.8.0` — the version pinned by `.github/workflows/ci.yml` |
| base | `main` @ `581d79dc01e11fcbab9149eec95707d4637b46e4` |
| branch | `chore/revendor-core-main` |
| date | 2026-09-20 |

`ubuntu-24.04` / amd64 is the qualified acceptance target (ADR-009 / Q-027); these
local arm64 runs carry no support claim and are reproduced by `ci-required` on the
head SHA. The `docker-build` lane was **not** run locally — an amd64 image must not
be built under emulation on this machine — and runs natively in CI.

## Files

| File | What it shows |
|---|---|
| `revendor-provenance.txt` | that `415a6d19cfc0acedd8ad84c1857c95db0ed63627` is the tip of core's `main`; that the previously recorded `2b9c540…` is unreachable on the remote (branch 404, `compare` → `diverged`); core's own diff between the two; and **git blob id, sha256 and byte count agreement** between `415a6d1:api/<file>` and each vendored copy |
| `revendor-key-and-vectors.txt` | that the published-key refusal still refuses `key_utf8` read out of the **re-vendored** file, and that the new `key_utf8_warning` sibling field does not break the vector loader — all 5 ACCEPT and 24 REJECT vectors still consumed |
| `F7-before-the-fix.txt` | the finding: `make contract-drift` is **green** with a vendored file edited in place, and green with a manifest `sha256` zeroed; `go test -list` shows the guard's name is absent from the lane's `-run` regex |
| `F7-after-the-fix-red-green.txt` | **round 1.** Six mutations red under `make contract-drift`. Its `-run` case used `-run 'Contract\|Drift\|Schema'`, whose `Contract` fragment happened to match the in-lane guard's own name, so it went red for an accidental reason. Superseded by the round-2 file below; kept because it is the transcript the verifier assessed |
| `F7-round2-lane-guard-red-green.txt` | **round 2, verifier FINDING 1 + 3.** Ten mutations, each **red** under `make contract-drift`, every one applied *together with* a real in-place edit of a vendored file: `-run 'TestVerifier'` (the verifier's exact case), `-run` selecting nothing, `-run` via `$(TESTFLAGS)`, `GOFLAGS` in the environment, a duplicate `contract-drift:` target, an included makefile, a wrapper script, the guard step deleted, the in-place edit alone, and a zeroed `sha256` |
| `F8-before-the-fix.txt` | the finding: `scripts/ci-required-guard.sh` is **green** with `scripts/testdata/` deleted, green with an empty `wf-*.yml` glob, and green with a single negative fixture deleted |
| `F8-after-the-fix-red-green.txt` | **round 1.** Five mutations red: missing directory, empty glob, missing floor fixture, missing accept fixture, and a fixture rewritten to clean YAML |
| `F8-round2-fixture-rules-red-green.txt` | **round 2, verifier FINDING 2.** An unreadable reject fixture, an **emptied** one, one truncated to invalid YAML, one edited to trip a *different* rule than it declares, the quoted-key fixture unquoted, one made actually valid, and the accept fixture unreadable — each **red** with its own named failure; plus the round-1 reds A–E re-run and still red |
| `F5-F6-round3-one-edit-bypasses-red-green.txt` | **round 3, verifier FINDINGS 5, 6 and 7.** The one-edit Makefile mutations that round 2 did not catch, each applied *with* a drifted vendored file, each recorded against four readings — `L` (`make contract-drift`), `W` (the out-of-make guard), `JOB` (the CI job: `W` then `L`, the required check), `T` (`go test ./internal/httpapi/`): a `-` prefix on either guard line, `\|\| true` on either guard line, and a duplicate target that **replaces** the recipe without the guard. Also the workflow anchor deleted and made conditional, the fixture-floor pin, and the **stated residual** `SHELL := /usr/bin/true`, which no in-Makefile check can catch |
| `lanes-local.txt` | every local lane — `fmt-check`, `vet`, `echo-containment`, `build`, `contract-drift`, `test`, `test-noskip`, `tidy-check`, the fan-in guard, the workflow checker, `govulncheck` — with exit codes |

## Counts (fix round 3)

- `make test` (`-race -count=1 ./...`): 6 packages `ok`, exit 0.
- `make test-noskip`: **347 pass events, 0 skips**, exit 0 (the lane's own floor is 40).
  321 in round 1, 338 in round 2; the additions are lane-guard cases, all passing, none skipped.
- `make contract-drift`: `324 tests ran across 4 package(s), 0 failures, none deselected`, exit 0.
- `./scripts/contract-drift-guard.py workflow`: the out-of-make anchor is present at
  `.github/workflows/ci.yml:jobs.contract-drift` step 2, unconditional, before `make contract-drift`
  at step 3.
- `make ci`: exit 0.
- `scripts/ci-required-guard.sh`: 6 fixtures exercised, floor 6, exit 0.
- `govulncheck ./...`: "No vulnerabilities found", exit 0.

## What changed, and what did not

The re-vendor forced **no** code change in this repository.

Core's `api/` directory changed in **three** files between `2b9c540` and `415a6d1`
(`git diff --numstat 2b9c540 415a6d1 -- api/`):

```
29  0  api/README.md                       <- NOT vendored here; nothing follows from it
 1  0  api/search-hmac-testvectors.json
 8  0  api/search-internal.openapi.yaml
```

Of the two files this repository **vendors**, the diff is `2 files changed, 9
insertions(+)`, no deletions — both additive prose: a "Who enforces what" paragraph in
the OpenAPI `hmacSignature` description, and a `key_utf8_warning` string beside
`key_utf8` in the vectors. No schema, no fixed number, no vector, and no field this
repository reads changed. `TestTheContractsFixedNumbersMatchTheImplementation` still
finds every number it pins.
