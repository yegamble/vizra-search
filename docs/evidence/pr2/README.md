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
| `F7-after-the-fix-red-green.txt` | six mutations, each **red** under `make contract-drift` specifically, green when restored: each vendored file edited in place, a zeroed `sha256`, a file dropped from the manifest, a `-run` filter put back on the lane, and a guard moved to a package the lane does not list |
| `F8-before-the-fix.txt` | the finding: `scripts/ci-required-guard.sh` is **green** with `scripts/testdata/` deleted, green with an empty `wf-*.yml` glob, and green with a single negative fixture deleted |
| `F8-after-the-fix-red-green.txt` | five mutations, each **red** with a named failure: missing directory, empty glob, missing floor fixture, missing accept fixture, and a fixture that stopped discriminating |
| `lanes-local.txt` | every local lane — `fmt-check`, `vet`, `echo-containment`, `build`, `contract-drift`, `test`, `test-noskip`, `tidy-check`, the fan-in guard, the workflow checker, `govulncheck` — with exit codes |

## Counts

- `make test` (`-race -count=1 ./...`): 6 packages `ok`, exit 0.
- `make test-noskip`: **321 pass events, 0 skips**, exit 0 (the lane's own floor is 40).
- `make ci`: exit 0.
- `scripts/ci-required-guard.sh`: 6 fixtures exercised, floor 6, exit 0.
- `govulncheck ./...`: "No vulnerabilities found", exit 0.

## What changed, and what did not

The re-vendor forced **no** code change in this repository. Core's two edits between
the old and new commits are both additive prose: a "Who enforces what" paragraph in the
OpenAPI description, and a `key_utf8_warning` string beside `key_utf8` in the vectors
file. No schema, no fixed number, no vector, and no field this repository reads changed.
`TestTheContractsFixedNumbersMatchTheImplementation` still finds every number it pins.
