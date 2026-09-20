# vizra-search — engineering contract

This file governs `yegamble/vizra-search`. It sits **under** the meta contract
in `yegamble/vizra` (`AGENTS.md`), which is authoritative on completion and
evidence, guardrails, review rules and merge authorization. Read that first.
Where this file is silent, the meta contract applies; where it is specific, it
is because this repository sits on a trust boundary.

## What this service is

`vizra-search` is the Vizra internal search service. The ruling that created it
is **Q-001** in `vizra/docs/OPEN_QUESTIONS.md`, copied into
`vizra/docs/adr/ADR-002` § "Search service and boundary", accepted by the owner
on 2026-09-20. Three sentences from it bind everything here:

- It is **a real minimal service, not a placeholder**: `/healthz`, `/readyz`,
  `/version`, and HMAC-verified `/internal/v1/search|suggestions|events` that
  return an explicit `not_indexed` status which core treats as fallback.
- **Its CI lanes test exactly that — nothing skipped or fake.**
- A configured but unreachable or misconfigured search is a hard `doctor` FAIL
  and a degraded readiness signal while requests are still served from SQL —
  **never a silent fallback. Search is never a hard dependency.**

At M0 this service owns no migrations, no index, no database and no cache. It
reports **no `search_schema_version`** — the field is present and `null`, so
core can tell "no schema yet" from "field missing".

## The three rules that are easy to break

### 1. `not_indexed` is an answer. A fault is a fault.

`not_indexed` means "I hold no index for this; use your own SQL path". Core
treats it as an instruction, marks nothing degraded, and does not retry.

A **fault** — a 5xx, a rejected signature, a transport error, a timeout — means
core still serves the request from SQL but reports `search: degraded` and turns
`vizra doctor` red. That distinction is the whole point of the status field.

So: never answer `not_indexed` when something is wrong. A draining process
answers **503**, not `not_indexed`, because a draining process is a fault from
core's point of view. `TestDrainingInternalCallsAreAFaultNotAnEmptyIndex`
holds that line.

### 2. This repository does not own the contract.

`api/search-internal.openapi.yaml` is a **vendored, byte-identical copy** of the
canonical file in `yegamble/vizra-core`. `api/CONTRACT-SOURCE.json` records the
source repository, path, commit SHA and sha256 of the vendored bytes.

- Never edit `api/search-internal.openapi.yaml` here. The drift check verifies
  its sha256 against the manifest, so an in-place edit fails CI by design — that
  is the failure mode a two-repository drift check exists to prevent.
- If the contract is wrong, say so to the chair. The change lands in
  `vizra-core` first; this repository then re-vendors it and updates the
  manifest's `source_commit` in the same PR.
- `internal/httpapi.Routes()` is compared against the contract in both
  directions, and every response body is validated against the contract's
  schemas, all of which set `additionalProperties: false`. A renamed field is a
  CI failure, not a tolerated extra.

### 3. The route table must stay honest.

`internal/httpapi.routes` classifies every status code as either **emitted** or
**declared-but-not-emitted with a written reason**.

- Every *emitted* status is provoked by a real request in
  `TestEveryEmittedStatusIsReachable`. A status you cannot provoke is not
  emitted; do not claim it.
- Every *not emitted* status needs a reason a reviewer can read
  (`TestEveryNotEmittedStatusCarriesAReason`).
- The union of the two must equal the contract's declared set exactly, so a
  status added in core turns this repository red until someone classifies it.

Do not "fix" a drift failure by adding a status to the table. Make the service
actually emit it, or write down why it cannot.

## HMAC boundary

The scheme is fixed by the canonical contract
(`components.securitySchemes.hmacSignature`), not by this repository.

```
X-Vizra-Timestamp: <unix seconds, decimal digits>
X-Vizra-Nonce:     <at least 16 bytes of randomness, lowercase hex>
X-Vizra-Signature: v1=<lowercase hex HMAC-SHA256>

canonical = "v1\n<METHOD>\n<path>\n<timestamp>\n<nonce>\n<sha256-hex(raw body)>"
```

Rules that are tested and must not be relaxed:

- Comparison is **constant time** (`hmac.Equal`).
- A timestamp more than **300 s** from the verifier's clock, in either
  direction, is refused.
- A body above `MAX_INTERNAL_BODY_BYTES` (default **1 MiB**) is refused with
  **413 before the body is read**. A declared `Content-Length` above the limit
  is refused without reading a byte.
- Rejection is **always 401** with `{"error":{"code":"signature_rejected", …}}`
  and **must not say which of the three headers was wrong**. The specific
  reason goes to the log, never to the caller
  (`wantSignatureRejected` enforces both halves).
- An unconfigured verifier — no key, or no skew bound — fails every request
  closed. It never defaults to accepting.

### Known limitation, stated rather than implied

**There is no nonce store at M0.** The timestamp window is the only replay
bound, so an *identical* request can be replayed within 300 s. A *modified*
replay is impossible, because the method, path, nonce and a digest of the exact
body are all bound into the MAC. The canonical contract states the same
limitation ("Nonce replay rejection is required once search owns storage"). When
this service gains storage, nonce rejection lands with it.

## Configuration

Production is the **default** mode: an env file that forgets `VIZRA_SEARCH_MODE`
still gets the production refusals. An unrecognised mode fails closed.

| Variable | Default | Notes |
|---|---|---|
| `SEARCH_HMAC_KEY` | — | **Required in every mode.** Named by the contract. |
| `MAX_INTERNAL_BODY_BYTES` | `1048576` | Named by the contract. |
| `VIZRA_SEARCH_MODE` | `production` | `production` or `development`. |
| `VIZRA_SEARCH_ADDR` | `:8081` | Never published off-host (ADR-002 / Q-017). |
| `VIZRA_SEARCH_MAX_CLOCK_SKEW` | `300s` | The contract's window. |
| `VIZRA_SEARCH_REQUEST_TIMEOUT` | `5s` | Bounds each handler. |
| `VIZRA_SEARCH_SHUTDOWN_GRACE` | `15s` | Drain window. |

In production mode the boot refuses: an empty key, the documented development
key `dev-insecure-hmac-key-do-not-use-in-production`, anything shorter than 32
bytes, anything that looks like a placeholder (`dev-`, `test-`, `changeme`,
`insecure`, …), and a key with fewer than 8 distinct byte values. `validate()`
collects **every** problem rather than returning the first (ADR-002 §
Configuration ownership), and no error message ever echoes the rejected key.

`config.LoadFrom(lookup)` and `config.CheckEnv(map)` are the ADR-002 seam: setup,
doctor and CI validate a candidate env file with the boot code itself, so they
can never disagree with boot.

## Logging and redaction (ADR-002 § Logging and redaction)

No process logs credentials, signatures, nonces, signed URLs or request bodies.
`Config.String()` and `Config.LogValue()` redact the key; the request logger
receives no headers and no body. `TestLogsNeverCarrySignatureMaterial` and
`TestConfigNeverRendersTheKey` are the proof, and they must not be weakened.

## Verification

`make ci` is the complete gate; every lane in it is listed in
`.github/required-checks.txt` and aggregated by `ci-required`, which runs on
`pull_request` **and** `merge_group` and treats anything other than `success` —
including a check that never ran — as a failure.

| Lane | What it proves |
|---|---|
| `fmt-check` | gofmt clean |
| `vet` | `go vet ./...` |
| `echo-containment` | ADR-001: Echo is imported only by `internal/httpapi` |
| `build` | the binary links and reports its identity |
| `contract-drift` | the handlers and response bodies match the canonical contract |
| `test` | `go test -race -count=1 ./...` |
| `test-noskip` | **0 skipped tests** and a non-trivial collected count (Q-001) |
| `tidy-check` | `go.mod`/`go.sum` are tidy |
| `govulncheck` | no known vulnerability in the dependency graph |
| `docker-build` | the image builds natively, refuses the dev key, and answers `not_indexed` over HTTP |

`test-noskip` fails on **any** skip, including a package with no test files. If
you add a package, add tests to it; do not loosen the guard.

### Evidence rules

The meta `AGENTS.md` applies verbatim: a required test that is skipped, missing,
cancelled, timed out or not collected is **not** a pass; record exact commands,
exit codes, counts, SHA and environment; nothing is VERIFIED because it
compiles or returns 200. Do not weaken an assertion, delete a case or narrow
scope to turn CI green.

## Platform

ADR-009 / Q-027: Ubuntu 24.04 on native amd64 is the only qualified acceptance
target, and runtime images are published `linux/amd64` only. Build natively;
never build an emulated amd64 image on an Apple-Silicon machine. A local arm64
build is for development and carries no support claim.

## Pinned versions

| Thing | Pin | Where confirmed |
|---|---|---|
| Go | `go 1.26.0` + `toolchain go1.27.1` | ADR-001 line 1.27; `go.dev/dl` release list |
| Echo | `github.com/labstack/echo/v5 v5.3.1` | ADR-001 (≥ v5.3.1); Go module proxy |
| yaml | `gopkg.in/yaml.v3 v3.0.1` | Go module proxy |
| build image | `golang@sha256:69a7b978…f99195` (`1.27.1-bookworm`, OCI index covering amd64 and arm64) | Docker Hub registry, 2026-09-20 |
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` (v7.0.1) | GitHub API tag → commit |
| `actions/setup-go` | `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e` (v7.0.0) | GitHub API tag → commit |

Third-party actions are pinned by commit SHA, never by tag.

## Scope at M0, and what is deliberately absent

In scope: the six operations above, the HMAC boundary, the drift check, `make
ci`, the Dockerfile and the workflows.

Deliberately **not** here, and not to be added without a dispatched slice:
indexing, PostgreSQL, migrations, ranking, event storage, compose wiring, the
`/admin/search` surface, and `SEARCH_MODE` selection (that is core's
configuration, not this service's).

`vizra-search` never writes core tables, and core never reads schema `search`.
When this service gains tables they live in PostgreSQL schema `search` of the
core database, in a migration directory owned by this repository.
