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

Two files are **vendored, byte-identical copies** of canonical files in
`yegamble/vizra-core`, and `api/CONTRACT-SOURCE.json` records the source
repository, the commit SHA, and a **separate sha256 for each file**:

| Vendored file | What it is |
|---|---|
| `api/search-internal.openapi.yaml` | the canonical OpenAPI contract |
| `api/search-hmac-testvectors.json` | the **normative** HMAC conformance vectors — `vectors` are ACCEPT cases, `negative_vectors` are REJECT cases, and an implementation MUST consume both halves |

The reject half matters more than the accept half. The contract says why:
"agreeing on what is accepted while disagreeing on what is rejected is how two
implementations of the same scheme diverge." That is not hypothetical — it had
already happened here, and the vectors exist because of it.

- Every `$ref` in the document must be local (`#/...`). A reference to another
  file or a URL is refused at parse time, before anything resolves it, so the
  drift check can never depend on a document nobody reviewed and the parser can
  never be turned into a file-disclosure or SSRF primitive.
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
(`components.securitySchemes.hmacSignature`) and by the normative vectors, not
by this repository.

```
X-Vizra-Timestamp: <unix seconds, BARE DECIMAL DIGITS>
X-Vizra-Nonce:     <16..64 bytes of randomness, LOWERCASE hex>
X-Vizra-Signature: v1=<LOWERCASE hex HMAC-SHA256>

canonical = "v1\n<METHOD>\n<path as sent>\n<timestamp>\n<nonce>\n<sha256-hex(raw body)>"
```

### Every field enters the canonical string VERBATIM

Nothing uppercases, trims, reparses or reformats any field. Non-canonical input
is **refused, never rewritten**. This is the rule that had already been broken:
one side rebuilt the timestamp through `ParseInt`→`FormatInt`, so
`" 1789000000 "`, `"+1789000000"` and `"01789000000"` verified here and were
refused by core.

| Field | Rule |
|---|---|
| method | uppercase ASCII only, exactly as sent — a lowercase method is **rejected**, not uppercased |
| path | `req.URL.EscapedPath()`, the request path as sent — **never** Echo's route template `c.Path()`, which would drop a concrete path segment out of the MAC the moment a parameterised route lands |
| timestamp | `^[1-9][0-9]*$` — no sign, no leading zero, no whitespace, no separators, no other base |
| nonce | 32–128 lowercase hex characters, even length — uppercase is **rejected**, not lowercased |
| signature | `v1=` + exactly 64 **lowercase** hex characters |
| headers | each of the three appears **exactly once**; a duplicate is rejected, not resolved to the first or the last |

### The timestamp window actually closes

The timestamp's **magnitude** is validated against an absolute range
`[1000000000, 4102444800]` **before any arithmetic**, and the skew is then
computed on plain `int64` seconds against ±300 s.

This is not decoration. The previous implementation computed
`now.Sub(time.Unix(ts, 0))` and folded the sign. `time.Time.Sub` **saturates at
`math.MinInt64`** for a far-future argument, and negating `math.MinInt64` yields
itself — still negative — so the comparison failed open and a validly signed
request with a timestamp of `253402300799` was **accepted and never expired**.
With no nonce store, that window is the only replay bound the service has.

- No `time.Duration` in `internal/hmacauth` is ever derived from an unvalidated
  header. `TestTheSkewArithmeticCannotSaturate` pins that as a source-level
  property, and `TestTimestampWindowClosesAcrossTheWholeMagnitudeRange` drives
  the whole magnitude range in both directions including min/max int64.
- A verifier whose **own** clock falls outside the absolute range fails closed.

### Other rules that are tested and must not be relaxed

- Comparison is **constant time** (`hmac.Equal`), over the whole MAC.
- A body above `MAX_INTERNAL_BODY_BYTES` (default **1 MiB**) is refused with
  **413 before the body is read** — both for a declared `Content-Length` and
  for an undeclared/chunked body, which stops after `limit+1` bytes.
- A **query string** on an internal route is refused before verification. The
  canonical string has no query field, so a query is unsigned and an attacker
  could append one to a captured request without invalidating it.
- The drain **503 sits after authentication**, so an unauthenticated caller
  learns nothing about this service — not even whether it is draining.
- Rejection is **always 401** with `{"error":{"code":"signature_rejected", …}}`
  and **must not say which rule was broken**. The specific reason goes to the
  log, never to the caller.
- The **refusal path** logs no request body. A 401 is most often core's own
  clock skew or a rotated key, and that body is a real member's query text.
- An unconfigured verifier — no key, or no skew bound — fails every request
  closed. It never defaults to accepting.

### Known limitations, stated rather than implied

**There is no nonce store at M0.** The timestamp window is the only replay
bound, so an *identical* request can be replayed within 300 s. A *modified*
replay is impossible: the method, path, nonce and a digest of the exact body are
all bound into the MAC. The contract states the same limitation. This is pinned
by `TestIdenticalRequestsCanStillBeReplayedInsideTheWindowAtM0`, whose name *is*
the limitation — so the day this service owns storage, that test must be
rewritten to assert rejection rather than quietly kept passing.

**There is no key rotation.** Exactly one key is read and one key verifies, so
rotating `SEARCH_HMAC_KEY` requires core and search to change it in the **same
instant**. In practice that is a window in which every internal call 401s —
which by this contract's own rules means `search: degraded` and `vizra doctor`
FAIL — and an operator who learns the key leaked has no clean remediation. The
realistic consequence is that nobody ever rotates it. Multi-key verification
(accept any configured key, each held to the same production validation, core
signing with the first) turns rotation into two ordinary restarts; it is queued,
not in this slice. Until it lands, an operator rotating the key should expect a
brief degraded window and should schedule it deliberately.

## Configuration

Production is the **default** mode: an env file that forgets `VIZRA_SEARCH_MODE`
still gets the production refusals. An unrecognised mode fails closed.

| Variable | Default | Notes |
|---|---|---|
| `SEARCH_HMAC_KEY` | — | **Required in every mode.** Named by the contract. |
| `MAX_INTERNAL_BODY_BYTES` | `1048576` | Named by the contract. **Production refuses any value above 8 MiB.** |
| `VIZRA_SEARCH_MODE` | `production` | `production` or `development`. |
| `VIZRA_SEARCH_ADDR` | `:8081` | Never published off-host (ADR-002 / Q-017). |
| `VIZRA_SEARCH_MAX_CLOCK_SKEW` | `300s` | The contract's window. **Production refuses any value above 300s.** |
| `VIZRA_SEARCH_REQUEST_TIMEOUT` | `5s` | Bounds each handler. |
| `VIZRA_SEARCH_SHUTDOWN_GRACE` | `15s` | Drain window. |

In production mode the boot refuses: an empty key, the documented development
key `dev-insecure-hmac-key-do-not-use-in-production`, anything shorter than 32
bytes, anything that looks like a placeholder (`dev-`, `test-`, `changeme`,
`insecure`, …), and a key with fewer than 8 distinct byte values. `validate()`
collects **every** problem rather than returning the first (ADR-002 §
Configuration ownership), and no error message ever echoes the rejected key.

### Ceilings, not just defaults

The contract fixes two numbers, and a default is not a bound. Production
**refuses** a `VIZRA_SEARCH_MAX_CLOCK_SKEW` above 300 s and a
`MAX_INTERNAL_BODY_BYTES` above 8 MiB, naming the offending variable and
echoing no other configuration. With no nonce store, the skew is the replay
bound: an operator debugging clock drift must not be able to widen it to an
hour without being told. The body cap is the memory bound on a path that runs
**before** any signature is verified.

Development may exceed both, and the boot log says so in a warning that names
the mode, what it relaxes, and never contains the key.

`config.LoadFrom(lookup)` and `config.CheckEnv(map)` are the ADR-002 seam: setup,
doctor and CI validate a candidate env file with the boot code itself, so they
can never disagree with boot — including these ceilings.

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
| `contract-drift` | the handlers, response bodies, HMAC scheme and both vendored digests match the canonical contract, and every normative vector — ACCEPT and REJECT — is consumed |
| `test` | `go test -race -count=1 ./...` |
| `test-noskip` | **0 skipped tests** and a non-trivial collected count (Q-001) |
| `tidy-check` | `go.mod`/`go.sum` are tidy |
| `govulncheck` | no known vulnerability in the dependency graph |
| `docker-build` | the image builds natively, refuses the dev key, and answers `not_indexed` over HTTP |

`test-noskip` fails on **any** skip, including a package with no test files. If
you add a package, add tests to it; do not loosen the guard.

`make ci` includes `tidy-check`, so a local `make ci` covers the same lanes CI
runs.

### The manifest is editable by the PR it gates

`.github/required-checks.txt` is read from the checkout under test, so the PR
being gated can edit it. Checking only that every name *present* maps to a real
job is not enough — deleting a lane's line would leave `ci-required` green with
that lane no longer required. `scripts/ci-required-guard.sh` therefore also
enforces:

- a **floor** of lanes (`build`, `test`, `test-noskip`, `contract-drift`,
  `govulncheck`) that may never be removed from the manifest. The floor lives in
  `scripts/ci-required-guard.sh` — not in the workflow, and not in the manifest
  it guards. Being one file away is a speed bump, not a control: that script is
  also checked out from the PR under test. **What actually closes this is the
  owner ruleset requiring CODEOWNERS review on `/.github/` and `/scripts/`,
  which is an owner action after this PR lands and is not part of it. Until then
  "ci-required is the gate" is a convention;**
- every manifest entry is a **bare job name** — no trailing comment, no
  `optional` marker, no colon-separated field — so a lane cannot be neutered in
  place instead of deleted;
- no `continue-on-error` key anywhere in `.github/workflows/`;
- every pullable Dockerfile base image is pinned by `@sha256` digest
  (`scratch` is exempt: it is the reserved empty base and has no digest).

A PR may **add** lanes to the manifest. It may not remove a floor lane.

`.github/CODEOWNERS` assigns `/.github/`, `/scripts/`, `/Makefile`, `/api/`,
`internal/hmacauth`, `internal/config` and this file to the owner. **CODEOWNERS
is advisory until a ruleset requires that review**, and applying the ruleset is
an owner action after this PR lands (ADR-002 item 9: `ci-required` must exist
before it can be required).

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
| `govulncheck` | `golang.org/x/vuln/cmd/govulncheck@v1.8.0` | Go module proxy `@latest`, 2026-09-08. v1.1.4 predates Go 1.27 and crashes on the linux/amd64 runner. |
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
