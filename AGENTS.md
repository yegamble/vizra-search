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

**Re-vendor with the command, never by hand.**

```
make vendor-contract CORE=<path-to-a-vizra-core-checkout>   # writes both files + the manifest
make vendor-contract-check                                  # verify; needs no core checkout
make vendor-contract-selftest                               # fire every refusal below
```

`scripts/vendor-contract.py` is the **single writer** of the two vendored files
and of `api/CONTRACT-SOURCE.json`. Hand-vendoring is how the manifest and the
bytes come apart, and both ways it can happen have already happened here:
PR #1 hand-recorded a commit on core's *feature branch*, which a squash-merge
then deleted, so the provenance pointed at an object no reviewer could fetch;
and a hand-typed `sha256` is a checksum of someone's attention rather than of
the bytes. The script writes the bytes, reads them **back off disk**, and
digests what it read.

**What it refuses.** Each of these has a fixture in
`scripts/vendor-contract-selftest.py` that shows it firing by name; a refusal
without a fixture is a claim, not a control.

| refused | how |
|---|---|
| a checkout whose remote is not the canonical repository | `git remote get-url` is **measured**, normalised across https / ssh / scp-like / userinfo forms, and must be `github.com/yegamble/vizra-core` — **exactly two path segments**: `github.com/attacker/x/yegamble/vizra-core` used to be read as its last two segments and accepted |
| a ref that is not the canonical remote-tracking branch | the ref is resolved to a **full refname** and must equal `refs/remotes/<remote>/main` exactly — a tag named `main`, a tag named `origin/main` shadowing the remote-tracking ref, `refs/heads/main`, and any branch `x/main` all resolve elsewhere and are named in the refusal |
| a commit that is not on that ref | `merge-base --is-ancestor <commit> refs/remotes/<remote>/main`, checked against the **resolved** ref, not against anything the caller passed. Reachable via `--commit` |
| a shallow clone | ancestry cannot be decided against a truncated history |
| laundering the ref into the manifest | the manifest records the full refname **resolved** and the tip it pointed at. It used to write `args.ref.split("/")[-1]`, which turned `fake/main` into `main` |
| a forged `source_ref_tip` | the field used to be written and never read. `--check` now requires a 40-character lowercase SHA that is not the null id; `--check --core` requires it to be a commit in core, **on** the recorded ref, and to **contain** `source_commit`. A recorded tip behind core's current main is reported as a note, not a failure: any on-ref commit that contains `source_commit` passes, so the check cannot prove the tip was the one current at vendoring time |

An earlier version of this section claimed the script "refuses a commit that is
not an ancestor of that branch tip, and a `--ref` that is not a `main` branch".
The first half could not fire and the second was a string-suffix test that an
independent verifier walked past twice. Both are now true as written above, and
tested.

**What it cannot prove — do not read more into it than this.** A local clone's
remote URL and its refs are whatever the owner of that checkout set them to;
`git remote set-url` and `git update-ref refs/remotes/origin/main` are one
command each, and the script never fetches. **It defends against a mistake, not
against someone who controls the checkout it is pointed at**, and it does not
authenticate core's bytes. The control for poisoned *normative* bytes is
`contract-drift`, where the 5 ACCEPT and 24 REJECT vectors are actually
consumed; a poisoned *non-normative* field would not be caught by those tests.
The end-to-end answer is a reviewer comparing the recorded ref and commit
against `github.com/yegamble/vizra-core` themselves — which is what recording an
unambiguous, fetchable full refname is for.

It only ever reads the core checkout (`remote get-url`, `rev-parse`,
`for-each-ref`, `log`, `merge-base`, `cat-file`, `show`), so it is safe to point at a
checkout someone else is working in, and it reads committed objects rather than
that working tree.

`vendor-contract` and `vendor-contract-check` are deliberately **not** CI lanes:
CI has no core checkout, and `contract-drift` already fails on any drift between
the vendored bytes and the manifest. `vendor-contract-selftest` needs neither a
core checkout nor a network, so it **is** a required lane — in `ci:`, in
`.github/required-checks.txt`, in `FLOOR_LANES`, and a job in `ci.yml` — and
removing a refusal from `vendor-contract.py` is red in CI, not only on a laptop.
Its 17 fixtures are a floor (`EXPECTED_CASES`).
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

Production is the **default** mode: an env file that forgets `VIZRA_MODE`
still gets the production refusals. An unrecognised mode fails closed.

| Variable | Default | Notes |
|---|---|---|
| `SEARCH_HMAC_KEY` | — | **Required in every mode.** Named by the contract. |
| `MAX_INTERNAL_BODY_BYTES` | `1048576` | Named by the contract. **Production refuses any value above 8 MiB.** |
| `VIZRA_MODE` | `production` | `production` or `development`. The **platform** name — `vizra-core` reads it for the same concept. |
| `VIZRA_SEARCH_MODE` | — | **Not read here.** `vizra-core`'s search **topology**, owned by core. Refused by name **only** when it carries this service's old runtime vocabulary; every other value is ignored in silence — see below. |
| `VIZRA_SEARCH_ADDR` | `:8081` | Never published off-host (ADR-002 / Q-017). |
| `VIZRA_SEARCH_MAX_CLOCK_SKEW` | `300s` | The contract's window. **Production refuses any value above 300s.** |
| `VIZRA_SEARCH_REQUEST_TIMEOUT` | `5s` | Bounds each handler. |
| `VIZRA_SEARCH_SHUTDOWN_GRACE` | `15s` | Drain window. |

In production mode the boot refuses: an empty key; anything shorter than 32
bytes; anything that looks like a placeholder (`dev-`, `test-`, `changeme`,
`insecure`, …); a key with fewer than 8 distinct byte values; and — **by exact
value** — every key this project publishes.

### One operator-facing name per concept (2026-09-21)

`VIZRA_SEARCH_MODE` means **search topology** product-wide, and it is **owned
and read by `vizra-core`**. It says whether core talks to a search service at
all, and to which one. Its vocabulary is core's, and this repository
deliberately does not restate it. It is not this service's variable and was
never a good name for this service's runtime mode.

Until this date `vizra-search` read that same name as its own runtime mode with
the vocabulary `development | production`: one operator-facing name, two
incompatible vocabularies. A shared env file — which is the deployment shape the
meta repository actually ships — would therefore either stop search booting or,
worse, silently pick a mode. **The runtime mode here is now `VIZRA_MODE`**, the
name core already uses for it, with core's vocabulary and core's meaning.

Nothing is deployed, so there is **no compatibility alias**. What
`VIZRA_SEARCH_MODE` does at boot now — one refused class, everything else
ignored:

| Value in `VIZRA_SEARCH_MODE` | Result |
|---|---|
| `development`, `production` (any case, surrounding whitespace ignored) | **boot refusal, by name, in every mode**, naming `VIZRA_MODE` as the replacement |
| **anything else** — core's topology values, values this service has never heard of, whitespace-only, empty | **ignored in silence**: never read, never logged, never echoed |

Both halves are deliberate and are not to be relaxed:

- The refusal applies in **every mode**, not only in production. `vizra-core`
  refuses its retired key names inside its production block, and that is right
  for a secret; this name decides the **mode itself**, so development cannot be
  the mode in which the check is skipped. The concrete danger is an operator
  with `VIZRA_SEARCH_MODE=development` and no `VIZRA_MODE`: silently they get
  production (and misread the refusal of their development key) or silently they
  get development (believing the production refusals still apply). Neither
  silence is acceptable; not booting is. That exact spelling is an operator
  **asking for a mode**, which is why it alone is refused.
- **Everything else is ignored, including values this service does not
  recognise.** `VIZRA_SEARCH_MODE` is core's variable, and validating core's
  vocabulary here would buy no safety while coupling two repositories: the day
  core extended its vocabulary, every search instance reading a shared env file
  would refuse to boot. So this repository holds no copy of core's vocabulary
  and no test pretending to pin one.

  **The accepted cost, stated plainly:** a typo such as
  `VIZRA_SEARCH_MODE=developmnt` with no `VIZRA_MODE` boots **production** — the
  strict mode — and the operator finds out because the development affordances
  they wanted (the published dev key, the relaxed ceilings) are refused. That is
  the fail-safe direction. Production is the **default**, and the only dangerous
  outcome — running development without asking for it — requires an explicit
  `VIZRA_MODE=development` and can never come from this variable.
  `TestNoValueInTheOldNameCanEverProduceDevelopment` and the matrix rows
  `old-name-typo-of-development` and `old-name-unknown-alone` hold that line.

No refusal message ever echoes the value an operator supplied — only variable
names and this service's own runtime vocabulary, which are constants in
`internal/config/config.go`. That sentence is a **test**, not a habit, and the
test's reach is itself a test:

- `TestNoRefusalEchoesTheSuppliedValue` provokes **every `v.addf` site** in the
  loader — 17 of them as of 2026-09-21, across 14 distinct messages, two of
  which are emitted from more than one place (one from two sites, one from
  three) — and fails if a value a probe supplied comes back in the error. It
  also checks `Config.String()` and `Config.LogValue()` for an **ignored**
  value. Six rows drive their sites with a marker assembled at run time — eight
  sites in all; the rest fire only for a constrained value (a parseable duration
  above the ceiling, a placeholder-shaped key, the retired vocabulary), and each
  such row **says which and why** next to the value it asserts absent.
- `TestEveryRefusalSiteInTheLoaderHasANoEchoRow` parses **every non-test `.go`
  file of package `config`** — not `config.go` alone — counts every `addf` call
  in any of them, and fails unless the table accounts for each one. A refusal
  added without a row is red, in `config.go` or in a second file. A format
  string the guard cannot read is a failure, not a silent skip.
- `TestNoRefusalBypassesTheNoEchoTable` closes the other ways this package
  could build a refusal, over the same files: an `fmt.Errorf`, `errors.New` or
  `errors.Join` is red unless it is one of the three reviewed ones (the
  `ErrInvalidConfig` sentinel, the nil-`Lookup` refusal, and the aggregator in
  `(*validator).err`); the validator's `problems` list may be touched only
  inside `addf` and `err`, so a helper that appends its own message is red;
  `addf` may only be called, never taken as a value; and no `Error()` method —
  a custom error type — may be declared in the package.
- Every refusal row of the boot matrix greps the process output for the value it
  supplied, exempting the two vocabulary words exactly as spelled.

**So the guard's reach is exactly this:** every error value *constructed in
package `config`*, in any of its non-test files. **What it does not see**, and
review is the only control for: an error produced by **another** package and
returned as-is (for example `return nil, err` from `strconv` inside `LoadFrom`
— `strconv`'s own message quotes its input), a `panic` carrying a value, and a
log line.

The Lookup seam is enforced the same way.
`TestNothingOutsideTheSeamReadsTheProcessEnvironment` parses every non-test
`.go` file in the module and fails on any reference to `os.Getenv`,
`os.LookupEnv`, `os.Environ`, `os.ExpandEnv`, `syscall.Getenv` or
`syscall.Environ` — called or taken as a value, under any import name, and a
dot-import of either package — except the single `os.LookupEnv` inside
`osLookupEnv` in `internal/config/env.go`. Every refusal above is tested through
an injected `Lookup`, so a direct read anywhere else would reach around all of
them unseen. Not seen: reflection, cgo, and reading `/proc/self/environ` as a
file.

`--mutate echo-the-value` turns the first and the matrix red;
`--mutate add-an-unrowed-refusal` turns the second red. The mutations that
prove the widened reach — a refusal echoed through `fmt.Errorf`, through a new
helper, and from a second file of the package, and a stray `os.Getenv` in
`Config.String()` — are in `docs/evidence/ci-hardening/`.

The boot matrix behind this table runs against the **real binary**:
`./scripts/boot-matrix.sh` (20 cases plus the focused suite), with five
controlled mutations — `--mutate fallback-to-the-old-name`,
`--mutate drop-the-refusal`, `--mutate default-to-development`,
`--mutate unknown-value-as-development`, `--mutate echo-the-value` — each of
which must turn it red. The transcripts are in `docs/evidence/pr4/`.

### Published keys are refused by exact value

A committed key is a published key. Three classes are refused outright:

| Key | Why a heuristic cannot catch it |
|---|---|
| `dev-insecure-hmac-key-do-not-use-in-production` | it is caught, three times over — but it keeps its own message |
| the `key_utf8` of `api/search-hmac-testvectors.json` | exactly 32 bytes of mixed-case alphanumerics with 32 distinct byte values. It passes **every** heuristic here, and it is the one key whose documentation is a committed file an operator will read and copy |
| every key literal in this repository's own `_test.go` sources | likewise indistinguishable from a good key |

The refusal is by exact value and never echoes it. Widening the heuristics to
catch the vectors key is not an option: a rule broad enough to reject that
string would reject good keys too. `vizra-core` refuses the same value on its
side — **a shared secret is only as strong as the weaker of the two loaders.**

Two tests keep this honest, and neither duplicates a literal:

- `TestTheVectorsPublishedKeyIsStillTheOneWeRefuse` reads `key_utf8` out of the
  vendored file **at test time**, so re-vendoring a changed vectors file cannot
  silently un-refuse the key.
- `TestEveryKeyLiteralInThisRepositoryIsRefused` parses every `_test.go` with
  `go/ast` and fails on any string bound to a key-shaped identifier that
  production would accept. The refused list cannot rot.

Consequently a test that needs a production-valid key **generates one** rather
than hard-coding it, exactly as an operator is told to (`openssl rand -hex 32`).
Development mode still accepts all of these keys — the conformance vectors have
to be runnable and `make run` boots with the dev key. `validate()`
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
| `contract-drift` | the handlers, response bodies, HMAC scheme and both vendored digests match the canonical contract, and every normative vector — ACCEPT and REJECT — is consumed; the lane's own shape is checked before and after the tests run, so nothing can be deselected |
| `test` | `go test -race -count=1 ./...` |
| `test-noskip` | the whole suite run **without a make step** (the two tests inside it that read the Makefile go through the digest-gated `scripts/makegate.py`): **0 skipped tests**, no package without test files, **every package at or above its executed-test floor**, no package without a floor, `go test`'s own exit code judged; counts printed in the log (Q-001) |
| `tidy-check` | `go.mod`/`go.sum` are tidy |
| `govulncheck` | no known vulnerability in the dependency graph |
| `vendor-contract-selftest` | every refusal `scripts/vendor-contract.py` advertises fires, by name, against throwaway repositories |
| `docker-build` | the image builds natively, refuses the dev key, and answers `not_indexed` over HTTP |

`test-noskip` fails on **any** skip, including a package with no test files,
and there is no skip allowlist: `scripts/go-test-report.py` refuses a non-empty
`allowed_skips`. If you add a package, add tests to it **and a floor** in
`scripts/test-floors.json`; do not loosen the guard. Floors only rise, and a
lowered one is a reviewed diff.

`make ci` runs exactly the make lanes CI runs plus `test-noskip` (local parity
for the direct lane), and `scripts/ci-required-guard.py` fails when the two
disagree.

#### The make lanes cannot be silenced — what the guards ARE, and what they CANNOT do

Every required lane but `test-noskip`, `govulncheck` and `docker-build` runs
through `make`, where one word on the workflow line (`make -i test`) or one
line in the `Makefile` (`MAKEFLAGS += -i`, `SHELL := /usr/bin/true`) makes a
failing lane exit 0. The design is ported from `vizra-core` PR #9 (merged as
`eeeea06`), which took three verifier rounds to get right. Its lesson: a
**blacklist** over arbitrary shell cannot be complete — core's first version
refused a list of flags, and a verifier found thirteen spellings it missed. So
the control is **default-deny on the shape of the steps and their
surroundings**:

- **Pinned steps.** Every step in a required lane that mentions `make` must be
  **byte-equal** to an entry in `.github/pinned-steps.yml`, and every step that
  mentions `go test` must be byte-equal to its pinned direct body. Either may
  carry no key but `name`, `run` and `id` — so no `if:`, `env:`, `shell:`,
  `working-directory:`, `continue-on-error:` or `timeout-minutes:`. No flags,
  no overrides, no chains, no indirection. `make -i test`, `make -j -i test`,
  `MAKEFLAGS=-i make test`, `export MAKEFLAGS=-i` above it, `M=make; $M -i`,
  a shell function named `make`, backticks, `bash -c`, a PATH prefix, `if:
  always() && false`, `working-directory:` and `shell: bash -c '{0} || true'`
  are each red by name.
- **Present.** `required_invocations` records what each lane MUST run,
  byte-equal. Deleting a gate step, or replacing it with something that reaches
  make through an indirection no classifier sees (`${MAKE:-make} -i test`), is
  red whatever replaced it.
- **The pinned anchor.** The step IMMEDIATELY before every make step must be
  exactly `./scripts/make-integrity-guard.sh --workflow`; a step that names the
  guard without being byte-equal to it is refused anywhere in the lane, so a
  compound anchor that writes `$GITHUB_ENV` after the guard exits, or a no-op
  that only names it, is red. Adjacency is what makes its runtime checks mean
  anything: a `$GITHUB_ENV` or `$GITHUB_PATH` write by an earlier step applies
  to LATER steps, so it reaches the anchor exactly as it reaches make.
- **Strictness is chosen by the invocation, never the environment.**
  `--workflow` is part of the pinned bytes. In that mode the anchor refuses
  `MAKEFLAGS`, `GNUMAKEFLAGS` and `MFLAGS` if set at all (even empty);
  `MAKELEVEL`, `MAKE_RESTARTS`, `MAKEOVERRIDES` and `MAKECMDGOALS` if present;
  `MAKEFILES`, `BASH_ENV` and `ENV`; a `SHELL` that is not a shell; a `make`
  that does not resolve to a file named make in a system directory; and every
  variable the `Makefile` takes from the environment as the anchor reads it —
  assigned with `?=`, or referenced as `$(NAME)`/`${NAME}` and never assigned,
  computed from the `Makefile` itself (today `VERSION`, `COMMIT`,
  `BUILD_TIME`, `IMAGE`, `CORE`, `CORE_REMOTE`) — plus `GOFLAGS`. The
  Makefile grammar (below) lets a pinned makefile read a variable only as
  `$(NAME)`/`${NAME}`, so `$V`, `$(V:a=b)`, `ifdef V`, `$(origin V)` and
  `$(value V)` cannot be written at all. One read the anchor does NOT refuse
  remains possible: an immediate `:=` value referencing a name that is
  assigned only LATER in the file, which make takes from the environment at
  that point. Every make process the gate starts runs without such a name
  (below), but the lane's own pinned `make` step is not a gate process and
  would still receive it if an earlier step planted it. Today's `Makefile`
  has no such read. The same names are refused statically as job- or workflow-level
  `env:` of any lane that runs make or `go test`.
- **The `Makefile`, gated on its bytes.** Reading a `Makefile` executes
  parts of it, so the anchor's own dry-run could write the next step's
  environment. *Found while porting, not in core's history:* with
  `POISON := $(shell echo MAKEFLAGS=-i >> "$$GITHUB_ENV")` the ported anchor
  exited 0 and the runner's env file then held `MAKEFLAGS=-i`. The first fix
  was a default-deny scanner over the `Makefile` text. The vizra-security desk
  review of PR #5 showed two constructs make evaluates that it missed
  (secondary expansion of a `$$`-escaped prerequisite, and `.RECIPEPREFIX`),
  and why that shape of control cannot be sound: it has to re-implement make's
  parser. **So the control moved from grammar to digest.**
  `.github/pinned-makefiles.yml` pins the sha256 of every file make may read
  (today only `Makefile`; the `makefiles:` shape vizra-core PR #10 uses).
  **Every place a script or test in this repository starts make goes through
  one helper, `scripts/makegate.py`** — the anchor, the contract-drift shape
  check (which runs *before* the anchor in its job), and the lane test inside
  `test-noskip` — and `TestEveryPlaceThatStartsMakeIsGated` fails on any make
  call it matches outside that helper, in exactly these forms (the list of
  what it does not match is under "What they cannot do"): in `.go` files,
  parsed with `go/ast`, an `os/exec` `Command`/`CommandContext` call —
  `os/exec` imported as `exec`, under an alias, or dot-imported — with a
  `make`/`gmake` string literal (any path) in ANY argument position, or a
  string literal with make in shell command position; in `.py` files, parsed
  with Python's `ast`, (a) a call to any `subprocess` function or to an `os`
  function whose name starts `system`/`popen`/`exec`/`spawn`/`posix_spawn` —
  imported as a module (any alias), by `from … import name [as alias]`, or by
  `from … import *` (then the bare names `run`, `call`, `check_call`,
  `check_output`, `Popen`, `getoutput`, `getstatusoutput`, or the `os`
  prefixes above) — with, anywhere in its arguments, a string that is
  `make`/`gmake` (any path) — so `["env", "make", …]` too — or a string with
  make in shell command position (`shell=True`, `os.system`), or a name
  `make`/`gmake`; and (b) anywhere in the file, a list or tuple literal whose
  first element is the string `make`/`gmake` (any path), so an argv held in a
  variable (`ARGV = ["make", "ci"]`) is matched where it is written; in `.sh`
  files, a non-comment line with make (any path, e.g. `/usr/local/bin/make`)
  in command position: at the start, or after `;` `&` `|` `(` `` ` `` `{`
  `!` (so `&&` and `||` too) or
  `then`/`do`/`if`/`elif`/`else`/`while`/`until`/`time`, optionally behind
  `VAR=value` words and `exec`/`command` (no flags) or `env`/`nohup`/`sudo`
  (with flags — each optionally followed by one separate argument that does
  not start with `-`, so `env -u X make` and `sudo -u bob make` — and
  `VAR=value` words). (The pinned `make`
  workflow STEPS are the other starter; the anchor adjacent to each is their
  guard.) The helper starts make only when all of this holds, and any failure
  stops it BEFORE make:
  - each pinned file is a regular, non-symlink file whose bytes match the pin;
  - the reviewed bytes include nothing unpinned (read statically, without
    running them), and no `GNUmakefile`/`makefile` sits beside the Makefile,
    compared case-folded;
  - **every line of the reviewed bytes fits the Makefile grammar** — an
    ALLOWLIST, default-deny, like the pinned workflow steps (chair ruling
    after the PR #5 closing re-verification: every denylist round found
    another spelling). The bytes are decoded ONCE (strict UTF-8, no
    newline translation) and split into lines ONCE, by
    `makegate.makefile_lines`: on LF only, a line ending in an ODD run of
    backslashes joined to the next as make joins it. **That one sequence of
    logical lines serves every check that reads Makefile text** — this
    grammar, the by-name refusals, the static read set, the environment
    readings, the anchor's closure, definition and recipe readings,
    `ci-required-guard`'s selection and parity readings and
    `contract-drift-guard`'s lane reading; none of them splits the text
    itself (`TestEveryMakefileReaderConsumesTheOneLineReader`). That test
    also scans the AST of the four files (`makegate.py`, the anchor,
    `ci-required-guard.py`, `contract-drift-guard.py`) for exactly these
    spellings, and allows each only at a NAMED read of a non-makefile input,
    listed in the test by function:
    - an attribute named `splitlines`, `readlines`, `read_text`,
      `read_bytes`, `decode` or `open`, called or not;
    - the bare name `open`;
    - an import of a name spelled like one of those, or `M` or `MULTILINE`;
    - an attribute `MULTILINE`, or `re.M`;
    - a string constant holding an inline `(?…m…)` flag group;
    - a `.split(…)`/`.rsplit(…)` call whose first argument is the literal
      `"\n"`, `b"\n"` or `"\r\n"`.

    A helper planted with one of those spellings anywhere else is red
    (`TestTheOneReaderSourceCheckRefusesAPlantedReader`). **Any other way to
    read or split Makefile text is review's to catch, not the test's.** For
    example: `re.split(r"\n", t)`; `t.split(NL)` with the newline in a
    variable; iterating `io.StringIO(t)`; `subprocess.check_output(["cat",
    "Makefile"])`. The same holds for a Makefile read added inside a named
    function with the spelling already allowed there, and for a name built
    at run time. Before any
    shape is judged, a line is refused if it holds a byte on which make's
    own line reading could still differ from that one: a carriage return
    (anywhere, so CRLF too), a NUL or any other control character except
    TAB, an invisible format character, or non-ASCII whitespace such as
    NBSP. Each logical line must then be exactly one of:
    - empty (a line of only spaces or TABs is refused), or a comment line
      with `#` in column 0. A comment — on its own line or after an
      assignment or rule — may not end in an unescaped backslash, because
      make continues a comment onto the next line (manual §3.1). A `#`
      inside `$(…)` is refused, so where a comment starts never depends on
      how a make version reads it;
    - an assignment `NAME op value` at the start of the line, where NAME is a
      literal identifier other than a directive keyword (`ifdef`, `ifndef`,
      `ifeq`, `ifneq`, `else`, `endif`, `include`, `-include`, `sinclude`,
      `define`, `endef`, `export`, `unexport`, `override`, `private`,
      `undefine`, `vpath`, `load`, `-load`), `.SHELLFLAGS` or `.DEFAULT_GOAL`, op is `:=`, `?=`
      or `=`, and the value uses only `$$`, `$(NAME)`/`${NAME}` references and
      `$(shell …)` whose own text uses only those references;
    - `.PHONY: names`, with literal names;
    - a rule line `name: prerequisites`: ONE literal target, not starting
      with `.` and not a directive keyword, then literal prerequisite words, with no `;`, `$`, `%`, `|`,
      `=`, second `:`, `::` or `&:`;
    - a TAB recipe line of the rule above it (empty and comment lines between
      recipe lines keep the rule open, any other line closes it), read raw,
      whose text uses only `$$` and `$(NAME)`/`${NAME}` references, and not
      `$(MAKE)`. No function may be called in a recipe: this `Makefile` calls
      none (`RECIPE_FUNCTIONS` is empty).

    Any other line is refused with its line number. So a conditional,
    `include`, `define`, `export`, `override`, `private`, `vpath`, a function
    other than `$(shell …)` in a value, a computed name, an inline `;`
    recipe, several targets, a special target other than `.PHONY`, or a
    pattern or suffix rule cannot appear, in any spelling. Today's `Makefile`
    passes unchanged (`TestTheRealMakefileFitsTheGrammar`). Which bytes make
    itself reads differently from `makefile_lines` (a continued comment, a
    CR, a NUL, a directive keyword as a name) is taken from the GNU Make
    manual and a reading of make's source, NOT measured here: this
    repository runs make on no such bytes, because each is refused before
    make. Within the
    grammar, these are also refused BY NAME, as a second and more specific
    diagnosis:
    - any SHELL or .SHELLFLAGS assignment other than the one approved line;
    - any MAKEFLAGS, GNUMAKEFLAGS or MFLAGS assignment;
    - `+` recipe lines and `$(MAKE)`, both of which run even under `-n` and
      `-q`;
    - a TAB recipe line whose body (after any `@`/`-`/`+`) begins with `$`
      other than `$$`, because what it expands to — a `-` prefix, say —
      cannot be known without running make.

    The older by-name checks for the constructs the grammar now excludes
    (`.RECIPEPREFIX`, `.SECONDEXPANSION`, `.ONESHELL`, `.IGNORE`, `.DEFAULT`,
    `.POSIX`, `.EXTRA_PREREQS`, `$(eval …)`, computed names, the rule-line
    spellings) stay as diagnoses. They match only the spellings they name;
    the grammar is what refuses the rest;
  - `MAKEFILES` is unset, and every process runs without make's flag variables,
    `MAKEFILES`, `BASH_ENV`, `ENV` or the runner's command-file variables;
    every make process, whichever caller opened the gate, also runs without
    any environment variable whose name appears as a word ANYWHERE in the
    pinned makefiles' text — over-matching on purpose, so every way make can
    read one (`$(V)`, `${V}`, `$V`, `$(V:a=b)`, `ifdef V`, `$(origin V)`,
    `$(value V)`, a read before a later `:=`) is covered — except a short
    keep-list (`PATH`, `HOME`, `TMPDIR`, `USER`, `LOGNAME`, `LANG`,
    `LANGUAGE`, `LC_ALL`, `LC_CTYPE`, `TERM`, `SHELL`, `PWD`, `TZ`), and
    without `GOFLAGS` and the anchor's list above; a variable name make
    assembles from parts, appearing as no single word, is not dropped;
  - `make` is a regular file in a system directory, started by that real path;
  - **`make -q <every pinned makefile>`**, ONE invocation naming them all —
    which runs no ordinary recipe (a `+` or `$(MAKE)` recipe line still runs under -q; one can come only from the pinned, reviewed bytes) — says make would
    not REMAKE any of them. make remakes an out-of-date makefile even under
    `-n`, from its own built-in rules: a newer unpinned `Makefile.sh` beside
    the Makefile was turned into the Makefile by `% : %.sh` during the anchor's
    own `make -pn`, after the digest had passed (PR #5 re-verification,
    FINDING 2). The same probe covers `.c`/`.o`/`.y`/`.l` and `SCCS/s.`
    siblings; on GNU Make 3.81 and 4.3 the RCS `,v` forms did not make make
    remake an existing Makefile, so they are correctly green, and the bytes
    are checked either way.
  After every make run the pinned files are re-hashed and must be unchanged,
  and the anchor names them as goals on every later make command and checks
  that `MAKEFILE_LIST` is exactly the pinned set, and it ends with the same
  `make -q` probe again. `ci-required-guard.py` makes the same byte,
  symlink and include checks without running make, and of the siblings it
  checks only `GNUmakefile`/`makefile`: a remake source such as a newer
  `Makefile.sh` is caught only by the `make -q` probe, i.e. by the anchor and
  the other gate callers.
  `-r`/`--no-builtin-rules` is deliberately NOT used: in the probe it would
  hide the very built-in remake the unmodified pinned `make` step would
  perform. **What it guarantees, exactly:** make runs
  only on reviewed bytes — and those reviewed bytes run their own reviewed
  `$(shell …)` calls while being read (today four: `go env GOROOT`,
  `git describe`, `git rev-parse HEAD`, `date`). A `Makefile` edit is
  mergeable only together with a reviewed edit to the pin
  (`shasum -a 256 Makefile`). Then, after make has read the reviewed bytes:
  make's resolved database (`make -pn`) must hold the approved SHELL and
  .SHELLFLAGS and nothing in MAKEFLAGS; every TAB recipe line of the
  EXPLICIT rules of the named gate targets and of their prerequisite closure
  (followed through the literal prerequisites of explicit rules, read with
  comments stripped) may carry no `-` prefix and no `|| true`-family suffix,
  and no gate target may be defined twice or inside a conditional. These
  readings consume the SAME logical lines the grammar judged
  (`makegate.makefile_lines`), and decide which rule a TAB line belongs to
  exactly as the grammar does (`makegate.recipe_lines`: empty and comment
  lines keep a recipe open, any other line closes it, as GNU Make's manual
  §5.1 says make ignores blank and comment lines among recipe lines). So, for
  the grammar and for these readings alike, a rule's recipe is exactly the TAB
  lines after it, up to the next line that is neither empty nor a comment;
  and no pattern, suffix or `.DEFAULT` rule or `$`-named prerequisite can be
  written. A recipe make supplies from its BUILT-IN implicit rules is NOT
  scanned (see the residuals); make's own `--dry-run` must show no
  command that EXPANDS to a swallowed exit (`cmd $(SWALLOW)`); and make's
  warnings must show no duplicate definition. They run after make has read the file and are a check on what a
  reviewer approved, not a grammar of make. Exactly one recipe line may end
  `|| true`: contract-drift's `go test` line, keyed to that target and those
  bytes, because its next line `ran` is the lane's verdict.
- **Strict YAML.** A duplicate key or a merge key (`<<:`) anywhere in a
  workflow or the pins file is refused, so the guard never reads a different
  value than a reviewer sees first. `defaults.run`, a job `container:`, a
  job-level `if:`, a reusable-workflow job and an undigested service image are
  refused on required lanes.
- **The direct lane.** `test-noskip` runs `go test -count=1 -json ./...`
  with no make step. Inside that suite, two tests read the Makefile with
  `make --dry-run` — only through `scripts/makegate.py`, the same gate as the
  anchor. Its pinned body refuses a set `GOFLAGS`, records `go test`'s
  exit code, fails the step on the report's verdict (`|| exit 1`), and ends
  `exit "$rc"`, so go test's own failure fails the step even if the report line
  were removed. `scripts/go-test-report.py` fails on any skip, any package with
  no test files, any package below its floor or without one, and an exit code
  the event stream does not explain.

**What they cannot do** — stated rather than implied, and not called complete:

- **Another step's effects on the machine.** A required lane may contain other
  `run:` steps and `uses:` actions, and through them anything at all before the
  anchor runs: a replaced Go toolchain, a rewritten test file, a different
  `python3`, a forwarding `make` stub planted in `/usr/local/bin`. The anchor
  checks what `make` IS (a file named make in a system directory), not what it
  DOES, and the pinned shell calls run whatever `go`, `git` and `date` resolve
  to.
- **Environment variables outside the named set.** Go's own `GOTOOLCHAIN`,
  `GOENV`, `GODEBUG`, `CGO_ENABLED` and the rest are not refused, at runtime or
  statically. The executed-test floors turn a suite made to run nothing red;
  anything subtler is review-only.
- **Reusable workflows and wrappers.** A `jobs.<id>.uses:` job has no steps to
  read (it is refused on a required lane, not inspected). A wrapper script or
  composite action that calls make carries no `make` token; `required_invocations`
  bounds the damage, but a lane may run one in addition. Likewise
  `TestEveryPlaceThatStartsMakeIsGated` matches only the forms listed above.
  Review-only: make named through a variable or constant other than a
  Python argv literal (`exec.Command(bin)`, `subprocess.run([MAKE])`, an
  argv built by concatenation), a wrapper script, other exec APIs and dynamic
  lookups (Go `syscall.Exec`, `os.StartProcess`, an `exec.Cmd{Path: …}`
  literal; Python `asyncio`, `pty`, `getattr`, `importlib`), make in a `.sh`
  position not listed (`xargs make`, `timeout 60 make`, `nice make`,
  `ssh host make`, `env -S 'make ci'`), and files it does not read (no `.go`/`.py`/`.sh` extension, or
  under `docs/`, `.git/`, `testdata/`, `bin/`, `node_modules/`).
- **A reviewer approving a malicious `Makefile` together with its pin
  update.** The digest proves the bytes were reviewed, not that the review was
  right: approved bytes run, including whatever `$(shell …)` they contain, while
  make reads them. The grammar bounds the SHAPE of what a reviewer can
  approve, not its meaning. Within it, approved bytes still decide:
  - the commands every recipe runs;
  - what each `$(shell …)` in an assignment value runs while make reads the
    file (four today, all pinned bytes);
  - what a variable referenced from a recipe expands to. A swallowed exit
    produced that way is caught by the dry-run reading. A `-`/`+` prefix
    cannot be produced that way, because a recipe body may not begin with an
    expansion.

  Review is the control there, and CODEOWNERS is advisory. One limit of the
  readings after make, stated because a reader could assume otherwise: the
  `-`-prefix and suffix scan covers the TAB recipe lines of the EXPLICIT
  rules of the named closure only. A recipe make supplies from its BUILT-IN
  implicit rules is not scanned: for a closure prerequisite with no explicit
  rule (printed as a note; there are none today), or for a target whose
  explicit rule has no recipe and is not `.PHONY`. The dry-run cannot show a
  `-` prefix. vizra-core #11 (open, B5b) refuses non-explicit and non-.PHONY
  closure targets, per the vizra-security desk review of this PR. Search
  adopts core's anchor in a follow-up.
- **Edits to the controls themselves.** `.github/pinned-steps.yml`,
  `.github/pinned-makefiles.yml`, `scripts/test-floors.json`, `FLOOR_LANES`,
  the guards and the workflows are all checked out from the pull request under
  test. Widening a pin, lowering a floor or editing a guard is **visible** in a
  reviewed diff; it is not **prevented**.
- **CODEOWNERS is advisory.** These paths are owner-assigned, but no ruleset
  requires that review yet, so it is a label, not a backstop.

The controls are themselves tested: `scripts/scripts_test.go` applies each
evasion above as a controlled mutation of this repository's **real** workflow,
manifest, pins and `Makefile` (digest before and after, refused unless it
applied exactly once, restored byte-identically, green again), and runs the
pinned direct body against a planted failing and skipped test.

#### `contract-drift` selects by package, never by test name

The lane originally selected its tests with a `-run` regex of name fragments.
That is a guard tied to a naming habit: rename a test to something the regex
does not match and it silently leaves the lane, with nothing to say so. It
happened. The manifest guard was `TestVendoredContractMatchesItsManifest`, which
the regex's `Contract` fragment matched; it was renamed to
`TestEveryVendoredFileMatchesItsManifest`, which matches no fragment in the
regex. After that, **editing a vendored file in place, or zeroing a sha256 in
`api/CONTRACT-SOURCE.json`, left `make contract-drift` green**. The mutation died
only under the broader `make ci`, which is not the lane whose name says it checks
drift.

So the lane names **packages** and runs all of their tests, with no
test-selecting flag. A new guard is in the lane the moment it is written,
wherever it is written and whatever it is called. Do not re-add a name filter to
make the lane faster.

**The rule is enforced from outside `go test`.** The first attempt put it in a
Go test inside the lane — and a Go test inside the lane is selected by the same
`go test` invocation it polices. `-run 'TestVerifier'` deselected the guard that
forbids `-run`; the lane printed `ok … [no tests to run]` and exited **0** with a
vendored contract file edited in place. A juror the defendant can dismiss is not
a control.

`scripts/contract-drift-guard.py` is therefore a recipe step, and the lane is
three commands: `recipe`, then `go test`, then `ran`.

- `recipe` asks **`make --dry-run`** what the lane will actually run, rather than
  reading the `Makefile` text. Asking make resolves in one move every
  indirection a text parser missed: a variable (`$(TESTFLAGS)`), an included
  makefile, and a duplicate `contract-drift:` target — make runs the **last**
  definition while a text parser reads the first. It then refuses any flag
  except `-count=1` and `-json` (so `-run`, `-skip`, `-short`, `-tags`, `-bench`
  and `-fuzz` are refused by name and anything invented later by default), an
  environment assignment prefix, a wrapper script in place of `go test`,
  `GOFLAGS`/`GOTESTFLAGS` carrying a selecting flag **in the environment**, and
  any package holding a vendored-file guard that is missing from the list.
- `ran` reads the report afterwards and fails if any listed package ran **zero**
  tests — which is what a filter selecting nothing looks like from outside — or
  reported `[no tests to run]` or `[no test files]`.

`recipe` also reads the **Makefile text**, because some ways of disarming a
recipe line are invisible to `make --dry-run`. It refuses a `-` prefix on any
recipe line (make ignores that line's exit status, and the dry-run prints the
command *without* the `-`, so the guard could refuse the lane, print its
refusal, and the lane would still exit 0), a `|| true` / `|| :` / `; true`
appended to a guard step, a second `contract-drift:` target, and a lane defined
inside a make conditional.

**A recipe step alone is not enough, because every check invoked by the recipe
dies with the recipe.** A duplicate `contract-drift:` target that supplies its
own recipe replaces the guard steps outright, so nothing in-recipe runs. There
are therefore three readings:

1. `recipe` and `ran`, as recipe steps — the fast, local one;
2. `recipe` again as its **own step in `.github/workflows/ci.yml`, before
   `make contract-drift`**. Being outside make, no Makefile edit can remove it.
   `scripts/ci-required-guard.sh` (in the `ci-required` job) and
   `TestTheLaneGuardIsAnchoredInTheWorkflow` both assert that step exists, is
   unconditional and is not `continue-on-error`;
3. `TestThisRepositoryPassesItsOwnLaneGuard`, which runs the guard against the
   real `Makefile` from the ordinary suite, so `test` and `test-noskip` object
   to a tampered lane even when the in-recipe step is gone.

The rest of `internal/httpapi/lane_selection_test.go` drives the guard against
all nineteen bypasses in a temporary repository, with a positive control, so a
guard that silently stopped refusing one is itself a red lane.

**What these readings do stop.** Each was measured with a vendored file edited
in place, and each turns a required check red:

- a `-` prefix on a guard line, and `|| true` appended to one — red at all three
  readings, because `recipe` reads the `Makefile` text as well as the dry-run;
- a duplicate `contract-drift:` target that replaces the recipe — red at
  readings 2 and 3. Reading 1 cannot run at all, so `make contract-drift` alone
  stays green;
- a test-selecting flag, whether written into the recipe, reached through a
  variable or an included makefile, or carried in `GOFLAGS`/`GOTESTFLAGS`; a
  wrapper script in place of `go test`; a lane defined inside a make
  conditional; a package holding a vendored-file guard dropped from the lane's
  package list, or listed but running zero tests;
- deleting the workflow anchor, making it conditional, marking it
  `continue-on-error`, or moving it after `make contract-drift` — red on
  `ci-required` and on the `test` lane, not on `contract-drift` itself.

**What they do not stop, stated rather than implied:**

- A `Makefile`-level `SHELL := /usr/bin/true` or `MAKEFLAGS += -i` used to be
  listed here: one line that no-ops every recipe, `contract-drift` included,
  with no CI lane to catch it. It is now refused **by name, before
  `make contract-drift` runs**, by the pinned make-integrity anchor (see "The
  make lanes cannot be silenced" above), and `test-noskip` runs every package —
  the drift guards included — without a make step.
- Editing `.github/workflows/ci.yml` as well removes reading 2. That is a second
  file and a second diff, and `ci-required` is red while the step is missing —
  but `ci-required-guard.sh` is itself checked out from the PR under test.
- Every one of these paths is CODEOWNERS-assigned, and **CODEOWNERS is advisory
  until the owner's ruleset requires that review**, which does not yet exist —
  so the human review that backstops the first bullet is enforced by nothing.

### The manifest is editable by the PR it gates

`.github/required-checks.txt` is read from the checkout under test, so the PR
being gated can edit it. Checking only that every name *present* maps to a real
job is not enough — deleting a lane's line would leave `ci-required` green with
that lane no longer required. `scripts/ci-required-guard.sh` (which ends by
running `scripts/ci-required-guard.py`) therefore also enforces:

- a manifest that lists **no** checks — every line a comment — fails **loudly,
  by name** (`REQUIRED-CHECKS MANIFEST EMPTY`). It used to die in silence:
  `required="$(grep -v …)"` under `set -e` exits 1 when grep selects nothing,
  so the gate failed closed with an empty log and nobody could tell why;

- a **floor** of lanes (`build`, `test`, `test-noskip`, `contract-drift`,
  `govulncheck`, `vendor-contract-selftest`) that may never be removed from the
  manifest. The floor lives in `scripts/ci-required-guard.py` (`FLOOR_LANES`) —
  not in the workflow, and not in the manifest it guards. Being one file away is a speed bump, not a control: that script is
  also checked out from the PR under test. **What actually closes this is the
  owner ruleset requiring CODEOWNERS review on `/.github/` and `/scripts/`,
  which is an owner action after this PR lands and is not part of it. Until then
  "ci-required is the gate" is a convention;**
- every manifest entry is a **bare job name** — no trailing comment, no
  `optional` marker, no colon-separated field — so a lane cannot be neutered in
  place instead of deleted;
- no `continue-on-error` key anywhere in `.github/workflows/`, checked by
  **parsing** the YAML (`scripts/check-workflows.py`) rather than grepping it.
  A literal grep is evaded by a quoted key, a capitalised key, or a value that
  is a `${{ }}` expression — and it trips over its own error message. The key
  is matched after unquoting and case-folding, its **value is ignored** (`false`
  is refused too: "currently false" is not a property CI can rely on), and an
  unparseable workflow fails closed. The negative fixtures in
  `scripts/testdata/` are exercised on every run, so a checker that stopped
  matching is itself a red lane. Those fixtures are a **floor** too, named one
  by one: a missing `scripts/testdata/`, an empty `wf-*.yml` glob, or a single
  absent fixture is a named failure with a count, not a loop that quietly runs
  zero times. `for fixture in scripts/testdata/wf-*.yml` alone was green when
  the fixtures were gone — with no match bash passes the literal glob through,
  the checker is handed a path that does not exist and exits non-zero, and the
  "must be rejected" branch reads that as a pass.

  **A fixture must be rejected for the rule it was written to trip.** Reading
  *any* non-zero exit as "correctly rejected" left the same hole one level down:
  a checker that cannot read or parse its input also exits non-zero, so
  `chmod 000` on a reject fixture — or, the case that actually reaches CI
  through git, **emptying** one — kept the guard at exit 0 while it printed a
  fixture count it had not earned. (`test -f` tests existence, not readability,
  though its message said otherwise.) So `check-workflows.py` answers three
  ways — `0` clean, `1` `VIOLATION`, `2` `UNEVALUABLE` — and prints a
  machine-readable `VIOLATION <path> at=<job|step> key=<raw spelling>
  value=<literal-true|literal-false|expression|other>` line. Each reject fixture
  **declares** the rule it must trip, next to the floor list in
  `scripts/ci-required-guard.sh`; the guard requires the fixture to be readable
  and non-empty *before* the checker runs, requires exit `1` **exactly**, and
  requires the reported rule to be the declared one. Exit `2` is a named guard
  failure. A fixture rewritten so it trips a different rule — the `false` value
  changed to `true`, the quoted key unquoted — is red, because a fixture that
  has stopped testing what it was written for is a decoration, not a fixture;
- every pullable Dockerfile base image is pinned by `@sha256` digest
  (`scratch` is exempt: it is the reserved empty base and has no digest).

A PR may **add** lanes to the manifest. It may not remove a floor lane.

The aggregate itself picks the **latest** check-run per name, ordered by
`started_at`, and **fails loudly** when two completed runs of one name disagree
— it does not pick a winner. A stale `success` must never mask a current
failure. The rules live in `scripts/ci-required-select.sh`, which also runs
outside Actions so they can be demonstrated.

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
`/admin/search` surface, and search **topology** selection —
`VIZRA_SEARCH_MODE` is core's configuration, not this service's. Since
2026-09-21 this service reads it as nothing at all and validates nothing about
it beyond refusing its own retired runtime vocabulary (see § "One
operator-facing name per concept").

`vizra-search` never writes core tables, and core never reads schema `search`.
When this service gains tables they live in PostgreSQL schema `search` of the
core database, in a migration directory owned by this repository.
