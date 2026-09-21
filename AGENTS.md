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
| a checkout whose remote is not the canonical repository | `git remote get-url` is **measured**, normalised across https / ssh / scp-like / userinfo forms, and must be `github.com/yegamble/vizra-core` |
| a ref that is not the canonical remote-tracking branch | the ref is resolved to a **full refname** and must equal `refs/remotes/<remote>/main` exactly — a tag named `main`, a tag named `origin/main` shadowing the remote-tracking ref, `refs/heads/main`, and any branch `x/main` all resolve elsewhere and are named in the refusal |
| a commit that is not on that ref | `merge-base --is-ancestor <commit> refs/remotes/<remote>/main`, checked against the **resolved** ref, not against anything the caller passed. Reachable via `--commit` |
| a shallow clone | ancestry cannot be decided against a truncated history |
| laundering the ref into the manifest | the manifest records the full refname **resolved** and the tip it pointed at. It used to write `args.ref.split("/")[-1]`, which turned `fake/main` into `main` |

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
`for-each-ref`, `log`, `merge-base`, `show`), so it is safe to point at a
checkout someone else is working in, and it reads committed objects rather than
that working tree.

`vendor-contract` and `vendor-contract-check` are deliberately **not** CI lanes:
CI has no core checkout, and `contract-drift` already fails on any drift between
the vendored bytes and the manifest. `vendor-contract-selftest` needs neither a
core checkout nor a network and therefore could be one; that is proposed to the
chair rather than done here.
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

In production mode the boot refuses: an empty key; anything shorter than 32
bytes; anything that looks like a placeholder (`dev-`, `test-`, `changeme`,
`insecure`, …); a key with fewer than 8 distinct byte values; and — **by exact
value** — every key this project publishes.

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
| `test-noskip` | **0 skipped tests** and a non-trivial collected count (Q-001) |
| `tidy-check` | `go.mod`/`go.sum` are tidy |
| `govulncheck` | no known vulnerability in the dependency graph |
| `docker-build` | the image builds natively, refuses the dev key, and answers `not_indexed` over HTTP |

`test-noskip` fails on **any** skip, including a package with no test files. If
you add a package, add tests to it; do not loosen the guard.

`make ci` includes `tidy-check`, so a local `make ci` covers the same lanes CI
runs.

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

- A `Makefile`-level `SHELL := /usr/bin/true` or `MAKEFLAGS += -i`. Either is
  **one line**, and either makes every recipe in this repository a no-op —
  `contract-drift`, `test` and `test-noskip` alike. Measured with a vendored
  file edited in place: `make contract-drift`, `make test` and `make test-noskip`
  **all exit 0**. No check written inside a `Makefile` can prevent that, and
  **no CI lane catches it today**: the workflows invoke `make test` and
  `make test-noskip`, not `go test`, so they are no-opped too, and the only
  command that goes red is a direct `go test ./internal/httpapi/`, which nothing
  in CI runs. The exposure is generic to any make-driven gate, is equally true
  of `main`, and is not introduced by this lane — what is new is that it is
  written down. Closing it is **queued as a cross-repo hardening item**: an
  out-of-make check that refuses a `SHELL`, `.SHELLFLAGS` or `MAKEFLAGS`
  override anywhere in the `Makefile`, plus one required lane that runs
  `go test` without make. Until that lands, the only backstop is human review of
  the `Makefile` diff.
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
`/admin/search` surface, and `SEARCH_MODE` selection (that is core's
configuration, not this service's).

`vizra-search` never writes core tables, and core never reads schema `search`.
When this service gains tables they live in PostgreSQL schema `search` of the
core database, in a migration directory owned by this repository.
