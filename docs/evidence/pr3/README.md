# PR #3 evidence — re-vendor the internal contract and HMAC vectors from core `main@4a80a1e`

Branch `chore/revendor-core-4a80a1e`, based on `main@808a5499dae1d58971d740f34749c2f35149fa4d`.

This PR is a **pin bump, not a behaviour change**. No production Go code changed; no test was
weakened, deleted, renamed or skipped.

| file | what it shows |
|---|---|
| `provenance.txt` | that the recorded `source_commit` is **on core's `main`**, what changed under core's `api/`, and that no normative vector moved |
| `revendor-run.txt` | the re-vendor performed by this repository's own command, with every digest side by side (core / vendored / manifest) and the git blob ids agreeing |
| `D-A-before-revendor-red-green.txt` | **before** the re-vendor, core `main`'s vectors file makes `TestEveryVendoredFileMatchesItsManifest` red **by name**; restore → green |
| `D-C-after-revendor-red-green.txt` | **after** the re-vendor, a one-byte edit of each vendored file turns `make contract-drift` **and** `make ci` red by name; restore → green |
| `D-V-vectors-consumed.txt` | all **5 ACCEPT** and **24 REJECT** vectors consumed from the re-vendored file, counted from the machine-readable run; **0 skips, 0 failures** |
| `lanes-local.txt` | every local lane with its exit code, and what was not run |

## What actually changed

Core `415a6d1` → `4a80a1e`, restricted to the two files this repository vendors:
**one line**, in a non-normative prose field.

```
-  "key_utf8_warning": "... must NEVER be used as VIZRA_SEARCH_HMAC_KEY, ..."
+  "key_utf8_warning": "... must NEVER be used as SEARCH_HMAC_KEY, ..."
```

`api/search-internal.openapi.yaml` is **byte-identical** across the two commits — blob
`848503cca45dc427fede810d3ab30e73e07bd392` on both sides. `api/README.md` also changed in core
but is not vendored here.

That no normative vector moved is **measured, not asserted**: `jq -cS '.vectors'` and
`jq -cS '.negative_vectors'` hash identically at `415a6d1` and `4a80a1e` (`9d7bfdc4…` and
`a835c72f…`), both sides carrying 5 and 24.

This prose change is the correction this repository asked for in the PR #2 handoff note: core's
warning named `VIZRA_SEARCH_HMAC_KEY` while the canonical contract and this service both use
`SEARCH_HMAC_KEY`. The old string is referenced nowhere else in this repository — only inside the
vendored file itself, and in PR #2's evidence, which is a historical record and is left alone.

## Digests

| file | core `4a80a1e` | vendored | manifest | bytes |
|---|---|---|---|---|
| `api/search-internal.openapi.yaml` | `a78d8aa7…a735448` | same | same | 25297 |
| `api/search-hmac-testvectors.json` | `f95623b0…2c2862` | same | same | 22321 |

Previously vendored: `ff21e6b8…3d35c3`, 22327 bytes, pinned at core `415a6d1`.

Git agrees independently of any digest this repository computes: `git hash-object` of each
vendored file equals core's blob id at `4a80a1e` (`848503cc…` and `1509da85…`).

## Why there is now a vendoring command

`scripts/vendor-contract.py` + `make vendor-contract` are new in this PR. Until now there was no
command: PR #1 and PR #2 both vendored by hand and a human typed the digests into the manifest.
Both failure modes that produces have already happened here — PR #1 recorded a commit on a feature
branch that a squash-merge then deleted, and a hand-typed `sha256` is a checksum of someone's
attention rather than of the bytes. The script is the single writer of all three files, resolves
the commit itself, refuses a commit that is not an ancestor of the branch tip, refuses a `--ref`
that is not `main`, and digests the bytes it reads **back off disk** after writing them. It only
ever reads the core checkout.

It is **not** wired into CI: CI has no core checkout, and `contract-drift` already fails on any
drift between the vendored bytes and the manifest. No CI guard, workflow or required-check
manifest was touched in this PR.

## How the demonstrations avoid scoring themselves green

`scripts/revendor-demo.sh` refuses to score a mutation it cannot prove happened. It records the
target's sha256 before and after writing each mutation and aborts with `MUTATION DID NOT APPLY` if
the digest did not move; it re-checks the digest after restoring and aborts if the file did not
come back byte for byte; it restores through an `EXIT` trap; and every red is asserted **by name**
— the lane must fail naming `TestEveryVendoredFileMatchesItsManifest` and the specific file, not
merely exit non-zero. Each mutation is a single byte inside a YAML comment or a non-normative JSON
prose string, so both files stay parseable and a parse error cannot masquerade as a digest
failure. This is the same principle as PR #2's fixture rules, applied to this PR's own evidence.

## Status

READY_FOR_REVIEW. Not VERIFIED — the builder does not verify or merge its own work.
