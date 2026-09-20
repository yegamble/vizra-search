@AGENTS.md

Read the meta contract in `yegamble/vizra` (`AGENTS.md`), this repository's
`AGENTS.md`, the assigned slice brief and the ADRs it cites before editing. Do
not preload the repository.

Three things in this repository are easy to get wrong and are each guarded by a
test that must not be weakened:

1. `api/search-internal.openapi.yaml` is vendored from `vizra-core` and is not
   ours to edit. Re-vendor it; never patch it to make a drift check pass.
2. `not_indexed` is a successful answer. A fault is a 5xx. Never blur them.
3. The route table's *emitted* statuses must each be provokable by a real
   request; anything else needs a written reason.

Before context compaction, preserve acceptance IDs, branch/SHA, modified files,
exact verification commands and results, blockers, and the next concrete action
in the slice execution plan under `vizra/docs/plans/`. Never replace evidence
with a narrative success summary.
