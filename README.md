# vizra-search

Vizra internal search service: PostgreSQL FTS/trigram + Redis,
HMAC-authenticated, ranked IDs only, never a hard dependency (component of
[yegamble/vizra](https://github.com/yegamble/vizra)).

## Status: M0 — a real service that answers honestly

Per the **Q-001** ruling (`vizra/docs/adr/ADR-002`, accepted 2026-09-20),
`vizra-search` exists from M0 as a real minimal service rather than a
placeholder. It currently owns no migrations, no index and no database, and it
says so:

| Operation | Auth | M0 behaviour |
|---|---|---|
| `GET /healthz` | none | `200 {"status":"ok"}` — liveness only, 200 even while draining |
| `GET /readyz` | none | `200 {"status":"ok","components":[],"search_schema_version":null,…}`; `503 {"status":"unavailable"}` while draining |
| `GET /version` | none | build identity, with `search_schema_version: null` |
| `POST /internal/v1/search` | HMAC | `200 {"status":"not_indexed","results":[],"total":0,…}` |
| `POST /internal/v1/suggestions` | HMAC | `200 {"status":"not_indexed","suggestions":[]}` |
| `POST /internal/v1/events` | HMAC | `200 {"status":"not_indexed","accepted":0,"duplicates":0}` |

`not_indexed` is a **successful** answer meaning "I hold no index; use your own
SQL path". Core treats it as an instruction to fall back, not as a fault. A
5xx, a rejected signature or a timeout *is* a fault: core still serves from SQL
but reports `search: degraded` and `vizra doctor` FAILs. Search is never a hard
dependency, and the fallback is never silent.

## The contract

`api/search-internal.openapi.yaml` is a byte-identical vendored copy of the
canonical document owned by `vizra-core`; `api/CONTRACT-SOURCE.json` records its
source commit and sha256. Both repositories drift-check it, so a change on one
side turns the other red. **Do not edit the vendored copy** — see `AGENTS.md`.

## Running it

```sh
make run     # development mode on :8081 with the documented dev key
make ci      # every required lane: fmt, vet, echo-containment, build,
             # contract-drift, test -race, test-noskip, and nothing skipped
make docker-build
```

Production mode is the default, and it refuses an empty key, the documented
development key, a short key or a placeholder. Configuration is documented in
`AGENTS.md`.
