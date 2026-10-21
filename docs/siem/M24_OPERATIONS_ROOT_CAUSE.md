# M24 Operations P0 root-cause analysis

Status: source fix implemented and validated on disposable schema-17 databases. Live deployment was not performed.

## Failure evidence

The M23 authenticated Operations cold request exceeded the 30-second client timeout. The synchronous SQLite worker continued consuming approximately one CPU core for more than five minutes after the client had gone away. A controlled backend restart was required to end that abandoned read. Health and ingestion remained responsive, which rules out a global event-loop stall and makes a database write lock an unlikely primary cause.

The production database at the M24 audit point was schema 17, 100,000 retained events and 2,015,412,224 bytes. The failing live endpoint was not called again during M24.

## Exact request-path cause

`OperationalRepository.overview()` executed two independent full-table aggregates over `security_events` on every cold cache miss:

1. A quality aggregate performed `COUNT(*)` plus four `SUM(CASE ...)` expressions. One expression called `length(raw_event_json)` for every retained row. The live rows contain large raw and structured JSON values, so this path forced high-volume page reads and JSON-column access even though the dashboard only needed summary metadata.
2. A retention aggregate performed `COUNT(*)`, `MIN(occurred_at)`, `MAX(occurred_at)`, and `MAX(ingested_at)` across the same 100,000-row table.

Read-only `EXPLAIN QUERY PLAN` against the live schema-17 database reported:

| Query | Plan |
| --- | --- |
| Legacy quality aggregate | `SCAN security_events` |
| Legacy retention aggregate | `SCAN security_events` |
| Retained-count metadata | `SEARCH security_event_store_state USING INTEGER PRIMARY KEY (rowid=?)` |
| Oldest/newest event probes | covering `idx_security_events_occurred_id` with `ORDER BY ... LIMIT 1` |
| Last-ingested probe | covering `idx_security_events_ingested` with `ORDER BY ... LIMIT 1` |

The legacy cache was populated only after both scans completed. Equivalent concurrent cold requests therefore started duplicate work rather than sharing one computation. The Starlette worker-thread boundary protected the event loop, but HTTP cancellation did not interrupt the SQLite connection; a disconnected client could leave the worker consuming CPU indefinitely. SQLite `busy_timeout` did not help because it bounds lock waiting, not query execution.

The evidence does not support JSON response serialization, RBAC, CSRF, network relay, or Python aggregation as the dominant cause: the server-side worker remained inside the database read, the query plan shows the scans, and unrelated health/ingestion requests continued.

## Request-path redesign

The M24 implementation removes all `COUNT`, `MIN`, `MAX`, and JSON completeness aggregation over `security_events` from the Operations request path.

- Exact retained count now comes from schema-17 `security_event_store_state.retained_records`, which the existing ingestion/retention transaction maintains durably.
- Oldest/newest/last-ingested timestamps use existing covering indexes and `ORDER BY ... LIMIT 1`.
- Field-completeness totals that are not materialized in schema 17 return `UNKNOWN` with reason `NOT_MATERIALIZED_SCHEMA17`; no value is guessed.
- Retained database count, current sender state, current forward-generation counters, and unreconciled historical state remain explicitly separate.
- Historical continuity remains `UNPROVEN`.

No schema migration, backfill, historical replay, retention-policy change, batch activation, or production detection activation is required.

## Bounded execution and failure behavior

Each fresh overview owns a read-only SQLite connection. A progress handler checks both a hard two-second deadline and a per-request cancellation event. Client disconnect/coroutine cancellation sets that event; SQLite returns `interrupted`, the connection is closed in `finally`, and no write connection is touched. With no usable snapshot, the API returns a typed retryable `503` (`OPERATIONS_QUERY_TIMEOUT` or `OPERATIONS_QUERY_UNAVAILABLE`).

The cache is bounded to eight entries, at most four distinct computations, and 32 waiters per equivalent request. Equivalent misses use one single-flight owner. A verified snapshot can be served as `STALE` for at most 30 seconds while refresh is in progress or after a bounded refresh failure. Freshness, reason, hit/miss, joins, stale serves, in-flight count and waiter count are returned in the typed response.

Authentication and `soc:read` authorization still execute before cache access. The cached projection contains no analyst-specific data. CSRF behavior for mutations is unchanged.

## Frontend behavior

The Operations page now renders `FRESH`, `CACHED`, `STALE`, and `UNKNOWN` states, keeps the last bounded snapshot visible after a refresh failure, and distinguishes session expiry, permission denial, backend timeout, and backend unavailability. Unknown completeness totals display as `UNKNOWN`, never zero. Legacy continuity remains visibly `UNPROVEN`; forward service activity does not imply whole-SIEM health.

The parser accepts the preceding M23 response shape during a backend rollback and labels its old completeness values `EXACT / LEGACY_LIVE_FULL_SCAN`. This compatibility path does not cause the M24 backend to execute the legacy scan.

## Evidence

- Disposable benchmark: `artifacts/runtime/m24-operations-performance.json`
- Benchmark driver: `scripts/benchmark_m24_operations.py`
- Backend regression: `backend/tests/test_operations.py`
- Performance report: `docs/siem/M24_OPERATIONS_PERFORMANCE.md`
- Release gate: `docs/siem/M24_LIVE_ROLLOUT_GATE.md`
