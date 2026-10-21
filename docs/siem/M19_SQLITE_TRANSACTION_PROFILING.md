# M19 SQLite transaction profiling

Status: **PASS — source instrumentation and disposable evidence**

## Instrumented boundary

The batch response now exposes monotonic, non-sensitive timings for request
reception, API-key authentication, JSON parsing, schema validation,
normalization, connection setup, `BEGIN IMMEDIATE` lock wait, deduplication,
alert lookup, inserts, retention sub-stages and commit. It also reports SQL
statement count, considered/deleted retention rows, protected skips and whether
a full age sweep ran.

The SQLite trace callback counts statements only for one batch connection. It
does not retain or log SQL text and is not enabled globally. Timeout logs contain
only the bounded stage name and numeric timings; payloads, event identifiers,
headers and credentials are excluded.

| Requested phase | Measurement |
|---|---|
| Request reception/routing | middleware monotonic delta |
| Authentication | constant-time key check duration |
| JSON/schema/normalization | distinct route timers |
| Connection | `_connect()` duration |
| Lock/BEGIN | `BEGIN IMMEDIATE` duration |
| Dedup/alert lookup/insertion | distinct repository timers |
| Index maintenance | included in insertion/delete SQLite call; not separable by sqlite3 |
| Retention | state, age delete, count, candidate, protection, delete, metadata, audit |
| WAL synchronization | included in `commit_ms`; SQLite exposes no finer Python timer |
| Response serialization | outside the route-return boundary; not claimed |
| Network acknowledgement | shipper request latency is authoritative; not claimed by backend |

## Representative schema-17 backup

`artifacts/runtime/m19-postoptimization-profile.json` used an immutable source
backup and auto-removed writable copy. Ten batch-10 samples at 100k records
reported:

- transaction p50 1,347.404 ms; p95 1,491.578 ms; max 2,314.234 ms;
- retention p50 1,281 ms; p95 1,422 ms;
- candidate selection p95 15 ms;
- commit p95 47 ms;
- lock wait p95 0 ms;
- maximum 273 traced SQLite statements, including trigger work;
- 100k database/state counts and zero foreign-key errors.

The remaining dominant normal-path stage is retention deletion, principally the
schema-17 FTS delete trigger. Detailed timing is intentionally run only against
disposable copies.

## Diagnostic truth boundaries

In-process percentiles reset on backend process start and are labelled
`POST_PROCESS_START_ONLY`. Historical v2 unique/duplicate counts remain
`UNKNOWN`. Operations protected-evidence counts now come from the latest audit
and explicitly say `EXACT`, `LOWER_BOUND`, `CACHED`, or `NOT_MEASURED`; dashboard
reads no longer trigger the expensive global count.
