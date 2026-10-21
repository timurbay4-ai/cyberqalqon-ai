# M18 ingestion profiling

## Measured path

```mermaid
flowchart LR
  A[Wazuh archives.json] --> B[bounded reader and filter]
  B --> C[one persistent httpx client]
  C --> D[WSL relay and TCP 16000 portproxy]
  D --> E[FastAPI validation and normalization]
  E --> F[BEGIN IMMEDIATE]
  F --> G[indexed idempotency lookup]
  G --> H[event and FTS/index writes]
  H --> I[one bounded retention pass]
  I --> J[durable commit]
  J --> K[typed acknowledgement]
  K --> L[atomic v3 cursor state write]
```

The M18 baseline proved that the deployed `batch=25` is only a local archive
read bound. Every eligible record still uses one HTTP request, one SQLite
connection, one transaction, one retention invocation and one commit. The
client already reuses one `httpx.Client`, so missing keep-alive was not the
primary problem.

## Stage measurements

`artifacts/runtime/m18-stage-profile.json` used disposable schema-17 databases
at the 10,000-row cap, 100 new events and synchronous FULL. Values are backend
response timings; client p95 includes TestClient overhead.

| Stage p95 | Batch 10 | Batch 25 |
|---|---:|---:|
| Request body parse | <1 ms | <1 ms |
| Normalize | 31 ms | 63 ms |
| Database total | 219 ms | 438 ms |
| Transaction | 204 ms | 437 ms |
| Retention | 110 ms | 282 ms |
| Commit | 31 ms | 31 ms |
| Backend total | 250 ms | 500 ms |
| Client request | 259.6 ms | 508.5 ms |

Parsing is negligible and normalization scales approximately with event count.
The dominant work is the indexed SQLite write plus protected-evidence retention
at the cap. Commit/fsync is visible but is amortized by the batch. Removing
indexes or weakening `synchronous=FULL` was rejected.

## Live evidence

At the 2026-10-15 M18 baseline the live single-event request point was 807.15
ms. The pre-deployment snapshot later observed 15,020.213 ms and retry growth
under simultaneous archive growth and read-only validation/backup I/O. These
are point samples, not p95 values. Over 3,865.668 seconds between bounded
snapshots:

- archive growth: 22,067.46 B/s;
- cursor progress: 4,748.88 B/s;
- net lag growth: 17,318.58 B/s.

Therefore the live pipeline is not recovered. The synthetic improvement is
engineering evidence only; Windows/WSL network time and device-level disk
throughput were not isolated as independent distributions.

## Query and lifecycle findings

- Idempotency uses the unique `event_id` and `deduplication_id` indexes.
- Oldest-first limit retention uses `idx_security_events_occurred_id`.
- Protected evidence uses indexed alert/case/incident references, but still
  adds correlated lookup cost for each deletion candidate.
- The event table has 20 explicit secondary indexes plus primary/dedup indexes
  and FTS maintenance. They are retained because search regressions require
  them and no safe redundant index was proven.
- Single-event mode keeps its established connection-per-request behavior.
  Batch mode opens one connection and one transaction for the entire bounded
  batch.
- WAL mode and FULL synchronous durability remain unchanged.
