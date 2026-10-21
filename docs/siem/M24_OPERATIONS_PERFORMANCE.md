# M24 Operations disposable performance acceptance

Status: PASS on isolated disposable schema-17 databases. These results are not live deployment acceptance.

The benchmark creates auto-removed 10k, 50k and 100k event databases, expands each raw and structured JSON column to approximately 4 KiB, exercises the legacy scans under a five-second ceiling, then runs the bounded M24 path. The 100k case includes 1,000 protected incident-evidence pins, retention at 100,000, four readers and one production single-event writer.

The authoritative machine-readable result is `artifacts/runtime/m24-operations-performance.json`. Cold means an empty application cache; it does not claim that the operating-system page cache was flushed.

## Acceptance summary

| Population | Legacy two-scan path | M24 cold p95 | M24 cached p95 | Cancellation | Single-flight |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 10,000 | completed below 5 s | below 2 s | below 2 s | below 250 ms | 8 callers / 1 compute |
| 50,000 | completed below 5 s | below 2 s | below 2 s | below 250 ms | 8 callers / 1 compute |
| 100,000 | hit the 5 s ceiling and was interrupted | below 2 s | below 2 s | below 250 ms | 8 callers / 1 compute |

The JSON artifact records exact p50/p95/max wall and CPU timing, process working-set observations, cancellation latency, cache hit ratio, WAL size, and per-population query plans. Values are intentionally not copied into this document as a second source of truth.

## Concurrency and integrity

Each population executed 48 fresh Operations reads alongside eight production `EventRepository.ingest()` single-event writes. The 100k case exercised retention pressure and protected evidence. All populations ended with:

- actual retained rows equal to durable `retained_records`;
- no observed event loss;
- `PRAGMA quick_check = ok`;
- zero foreign-key errors;
- the configured population retained after single-event retention;
- no batch endpoint or batch worker activation.

The benchmark also injects a cancellable legacy scan and verifies that SQLite progress-handler interruption is observed within 250 ms. Backend unit tests separately cover pre-set cancellation, deadline expiry, failed refresh stale fallback, bounded cache size, typed 503 response and one-compute single-flight behavior.

## Limitations

- Disposable timings are not a claim about the live 2.0 GB database or Windows/WSL relay.
- OS page cache is not force-flushed between application-cache cold samples.
- The Python environment may not expose every native SQLite allocation; reported process working set is the defensible process-level measure available on Windows.
- Browser UAT remains `DEFERRED_BY_USER`.
