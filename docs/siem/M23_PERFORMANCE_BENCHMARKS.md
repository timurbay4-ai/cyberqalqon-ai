# M23 performance benchmarks

Three evidence classes are intentionally separate.

## Disposable benchmark

- Operations at 100k: fresh p50/p95 138.617/157.173 ms; cached 0.027/0.060 ms.
- Filtered checkpoint fixture: 500 records, legacy per-record persistence 987.833 ms versus current filter+single persistence 45.512 ms.
- Checkpoint writes: 500 → 1 (99.8% reduction); cursor at EOF, accounting exact, deep chain VALID.
- 100k single-event insertion: 11.554 events/s, p95 97.128 ms.
- Concurrent 100k: zero reader/writer errors, integrity PASS.

## Read-only live observation

The 50.237-second window drained at −18,912.874 B/s average with stable generation, zero delivery errors, and 6/6 relay/gateway health. It does not prove future sustained drain.

## Live deployment acceptance

**NOT PERFORMED.** M23 source changes are not loaded by the running backend or forward service. A controlled rollout, backup, restart, observation, and rollback gate remain required.

Artifacts: `m23-performance.json`, `m23-sqlite-matrix.json`, `m23-sqlite-concurrency.json`, and `m23-live-observation.json` under `artifacts/runtime/`.
