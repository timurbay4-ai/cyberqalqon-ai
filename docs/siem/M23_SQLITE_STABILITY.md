# M23 SQLite and retention stability

All tests used disposable schema-17 databases with WAL and full durability. The live schema and retention policy were unchanged.

| Scenario | Result |
| --- | --- |
| 50k, 90k, 99k, 100k populations | PASS |
| 100k with oldest 1,000 protected | PASS |
| Unique/duplicate HTTP semantics | PASS (201/200 separated) |
| quick_check / foreign keys | `ok` / 0 for every variant |
| retained count/state count | exact for every variant |
| 3 readers + 1 writer at 100k | 216 reads, 20/20 writes, zero errors |

At 100k single-event, insertion throughput was 11.554 events/s and request p50/p95 77.452/97.128 ms. The concurrent test measured reader p50/p95 147.039/175.678 ms and writer-batch p50/p95 602.225/644.320 ms; WAL reached 22,837,192 bytes before close. Protected batch-10 retention p50/p95 was 343/437 ms.

The benchmark matrix also contains batch variants for comparative diagnosis only. Batch-10/25 remain disabled in production. The experimental reverse-map/FTS schema change remains a separate schema approval gate.

Evidence: `artifacts/runtime/m23-sqlite-matrix.json` and `artifacts/runtime/m23-sqlite-concurrency.json`.
