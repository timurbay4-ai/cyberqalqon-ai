# M18 performance evidence

`artifacts/runtime/m18-benchmark.json` is a disposable TestClient benchmark on
schema 17 with FULL synchronous durability, 100 new events plus a full duplicate
replay per variant. Temporary databases were automatically removed; the live DB
was never opened by the benchmark.

| Cap | Batch | Insert events/s | Speedup | Request p95 ms | Retention p95 ms | HTTP requests/event |
|---:|---:|---:|---:|---:|---:|---:|
| 10k | 1 | 8.338 | 1.000x | 127.444 | n/a | 1.00 |
| 10k | 10 | 23.895 | 2.866x | 250.705 | 125 | 0.10 |
| 10k | 25 | 24.926 | 2.989x | 519.755 | 282 | 0.04 |
| 10k | 50 | 25.679 | 3.080x | 957.053 | 578 | 0.02 |
| 10k | 100 | 26.556 | 3.185x | 1,836.078 | 1,188 | 0.01 |
| 50k | 1 | 2.733 | 1.000x | 543.215 | n/a | 1.00 |
| 50k | 10 | 8.446 | 3.090x | 794.201 | 672 | 0.10 |
| 50k | 25 | 11.839 | 4.332x | 1,613.318 | 1,391 | 0.04 |
| 50k | 50 | 13.678 | 5.005x | 2,804.533 | 2,453 | 0.02 |
| 50k | 100 | 12.250 | 4.482x | 5,671.759 | 4,969 | 0.01 |
| 100k | 1 | 2.319 | 1.000x | 475.186 | n/a | 1.00 |
| 100k | 10 | 6.622 | 2.856x | 1,348.426 | 1,235 | 0.10 |
| 100k | 25 | 4.255 | 1.835x | 5,905.801 | 5,547 | 0.04 |
| 100k | 50 | 6.873 | 2.964x | 5,478.206 | 5,109 | 0.02 |
| 100k | 100 | 7.023 | 3.028x | 12,253.990 | 11,531 | 0.01 |

All 15 variants returned 201 for new rows, 200 for full replay, `quick_check=ok`,
zero foreign-key errors and the exact configured retained count. Peak traced
Python memory was approximately 2.6–3.5 MiB per variant. CPU totals and DB/WAL
growth are recorded in the JSON artifact. WAL growth appears zero because each
isolated app closed/checkpointed before measurement; it is not a claim of zero
physical writes. Device-level disk bandwidth and variance across repeated full
runs remain unmeasured.

The conservative canary recommendation is batch 10, optionally 25 after stable
evidence. Batch 100 has unacceptable per-request latency at the live-size cap.

The synthetic ceiling exceeds the prior mixed live acknowledgement rate but
does not prove 30% headroom over the current eligible incoming rate. Current
live lag grew 17,318.58 B/s between M18 snapshots, so backlog stabilization and
recovery are both WARNING, not PASS.
