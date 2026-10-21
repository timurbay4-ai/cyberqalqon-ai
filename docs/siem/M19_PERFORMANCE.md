# M19 performance

Status: **PASS for isolated engineering; live throughput UNKNOWN**

Artifacts:

- `artifacts/runtime/m19-preoptimization-profile.json`
- `artifacts/runtime/m19-postoptimization-profile.json`
- `artifacts/runtime/m19-benchmark.json`
- `artifacts/runtime/m19-concurrency.json`

All databases were temporary copies or synthetic schema-17 databases with
`synchronous=FULL`. The live database was not opened by the benchmark.

| Scenario | Cap | Batch | Events/s | Request p95 | Retention p95 |
|---|---:|---:|---:|---:|---:|
| normal | 50k | 1 | 4.486 | 222 ms | n/a |
| normal | 50k | 10 | 8.257 | 1,137 ms | 938 ms |
| normal | 50k | 25 | 8.767 | 2,918 ms | 2,500 ms |
| normal | 90k | 1 | 11.102 | 97 ms | n/a |
| normal | 90k | 10 | 8.639 | 2,015 ms | 1,750 ms |
| normal | 90k | 25 | 18.765 | 1,688 ms | 1,515 ms |
| normal | 99k | 10 | 17.174 | 582 ms | 515 ms |
| normal | 100k | 1 | 10.638 | 108 ms | n/a |
| normal | 100k | 10 | 17.309 | 601 ms | 532 ms |
| normal | 100k | 25 | 18.722 | 1,372 ms | 1,281 ms |
| oldest 1,000 protected | 100k | 10 | 10.125 | 2,427 ms | 2,172 ms |
| oldest 1,000 protected | 100k | 25 | 18.288 | 1,496 ms | 1,375 ms |

Each batch row has 20 successful requests, making nearest-rank p95 meaningful;
single rows have 100. All new requests returned 201, all full replays returned
200, integrity passed, foreign-key errors were zero, and retained/state counts
matched. Python peak traced memory was 2.72–3.57 MiB. CPU totals and database
growth are in the artifact. Reported WAL growth is zero after app shutdown and
checkpoint; it is not a claim of zero physical WAL writes.

The 90k batch-10 run was slower than its single baseline, demonstrating real
cache/I/O variance. At 100k, batch-10 and batch-25 were 62.7% and 76.0% faster
than the same-run single baseline. Dense protected batch-10 did not achieve 30%
headroom over that baseline, while protected batch-25 did. These synthetic
ratios do not prove headroom over the live eligible incoming event rate.

The one-writer/three-reader 100k run completed 20 batch-10 writes and 249 reads
with no errors: writer p95 1,003.452 ms, reader p95 243.595 ms, 22,779,512-byte
WAL before close, `quick_check=ok`, and zero FK errors. No multi-writer live
design is proposed.
