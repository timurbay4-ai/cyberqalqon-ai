# M16 capacity benchmark

`scripts/benchmark_m16_capacity.py` used one automatically removed schema-17
database. It never opened the live database. Inserts were sequential and bounded;
the concurrency probe used four read workers/eight reads. Each checkpoint passed
`quick_check` and foreign-key validation, then exercised the real M16 retention
path with a synchronized repository counter.

| Events | DB bytes | Insert rows/s | Event query p95 | Workbench p95 | IOC p95 | Retention |
|---:|---:|---:|---:|---:|---:|---:|
| 50,000 | 178,409,472 | 325.6 | 9.674 ms | 206.956 ms | 656.324 ms | 505.349 ms |
| 100,000 | 365,088,768 | 244.0 | 12.000 ms | 252.804 ms | 759.855 ms | 978.488 ms |
| 150,000 | 551,047,168 | 205.1 | 11.053 ms | 252.403 ms | 693.378 ms | 1,379.086 ms |
| 250,000 | 927,862,784 | 213.2 | 14.337 ms | 348.143 ms | 811.347 ms | 39,505.217 ms |

At every checkpoint, the retention probe inserted one row, deleted exactly one
ordinary oldest row, returned to the exact cap, recorded `ENFORCED`, reported
zero protected/over-limit rows, and left the durable count equal to the actual
count. The four-reader wall time ranged from 2,271 to 3,764 ms; the slowest
individual read ranged from 1,189 to 1,934 ms.

The synthetic rows consumed about 3.6–3.7 kB per event, but the live 100,000-row
database was about 1.94–2.00 GB because its payload/index mix is materially
larger. Synthetic size must not be used as a live storage forecast.

The 500,000 checkpoint was not run because host free memory was low. The 250,000
retention spike and the live database's larger bytes/event make 100,000 the
conservative current target. Raising the live cap is not approved or recommended
until cold-storage attestation, lower-memory testing and replay backpressure are
in place. These measurements are local observations, not an SLA.
