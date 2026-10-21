# M17 ingestion bottleneck

## Measured live trend

Two bounded samples on the same archive generation span 558.181 seconds.
Cumulative endpoints, including the interval between samples, show:

| Metric | Rate |
|---|---:|
| Archive growth | 29,158.086 bytes/s |
| Cursor progress | 20,297.245 bytes/s |
| Net lag growth | **8,860.841 bytes/s** |
| v2 successful acknowledgements | 1.478014/s |
| Filtered records | 2.522477/s |
| Retention insert proxy | 1.478014/s |

The archive grew by 16,275,502 bytes while the cursor moved 11,329,545 bytes;
lag increased by 4,945,957 bytes. Classification is **WARNING / GROWING**.
There is no drain ETA.

The v2 acknowledgement counter mixes new inserts and duplicate
acknowledgements. Eligible generation rate, unique inserts and duplicates are
therefore `UNKNOWN`. Byte rates are exact endpoint deltas; record counts are
not inferred from bytes.

## Limiting stages

Evidence identifies two serial costs rather than CPU saturation:

1. The live shipper performs one reused-connection HTTP request per selected
   record through the Windows/WSL relay.
2. Every new event uses an individual `BEGIN IMMEDIATE` transaction. At the
   exact 100,000-row cap, pre-M17 retention re-evaluates an archive-wide age
   predicate for each insertion.

The M16 disposable 100,000-row probe measured 978.488 ms for one real
insert-plus-retention operation. Live relay health samples were 168–412 ms,
and later backend health took 7,145 ms while ingestion remained active. The
passive validator consequently reported backend, frontend proxy and WSL relay
health failures at its unchanged five-second budget.

Host CPU was 26% at baseline and disk capacity was adequate. Free RAM was only
about 0.79 GiB, so parallel workers and heavyweight benchmarks were rejected.
WAL remained 12,701,992 bytes across the rate samples. SQLite busy/lock event
frequency and host disk I/O throughput are `UNKNOWN`; no instrumentation exists
that can state those values truthfully without a live invasive benchmark.

## Bounded optimization

Retention now uses its transactionally maintained exact row counter for
between-sweep cap enforcement and keeps the full age sweep/reconciliation on a
five-minute boundary. Protected-evidence predicates and the 100,000 cap remain
unchanged. At a disposable 50,000-row cap, three A/B operations measured a
legacy median of 255.774 ms and optimized median of 144.854 ms (1.766x).
Integrity, foreign keys, row cap and durable retained counter all passed.

This source change is not represented as a live recovery until the running
backend process is reloaded through a controlled application maintenance step.
