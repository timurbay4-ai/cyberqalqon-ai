# M19 failed-canary forensics

Status: **PASS with one retained uncertainty**
Evidence date: 2026-10-15

## Reconstruction

The M18 batch-10 canary ran for 214.232 seconds with one worker. Its durable
cursor advanced from 42,723,427 to 44,749,863 only after successful HTTP
acknowledgements. The 23 batch requests split into 17 HTTP 201, one HTTP 200 and
five HTTP 503 responses. The 18 successful requests acknowledged 165 items:
155 unique insertions and 10 duplicate acknowledgements. The duplicate-only
retry accounts for the HTTP 200; it did not create duplicate database rows.

HTTP request counts are not event counts. A 201 can acknowledge a mixed batch,
and a 503 acknowledges no items. The final checks found no duplicate event IDs,
no duplicate deduplication IDs, `quick_check=ok`, and zero foreign-key errors.
The shipper recorded six additional retry attempts, zero protocol errors and
zero delivery rejections. A retry can arise without a distinct HTTP 503, so six
retries must not be relabelled as six server failures.

## 503 attribution

The contemporaneous M18 report classified all five 503s as retryable
pre-commit deadline failures. The retained Uvicorn access log independently
confirms exactly five 503 responses. The final failed-canary state records a
15,020.169 ms last request and a retry category. No SQLite busy/lock exception,
4xx, protocol error, or delivery rejection was recorded.

There is an important forensic limitation: the access log retained status
codes but not the typed JSON error bodies or stage timings. The old route could
also emit 503 for a SQLite operational/database failure. Therefore the
aggregate attribution to the 15-second deadline is **high confidence**, but the
exact error code for each of the five individual responses is **UNKNOWN** from
raw retained logs. M19 adds safe stage/timing logging so this ambiguity will not
recur.

## Measured causal chain

The verified pre-canary schema-17 backup was opened read-only. The old exact
protected-evidence count took 6,462.776 ms in the baseline sample and later
varied up to 21,574.146 ms under host I/O pressure. It scans the wide 100k-event
table twice. Baseline disposable batch-10 retention was 7,516 ms p50, the full
five-minute sweep was 11,937 ms, and maximum transaction time was 10,685.665
ms. The FTS delete trigger then performs an event-ID virtual-table scan once per
deleted row. The combined cost and I/O variance can cross the 15-second guard.

This proves the near-capacity retention design contained operations capable of
consuming most or all of the deadline. It does not retroactively provide the
missing per-request M18 stage trace.

## Outcome classification

| Item | Result |
|---|---|
| Durable successful batch inserts | PASS |
| Duplicate retry idempotency | PASS |
| Failed request cursor safety | PASS |
| Five 503 count reconstruction | PASS |
| Aggregate deadline attribution | PASS (high confidence) |
| Per-503 typed error attribution | UNKNOWN |
| Production performance after M19 | NOT TESTED / blocked by approval gate |

Sources: `M18_LIVE_CANARY_VALIDATION.md`, retained canary access logs, failed
v3 state backup, and `artifacts/runtime/m19-preoptimization-profile.json`.
