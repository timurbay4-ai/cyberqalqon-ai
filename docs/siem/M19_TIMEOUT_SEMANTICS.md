# M19 deadline and timeout semantics

Status: **PASS with explicit transport limitation**

The 15-second repository deadline starts immediately before retention-time
validation. It therefore includes validation, database connection, lock wait,
deduplication, alert lookup, inserts and retention. It excludes HTTP reception,
API-key authentication, JSON parsing and normalization.

Guards run after lock acquisition, deduplication, alert lookup, during the
insert loop, and immediately after retention. SQLite calls are synchronous and
cannot be interrupted safely by the Python guard; a long statement is detected
when it returns. The guard is deliberately pre-commit. Once commit begins, the
server completes it and returns the durable outcome even if commit crosses the
nominal budget. Returning a speculative timeout after a successful commit would
create a more ambiguous acknowledgement.

If cancellation or an exception occurs before commit, `rollback()` runs. A
client/network timeout does not prove the server failed; the v3 shipper retries
the same deterministic identities and advances the cursor only after a valid
201/200 acknowledgement. If commit succeeded but the response was lost, retry
is duplicate-only and safe.

The timeout exception now records only a bounded stage and numeric timings. The
Operations counters distinguish deadline violations and SQLite operational
errors. The timeout was not increased; isolated optimized p95 values are well
below 15 seconds. HTTP socket acknowledgement time remains measured by the
shipper, not fabricated by the backend.
