# M20 batch-10 canary readiness

Decision: **BLOCKED — readiness engineering PASS, activation prohibited**.

Current disposable evidence is favorable: 100k batch-10 request p95 1.209 s,
oldest-1,000-protected p95 1.361 s, no deadline failures, clean idempotency,
protected evidence and integrity. One-writer/three-reader concurrency completed
20 batches with writer p95 601.057 ms, reader p95 157.055 ms and no errors.

That does not meet the live gate. Before a future canary:

1. repair and verify the scoped gateway path under separate approval;
2. reconcile archive rotation without cursor reset or historical replay;
3. deploy and accept the optimized backend in single-event mode under separate
   approval;
4. prove stable liveness/readiness and bounded real single-event measurements;
5. refresh the DB and final stopped-shipper state backups;
6. record the authoritative current cursor/device/inode/size;
7. schedule one worker, batch 10, adaptive false and a bounded observation
   window; and
8. obtain the separate batch-10 canary approval.

Stop on any 5xx repetition, deadline/busy/protocol error, cursor regression,
unexpected duplicate row, integrity/FK problem, evidence-preservation risk,
relay instability or worsening backlog without adequate throughput. Batch 25
remains blocked until batch 10 is independently accepted. No M20 batch canary
ran.
