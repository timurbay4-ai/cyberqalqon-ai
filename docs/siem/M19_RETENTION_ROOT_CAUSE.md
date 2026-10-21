# M19 retention root cause

Status: **ROOT CAUSE PROVEN for the slow design; live fix not deployed**

At the 100,000-event cap, every new event requires removal of an old deletable
event. The old transaction did the following once per batch:

1. select/delete retention candidates;
2. scan all protected evidence through a UNION;
3. join that UNION back to all security events to obtain an exact count;
4. fire the FTS delete trigger for each removed event;
5. update metadata/audit and commit with `synchronous=FULL`.

The exact protected count was redundant for enforcing the cap. It was used only
for an observational audit value, yet the representative backup measured it at
6.46–21.57 seconds. Its plan scans `security_events` for alert links, scans it a
second time for the outer join, and builds/searches a temporary UNION result.

The M19 remediation:

- uses the durable retained counter between five-minute reconciliation sweeps;
- selects oldest candidates by `(occurred_at,event_id)` keyset order;
- performs four bounded, transaction-local protection checks per page;
- deletes exactly the selected unprotected IDs once per batch;
- never performs the exact global protected count in the write transaction;
- records an honest `LOWER_BOUND` from protected skips when evidence forces an
  explicit `PROTECTED_OVER_LIMIT` result;
- uses cached/lower-bound audit data for Operations instead of a dashboard scan.

No evidence decision is cached across transactions. New events in the current
batch are preserved. Case links, incident pins, case evidence and alert-linked
events remain deletion barriers. Ordering is deterministic, and an inability to
reach the configured cap is explicitly audited rather than hidden.

Before/after on the same 100k backup shape:

| Measure | Before | After |
|---|---:|---:|
| Batch-10 retention p50 | 7,516 ms | 1,281 ms |
| Batch-10 transaction p50 | 7,571.612 ms | 1,347.404 ms |
| Five-minute full-sweep retention | 11,937 ms | 1,375 ms |
| Global protected count in normal write | yes | no |

The old count is 83.0% of the baseline retention p50. The after path is 82.9%
faster at p50. These are disposable-copy results, not a live production claim.
