# M20 schema and FTS index readiness

Status: **candidate proven disposable; live migration BLOCKED**.

The schema-17 retention candidate plan uses
`idx_security_events_occurred_id`: 10/25 candidate reads took 0.379/0.095 ms.
The dominant cost is the `security_events_fts_delete` trigger. FTS5 declares
`event_id UNINDEXED`, so every row deletion searches the FTS virtual table by
an unindexed text field. On the fresh 100k backup, batch-10 retention delete
p95 was 937 ms and the complete full sweep was 994.350 ms.

Existing schema 18 is `advanced_detection_readiness`; it does not repair this
FTS path. It remains unapplied.

## Disposable candidate

`scripts/benchmark_m20_fts_candidate.py` created a normal table mapping
`event_id -> FTS rowid` and rewrote only the three FTS maintenance triggers on
a disposable copy. Results:

- 100,000 mapping rows; zero missing/invalid mappings;
- migration 1.400 seconds;
- database growth 8,331,264 bytes (0.41% of the 2.014 GB source);
- batch-10 transaction p50/p95 31/62 ms;
- retention-delete p50/p95 0/0 ms at timer resolution;
- commit p95 16 ms;
- `quick_check=ok`, FK errors 0, duplicate event-ID groups 0;
- reverse rollback 0.041 seconds, all three original triggers restored,
  post-rollback integrity clean.

This is strong justification for a future migration after schema 18, not
permission to change the live schema. A production proposal must version the
map as a new migration, verify FTS rowid stability, quantify insert/update
write amplification and free-disk headroom, take a fresh backup, rehearse
upgrade/rollback on the current backup, and obtain explicit schema approval.
No application-only safe change can make an FTS5 `UNINDEXED` column searchable
without either changing trigger/schema design or rebuilding the FTS layout.
