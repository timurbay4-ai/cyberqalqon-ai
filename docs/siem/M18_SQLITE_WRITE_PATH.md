# M18 SQLite write path

## Transaction boundary

One batch performs:

1. strict envelope and event normalization before owning the writer lock;
2. one connection and `BEGIN IMMEDIATE`;
3. two bounded `IN` lookups for all event and deduplication identities;
4. one bounded lookup for all source alert IDs;
5. deterministic ordered inserts inside the same transaction;
6. one durable retained-record counter increment;
7. at most one retention invocation for the batch;
8. a deadline check immediately before commit;
9. one commit, followed by the HTTP acknowledgement.

Any exception rolls the entire transaction back. Same-batch repeated evidence
is classified as DUPLICATE. The same `event_id` with different evidence is a
conflict and rolls back earlier rows in that batch.

## Preserved properties

- WAL journal mode and `synchronous=FULL` remain unchanged.
- Foreign keys remain enabled by every application connection.
- Existing index and FTS semantics remain unchanged.
- Alert, incident, case and evidence links are not rewritten.
- Only one shipper request is outstanding; no connection pool or concurrent
  writer was introduced.
- Schema remains 17; M18 adds no migration.

The bulk optimization is transaction and lookup amortization, not unsafe PRAGMA
tuning. At 10k cap the batch-10 commit p95 was 31 ms while the transaction p95
was 204 ms. At larger caps retention/index work, not commit alone, dominated.

## Failure safety

Tests cover rollback on invalid input, event-ID conflict, pre-commit deadline,
simulated crash before retention/commit, SQLite busy and internal database
errors. Commit-then-lost-response is recovered through full-batch idempotent
replay; it never assumes a timeout means no insert.
