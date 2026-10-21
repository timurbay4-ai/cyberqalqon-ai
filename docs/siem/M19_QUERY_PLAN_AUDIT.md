# M19 query-plan and index audit

Status: **PASS with future schema recommendation**

Artifact: `artifacts/runtime/m19-query-plan-audit.json`.

## Findings

- `idx_security_events_occurred_id` drives the oldest-event keyset scan. The
  100k backup returned 10/25 candidates in 0.974/0.648 ms in one read-only run.
- Primary/unique indexes cover event and deduplication identity.
- `idx_case_events_event(event_id,case_id)` supports case-link protection.
- Incident pins are indexed by incident/order, not
  `(evidence_type,evidence_id)`; bounded protection lookup scans its autoindex.
- Case evidence is indexed by case/order, not
  `(reference_type,reference_id)`; bounded lookup likewise scans.
- Alert PK lookup is efficient for bounded candidate references.
- `security_events_fts.event_id` is `UNINDEXED`. The delete trigger therefore
  reports `SCAN security_events_fts VIRTUAL TABLE INDEX 0:` once per deleted
  row. A rowid predicate uses the efficient `INDEX 0:=` path.
- On the verified backup, all 100,000 base/FTS rows had aligned rowids; checking
  that relationship itself took 3,900.417 ms and is not a live-path operation.

There are 22 event indexes and three FTS maintenance triggers. Adding more
event-table indexes without evidence would increase every insert/delete. No
index or trigger schema change was made in M19 and schema remains 17.

## Separate migration proposal

A future, separately approved migration should benchmark:

1. `(evidence_type,evidence_id)` on `incident_evidence_pins`;
2. `(reference_type,reference_id)` on `case_evidence_refs`;
3. an FTS design whose row deletion is keyed by stable rowid rather than an
   unindexed event-ID scan, including a full consistency rehearsal.

That proposal must measure index size, write amplification, migration duration,
rowid/FTS consistency, WAL growth and rollback. It cannot be applied directly
to live schema 17, and schema 18 remains explicitly blocked.
