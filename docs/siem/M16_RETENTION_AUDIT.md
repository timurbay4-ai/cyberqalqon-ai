# M16 retention audit

Audit date: 2026-10-14. Live schema: 17. No live retention setting was changed.

## Finding

The 100,000 value is an application-enforced global row budget for
`security_events`, not a dashboard or per-source query limit. The default comes
from `SIEM_EVENT_MAX_RECORDS`; `SIEM_EVENT_RETENTION_DAYS` separately defaults to
30 days. `EventRepository.ingest()` rejects records already outside that time
window, inserts accepted records transactionally, and calls `_enforce_retention()`.

Before M16, cleanup removed events older than the time cutoff and then removed
the oldest rows until the global count returned to the cap. Cleanup ran during
ingestion, not in a separate scheduler. Its decision was not recorded in the
security audit, and it did not exclude investigation evidence. A newly inserted
row could also be selected as the oldest row and disappear before the API
returned.

## M16 behavior

- Every new insert transactionally increments the durable retained-row counter.
- At pressure, age cleanup runs first and FIFO cleanup runs second.
- The just-inserted event is excluded from the same transaction's FIFO victim set.
- Events linked by `case_events`, event evidence pins, case evidence references,
  or an existing alert are protected.
- Incident-linked alert evidence is protected through its alert relationship.
- When protected evidence prevents the count returning to the cap, the database
  remains over the cap and reports `OVER_LIMIT_PROTECTED`; evidence is not deleted
  to make the metric green.
- Cleanup decisions are aggregated into one `SECURITY_EVENT_RETENTION` security
  audit record per five-minute window. The audit contains counts and policy
  parameters, never event IDs or raw payloads.
- Retention overview reads the actual row count and reports protected rows,
  over-limit rows, utilization, and oldest/newest event timestamps.

The five-minute cleanup throttle remains for below-cap operation. Because the
row counter is incremented in the same transaction as every repository insert,
the first row above the cap bypasses the throttle and triggers cleanup.

## Tests

Disposable regression covers rapid inserts at the cap, case links, evidence
references, alert-linked events, protected over-limit pressure, audit content,
and concurrent read/ingest. Tests require `quick_check=ok`, no foreign-key
violations, and the configured cap unless protected evidence requires an honest
over-limit state.

## Boundary

Retention protects normalized evidence references known to schema 17. It does
not prove a cryptographically verified cold copy exists before every ordinary
unreferenced event deletion. Raw Wazuh archives are preserved independently,
but archive-before-delete attestation remains an M17 hardening item. Schema-18
shadow findings were not activated or migrated live.
