# M18 retention fast path v2

The live policy remains 30 days and 100,000 normalized events. M18 changes the
frequency of safe work, not the policy.

- A new batch increments the durable retained counter once.
- The existing five-minute age sweep remains the reconciliation boundary.
- At the cap, limit cleanup runs once per batch rather than once per event.
- All newly inserted batch IDs are protected from immediate deletion until
  they have been durably acknowledged.
- Case links, incident pins, case evidence references and alert-linked events
  remain excluded from deletion.
- Deletion remains chronological by `occurred_at, event_id` and bounded by the
  exact overflow.
- If only protected/newly inserted evidence remains, the store truthfully
  reports `OVER_LIMIT_PROTECTED`; it never deletes protected evidence to make a
  metric green.

The 10k stage profile measured retention p95 of 110 ms for batch 10 and 282 ms
for batch 25. The 50k/100k benchmarks show that retention pressure is nonlinear
and that 100 is not automatically optimal. Protected-evidence pressure and
counter correctness are covered by repository and API regressions.

Historical replay remains disabled. Old rotated archives are not admitted into
active retention merely because a new endpoint exists.
