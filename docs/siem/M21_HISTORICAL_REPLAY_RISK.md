# M21 historical replay risk

Status: **DESIGNED ONLY — NOT EXECUTED**.

## Outcomes that must not be conflated

- **A. Forward ingestion:** deliver records arriving after an approved new
  boundary. It says nothing about older bytes.
- **B. Historical replay:** submit preserved archive records from explicit
  per-generation checkpoints at a bounded rate.
- **C. Full historical continuity:** prove all source telemetry was collected
  without gaps. Existing downtime contradicts this claim.
- **D. Exactly-once restoration:** prove every eligible record was committed
  once or durably duplicate-acknowledged. Retention-capped identities and the
  unsigned exact-cursor interval do not provide this proof.

A or B may be operationally useful, but neither proves C or D.

## Future replay plan

1. Freeze an evidence inventory for every generation, including stored and
   decoded hashes, sidecars, boundaries and malformed counts.
2. Use one independent checkpoint per immutable generation. Never copy the
   legacy cursor onto a different inode.
3. Freeze the selector/canonicalization version and dry-run fingerprints
   against a payload-free retained identity export.
4. Audit exact fingerprint matches as proven retained duplicates; treat
   source-ID-only matches as probable; treat retained absence as uncertain.
5. Replay in chronological generation order with one controlled writer,
   bounded single-event rate, idempotent 200/201 accounting and durable audit.
6. Do not synthesize uncollected downtime events or the day-19 NUL tail.
7. Measure retention deletion and preserve incident/case evidence before each
   batch. Current 100,000-event capacity can evict unrelated rows.
8. Stop on source mutation, cursor mismatch, malformed-policy drift, repeated
   5xx, protocol error, rejection, integrity failure or resource pressure.

## Irreversible risks

- New inserts can evict older retained events under the unchanged cap.
- Records previously ingested but aged out may be inserted again because the
  database is not a permanent idempotency ledger.
- Replaying preserved files cannot recover source events never collected.
- Operator acceptance of unsigned provenance is a risk decision, not a new
  technical proof.

Historical replay therefore requires a separate retention-impact rehearsal,
resource budget, exact generation list, bounded rate and explicit approval.
