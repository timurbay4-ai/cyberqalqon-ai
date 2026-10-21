# M17 delivery accounting

The backend contract is verified in code and tests:

- HTTP 201 plus `{status: "created", duplicate: false}` = unique insert.
- HTTP 200 plus `{status: "duplicate", duplicate: true}` = duplicate acknowledgement.
- 400/409/413/415/422 = permanent delivery rejection.
- transport errors and other server statuses = retryable.
- mismatched or malformed 200/201 bodies = protocol error.

The live and historical shippers advance a selected record only after the two
valid acknowledgement forms. Retry and protocol error preserve the record
offset. Permanent rejection is durably counted and sets a terminal `BLOCKED`
state without advancing; it is not silently skipped.

v3 counters distinguish unique insertions, duplicate acknowledgements,
filtered input, invalid JSON/UTF-8, oversized records, protocol errors,
delivery rejection and retries. The v2 live history does not: its successful
acknowledgement count remains a legacy mixed value.

`DELIVERY SUCCESS`, `DATABASE INSERT SUCCESS`, and `CURRENTLY RETAINED EVENT`
are separate facts. A 201 proves insertion; a 200 proves idempotent prior
presence. Retention may later remove an unprotected normalized event, so a
successful historical delivery is not a promise of indefinite row presence.

The preserved M16 payload-free audit remains 160 invalid UTF-8 plus two invalid
JSON records. The current active v2 state has observed one further malformed
record, but its subtype is `UNKNOWN` until a bounded generation-aware audit is
performed. No malformed record is counted as delivered.
