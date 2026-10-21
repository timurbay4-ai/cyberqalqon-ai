# M16 delivery accounting

The backend contract is explicit:

- HTTP 201: a new event was inserted.
- HTTP 200: the deduplication identity already existed and was acknowledged.
- Other 2xx statuses are not silently interpreted as new inserts.
- Retryable transport/server outcomes do not advance the archive cursor.
- Permanent rejection is counted separately.

Source version 3 of the event shipper and the historical replayer maintain
separate accepted, duplicate, filtered, malformed, oversized, rejection and
retry counters. State readers remain compatible with older state versions and
return `null`/`UNKNOWN` for fields that were not historically captured.

The active WSL service still uses its older version-2 durable state. Its
historical `accepted` value combines outcomes that cannot now be separated.
Accordingly, the live duplicate count is **UNKNOWN** and was not inferred.

The previously reported `18,731 + 2,596 = 21,327` and “at least 20,885” values
span different observations/generations. The full rotated archive audit found
18,776 eligible records before the trusted tail offset, 45 more than the old
18,731 successful-delivery counter. That difference does not prove duplicates,
loss, or a counter reset; no durable historical field can distinguish those
possibilities. M16 preserves the discrepancy instead of correcting it.

## Malformed audit

Exactly 162 previously acknowledged malformed records were classified without
raw payload retention:

| Scope | Invalid UTF-8 | Invalid JSON | Total |
|---|---:|---:|---:|
| Original rotated prefix | 80 | 0 | 80 |
| Rotated unread tail | 72 | 2 | 74 |
| Active acknowledged prefix | 8 | 0 | 8 |
| Total | 160 | 2 | 162 |

None of these records is reported as an accepted event. The audit retains source
generation, start/end offset, SHA-256 line hash and failure category only.
