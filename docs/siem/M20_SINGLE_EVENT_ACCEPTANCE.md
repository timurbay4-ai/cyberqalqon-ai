# M20 single-event acceptance

Status: **source/disposable PASS; live acceptance BLOCKED**.

The optimized retention code does not require batch mode. Source and isolated
tests prove:

- API-key authorization remains mandatory.
- HTTP 201 acknowledges a durable new insert; HTTP 200 acknowledges an exact
  idempotent replay.
- Failed pre-commit work rolls back; commit-then-lost-response replay is
  duplicate-only.
- The shipper advances its cursor only after a valid 201/200 contract response.
- One worker, single-event protocol and batch-disabled defaults remain intact.
- Alert links, incident pins, case evidence and case-event links remain
  deletion barriers.
- Keyset retention ordering is deterministic and the global exact protected
  count is absent from the write path.
- Schema 17, foreign keys, audit decisions and `LOWER_BOUND` provenance pass.

At 100k disposable capacity, single ingestion measured 5.519 events/s with
request p95 186.684 ms; exact replay returned HTTP 200 and integrity remained
clean. The production-like source backup profile measured batch-10 transaction
p50 1,032.985 ms, p95 1,703.189 ms and full sweep 994.350 ms. These numbers are
not live acceptance.

Live production acceptance is unavailable because the backend listener is
absent, the gateway path times out and the shipper cursor names a rotated inode.
No synthetic result is substituted for a real operational result.
