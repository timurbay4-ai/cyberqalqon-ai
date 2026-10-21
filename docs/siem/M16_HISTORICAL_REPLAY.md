# M16 historical replay

Status: **BLOCKED for live execution; PASS on disposable schema-17 data**.

The M16 replay implementation is intentionally separate from the live event
shipper. Every batch requires an explicit operator approval flag, is limited to
1–1,000 records, runs as one worker, and is rate-limited to 0.1–1,000 selected
records per second. Durable state is scoped to one immutable archive generation.

The replay state records accepted, duplicate, filtered, malformed, oversized,
delivery-rejected and retry counters. A transient delivery result pauses without
advancing the current record. Pause/resume, crash-safe offsets, EOF digest
validation and idempotent duplicate acknowledgment are covered by unit tests.

A deployment regression replays a disposable gzip archive through the normal
authenticated schema-17 ingest API. The first delivery returns HTTP 201, the
replay of the same evidence returns HTTP 200 duplicate, the database retains one
row, and `quick_check` remains `ok`.

## Live approval gate

Live replay was not started because:

- the live event store is already at its 100,000-row configured budget;
- protected evidence may legitimately push the store over budget;
- 53,748 eligible records remain in the audited rotated tail;
- current live backlog is still being handled by the existing shipper;
- the new replay CLI is source-tested but not deployed into the privileged WSL
  service installation;
- the user has not separately approved live historical replay or a retention
  policy change.

Approval must specify the generation, maximum rate, batch size, monitoring and
stop thresholds, database capacity decision, and rollback/pause procedure. It
must not reset the live cursor or start a second uncontrolled reader.
