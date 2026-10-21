# M19 batch remediation

Status: **PASS in source and disposable tests; NOT DEPLOYED**

The transaction remains whole-batch atomic. Validation and normalization finish
before `BEGIN IMMEDIATE`; one dedup query classifies the bounded batch; new rows
are inserted; retention runs once; a pre-commit deadline guard executes; and
one commit durably acknowledges the batch. Any exception before commit rolls
back every insert. No partial-success protocol was introduced.

Changes are intentionally small:

- bounded keyset retention and transaction-local bulk protection checks;
- removal of the write-path global protected count;
- detailed bounded stage counters/timers;
- safe typed timeout diagnostics;
- Operations metrics for lock wait, commit, candidate/protection latency,
  timeout/deadline counts and SQLite busy errors;
- cached/lower-bound protected-count provenance.

Correctness tests cover all-new, mixed, duplicate-only, invalid middle item,
event-ID conflict, busy writer, expired deadline, exception before commit and
commit-then-lost-response retry semantics. Replaying a committed batch returns
duplicates without extra database rows. A failed transaction produces no
acknowledgement and the shipper must leave its cursor stationary.

The v3 client remains unchanged and live batch mode remains disabled. HTTP 201
and 200 accounting, historical-v2 `UNKNOWN`, bounded backoff, malformed
separation and archive identity behavior remain governed by the M17/M18 tests.
