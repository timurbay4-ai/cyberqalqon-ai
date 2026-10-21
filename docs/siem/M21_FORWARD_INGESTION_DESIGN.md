# M21 independent forward-ingestion design

Status: **SOURCE-IMPLEMENTED, DISPOSABLE-TESTED, NOT LIVE-WIRED**.

`wazuh/cyberqalqon_sender/forward_ingestion.py` reuses the existing archive
selector and accepts the existing single-event delivery contract. It has no
production CLI or systemd wiring, intentionally preventing accidental start.

## State model

Each generation receives a separate namespace and state file keyed by a
generation ID derived from namespace, device, inode, registration ctime,
explicit start offset and decoded prefix hash. The state records:

- original and current source identities;
- explicit start boundary and prefix SHA-256;
- independent current offset and chained per-record digest;
- 201 accepted and 200 duplicate counters separately;
- filtered, malformed, oversized, retry, protocol and rejection counters;
- optional read-only legacy-state path, SHA-256 and captured cursor.

The legacy state is only read and hashed during registration. It is never used
as the new cursor and never written.

## Delivery safety

1. Validate source device/inode and the exact newline boundary.
2. Read at most the configured bounded record count with one worker.
3. Apply the existing selector.
4. Use the existing authenticated machine-ingestion delivery object at future
   wiring time; credentials are neither copied into state nor logged.
5. Advance and fsync state only after an explicit `accepted` or `duplicate`
   acknowledgement. Retry/protocol error keeps the record before the cursor.
6. A permanent rejection terminal-blocks the independent state.
7. Partial active writes wait without advancing.

The state is durably replaced through the existing atomic JSON writer. A lost
response after commit retries the same record; a later 200 duplicate advances
exactly once.

## Rotation

Plain active files require stable device/inode and may append. Gzip generations
are immutable and full-hashed. Rebinding after rotation is never implicit: the
candidate must reproduce the start prefix and chained processed-record digest,
then requires an explicit operator-approved call. Matching filenames or equal
record counts are insufficient.

## Stop/restart and rollback

- Stop: allow the current request to resolve, then retain the newest durable
  independent state.
- Restart: revalidate source identity and boundary before reading.
- Before any acknowledgement: the new namespace may be removed only under an
  approved rollout rollback; legacy state is still authoritative for legacy
  history.
- After acknowledgement: never restore an older independent cursor. Stop and
  reconcile from the newest durable state.
- This mechanism restores future delivery only. It does not assert that older
  generations were processed.
