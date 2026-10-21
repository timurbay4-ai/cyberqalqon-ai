# M15 telemetry recovery

Status on 2026-10-14: **STABLE_AT_LIVE_INGEST_EQUILIBRIUM**. The approved
TCP 16000 relay is healthy and the bounded shipper is advancing without new
transport retries. The eligible backlog is not zero because archive generation
is currently close to the configured delivery rate and a rotated archive still
requires a separate low-load recovery window.

## Approved recovery result

- The original recovery began at `device=2096,inode=33582108,offset=482` with
  30,654 eligible, 36,597 filtered and 80 malformed records in the point-in-time
  scan. The malformed records were audited separately and were never counted as
  accepted events.
- The last verified pre-rotation checkpoint was offset `228,463,941`: 18,731
  delivery-success responses, 22,590 filtered and 80 malformed. The deployed
  v2 state combines HTTP 200 duplicate acknowledgements with HTTP 201 creates,
  so its exact accepted/duplicate split is unavailable.
- Wazuh then performed its normal daily archive rotation. The preserved
  `ossec-archive-13.json.gz` is 903,384,951 uncompressed bytes. A read-only scan
  from the last verified checkpoint found 53,748 eligible, 69,602 filtered,
  74 additional malformed, zero oversized and zero partial records.
- The new live archive uses `device=2112,inode=33582042`. At the final health
  snapshot its cursor was `58,305,505` of 279,321,546 bytes; state counters were
  2,596 delivery-success responses, 4,973 filtered, eight malformed, zero
  delivery-rejected and 491 cumulative retries. The retry counter stopped
  increasing after relay repair.
- The final point-in-time live scan found 17,547 eligible and 21,748 filtered
  records remaining. Together with the preserved rotated tail, the remaining
  eligible backlog was 71,295 at that snapshot.
- The live database reached its configured 100,000-event retention cap, so row
  count is not an accepted-event counter. Its schema remained 17 and
  `quick_check=ok` with zero foreign-key violations.

No cursor was reset, no archive was deleted, and no historical recovery worker
was started. Starting a second worker while the live worker is at equilibrium
would increase SQLite/CPU load beyond the operator's constraint. The rotated
tail remains preserved and exactly accounted for.

## Verified runtime baseline

- Windows backend: `127.0.0.1:8000`, HTTP 200, owned by the existing Python process.
- Frontend: `127.0.0.1:5173`, HTTP 200.
- WSL gateway observed during diagnosis: `172.19.240.1` (must be rediscovered
  immediately before any change).
- Wazuh Manager, sender, event shipper and both relay services: active.
- Sender: queue 0, in-flight 0, dead-letter 0, delivered 39, retries 2.
- Live database: schema 17, 80,176 events, 40 alerts, three incidents,
  `quick_check=ok`, zero foreign-key violations.
- Host memory at the final benchmark checkpoint: 7.65 GiB total, 0.94 GiB free;
  system drive free space: 161.78 GiB.

The deep audit at `2026-10-13T06:02:53Z` found archive identity
`device=2096,inode=33582108`, size 281,152,916 bytes and cursor 482. The
281,152,434 unread bytes contained exactly 50,873 complete records: 23,042
eligible, 27,751 allowlist-filtered, 80 malformed and zero oversized. The
cursor identity matched the archive and no rotated archive was present. A later
passive-validator snapshot observed 294,584,067 bytes of lag, so the archive is
still growing while delivery is blocked.

The final deep snapshot at `2026-10-13T06:23:36Z` found 315,805,988 unread bytes,
57,003 complete unread records, 25,887 eligible, 31,036 filtered, 80 malformed,
zero oversized and one incomplete trailing record. Cursor remained 482 on the
same device/inode; retry count reached 618. Thus M15 processed zero eligible live
records and backlog grew by 2,845 eligible records between deep snapshots. Queue
and dead-letter remained zero; no loss was hidden by cursor movement.

## Recovery procedure after approval

1. Recheck the current WSL gateway, excluded port ranges and listener inventory.
2. Verify TCP 16000 remains free and outside every current IPv4/IPv6 exclusion.
3. Back up the installed relay script and record current port-proxy/firewall state.
4. Add an exact gateway TCP 16000 to loopback TCP 8000 port proxy.
5. Add only the WSL Hyper-V VM inbound TCP 16000 allow rule.
6. Change only the Ubuntu relay destination; keep its local endpoint at
   `127.0.0.1:18000` so sender and shipper configuration remains stable.
7. Restart only the backend relay, verify `/health`, then observe the existing
   shipper consuming from offset 482 under its configured batch/backoff bounds.
8. Record starting/ending eligible backlog, accepted, duplicate, rejected,
   filtered, malformed, dead-letter and delivery-rate values.

Rollback removes the exact new firewall rule and port proxy, restores the relay
backup, restarts only that relay, and leaves the cursor/state files untouched.
Expected relay-only interruption is under 30 seconds. The user approved this
procedure and it was executed with the documented rollback safeguards.

## Lossless safeguards added

The shipper state format is now version 3 while remaining able to read v1/v2.
It records duplicate attempts, consecutive retries, recovery transitions, last
success/failure/recovery timestamps and delivery rate. Duplicate acknowledgments
advance exactly once. Retry responses never advance the offset. Partial trailing
records now wait for their newline rather than being rejected. Existing durable
state fails closed on archive identity change, truncation or unreadable state
instead of silently bootstrapping to a new offset.

`cyberqalqon-sender backlog-status --json` performs a read-only point-in-time
scan and never mutates the cursor. Archive rotation remains an operator-assisted,
fail-closed condition: preserve the old inode, reconcile it against the cursor,
then resume; never reset the cursor to make health appear green.
