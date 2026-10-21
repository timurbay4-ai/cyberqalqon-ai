# M15 pipeline reliability

## Sources of truth

| Metric | Authority |
|---|---|
| Sender queue, leases, retries, dead letters | sender SQLite/status CLI |
| Shipper cursor and counters | durable shipper state file |
| Archive identity, size and record backlog | archive stat plus optional deep read-only scan |
| Relay connectivity | WSL loopback relay `/health` probe |
| Accepted ingestion and source freshness | CyberQalqon database |
| Agent connectivity | Wazuh API or manager evidence only |

Source freshness is never represented as agent connectivity. When Wazuh API
credentials are not available to a collector, the authoritative value remains
`UNKNOWN`. Deep backlog scanning is opt-in (`--deep-shipper-audit`) to avoid a
high-frequency read of a growing archive.

## Failure/recovery behavior

- Backend/relay unavailable: delivery returns retry, offset remains at the last
  acknowledged byte, consecutive retry and failure time stay observable.
- Duplicate delivery: backend duplicate acknowledgment is delivery-equivalent,
  counted separately, and advances once.
- Partial batch/restart: state is atomically replaced after each bounded batch;
  restart resumes at the stored offset.
- Crash after an uncertain sender request: the lease expires and the item is
  retried; a duplicate acknowledgment completes it safely.
- Archive partial tail: no rejection or offset advance until a complete line is
  present.
- Archive rotation/truncation: existing state fails closed, preserving evidence
  for explicit reconciliation.
- Malformed/oversized complete records: classified separately and skipped with
  durable counters; no payload is logged.
- SQLite busy: bounded database timeout produces an observable fail-closed error.
- Graceful stop: the worker exits through its stop event without clearing state.

Automated Wazuh coverage verifies retries, duplicate acknowledgments, partial
tails, partial-batch restart, cursor persistence, crash/lease recovery, malformed
and oversized records, archive mismatch, queue restart, dead-letter retention,
bounded drain and idle backoff. The complete suite passed 124 tests after M15.

Live relay recovery and live backlog drain were not simulated because doing so
would require the separately approved Windows/WSL network change. No live SIEM
service was deliberately stopped.
