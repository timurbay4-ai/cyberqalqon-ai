# M18 baseline

Captured at 2026-10-15T04:10:17Z before M18 product-code changes.

## Source and runtime

- Git branch: `main`
- Git HEAD: `f6a59a923cc58cb768c1e4dd748bb529e5c01a43`
- Working tree: dirty (169 entries); existing changes are preserved.
- Application version: `0.9.0`
- Backend command: Python 3.11, `uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000`
- Deployed sender package: `cyberqalqon-wazuh-sender 0.1.0`
- Event shipper: active, one task, no systemd restart, v3 durable state.
- Live shipper mode: single-event HTTP; local read batch 25; adaptive mode disabled.

No browser UAT was performed. No schema migration, replay, cursor reset, firewall,
portproxy, retention-policy, detection-policy, AI, or Git-history change was made.

## Live pipeline snapshot

| Metric | Value |
|---|---:|
| Archive device / inode | `2096 / 33582396` |
| Archive bytes | 105,872,332 |
| Durable cursor bytes | 17,506,646 |
| Live byte lag | 88,365,686 |
| State version | 3 |
| Unique insertions since v3 accounting | 895 |
| Duplicate acknowledgements since v3 accounting | 2 |
| Historical v2 acknowledgements | 269 (unique/duplicate split UNKNOWN) |
| Filtered / malformed / oversized | 2,935 / 8 / 0 |
| Retry / protocol / delivery rejection | 104 / 0 / 0 |
| Last request latency | 807.15 ms |
| Current delivery rate | 0.818355 records/s |

The archive and cursor identities match. The current inode remained unchanged;
there is no active-file rotation between the M17 and M18 baseline snapshots.
Five rotated generations remain preserved and historical replay is NOT_CONFIGURED.

## Database and host

| Metric | Value |
|---|---:|
| SQLite schema | 17 |
| `quick_check` | `ok` |
| Security events / alerts | 100,000 / 40 |
| Database bytes | 2,008,690,688 |
| WAL bytes | 30,957,712 |
| Journal mode / synchronous | WAL / FULL (`2`) |
| Page size / pages / freelist | 4,096 / 490,403 / 162 |
| Windows disk free | 167,919,620,096 bytes |
| WSL disk free | 1,015,166,210,048 bytes |
| WSL available RAM | 2,871,934,976 bytes |
| Windows free RAM | approximately 936 MiB |

The passive operational snapshot reports backend reachability and healthy
SQLite integrity. The event shipper is DEGRADED only because lag exceeds the
unchanged 8 MiB warning threshold. The read-only Wazuh API remains unavailable
because credentials are not configured; manager and enrolled agent service
evidence remain healthy.

## Existing ingestion path

The current shipper reuses one `httpx.Client`, so HTTP keep-alive is available.
However, `CYBERQALQON_EVENT_BATCH_SIZE=25` is only a local archive-read bound.
Every eligible record still performs one HTTP request to
`/api/v1/events/ingest`.

Each request currently performs:

1. bounded body read and JSON decoding;
2. normalization and redaction;
3. a new SQLite connection;
4. `BEGIN IMMEDIATE`;
5. indexed `deduplication_id OR event_id` lookup;
6. one insert plus FTS/index maintenance;
7. one retention invocation;
8. one durable commit;
9. response serialization;
10. durable shipper cursor update.

`EXPLAIN QUERY PLAN` confirms the idempotency lookup uses the two unique
indexes. The limit-retention scan uses `idx_security_events_occurred_id`, but
its protected-evidence predicate performs correlated lookups against case,
incident, evidence-reference, and alert tables. At the exact 100,000-event cap
this work is repeated for every newly inserted event.

The table currently has 20 explicit secondary indexes plus the event primary
key and deduplication unique index. Index/FTS maintenance is therefore a real
write cost, but no index is removed without workload evidence.

## Initial bottleneck hypothesis

This is a measured working hypothesis, not a final conclusion:

- network request count is one per eligible event despite local batch 25;
- SQLite connection, transaction, fsync, and retention costs are paid per event;
- the M17 single-row retention fast path reduced the previous full age scan,
  but the cap/protected-evidence work remains serialized per insert;
- CPU and disk capacity are not exhausted, so adding workers is not justified;
- batching one bounded atomic transaction is the lowest-risk way to amortize
  HTTP, commit, and retention costs while preserving one worker.

The authoritative baseline artifact is
`artifacts/runtime/m18-baseline-operational-health.json`.

## Safety gates

- Live schema: 17; schema 18 is not authorized.
- Retention: 30 days / 100,000 events, unchanged.
- `AI_ENABLED=false`.
- DET-001 through DET-009 remain `DISABLED_BY_POLICY / SHADOW_ONLY`.
- `BROWSER_UAT = DEFERRED_BY_USER`.
- Live M18 batch deployment is not authorized by this engineering phase.
