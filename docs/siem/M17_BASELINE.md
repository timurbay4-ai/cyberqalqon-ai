# M17 baseline

Captured on 2026-10-14 before any live shipper upgrade. Browser UAT is
**DEFERRED_BY_USER — NOT EXECUTED**.

## Repository and host

| Item | Observation |
|---|---|
| Branch / HEAD | `main` / `f6a59a923cc58cb768c1e4dd748bb529e5c01a43` |
| Worktree | Dirty, 159 porcelain entries at baseline; preserved |
| Host CPU | 26% point sample; not a sustained utilization measurement |
| RAM | 8,212,983,808 total; 847,028,224 free |
| C: free | 168,146,464,768 bytes before disposable M17 benchmarks |
| Backend / frontend / relay | HTTP 200 initially; later backend latency exceeded the validator's five-second budget under live ingestion pressure |
| Port proxy | `172.19.240.1:16000 -> 127.0.0.1:8000`; backend remains loopback-only |

Wazuh Manager, sender, event shipper and backend relay were `active`. The
sender queue and dead-letter counts were both zero. The read-only Wazuh API
collector remained `UNAVAILABLE`; service and Agent 001/002 evidence are not
relabelled as API authority.

## Database and retention

| Item | Observation |
|---|---|
| Schema | 17 |
| `quick_check` / foreign keys | `ok` / 0 errors |
| Events / alerts / incidents / cases | 100,000 / 40 / 3 / 0 |
| Database / WAL | 2,006,859,776 / 12,701,992 bytes at the operational snapshot |
| Retention | 30 days / 100,000 rows; protected evidence enabled |
| Oldest / newest occurrence | 2026-10-11T09:59:04.295Z / 2026-10-14T07:09:58.749Z |
| AI / schema-18 gate | `AI_ENABLED=false`; `ALLOW_M14_SCHEMA_MIGRATION=false` |

DET-001 through DET-009 remain `DISABLED_BY_POLICY` and `SHADOW_ONLY`.

## Archive and cursor

The active generation stayed on device `2096`, inode `33582042`. A later M17
snapshot recorded archive 975,314,365 bytes, cursor 454,475,839 and lag
520,838,526 bytes. State version is 2, archive identity matches, malformed is
1, oversized and delivery-rejected are zero, and retry count is 1,092.

Five gzip archives exist on disk (`07`, `09`, `10`, `12`, `13`). Only
generation `11b2f7...ea62d` (`ossec-archive-13.json.gz`) is registered in the
M16 generation manifest. Its audited unread tail has 53,748 eligible, 69,602
filtered and 74 malformed records. Current active eligible-record backlog is
`UNKNOWN`; no hundreds-of-megabytes dashboard scan was run.

Evidence artifacts:

- `artifacts/runtime/m17-rate-summary.json`
- `artifacts/runtime/m17-operational-health.json`
- `artifacts/runtime/m17-passive-validation.json`
