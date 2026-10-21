# M17 validation

Validation date: 2026-10-14. Browser UAT:
**DEFERRED_BY_USER — NOT EXECUTED**.

## Automated regression

| Area | Result |
|---|---|
| Backend | PASS — 259 tests |
| Frontend | PASS — 117 tests / 17 files |
| Wazuh sender/shipper/recovery | PASS — 149 tests |
| Deployment/validator | PASS — 24 tests |
| TypeScript | PASS |
| Production build | PASS |
| v2 -> v3 real-state-copy rehearsal | PASS |
| Retention 50k A/B integrity | PASS |
| Browser UAT | DEFERRED_BY_USER — NOT EXECUTED |

New focused coverage includes v2/v3 conversion, exact rollback boundary,
interrupted atomic replace, forward-version refusal, incorrect HTTP success
contract, duplicate and inserted acknowledgement, selected-record permanent
rejection, adaptive bounds, historical replay protocol failure and durable
blocked replay.

Backend full regression includes M11 detection, M12 investigation workbench,
M14 shadow/readiness, M15 golden-quality, retention, protected evidence, WAL,
backup/restore and concurrent reader/writer tests. Destructive cases use
disposable databases.

## Passive validator

Final observed result before the v3 gate: **FAIL — 8 PASS, 2 WARNING, 3 FAIL,
0 BLOCKED, 0 UNKNOWN, 1 DEFERRED_BY_USER**.

- PASS: Kali/manager services, enrollment, sender queue/dead-letter, malformed
  audit, SQLite integrity, safety gates and TCP 16000 portproxy.
- WARNING: event shipper lag and retention exactly at cap.
- FAIL: backend health, frontend health proxy and WSL relay exceeded the fixed
  five-second health budget during sustained ingestion pressure.
- DEFERRED_BY_USER: Chrome/Edge UAT.

The validator itself was hardened so a socket `TimeoutError` becomes explicit
evidence rather than aborting without a report. Thresholds were not relaxed.
SQLite still reported `quick_check=ok`, zero foreign-key errors, schema 17,
100,000 events and 40 alerts.

No source commit or push was created. Live shipper state remains v2; schema 18,
AI and DET-001–DET-009 remain gated.
