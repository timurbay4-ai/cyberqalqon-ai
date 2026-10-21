# M16 validation

Validation date: 2026-10-14. Live browser UAT:
**DEFERRED_BY_USER — NOT EXECUTED**.

## Implemented and verified

- Deterministic schema-17 retention with protected investigation evidence.
- Aggregated, payload-free retention audit.
- Exact over-limit/protected observability in backend and Operations UI contracts.
- Stable archive-generation registration for plain/gzip files.
- Bounded, approval-gated, durable historical replay on disposable data only.
- Payload-free malformed audit for rotated and active acknowledged data.
- Non-privileged frontend start and health-check scripts.
- Passive validator states that distinguish PASS, WARNING, PARTIAL, FAIL,
  BLOCKED and UNKNOWN, plus the explicit non-operational `DEFERRED_BY_USER`
  marker for browser UAT.
- Capacity benchmark through 250,000 disposable events.

## Safety gates

| Gate | Result |
|---|---|
| Live schema | PASS — remains 17 |
| Schema-18 apply | BLOCKED — not authorized; `ALLOW_M14_SCHEMA_MIGRATION=false` |
| DET-001–DET-009 | PASS — disabled by policy and shadow-only |
| AI | PASS — `AI_ENABLED=false` |
| Live historical replay | BLOCKED — not approved and live store is at cap |
| Live retention change | BLOCKED — not approved |
| Privileged frontend startup | NOT PERFORMED |
| Chrome/Edge UAT | DEFERRED_BY_USER |
| Git commit/push | NOT PERFORMED |

Exact full-regression and final passive-validator counts are recorded in the M16
handoff after the complete test run. Automated results must not be represented as
real-browser acceptance.

## Final automated regression

| Area | Result |
|---|---|
| Backend | PASS — 259 tests |
| Frontend | PASS — 117 tests / 17 files |
| TypeScript | PASS |
| Production build | PASS |
| Wazuh sender/shipper/recovery | PASS — 131 tests |
| Deployment/validator | PASS — 24 tests |
| Archive recovery focused suite | PASS — 7 tests |
| Disposable schema-17 replay | PASS — included in deployment suite |
| `git diff --check` | PASS; line-ending warnings only |
| Browser UAT | DEFERRED_BY_USER |

The final live SQLite read found schema 17, 100,000 events, 40 alerts, three
incidents, zero cases, `quick_check=ok`, and zero foreign-key errors. The oldest
retained occurrence had advanced to
2026-10-11T09:42:39.885Z, confirming that ordinary FIFO retention was active
before the M16 process reload. After relay recovery, new events reached the
reloaded backend while the database remained at 100,000 rows, and two M16
retention audit windows were recorded.

## Final passive validator

Current result: **WARNING — 11 PASS, 2 WARNING, 0 FAIL, 1 DEFERRED_BY_USER**.

- PASS: backend, frontend/proxy, Kali services, manager services, WSL relay,
  exact TCP 16000 portproxy listener, Wazuh Agent 001 enrollment, sender empty
  queue/dead-letter, malformed audit, SQLite integrity, release safety gates.
- WARNING: shipper lag and the database being exactly at its retention cap.
- DEFERRED_BY_USER: Chrome/Edge UAT.

The final operational snapshot recorded cursor 425,685,212 of 935,434,855 bytes,
with 509,749,643 bytes of lag, matching device/inode, 98 accepted, 102 filtered,
zero production delivery rejections, and a recently updated durable state. Retry
count held at 1,091 after connectivity returned. The cursor was not reset. The
current eligible-record count is `UNKNOWN` because the final collector did not
run a high-I/O deep archive scan.

The administrator-approved repair rebound the existing exact portproxy listener
and retargeted the existing minimal host firewall rule to the current WSL
adapter. The backend remained loopback-only. Firewall backup:
`C:\ProgramData\CyberQalqon\backups\m15-firewall-interface-20261014T170411Z`.
