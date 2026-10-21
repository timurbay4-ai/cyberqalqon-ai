# CyberQalqon SIEM v0.9 validation

This document is the evidence ledger for the v0.9 enterprise integration,
agent-management, and Windows telemetry milestone. Results distinguish
authoritative provider state from telemetry freshness and local service health.

## Phase 0 baseline (recorded before implementation)

Observed on 2026-10-10 before any v0.9 source change:

| Area | Result | Evidence |
| --- | --- | --- |
| Git | PASS | `main` at `f6a59a923cc58cb768c1e4dd748bb529e5c01a43`; worktree clean and aligned with `origin/main` |
| Runtime | PASS | Frontend `127.0.0.1:5173` and backend `127.0.0.1:8000` returned HTTP 200; the running process still advertised v0.8.0 and therefore required a controlled restart after implementation |
| SQLite | PASS | Schema 14; `quick_check=ok`; zero foreign-key violations; database file 25,821,184 bytes before WAL checkpoint/backup |
| Preserved records | PASS | 40 alerts, 5,790 security events, 3 incidents, 0 cases, 4 notifications, 4 audit records, and 4 operational transitions |
| Backend regression | PASS | 191/191 tests |
| Frontend regression | PASS | 99/99 tests |
| Sender/shipper/deployment/E2E | PASS | 129/129 tests |
| Passive local validator | PASS | 9/9 checks; no active attack probes were run |
| Wazuh Manager | PASS | Ubuntu 24.04 WSL2 service active; package `4.14.8-1`; listeners observed on 1514 and 55000 only |
| Linux agent | PASS | Manager `agent_control -lc` reported agent `001` / `cyberqalqon-test-web` Active |
| Wazuh API | BLOCKED | HTTPS listener exists, but no approved read-only credential and trusted CA are configured in CyberQalqon |
| Windows local service | PASS | `WazuhSvc` v4.7.5 is Running and Automatic |
| Windows enrollment | BLOCKED | `client.keys` exists but is empty; enrollment is configured; configured manager is a private address; protected log was not readable by the non-elevated process |
| Windows-to-WSL path | PARTIAL | Loopback relay 2514 is reachable; loopback enrollment 2515 is not listening; local Wazuh API 55000 is reachable |
| Live Windows events | BLOCKED | No authoritative enrollment or server-confirmed connection; no live Windows event may be claimed |

The configured private manager address is deliberately not copied into this
repository. No enrollment secret or credential was read or printed.

### Compatibility finding

Wazuh documents that manager/agent compatibility is guaranteed when the
manager version is equal to or newer than the agent. The installed manager
4.14.8 is newer than the Windows agent 4.7.5, so the observed blocker is not the
documented version ordering. No upgrade was attempted. Sources:

- <https://documentation.wazuh.com/current/upgrade-guide/index.html>
- <https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html>

Enrollment requires agent communication on TCP 1514 and, for automatic agent
request enrollment, TCP 1515. Wazuh API access uses HTTPS (normally TCP 55000),
JWT authentication, and RBAC; `GET /agents` requires `agent:read`. Sources:

- <https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/requirements.html>
- <https://documentation.wazuh.com/current/user-manual/api/requests-responses.html>
- <https://documentation.wazuh.com/current/user-manual/api/rbac/reference.html>

## Reusable v0.8.1 components

- The HTTPS-loopback-only, certificate-verifying, mutation-free Wazuh API
  adapter and backend-only `*_FILE` secret loader.
- Schema 13 operational state, transition deduplication, cooldown, per-user
  notifications, and bounded operational history.
- One-shot health collector with manager, sender, shipper, Windows service, and
  SQLite observations.
- Durable alert sender and event shipper counters, cursor, retry, dead-letter,
  and terminal-blocked measurements.
- Telemetry-derived Hosts/Sources views that correctly keep Wazuh connection
  state `UNKNOWN`.
- Windows Wazuh normalizer, narrow EventChannel definitions, deterministic
  fixtures, raw evidence retention, M9 correlation, incidents, cases, RBAC,
  CSRF, Origin, session, and audit controls.
- Dynamic loopback-only WSL relay, which resolves the private WSL address per
  connection and does not expose the manager publicly.

## Gaps found

- Wazuh inventory is limited to 500 rows and has no pagination, bounded body
  enforcement, manager version/health, groups, agent version, durable cache, or
  history.
- No authenticated `/api/v1/agents` workspace exists. `/api/v1/hosts` is an
  observed-telemetry asset view, not an authoritative agent inventory.
- Windows connectivity diagnosis is embedded in the collector and does not
  express the required deterministic classifications.
- Agent identity has no manager namespace in the current telemetry-only view.
- The operational collector exposes good sender/shipper counters but threshold
  configuration and source/agent health histories require extension.
- Windows normalized events retain provider/channel inside structured data, but
  the event contract does not expose all trustworthy process/parent fields
  consistently.

## Implementation priority

### P0 — acceptance-critical

1. Add schema 15 agent inventory/cache and bounded health history after a
   verified online backup and disposable-copy migration rehearsal.
2. Harden and complete the read-only Wazuh API adapter: bounded body, bounded
   pages/retries, manager metadata, full agent fields, strict identifiers, TLS
   failure handling, and contract tests.
3. Add authenticated `soc:read` agent list/detail/health and Wazuh integration
   status endpoints, preserving `UNAVAILABLE`/`UNKNOWN` when authority is absent.
4. Add a standalone deterministic, read-only Windows connectivity diagnostic
   and use its classification in the one-shot collector.
5. Improve Windows/Linux normalization identity and trustworthy Windows fields
   without creating alerts.
6. Upgrade Hosts to an Agent Management workspace with honest partial states.

### P1 — reliability and analyst workflow

1. Persist bounded agent transitions only from authoritative observations and
   reuse notification deduplication/cooldown/recovery behavior.
2. Extend sender/shipper/source status vocabulary and configurable thresholds.
3. Add WSL relay drift checks and documented recovery.
4. Measure query/normalization/overview latency, timeout behavior, database and
   bundle size, and process working set.

### P2 — dependent or privileged work

1. Provision a least-privilege Wazuh API reader and trusted CA.
2. Change the protected Windows agent target and complete supported enrollment.
3. Restart the Windows agent only after explicit approval, then verify an actual
   end-to-end Windows event.
4. Independently validate production deployment and scale; this local milestone
   does not claim enterprise production readiness.

## Validation log

Implementation, migration, performance, security, regression, browser UAT, and
remaining blocker results are appended below as the milestone progresses.

## Implemented v0.9 result

### Architecture and API — PASS/PARTIAL

- **PASS:** schema 15 adds namespaced durable agent inventory, bounded agent
  health history, a Wazuh integration cache, Windows provenance/process fields,
  and manager/agent/provider indexes.
- **PASS:** `GET /api/v1/agents`, `GET /api/v1/agents/{agent_key}`,
  `GET /api/v1/agents/{agent_key}/health`, and
  `GET /api/v1/integrations/wazuh/status` are `soc:read`-protected and are the
  only new routes. Runtime OpenAPI exposes `GET` only for all four.
- **PASS:** manager+provider+agent ID creates an opaque stable key. Hostname/IP
  changes cannot silently merge unrelated managers. Telemetry-only identities
  remain observed-only and `UNKNOWN`.
- **PASS:** stale or unavailable Wazuh provider cache now downgrades the current
  connection state to `UNKNOWN`; the last authoritative transition remains in
  bounded history rather than being presented as current.
- **PARTIAL:** the live lab returns three telemetry-evidence identities, all
  `UNKNOWN`; agent inventory is correctly empty because the Wazuh API is not
  configured. Mocked API contracts validate authoritative inventory.

### Secure Wazuh API — PASS code / BLOCKED live

The backend client uses only non-mutating `POST /security/user/authenticate`
plus `GET /agents`, `/manager/info`, and `/manager/status`. It requires HTTPS
loopback, system trust or an explicit CA bundle, rejects embedded credentials,
paths, query/fragment and external hosts, ignores proxy environment, follows no
redirect, bounds timeout/body/pages/retries, rejects unexpected agent IDs, and
has no mutation API method. Username/password file reads fail closed during a
bad rotation. Deterministic tests cover malformed/oversized/timeout responses,
strict IDs, exact methods, unavailable state, and retry bound.

Live result is **BLOCKED**: the HTTPS listener exists, but no approved
least-privilege reader credential and trusted CA are configured. No credential
was invented and TLS was not bypassed. Setup/rotation procedure is in
`docs/wazuh/WAZUH_API_INTEGRATION.md`.

### Windows and telemetry — PARTIAL/BLOCKED

- **PASS diagnostic:** `WazuhSvc` v4.7.5 is Running/Automatic; manager 4.14.8 is
  newer and version ordering is compatible by documented Wazuh policy.
- **BLOCKED enrollment:** deterministic result is
  `ENROLLMENT_PORT_UNAVAILABLE`; configured private manager is unreachable and
  does not match current WSL, key is absent, manager/relay 1515 are unavailable,
  manager confirmation is false, and protected log access is denied.
- **PASS transport subset:** loopback relay 2514 and manager listener 1514 are
  reachable; manager, sender, and shipper services remain healthy.
- **PASS contracts:** Windows Security/System/PowerShell/Defender fixtures,
  Unicode, nested XML-derived JSON, malformed identifiers, provider/channel,
  process/parent fields, timezone offsets, raw evidence reference, and redaction
  are covered. Normalization changes do not create alerts.
- **BLOCKED live Windows events:** no server-confirmed enrollment exists, so no
  end-to-end Windows telemetry result is claimed. Sysmon is not installed.

### Operations and notifications — PASS

The one-shot collector exposes sender queue depth/bytes/in-flight/retry/dead-
letter/terminal-blocked/delivery values, shipper cursor/archive lag and
malformed/oversized/rejected values, database last accepted/ingestion time, and
source freshness. Agent connectivity, source freshness, pipeline health, and
backend health remain separate. Thresholds are configurable and collection adds
no daemon.

The first recorded v0.9 snapshot produced six genuine stale-source transitions.
A repeated read-only snapshot produced zero transitions. Existing 15-minute
cooldown, deduplication, recovery, per-active-user notifications, audit, and
bounded 1,000-event/10,000-audit history remain active. No synthetic production
event was inserted.

## Database safety — PASS

Verified online backup:

- `backups/cyberqalqon-pre-v09-20261010T155801Z.db`
- SHA-256 `f632fce047a996bdf89f32a14176a49d0ca451e110bdc5f6e34f3428e34cd8a0`
- ACL inheritance disabled; owned by the local user

The schema-14 backup was copied to a disposable database and migration 15 was
applied twice. Both runs ended at version 15, `quick_check=ok`, zero FK
violations, and identical counts: 40 alerts, 5,793 events, 3 incidents, 0 cases,
4 notifications, 4 audits, 4 operational events.

Live observation on 2026-10-10 after legitimate ingestion/collector activity:

| Evidence | Count |
| --- | ---: |
| Alerts | 40 |
| Security events | 5,921 |
| Incidents | 3 |
| Incident-alert links | 14 |
| Cases / case links / case evidence | 0 / 0 / 0 |
| Evidence custody events | 0 |
| Analyst notifications | 10 |
| Security audits | 11 |
| Operational transitions | 10 |
| Authoritative agent rows / history | 0 / 0 |

Live schema is 15, database size 27,508,736 bytes, `quick_check=ok`, and FK
violations are zero. The manager+agent query uses
`idx_security_events_manager_agent`; alert relationship lookup uses the existing
correlation-candidate index. No live database reset or restore occurred.

## Regression and security validation — PASS

Final complete run: backend **203/203**, frontend **100/100**, and
Wazuh/sender/shipper/deployment/HTTP-E2E **137/137**. Frontend typecheck,
production build, backend compileall, `pip check`, `git diff --check`, and
`npm audit --audit-level=high` pass; npm reports zero vulnerabilities. Passive
validator is **9/9**; no active attack probes were run. The backend reports one
third-party Starlette/AnyIO deprecation warning and the HTTP E2E reports two
third-party `websockets` deprecation warnings; none failed a test.

Covered boundaries include human authentication/session digest, lockout,
expiration/logout, `soc:read` RBAC, viewer/admin separation, CSRF, exact Origin
and credentialed CORS, cross-user ownership, path traversal evidence IDs, React
text escaping/XSS fixtures, bounded SQL query enums/parameters, Wazuh loopback
SSRF restrictions, TLS verification, exact read-only methods, secret redaction,
oversized/malformed/timeouts/retry behavior, unexpected provider IDs, stale
cache downgrade, and credential-file rotation failure. Frontend source contains
no Wazuh username/password setting, no secret/private-key/JWT marker was found
in the diff, and neither `secrets/` nor `.env` is Git-tracked.

## Performance and resources — PASS for local lab

Isolated bounded benchmark (100 application samples, 2,000 normalization
samples; WSL operations three samples):

| Measurement | p50 | p95 / throughput |
| --- | ---: | ---: |
| Agent inventory | 21.262 ms | 44.969 ms |
| Agent detail | 35.134 ms | 63.429 ms |
| Operations overview | 15.113 ms | 27.600 ms |
| Windows normalization | 0.082 ms | 12,195.1 events/s (p50-derived), p95 0.151 ms |
| Sender queue lookup | 530.272 ms | 836.886 ms |
| Shipper lag calculation | 313.346 ms | 317.000 ms |

The backend process measured 62.03 MiB private bytes (2.34 MiB resident working
set reported by Windows at that instant), 2 threads. Production frontend assets
total 575,831 bytes (0.549 MiB); main JS is 324.47 kB / 93.45 kB gzip. Wazuh API
timeout defaults to 3 seconds with one retry and tests prove exactly two bounded
attempts. Cache TTL defaults to 60 seconds; stale state is visible and not
treated as current.

## Browser UAT — BLOCKED

Computer Use stopped before interaction because it could not confidently
identify the current Edge URL. This mandatory restriction was not bypassed;
there was no cookie injection, alternate automation, credential extraction,
login, or claimed visual PASS. Trusted repository/runtime URL is
`http://127.0.0.1:5173/`, but a human must independently confirm the address bar
before login. The 17-step user-controlled checklist is
`docs/release/BROWSER_UAT_V09.md`. All steps remain `NOT RUN` until the operator
returns credential-free results.

## Privileged approval boundary

The following remain **BLOCKED** until separate explicit approval:

1. Create/map a least-privilege Wazuh API user with only `agent:read` and the
   required `manager:read`; install the approved CA/credential files; controlled
   backend restart and live validation.
2. Back up manager configuration; temporarily enable password-protected authd
   1515; start a loopback-only 2515 relay; review the elevated agent-auth password
   mechanism; run the Windows installer first with `-WhatIf`, then enroll and
   restart `WazuhSvc` only in the approved window.
3. Verify a new distinct manager record without changing/removing Agent `001`,
   close authd/relay 1515, and generate one authorized benign Windows event for
   real end-to-end validation.

No manager, Windows service, key, certificate, firewall, enrollment, Defender,
or audit policy was changed in this milestone.

## Final local runtime sanity — PASS/PARTIAL

- Frontend and backend returned HTTP 200; OpenAPI version is 0.9.0.
- Wazuh Manager is `active`; manager CLI reports Agent `001`
  `cyberqalqon-test-web` Active (private IP redacted).
- Sender is HEALTHY: queue depth/bytes/in-flight/dead-letter/terminal-blocked are
  all zero; historical retry count is 2 and duplicate count is zero.
- Shipper is HEALTHY and backend-reachable: cursor 4,502,896 bytes, lag zero,
  2,041 accepted; historical malformed/oversized/retry counters are 16/15/312,
  and rejected deliveries are zero.
- Database is HEALTHY at schema 15 with 5,921 events and current ingestion
  timestamps.
- Windows agent remains UNAVAILABLE with
  `ENROLLMENT_PORT_UNAVAILABLE`; this is an honest operational blocker, not an
  overall pipeline failure.
