# CyberQalqon SIEM v0.8 release-candidate validation

- Validation date: 2026-10-10
- Application metadata: `0.8.0`
- Release label: `0.8.0-rc1`
- Schema: 14 (unchanged)
- Branch: `main`
- HEAD: `b07fdd50dc3df71976bf9467f8ecb98e68045926`

## Decision

**CONDITIONAL RELEASE CANDIDATE.** Automated application, dependency, database,
backup/restore, telemetry, security-boundary, build, sender, deployment, and E2E
checks pass. Final release approval remains blocked on authenticated manual
Chrome/Edge UAT. Wazuh API inventory and Windows agent enrollment also remain
explicitly unavailable; they are not represented as healthy.

No commit, push, reset, clean, rebase, database replacement, authentication
bypass, active network scan, or LLM installation was performed. `AI_ENABLED=false`
remained the local release profile.

## Baseline and inventory

The pre-change checkpoint is recorded in `REPOSITORY_INVENTORY_V08.md`. It found
schema 14, 4,266 live security events, 40 alerts, 3 incidents, one analyst, six
sessions, zero cases, 62 tracked modifications, 115 untracked paths, and no staged
file. All accumulated v0.1-v0.7 work was preserved.

Runtime databases, WAL/SHM files, backups, secrets, logs, temporary files, build
output, validator output, and generated `output/` artifacts are ignored. The exact
local ingest key was not found in visible repository content, and no private-key
header was found. The empty unusual directory named `` was not removed.

One legacy `frontend/src/pages/rules-page.tsx` module is not the active route but
remains test-covered. It was documented for reviewed consolidation rather than
deleted as presumed dead code. No verified duplicate implementation, broken
import, or unused direct dependency was found.

## Defects discovered and fixed

1. Default Vitest fork fan-out exhausted process startup capacity under concurrent
   WSL lab load. The test runner now uses one worker and disables file parallelism.
2. Testing Library's one-second async assertion window was shorter than a cold
   on-demand route transform on the supported low-resource lab. It is now bounded
   at five seconds while the overall test timeout remains bounded.
3. The frontend delivered all pages in one 512.85 kB JavaScript chunk. Routes now
   use React lazy loading, Suspense, and a bounded page error/reload boundary.
4. Vite could bind only to IPv6 `localhost` while release checks used
   `127.0.0.1`. Development and preview now bind IPv4 loopback explicitly.
5. `127.0.0.1:5173` was missing from default trusted development origins. It is
   now explicitly enumerated; wildcard CORS was not introduced.
6. A client disconnect during streamed alert ingestion could surface a traceback.
   It now produces the structured `client_disconnected` 400 response and has a
   dedicated regression test.
7. The passive validator accepted an active relay unit without testing its
   downstream path. It now performs a bounded health request through that path.
8. The WSL event shipper had a durable backlog because its relay could not reach
   a Windows listener on the current WSL virtual interface. Starting the supported
   listener allowed the existing cursor to catch up without reset or data deletion.
9. Environment templates advertised unused `APP_HOST`/`APP_PORT` values. Those
   unsupported entries were removed; startup arguments remain authoritative.
10. Generated `output/` files appeared as commit candidates. The directory is now
    ignored.

## Functional audit

All advertised product areas are wired into the authenticated shell: Overview,
Operations, Discover, Threat Hunting, Alerts, Incidents, Cases, Hosts/Sources,
Detection Rules, Threat Intelligence, Reports, Administration, Notifications,
and Preferences.

| Area | Automated evidence | Real-browser evidence |
| --- | --- | --- |
| Shell, login boundary, navigation, deep links, Back/Forward, keyboard shortcuts | Frontend App and experience tests PASS | BLOCKED |
| Overview, Operations, Hosts/Sources | Component/API regressions PASS; live passive health PASS | BLOCKED |
| Discover, search, filters, pagination, linked evidence | Component/API regressions PASS | BLOCKED |
| Alerts and Incidents, lifecycle, assignment, timeline, correlation | Backend/frontend regressions PASS | BLOCKED |
| Cases, evidence, playbooks, SLA, JSON/CSV/PDF reporting | Backend/frontend regressions PASS | BLOCKED |
| Detection Engineering, hunts, IOC matching and coverage | Backend/frontend regressions PASS | BLOCKED |
| Reports, Administration, notifications and preferences | Backend/frontend regressions PASS | BLOCKED |

Source review and automated tests found no verified dead top-level navigation
control. Loading, empty, bounded error, permission-denied, and copy/export states
have automated coverage where implemented. Responsive layout, browser focus,
downloads, and authenticated end-to-end behavior are not promoted to PASS without
the manual browser evidence in `BROWSER_UAT_V08.md`.

## Security findings

- Argon2id parameters, dummy verification for unknown users, lockout, digest-only
  opaque sessions, expiry, HttpOnly/SameSite cookies, production Secure cookies,
  exact Origin validation, CSRF, RBAC, machine keys, audit actors, parameterized
  SQLite access, bounded bodies, evidence references, and report redaction remain
  enforced.
- No React raw-HTML injection, browser session-token storage, arbitrary SQL/Python,
  shell execution, unsafe YAML load, verified path traversal, or visible live
  credential was found.
- Production Nginx retains HSTS, CSP, frame denial, MIME-sniffing prevention,
  referrer policy, and permissions policy.
- `npm audit --audit-level=low` reported zero vulnerabilities; `pip check` found
  no broken requirement.
- No compliance certification is claimed.

Live boundary probes produced all eight expected results:

| Probe | Expected and observed |
| --- | --- |
| Session without cookie | 401 |
| Cases without cookie | 401 |
| Login without Origin | 403 |
| Login with untrusted Origin | 403 |
| Login with trusted Origin and invalid body | 422 |
| Alert ingest without machine key | 401 |
| Event ingest without machine key | 401 |
| Exact-origin CORS preflight | 200 with credentials and `http://127.0.0.1:5173` |

The probes used no username/password and did not weaken or bypass a control.

## Database integrity and recovery

- Live database: `backend/data/cyberqalqon-local-lab.db`
- `PRAGMA quick_check`: `ok`
- Foreign-key violations: 0
- Journal mode: WAL
- Migration ledger: 14 entries, versions 1-14
- Current health snapshot: 4,722 events, 40 alerts, 3 incidents, 1 analyst,
  6 sessions, 0 cases. Event count is expected to advance while the shipper runs.
- Application connections enable foreign keys and a 5-second busy timeout.
- No v0.8 migration was required.

Supported online backup created before stabilization:

`backups/cyberqalqon-pre-v08-20261010T084500Z.db`

SHA-256:
`d4f644b2baa4cda97743f81f589ad6914bff6a1af4e45e5aa48232a5e99eb371`

The disposable restore at `tmp/v08-restore-rehearsal-20261010.db` preserved
schema/data, passed quick/foreign-key checks, and invalidated all six copied
sessions as designed. The live database was never replaced.

Audit reads are bounded to 10,000 newest entries and event retention is bounded
by configured age/count. Notifications currently have no independent scheduled
retention job; this remains documented rather than silently claimed as complete.

## Performance

Production bundle result:

| Metric | Before | After | Improvement |
| --- | ---: | ---: | ---: |
| Initial JavaScript | 512.85 kB | 317.73 kB | 38.0% |
| Initial JavaScript gzip | 129.40 kB | 91.93 kB | 29.0% |
| Page chunks | none | 0.36-27.66 kB | loaded on demand |

Representative local API measurements on the 4,266-event baseline:

| Request | p50 | p95 |
| --- | ---: | ---: |
| `/health` | 5.85 ms | 20.21 ms |
| Alert list | 3.16 ms | 6.45 ms |
| Event list | 23.40 ms | 33.82 ms |
| FTS `nginx` search | 5.12 ms | 6.70 ms |
| 30-day Overview | 140.46 ms | 191.71 ms |
| Incident list | 2.20 ms | 3.30 ms |
| Case analytics | 2.95 ms | 4.28 ms |
| 30-day report | 37.03 ms | 50.99 ms |
| Operations | 17.58 ms | 20.12 ms |

These are single-laptop observations, not production capacity or SLA guarantees.
No heavy dependency was added.

## Telemetry and recovery

At the final passive snapshot:

- Wazuh Manager v4.14.8: HEALTHY and active.
- Wazuh agent `001` / `cyberqalqon-test-web`: Active.
- Sender: HEALTHY, queue 0, pending 0, in-flight 0, terminal blocked 0,
  dead letters 0.
- Event shipper: HEALTHY, backend reachable, archive cursor equals archive size,
  lag 0, delivery rejected 0.
- Backend relay path: HTTP 200.
- Database: HEALTHY, quick check `ok`, schema 14.
- Wazuh API: UNAVAILABLE because approved read-only credentials/CA are absent.
- Windows agent: UNAVAILABLE for enrollment; service is active on v4.7.5, but
  it has no enrollment key and its legacy manager address is unreachable.

The shipper recovery reused the existing durable cursor. No spool, cursor,
dead-letter, or archive record was removed. No attack traffic was generated.

## Browser UAT

Status: **BLOCKED**.

The in-app browser loads the real protected frontend but cannot reach its local
auth API. Direct host requests through the same frontend proxy return the correct
401, so the host application path is healthy. The supported Windows helper found
Chrome but could not activate a captured window after refresh and one retry.

Core manual checklist result: 0 PASS, 0 FAIL, 20 BLOCKED. Permission-role,
responsive-viewport, download/PDF visual inspection, failure-state, focus, and
authenticated workflow matrices are also BLOCKED. No password was entered, no
test account was created through an unsupported mechanism, and no auth/CSRF
control was changed. `BROWSER_UAT_V08.md` contains exact expected results and
evidence naming.

## Final regression matrix

| Gate | Result |
| --- | --- |
| Backend | PASS: 191/191; one upstream Starlette/AnyIO warning |
| Frontend final full run | PASS: 97/97 across 16 files |
| Frontend cold-run observation | 96 PASS, 1 lazy-route timing FAIL; bounded wait fix applied, targeted 10/10 and two later full 97/97 runs PASS |
| TypeScript | PASS |
| Production build | PASS: 64 modules, route chunks emitted |
| Wazuh sender/shipper + deployment | PASS: 126/126 |
| HTTP E2E | PASS: 2/2; deterministic test provider only, no LLM started |
| Passive lab validator | PASS: 9/9 |
| Live security boundary probes | PASS: 8/8 expected statuses |
| SQLite integrity | PASS: quick check `ok`, 0 FK violations |
| Backup verification and disposable restore | PASS |
| Python compilation | PASS |
| Python dependency check | PASS |
| npm vulnerability audit | PASS: 0 vulnerabilities |
| Git whitespace check | PASS; line-ending conversion warnings only |
| Authenticated browser UAT | BLOCKED: 20/20 core steps unexecuted |

## Documentation and demo readiness

Release notes, changelog, install/start/stop/environment guide, backup/restore
procedure, troubleshooting, security assumptions, hardware guidance, known
limitations, browser UAT checklist, 15-step professional demo runbook, repository
inventory, and Git staging proposal are present. The demo defaults to passive
evidence and explicitly labels real, historical real, and synthetic samples.
Active validation remains separately authorized and is not part of the default
flow.

## Git state and staging

No file is staged. The accumulated working tree remains intentionally dirty. The
final exact-path scan reports 70 tracked unstaged files and 149 untracked files,
219 paths total. The increase from the inventory checkpoint is the preserved v0.8
source, test, configuration, and release-document work plus pre-existing work;
ignored runtime artifacts are not included.
`GIT_STAGING_V08.md` provides explicit review groups and excludes secrets,
databases, backups, runtime output, build output, generated PDFs, and the unusual
empty directory. Do not use `git add .`, commit, or push before browser acceptance
and explicit user approval.

## Remaining blockers

1. Execute and evidence authenticated manual Chrome/Edge UAT, including role,
   responsive, export/PDF, keyboard, history, error, and logout behavior.
2. Configure supported read-only Wazuh API credentials and CA if authoritative
   API inventory is required.
3. Complete supported elevated Windows agent enrollment with an approved key and
   current manager address.
4. Production-target Compose/TLS acceptance and capacity testing remain external
   environment gates.

Until blocker 1 is closed, this candidate is suitable for controlled technical
review and passive lab demonstration, but not final release approval.
