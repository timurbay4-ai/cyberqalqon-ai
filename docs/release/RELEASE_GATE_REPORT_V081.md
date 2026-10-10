# CyberQalqon SIEM v0.8.1 release gate report

- Validation date: 2026-10-10
- Source candidate: `0.8.1-rc1`
- Schema: 14
- Branch: `main`
- Baseline HEAD: `b07fdd50dc3df71976bf9467f8ecb98e68045926`
- Recommendation: **CONDITIONAL GO**

## Executive decision

CyberQalqon is accepted for the controlled local v0.8.1 release-candidate demo.
Automated regression, database recovery, security boundaries, real authenticated
Microsoft Edge UAT, telemetry health, and the repeatable SOC workflow all pass.
Four real browser defects were found, corrected, and covered by regression tests.

The release is not marked FINAL. The working tree remains intentionally
unstaged, uncommitted, and untagged; the live backend process still advertises
0.8.0 until a controlled restart; production HTTPS/Compose and capacity gates
are external to this local run. Wazuh API inventory and Windows-agent enrollment
remain explicitly unavailable rather than being represented as healthy.

No reset, clean, rebase, commit, tag, push, live-database overwrite, authentication
bypass, active scan, response action, or LLM installation was performed.
`AI_ENABLED=false` remained in force.

## Gate classification

| Gate | Result | Evidence and boundary |
| --- | --- | --- |
| G1 — Automated regression | **PASS** | Backend 191/191; frontend 99/99; Wazuh/deployment 126/126; HTTP E2E 2/2; TypeScript, production build, compile, dependency checks, npm audit, and diff whitespace checks pass |
| G2 — SQLite integrity and recovery | **PASS** | Live `quick_check=ok`, schema 14 and no foreign-key violations; supported backup checksum verified; disposable restore invalidated sessions and restarted successfully; live DB never replaced |
| G3 — Authentication and authorization | **PASS** | ADMIN/ANALYST/VIEWER boundaries, direct VIEWER mutation 403, CSRF 403, session expiry, logout/Back, audit actors, and report redaction verified |
| G4 — Real authenticated browser UAT | **PASS** | Microsoft Edge 155 on the actual Windows host: 20/20 core steps and 48/48 route/viewport checks pass |
| G5 — Operational telemetry health | **PASS** | Passive validator 9/9; Manager and agent active; relay HTTP 200; sender queue/dead-letter 0/0; shipper lag 0; unavailable authorities labelled truthfully |
| G6 — Secret-safe Git release manifest | **PARTIAL** | Candidate inventory, ignore checks, secret scan, exclusions, grouping, tag, review, and rollback plan are complete; no reviewed index, commit, or tag exists because approval was not granted |
| G7 — Repeatable SOC demonstration | **PASS** | Existing rule-100101/100111 evidence, T1046, correlation, hunt, operations, case/evidence/playbook/report/audit flow are documented; live mutation is not required |

## What was executed

### Real browser and UX

- Ran the full 20-step authenticated UAT in Microsoft Edge 155.0.4283.45 on
  Windows against a disposable copy of real lab evidence.
- Verified ADMIN, ANALYST, and VIEWER visibility and server-side permissions,
  valid-CSRF mutations, missing-CSRF rejection, session expiration, logout, and
  browser Back behavior.
- Opened all 12 authenticated top-level pages at 1440x900, 1024x768, 768x1024,
  and 390x844: 48/48 passed with zero document overflow and zero rendered error alerts.
- Verified dialog focus/Escape, Discover `/` focus, input-safe shortcuts, global
  navigation chords, copy controls, and JSON/CSV/PDF downloads.
- Rendered the two-page A4 case PDF and visually inspected both pages for clipping,
  overlap, evidence digest, limitation text, page numbers, and secret fields.

### Regression and security

- Backend: **191/191 PASS**; one upstream Starlette/AnyIO deprecation warning.
- Frontend: **99/99 PASS** across 16 files; TypeScript PASS.
- Production build: **PASS**, 64 modules; main JS 318.01 kB / 91.98 kB gzip;
  CSS 42.69 kB / 9.18 kB gzip; lazy route chunks emitted.
- Wazuh sender/shipper and deployment: **126/126 PASS**.
- HTTP E2E: **2/2 PASS** with the deterministic test provider; no LLM started.
- `npm audit`: zero reported vulnerabilities; `pip check` and Python compile PASS.
- Candidate secret scan found no private-key header, JWT, provider key, or
  non-ignored runtime secret; deterministic credential literals exist only in tests.

### Database, recovery, and resources

- Verified online backup
  `backups/cyberqalqon-pre-v081-uat-20261010T1005Z.db`, 21,426,176 bytes,
  SHA-256 `d02ff456d570c07e3044126b50d60c3bbbee486817e06b98b967ae196d7ad120`.
- Restored only to `tmp/v081-release-restore.db`: schema 14, `quick_check=ok`,
  zero foreign-key violations, 4,785 events, 40 alerts, 3 incidents, and copied
  sessions invalidated. The restored application reached health in 2,045.9 ms.
- Confirmed the durable event shipper retained its cursor and returned to lag 0
  with empty sender queues; no spool, cursor, dead letter, or archive was deleted.
- Representative real-browser timings: cold shell 471 ms, login-to-Overview
  401 ms on the performance pass, cold Discover 386 ms, cold Cases 374 ms,
  case detail 282 ms, hunt 886 ms, case creation 695 ms, and PDF 459 ms.
- Case-page browser heap was about 14.9 MB used / 18.4 MB total. At idle, the
  live frontend used about 12.9 MiB working set and the backend about 3.1 MiB;
  these single-laptop observations are not production capacity claims.

## Verified defects corrected

| ID | Correction | Final proof |
| --- | --- | --- |
| UX-081-001 | Invoke native browser `fetch` through an arrow wrapper so its receiver is not rebound | Native-like regression plus all 20 real Edge steps PASS |
| UX-081-002 | Normalize an omitted terminal `next_cursor` to `null` in the frontend contract | Contract regression and real Discover search/filter PASS |
| UX-081-003 | Bound panel/table min-content width and collapse narrow filters | 12 pages x 4 viewports, maximum overflow 0 px |
| UX-081-004 | Retry focus for the lazy Discover input with bounded cleanup | Fresh Edge tab focuses search; typed shortcut text does not navigate |

No open release-blocking UX defect remains. The initial unauthenticated 401 and
missing icon 404 were non-sensitive bootstrap noise, not protected-data leakage
or an authenticated workflow failure.

## Operational status

The final passive snapshot passed 9/9 checks. Backend and frontend returned HTTP
200; the four Kali units and five Manager-side units were active; the backend
relay path returned HTTP 200; agent `cyberqalqon-test-web` was active; sender
queue, pending, in-flight, terminal-blocked, and dead-letter counts were zero;
the archive cursor equalled archive size with lag zero; and SQLite reported
`quick_check=ok`, schema 14, 40 alerts, and 5,517 events. The event count is
expected to advance while ingestion runs.

Wazuh API inventory is `UNAVAILABLE` because approved read-only credentials/CA
are absent. The Windows Wazuh service exists but is not enrolled in the current
Manager. These are visible limitations, not silent health claims.

## Git snapshot state

The baseline remains `main` at
`b07fdd50dc3df71976bf9467f8ecb98e68045926`. Before the final three documents,
there were 70 tracked modified files, 151 untracked non-ignored files, and zero
staged files. The completed five-document v0.8.1 set raises the untracked count
to 154, subject to the final read-only recount.

`GIT_RELEASE_MANIFEST_V081.md` classifies source, tests, migrations, templates,
scripts, and documentation; excludes runtime/security material; proposes four
reviewable commit groups; and defines `v0.8.1-rc1` as the candidate tag. No Git
mutation was executed.

## Prepared but not executed

- Assembly of the reviewed Git index, commit creation, candidate tagging, and push.
- Controlled restart of the normal live backend/frontend to activate and verify
  the 0.8.1 source metadata; the running OpenAPI process still reports 0.8.0.
- Production HTTPS reverse-proxy browser UAT, production Compose rollout,
  multi-user capacity/load characterization, and infrastructure rollback drill.
- Wazuh API inventory validation pending approved read-only credentials and CA.
- Windows-agent enrollment pending an approved enrollment channel.
- Any active attack simulation, scan, destructive response, or LLM integration.

## Remaining blockers and recommendation

The mandatory local application and demo gates pass. Final release status is
withheld because G6 has no reviewed/staged snapshot, the live process has not
been restarted onto the 0.8.1 candidate, and production deployment/capacity
acceptance remains external.

**Recommendation: CONDITIONAL GO for a controlled local v0.8.1-rc1 demo and
reviewed release-snapshot preparation. Do not mark FINAL or publish `v0.8.1`
until the exact staged manifest is approved, scanned, re-tested, committed,
tagged, and the target deployment is restarted and smoke-tested.**

## Evidence index

- `BROWSER_UAT_RESULTS_V081.md` — exact 20-step, role, responsive, keyboard,
  download, and browser-performance evidence.
- `UX_DEFECT_REGISTER_V081.md` — verified defect causes, fixes, and closure.
- `GIT_RELEASE_MANIFEST_V081.md` — staging exclusions, review commands, grouping,
  tag proposal, and non-destructive rollback plan.
- `DEMO_ACCEPTANCE_V081.md` — passive-first repeatable SOC demo and stop conditions.
- `artifacts/lab-validation/v081-passive-final.json` — ignored machine-readable
  final passive health snapshot.
