# CyberQalqon SIEM v0.8.1 browser UAT results

- Validation date: 2026-10-10
- Browser: Microsoft Edge 155.0.4283.45 (Chromium, actual Windows host)
- Application source: 0.8.1-rc1
- Result: **20 PASS, 0 FAIL, 0 BLOCKED**

## Isolation and evidence handling

The live evidence database was not mutated. The supported online backup
`cyberqalqon-pre-v081-uat-20261010T1005Z.db` was restored to the ignored
`tmp/v081-browser-uat.db`. Three UAT-only roles were created in that disposable
copy with the existing authentication repository. Their credentials stayed in
the ignored, ACL-restricted `secrets/v081-browser-uat-credentials.json` and were
never printed, committed, or placed in a screenshot.

The isolated backend listened on `127.0.0.1:8011`; the isolated Vite proxy used
`127.0.0.1:5174`. Exact Origin, cookie, CSRF, and RBAC controls remained enabled.
`AI_ENABLED=false`. Screenshots and downloads are under the ignored
`artifacts/runtime/uat-v081/` tree.

## Core 20-step result

| ID | Role | Prerequisite | Exact action | Expected | Actual result | Status | Evidence / defect |
| --- | --- | --- | --- | --- | --- | --- | --- |
| UAT-01 | ANALYST | Disposable DB and UAT analyst | Sign in through the normal form | Overview opens without credential material in URL or storage | Overview opened; login was about 1,083 ms during the first run | PASS | `UAT-01-login-overview.png`; UX-081-001 fixed |
| UAT-02 | ANALYST | Authenticated session | Reload the page | Session and role persist | Session restored in 1,445 ms | PASS | `UAT-02-session-persistence.png` |
| UAT-03 | ANALYST | Copied real lab evidence | Inspect Overview | Truthful counts and freshness | 4,785 copied events and 3 active incidents rendered; stale evidence stayed labelled stale | PASS | `UAT-02-session-persistence.png` |
| UAT-04 | ANALYST | Discover and copied event store | Search `nginx` over seven days | Indexed terminal page renders | One result rendered in about 926 ms | PASS | `UAT-04-discover-search.png`; UX-081-002 fixed |
| UAT-05 | ANALYST | Discover loaded | Filter host `cyberqalqon-test-web` and rule `100101` | Only matching evidence remains | 24 matching events | PASS | `UAT-05-discover-filters.png` |
| UAT-06 | ANALYST | Filtered result | Open event detail | Normalized evidence and redaction render | Rule `100101`, level 10 event rendered | PASS | `UAT-06-event-detail.png` |
| UAT-07 | ANALYST | Copied alert evidence | Open alert `1791475133.970049` | Rule, level, agent, network, relation, and MITRE data render | Rule `100111`, level 10, agent `001`, and `T1046` rendered | PASS | `UAT-07-alert-detail.png` |
| UAT-08 | ANALYST | Disposable copied alert | Assign to the UAT analyst and acknowledge | Optimistic version and audit update once | Assignment 932 ms; acknowledgement 954 ms; version reached 3 | PASS | `UAT-08-alert-workflow.png` |
| UAT-09 | ANALYST | Existing copied incident | Open investigation workspace | Correlation, timeline, and linked alerts render | `CORR-001/002/003` and 9 linked alerts rendered in 805 ms | PASS | `UAT-09-incident-investigation.png` |
| UAT-10 | ANALYST | Disposable incident | Add, assign, and complete a prefixed checklist item | Checklist and activity update | 1/1 item completed | PASS | `UAT-10-incident-checklist.png` |
| UAT-11 | ANALYST | Disposable incident and copied alert | Pin alert evidence with annotation | Source time, actor, and immutable reference render | Existing alert reference pinned and displayed | PASS | `UAT-11-pinned-evidence.png` |
| UAT-12 | ANALYST | Copied normalized events | Hunt seven days for rule `100111` | Bounded results and relationships render | 17 matches; request about 886 ms | PASS | `UAT-12-threat-hunt.png` |
| UAT-13 | ANALYST | Detection catalog | Open rule `100111` and Coverage | Read-only rule and truthful authority state | `T1046` observed; Wazuh enabled state remained `UNKNOWN` | PASS | `UAT-13-detection-engineering.png` |
| UAT-14 | ANALYST | Disposable IOC store | Add a prefixed loopback IOC and inspect matches | Local bounded match, no enrichment or response action | HTTP 201; copied `source_ip` evidence matched | PASS | `UAT-14-threat-intelligence.png` |
| UAT-15 | ANALYST | Captured operational snapshot | Open Operations | Authority and unavailable states stay truthful | DB/sender/shipper/manager healthy; Wazuh API and Windows enrollment unavailable | PASS | `UAT-15-operations.png` |
| UAT-16 | ANALYST | Copied alert `1791475133.966297` | Create a prefixed case | Existing alert is linked without altering it | Case `CASE-4F56F1423B834A079DA5B1654B53DDA3` created in 695 ms | PASS | `UAT-16-case-created.png` |
| UAT-17 | ANALYST | Disposable case | Change owner, enter handoff, and add comment | Owner/version/activity/comment update | Edge UI POST returned 200 in 836 ms; final restore POST returned 200 in 258 ms; comment and handoffs rendered | PASS | `UAT-17-case-collaboration-final.png` |
| UAT-18 | ANALYST | Case and copied alert | Acquire/verify evidence, start network playbook, complete one safe step, move to triage, evaluate SLA | Digest verifies, no command executes, response timestamp records | Evidence `VERIFIED`; playbook 1/4; status `TRIAGING`; SLA evaluated 1 case with 0 duplicate notifications | PASS | `UAT-18-playbook-sla.png` |
| UAT-19 | ANALYST | Versioned case | Export JSON, CSV, and PDF | Authenticated safe downloads and report history | JSON 11,519 B/1,187 ms; CSV 3,634 B/1,384 ms; PDF 5,357 B/459 ms | PASS | `UAT-19-case-reports.png`; downloads ignored |
| UAT-20 | ANALYST, ADMIN | Completed UAT work | Review append-only audit; sign out; use Back | Actions have actors/outcomes; protected content does not return | Required case actions showed `SUCCESS`; logout 519 ms; Back stayed on login | PASS | `UAT-20-audit-logout.png` |

## Report visual inspection

The exported PDF was rendered with Poppler at 150 DPI and inspected page by
page. It is a two-page A4 report with readable title, case identity, status,
verified SHA-256 evidence digest, timeline, scope limitation, and page numbers.
There was no clipping, overlap, black glyph block, or credential/session term.
JSON and CSV structure was also inspected; no password, CSRF token, or session
cookie field was present.

## Cross-role and security matrix

| Check | ADMIN | ANALYST | VIEWER | Result |
| --- | --- | --- | --- | --- |
| Read events, alerts, incidents, cases, and evidence | Allowed | Allowed | Allowed | PASS |
| Alert and case mutation | Allowed | Allowed | Hidden/absent; direct request 403 | PASS |
| Case JSON/CSV/PDF export | Allowed | Allowed | Buttons disabled; explanatory copy shown | PASS |
| Analyst RBAC and security audit | Visible | Denied by server policy | Hidden; direct administration data unavailable | PASS |
| CSRF | Required | Required | Required | PASS: authenticated POST without token returned 403 `invalid_csrf_token` |
| Session expiration | Enforced | Enforced | Enforced | PASS: isolated five-second session returned to login after expiry/reload |

The VIEWER alert panel displayed stored evidence but no workflow mutation
controls and explicitly stated that the role was read-only. The case panel did
the same and disabled all three exports.

## Responsive, focus, and navigation checks

All 12 authenticated top-level pages were opened at 1440x900, 1024x768,
768x1024, and 390x844: **48/48 PASS** after UX-081-003 was fixed. There was no
document-level horizontal overflow and no rendered `role=alert` error. Wide
tables remained inside their intended horizontal scrollers.

The shortcut dialog received focus, Escape closed it, `/` navigated to Discover
and focused the lazy-loaded keyword input, typing `g a` in that input did not
navigate, and the global `g d`, `g a`, `g i`, and `g c` chords reached the
documented pages. This required UX-081-004.

## Executed versus prepared

The 20 core steps, role boundaries, CSRF, short-TTL expiry, PDF visual review,
keyboard flow, and 48 responsive route checks were actually executed. No core
step is manual-only. A production HTTPS/Compose browser pass and exhaustive
per-page network-failure injection were not executed in this local release
gate; bounded loading/error/retry behavior remains covered by automated tests.
