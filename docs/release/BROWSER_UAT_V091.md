# CyberQalqon SIEM v0.9.1 manual browser UAT

Status: **IN PROGRESS through operator-provided manual evidence**. Runtime preflight is PASS: the intended local frontend is
`http://127.0.0.1:5173/`, the backend and frontend return HTTP 200, and the live
Wazuh API integration is `AVAILABLE`. Computer Use could not independently
establish the native Chrome URL with sufficient confidence, so the restriction
was not bypassed. The operator instead supplied credential-free screenshots
from the manually authenticated Chrome session.

The operator must independently confirm the complete address bar before login,
use the normal login form, and retrieve an approved CyberQalqon analyst
credential locally. Do not paste a password, CSRF token, cookie, browser storage,
or credential-bearing screenshot into chat. The available protected Wazuh API
credentials are not CyberQalqon application login credentials.

Record `PASS`, `FAIL`, or `BLOCKED` for every step:

1. **URL/login** — exact loopback URL, protected login, normal authentication.
2. **Overview** — live counts, ingestion freshness, honest unavailable states.
3. **Discover** — search/filter/detail, timezone, raw evidence, empty/error state.
4. **Alerts** — list/filter/detail and immutable workflow/history evidence.
5. **Incidents** — related alerts, activity, evidence, browser history.
6. **Cases** — honest empty/populated state and evidence chain.
7. **Threat Hunting** — read-only hunt, no-result/error, sort and pagination.
8. **Threat Intelligence** — IOC list/detail/filter/expiry and role visibility.
9. **Operations** — manager/API/sender/shipper/database healthy; Windows Agent 002 healthy; source freshness separate.
10. **Agents** — authoritative Agents 001 and 002 online; no mutation controls.
11. **Agent filters** — status/OS/manager/source/search/sort/reset/pagination/zero result.
12. **Agent detail** — opaque link, authority, cache freshness, versions, sources, recent counts and health history.
13. **Deep links/history** — copy safe link, back/forward, Escape behavior.
14. **Navigation/accessibility** — keyboard, focus, labels, narrow layout, long text.
15. **Reports** — filters/timezone/empty state/export and safe filenames.
16. **Administration/RBAC** — role visibility, analyst/audit reads; make no user/password change solely for UAT.
17. **Logout** — normal sign-out; protected content unavailable after back.

## Result ledger

| Test | Expected | Actual observed | Result | Evidence / defect |
| --- | --- | --- | --- | --- |
| UAT-01 URL/login | Exact loopback URL, protected login, normal authentication | Operator screenshot shows `127.0.0.1:5173` and the authenticated CyberQalqon workspace/navigation | PASS | `codex-clipboard-f9c86d4f-67ac-499f-a7af-ad97772944bc.png`; operator-provided, outside Git |
| UAT-02 Overview | Live counts, ingestion freshness, honest unavailable states | Lower Overview region shows event categories and honest empty alert states. Visible counts: Windows security 6,925; Web 1,052; Local 688; Syslog 47; Ossec 32; Pam 30; Windows event 5. The upper status/freshness cards are not visible. | BLOCKED | Partial visual evidence only; a top-of-page Overview screenshot is required |
| UAT-03 Discover | Search/filter/detail, timezone, raw evidence, empty/error state | Not run | NOT RUN | — |
| UAT-04 Alerts | List/filter/detail and immutable workflow/history evidence | Not run | NOT RUN | Live mutation is prohibited for this UAT |
| UAT-05 Incidents | Related alerts, activity, evidence, browser history | Not run | NOT RUN | Live mutation is prohibited for this UAT |
| UAT-06 Cases | Honest empty/populated state and evidence chain | Not run | NOT RUN | Live mutation is prohibited for this UAT |
| UAT-07 Threat Hunting | Read-only hunt, no-result/error, sort and pagination | Not run | NOT RUN | — |
| UAT-08 Threat Intelligence | IOC list/detail/filter/expiry and role visibility | Not run | NOT RUN | Live IOC creation is prohibited for this UAT |
| UAT-09 Operations | Manager/API/sender/shipper/database and Windows health | Not run | NOT RUN | — |
| UAT-10 Agents | Authoritative Agents 001 and 002 online; no mutation controls | Not run | NOT RUN | — |
| UAT-11 Agent filters | Filters, search, sort, reset, pagination, zero-result state | Not run | NOT RUN | — |
| UAT-12 Agent detail | Authority, cache, versions, sources, counts and history | Not run | NOT RUN | — |
| UAT-13 Deep links/history | Safe link, back/forward and Escape behavior | Not run | NOT RUN | — |
| UAT-14 Navigation/accessibility | Keyboard, focus, labels, narrow layout, long text | Not run | NOT RUN | — |
| UAT-15 Reports | Filters, timezone, empty state, export and safe filenames | Not run | NOT RUN | — |
| UAT-16 Administration/RBAC | Role visibility and read-only administration/audit evidence | Not run | NOT RUN | Password or account changes are prohibited for this UAT |
| UAT-17 Logout | Normal sign-out; protected content unavailable after Back | Not run | NOT RUN | Must be the final browser step |

Current totals: 1 PASS, 0 FAIL, 1 BLOCKED, 15 NOT RUN. No browser restriction,
authentication control, CSRF protection, or session boundary was bypassed.
