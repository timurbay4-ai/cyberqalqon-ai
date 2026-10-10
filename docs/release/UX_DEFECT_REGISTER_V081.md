# CyberQalqon SIEM v0.8.1 UX defect register

- Validation date: 2026-10-10
- Disposition: **four verified defects fixed; no open release-blocking UX defect**

| ID | Severity | Discovery evidence | Root cause | Correction | Verification | Status |
| --- | --- | --- | --- | --- | --- | --- |
| UX-081-001 | Release blocker | Real Edge login reached the shell, but every API request failed with `Illegal invocation` and the UI claimed the backend was unavailable | `HttpBackendApi` stored the browser-native `fetch` function as an object property and invoked it with the API client as its receiver. Unit mocks did not enforce the native receiver contract | Default fetcher is now an arrow wrapper that calls global `fetch(input, init)` without rebinding it | New native-like receiver regression test; login and all 20 Edge steps PASS; frontend 99/99 | FIXED |
| UX-081-002 | High | Discover `nginx` search returned data but rejected the terminal page at `response.page.next_cursor` | FastAPI excludes `None`, so a final cursor is omitted; the frontend contract accepted only string or explicit null | Contract parser normalizes an omitted cursor to `null` while still rejecting other types | Contract regression test; Discover search and filters PASS in Edge | FIXED |
| UX-081-003 | Medium | Hosts widened a 390 px page by 125 px; Cases widened it by 548 px | Custom filter minimum columns and the Cases `.table-wrap` lacked narrow-screen containment; panels could retain descendant min-content width | Panels receive `min-width: 0`; `.table-wrap` uses the same bounded overflow behavior as `.table-frame`; inventory/rule filters collapse to one column at 560 px | Final 12-page x 4-viewport matrix: 48/48, maximum page overflow 0 px | FIXED |
| UX-081-004 | Medium | `/` navigated to Discover in real Edge but focus remained on `BODY` | Focus was attempted once at `setTimeout(..., 0)` before the lazy-loaded Discover route mounted | A bounded 40-attempt/50 ms focus retry stops immediately when `#discover-search` exists and is cleaned up on unmount | Fresh Edge tab: Discover input focused; typing shortcuts in it did not navigate; global chords PASS; 99/99 frontend tests | FIXED |

## Inspection summary

The authenticated audit covered Overview, Operations, Discover, Threat Hunting,
Alerts, Incidents, Cases, Hosts, Detection Engineering, Threat Intelligence,
Reports, and Administration. It exercised real search/filter/detail flows,
pagination end-state parsing, alert/incident/case mutations on a disposable DB,
copy/focus controls, three report downloads, audit history, logout/Back, role
visibility, and responsive layout.

No dead top-level navigation control, broken report download, misleading green
Wazuh API/Windows enrollment state, duplicated SLA notification, credential in
an export, or unhandled browser exception remained in the final run. Timestamps
included `GMT+5`; source freshness and agent authority stayed distinct.

The initial browser console produced one unauthenticated 401 and a missing icon
404 during bootstrap. Neither represented a protected-data leak or functional
page failure. The final authenticated 48-route responsive matrix added no new
console error and no rendered error alert.

## Non-blocking coverage boundary

Automated component tests cover loading, empty, API error, Retry, sorting,
pagination, and permission states. The release run did not manually intercept
every individual page GET in developer tools, and it did not repeat the full
matrix against a production HTTPS reverse proxy. Those are production acceptance
checks, not open defects in this local v0.8.1 candidate.
