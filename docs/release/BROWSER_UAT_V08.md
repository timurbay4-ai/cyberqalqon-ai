# CyberQalqon SIEM v0.8 browser UAT

## Execution status

**BLOCKED - authenticated workflows were not executed.**

Evidence collected on 2026-10-10:

- The supported in-app browser loaded the real frontend at
  `http://127.0.0.1:5173/`, including the protected analyst sign-in view, but the
  page reported that its local auth API was unavailable.
- Retrying after backend, proxy, and CORS validation produced the same state.
- From the host, the same frontend proxy returned the expected 401 structured
  response for an unauthenticated session, proving that the application path was
  healthy outside the in-app browser.
- The Windows browser helper discovered Chrome but could not activate either
  captured Chrome window after the required refresh-and-retry sequence.
- No password was entered, no authentication control was bypassed, and no
  dedicated account was created through an unsupported path.

The checklist below must be executed in a normal local Chrome or Edge window
with a dedicated, administrator-created test analyst before final approval.

## Preconditions

1. Use `http://127.0.0.1:5173/` for local HTTP development or the reviewed HTTPS
   production origin. Do not mix origins during a session.
2. Confirm backend `/health` and `/readiness`, frontend `/health`, and the nine
   passive validator checks are PASS.
3. Keep `AI_ENABLED=false`.
4. Have an administrator create one dedicated analyst account through the normal
   authenticated Administration workflow. Do not reset or reuse `soc-admin` for
   UAT and do not put the password in screenshots or logs.
5. Prefix mutable test records with `SYNTHETIC UAT v0.8` and remove them only
   through an approved application workflow. Never label them as real evidence.
6. Open browser developer tools only for response/status and console evidence;
   redact cookies, CSRF values, passwords, machine keys, raw personal data, and
   sensitive telemetry before saving evidence.

## Evidence naming

Save screenshots outside Git using:

`artifacts/runtime/uat-v08-<step>-<short-name>.png`

For each step record browser/version, viewport, URL, timestamp, expected result,
actual result, and PASS/FAIL/BLOCKED. Never capture the password field or cookie
values.

## Desktop workflow

| Step | Action | Expected result | Evidence |
| --- | --- | --- | --- |
| 1 | Sign in with the dedicated analyst | Overview appears; no credential details enter the URL/storage/console | Overview screenshot and session response status only |
| 2 | Refresh Overview and change time range | Loading state resolves to real totals; last-success timestamp updates; cards navigate | Before/after screenshot |
| 3 | Open Discover, search, apply exact filters, sort and paginate | URL keeps only approved non-sensitive fields; table/detail/empty/error states are coherent | Filtered table and detail |
| 4 | Copy an event ID, open its deep link, then use browser Back/Forward | Copy feedback appears; detail restores without losing page route | URL and restored detail |
| 5 | Open Alerts, search/filter/sort/paginate and inspect one alert | Rule, level, host, MITRE and evidence render as stored; no raw HTML executes | Alert detail |
| 6 | As analyst, acknowledge/assign one explicitly selected synthetic test alert only | Confirmation appears; version/history/audit update once | Confirmation and resulting history |
| 7 | Open Incidents, filter and inspect timeline, linked alerts and workspace | Deep links work; checklist/evidence mutations respect permissions and versions | Incident detail/workspace |
| 8 | Open Hosts and Sources | Source freshness is distinct from agent authority; unknown stays unknown without Wazuh API | Host and source panels |
| 9 | Open Detection Rules | Search, filters, pagination and linked alert navigation work; Wazuh editing remains unavailable | Rule detail and trust note |
| 10 | Open Threat Hunting | Run a bounded saved hunt; paginate; open event/alert/incident; CSV is capped and authenticated | Hunt results and export status |
| 11 | Open Threat Intelligence | Filter IOC inventory and perform bounded local matching; no external enrichment or blocking occurs | IOC result and safety copy |
| 12 | Open Operations | Components, current/last transition and recovery details match passive validator evidence | Operations screenshot |
| 13 | Create a `SYNTHETIC UAT v0.8` case and test ownership, comment and allowed lifecycle transitions | Optimistic version increments; invalid/terminal transitions are rejected; activity is append-only | Case detail and activity |
| 14 | Link existing synthetic references, acquire evidence, copy digest, verify, and run one deterministic playbook | Integrity status and custody update; approval/evidence gates block skipped steps; no command executes | Evidence and playbook panels |
| 15 | Evaluate SLA and export case JSON, CSV and PDF | Owner notification is deduplicated; files download via authenticated POST; secrets are redacted | SLA state, download names, visually inspected PDF |
| 16 | Open Reports, select a valid range and export JSON/CSV | Applied filters are visible; invalid ranges block requests; downloads use safe names | Report and error state |
| 17 | Open Notifications and follow one target; mark it read | Only the signed-in analyst's notification changes; target deep link opens | Notification before/after |
| 18 | Open Administration, save/reset preferences and review audit filters | Per-user values persist; viewer/analyst/admin controls match server permissions | Preferences and audit view |
| 19 | Press `?`, `/`, `g d`, `g a`, `g i`, `g c`, and `Esc`; repeat while focus is in a text field | Shortcuts work globally but never hijack typing; focus returns after dialogs | Keyboard checklist |
| 20 | Sign out, use Back, and request a protected deep link | Protected shell is not restored; server returns 401; no sensitive page remains usable | Login page after Back |

## Permission matrix

Repeat representative steps with each role:

- `VIEWER`: reads allowed; all mutations and exports requiring write permission
  are hidden or disabled and server returns 403 if called directly.
- `ANALYST`: alert/incident/case workflows allowed; analyst administration denied.
- `ADMIN`: administration allowed; self role/active-state changes remain denied.

Frontend visibility is not proof of authorization. Preserve the corresponding
401/403 response status as evidence without recording tokens.

## Responsive matrix

Test 1440x900, 1024x768, 768x1024 and 390x844 viewports. At each size verify:

- navigation remains reachable without overlapping primary content;
- tables scroll within their container instead of widening the page;
- detail panels fit the viewport and retain a visible close control;
- dialogs trap the apparent task focus and close with Escape;
- case filters/forms collapse to one column on narrow screens;
- text, digests and IDs wrap without covering controls;
- no horizontal page overflow outside intentional table/navigation scrollers.

## Failure handling

For each major page, use developer tools to block only that page's safe GET
request, then verify the bounded error and Retry state. Restore networking before
the next step. Do not tamper with mutation responses, cookies, CSRF, TLS, or
browser security controls. Also verify a true empty result using filters that
match no records rather than deleting data.

## Acceptance

Final browser status may become PASS only when every required desktop,
permission, keyboard, history, export, and responsive step has evidence. Any
unexecuted required step remains BLOCKED; an automated component test is not a
substitute for this checklist.
