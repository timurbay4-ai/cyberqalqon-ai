# SIEM v0.3 UX validation record

Validated on 2026-10-08 against the authorized local Windows/WSL lab. The checkout remained on
`main` at `b07fdd50dc3df71976bf9467f8ecb98e68045926`; no commit or push was created. v0.3 adds no
database migration and does not change AI/M8 behavior. `AI_ENABLED=false` remains required.

## Reused authoritative workflows

- authenticated same-origin analyst sessions, backend RBAC, CSRF mutation boundary, and central
  session-expiry handling;
- indexed SQLite alert/event reads, bounded keyset pagination, saved Discover searches, M9 incident
  lifecycle, notes, assignment, audit history, rule catalog, host/source projections, and reports;
- existing incident statuses only: `NEW`, `TRIAGED`, `INVESTIGATING`, `RESOLVED`, and
  `FALSE_POSITIVE`.

No alert acknowledgment, assignment, note, snooze, or unread state was fabricated. Those controls
remain absent because the alert model has no durable state, authorization, and audit contract.

## Implemented micro-features

| Area | Result | Evidence |
|---|---|---|
| Global navigation | PASS | URL-backed pages, browser back/forward, breadcrumbs, page/detail deep links |
| Keyboard | PASS | `/`, `?`, `g d`, `g a`, `g i`, and `Esc`; typing targets are excluded |
| Copy feedback | PASS | Shared accessible control for event/alert/incident/rule/host/IP/JSON values; failures are explicit |
| Time display | PASS | Local absolute time with timezone label; relative time tooltips; past/future/malformed tests |
| Discover | PASS | Clear search, active removable chips, clear all, 25/50/100 pages, safe shareable filters, history state, saved-search rename, event deep links |
| Alerts | PASS | Exact indexed rule ID filter, bounded page sizes, deep links, copy actions, source-event navigation |
| Incidents | PASS | Durable existing lifecycle/assignment/notes/history retained; copy incident/evidence references; deep links and bounded page sizes |
| Dashboard | PASS | Manual refresh, last-success timestamp, refresh/stale feedback, actionable metric drill-downs |
| Hosts/sources | PASS | Search/source filters, detail panel, copy actions, relative/absolute last seen, explicit source-vs-agent evidence explanation |
| Rules | PASS | ID/name/source/severity filters, detail panel, rule type, MITRE links, copy, and exact related-alert drill-down |
| Reports | PASS | Preset/custom range, preview metadata/timezone/filter summary, authenticated CSV/JSON downloads, progress/error/success feedback, empty result explanation |
| Notification center | DEFERRED | No durable per-user read model; adding one would require a migration, polling contract, RBAC, and audit design |
| User preferences | DEFERRED | P2; no browser-local preference or secret storage was added |

## Security checks

- Sensitive Discover fields (keyword, username, IPs, hostname, event ID, raw evidence) are never
  written to URL parameters. Safe categorical filters may be shared; full context is retained only
  in ephemeral browser history state.
- Report downloads keep authenticated cookies, a 31-day backend bound, authorization, audit,
  `Cache-Control: no-store`, `nosniff`, safe filenames, JSON serialization, and CSV formula
  neutralization.
- Telemetry remains React text, not executable HTML. MITRE links use fixed ATT&CK URL construction
  and `rel=noreferrer`.
- No credentials, ingest keys, event JSON, or analyst notes are added to URLs or local storage.
- Rule editing remains disabled. No bulk mutation or automatic response action was introduced.

## Automated gates

| Gate | Result |
|---|---|
| Backend | 161 PASS |
| Frontend | 77 PASS |
| TypeScript | PASS |
| Frontend production build | PASS |
| Targeted report/alert backend tests | 11 PASS |
| Browser component navigation, history, keyboard, copy, empty/error/export checks | PASS |
| Authenticated visual browser E2E | BLOCKED — localhost `/api` is blocked by the Codex in-app browser |

## Remaining limitations

- Alert-level status, acknowledgement, assignment, notes, activity history, unread state, and bulk
  operations require a new durable backend workflow and are not exposed.
- Discover configurable columns/reordering, automatic recent-search collection, persisted user
  preferences, incident checklist/pinned evidence, notification center, and automatic dashboard
  polling are deferred. The current implementation favors bounded server reads and no aggressive
  polling.
- Host IP is not displayed when the inventory API has no authoritative host-IP field. Agent state
  remains `UNKNOWN`; active/stale labels describe telemetry freshness only.
- Browser E2E remains separately blocked; automated component/API/build results are not presented
  as a browser E2E pass.
