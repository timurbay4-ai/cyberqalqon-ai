# CyberQalqon SIEM v0.9 manual browser UAT

> This is the preserved v0.9 result. The current v0.9.1 checklist and live API
> expectations are in `docs/release/BROWSER_UAT_V091.md`.

Status: **BLOCKED / NOT RUN** on 2026-10-10.

The Windows Computer Use helper stopped before page interaction because it
could not identify the current Edge URL with enough confidence to enforce its
safety policy. This is a mandatory boundary. No session cookie was injected, no
credential was read or entered, browser protections were not bypassed, and no
visual UAT result is claimed.

The trusted repository configuration binds Vite to
`http://127.0.0.1:5173/` (`frontend/vite.config.ts`) and proxies `/api`,
`/health`, and `/readiness` to `http://127.0.0.1:8000`. Before login, the human
operator must independently confirm that the complete address bar reads exactly
`http://127.0.0.1:5173/`. Do not proceed through an HTTPS certificate warning,
redirect to another host, or a browser permission dialog.

Use an approved local analyst credential retrieval mechanism. Never paste a
password, CSRF token, session cookie, screenshot containing credentials, or
browser storage into chat or an issue.

## Manual checklist

Record `PASS`, `FAIL`, or `BLOCKED` beside every item and include only
credential-free observations.

1. **URL and login** — independently confirm the exact loopback URL; verify the
   protected sign-in page; sign in through the normal form; confirm no credential
   appears in URL, page text, console, or storage exposed to JavaScript.
2. **Dashboard** — confirm live backend state, alert/incident/event counts,
   ingestion freshness, and no fabricated demo data.
3. **Discover** — search and filter; open an event; verify timezone display,
   raw-evidence reference, Windows provenance fields when present, loading,
   empty, and error states.
4. **Alerts** — list, filter, open a detail, and verify workflow/history without
   changing production evidence merely for UAT.
5. **Incidents** — list/open an existing incident; verify related alerts,
   investigation activity, evidence, and browser back/forward behavior.
6. **Cases** — confirm the empty or populated state is honest; if a case exists,
   inspect its evidence chain without adding or deleting records.
7. **Threat Hunting** — run a read-only hunt, inspect no-result/error states,
   sorting, pagination, and safe rendering of unusual text.
8. **Threat Intelligence** — inspect IOC list/detail, filters, expiration state,
   and role-appropriate actions; do not add a live IOC solely for UAT.
9. **Operations** — verify manager, API, sender, shipper, Windows agent, database,
   and source rows. Expected local result: Wazuh API `UNAVAILABLE`, sender and
   shipper `HEALTHY`, Windows agent `UNAVAILABLE` with enrollment blocker, and
   source freshness shown separately.
10. **Agent inventory** — open **Agents**; expected local result is `PARTIAL`,
    three telemetry-observed identities, `UNKNOWN` connection, and no fake
    authoritative inventory while API credentials/CA are absent.
11. **Agent filters** — test `UNKNOWN`, Linux/Windows, manager text, source,
    search, sort/order, reset, previous/next disabled states, and zero-result
    messaging.
12. **Agent detail** — open a row and verify opaque deep link, IDs/copy feedback,
    authority, freshness, sources, recent event/alert/incident counts, empty
    health history for telemetry-only identity, and troubleshooting guidance.
    Confirm there is no restart, enroll, reconfigure, upgrade, or remove button.
13. **Deep links/history** — copy an agent deep link without sensitive data;
    verify browser back/forward restores list/detail and Escape closes the panel.
14. **Navigation/accessibility** — exercise keyboard navigation, visible focus,
    shortcut help, screen-reader labels, narrow-window layout, long hostname,
    IPv6 rendering if real data exists, and no clipping/dead buttons.
15. **Reports** — generate/read a report and check applied filters, timezone,
    empty state, CSV/PDF behavior, and safe filenames. Do not upload/export
    evidence to an unapproved destination.
16. **Administration** — verify role-based visibility, session security, analyst
    and audit reads. Do not create/disable users or change a password for UAT.
17. **Logout** — use normal sign-out; confirm protected content disappears and
    browser back does not restore an authenticated page.

## Result handoff

The operator may return the numbered statuses and credential-free defect notes.
Only supplied/legitimately observed results may be copied into
`SIEM_V09_VALIDATION.md`; unreported steps remain `NOT RUN`.
