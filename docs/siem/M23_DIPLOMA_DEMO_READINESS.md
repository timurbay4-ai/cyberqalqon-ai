# M23 diploma demo readiness

Use a fully isolated demo backend/database and existing fixtures; never depend on the live backlog or replay.

1. Start an isolated schema-17 backend with a disposable database and demo-only machine key.
2. Authenticate a demo analyst through the normal human session/RBAC/CSRF path.
3. Emit one controlled local Windows Event Log or Linux fixture in the authorized lab.
4. Show Wazuh collection and the single-event delivery response.
5. Show normalized fields, raw-evidence availability, severity, hostname/user, and MITRE metadata.
6. Search/filter the event in Discover.
7. Open the supported alert/incident/case workflow and add an analyst note/evidence reference.
8. Use Investigation Workbench entity pivots and related-event view.
9. Open Operations and explain source authority, approval validity, current forward state, legacy UNPROVEN state, and historical replay NOT_STARTED.
10. Show audit history and role restrictions.

Acceptance evidence should record fixture ID, Wazuh rule, HTTP result, database row, analyst actions, and screenshots from the later Antigravity UAT. DET-001..DET-009 remain shadow-only; do not claim they autonomously create production incidents.

Future browser checklist: login/logout, CSRF rejection, navigation, Discover filters, event detail, incident/case notes and assignment, Workbench pivots, Operations freshness/approval fields, responsive layout, keyboard shortcuts, and empty/error/loading states. Chrome/Edge execution remains `DEFERRED_BY_USER`.
