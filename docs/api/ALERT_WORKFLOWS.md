# Alert workflows and notifications API

All endpoints require the existing authenticated same-origin analyst session. Reads require the
SOC reader boundary. Alert mutations additionally require `alert:write`; only `ADMIN` and
`ANALYST` roles receive that permission. Mutations retain the existing origin and CSRF checks.
`VIEWER` may read but cannot mutate.

## Alert workflow endpoints

| Method and path | Purpose |
|---|---|
| `GET /api/v1/alert-workflows` | Bounded workflow queue, counts, filters, sorting, and cursor page |
| `GET /api/v1/alert-workflows/assignees` | Active assignable `ADMIN`/`ANALYST` accounts |
| `GET /api/v1/alert-workflows/{alert_id}` | Alert, assignment, notes, and immutable activity history |
| `PATCH /api/v1/alert-workflows/{alert_id}/status` | Version-checked status transition |
| `PATCH /api/v1/alert-workflows/{alert_id}/assignment` | Version-checked assign/unassign |
| `POST /api/v1/alert-workflows/{alert_id}/notes` | Version-checked note creation, maximum 4,096 characters |
| `POST /api/v1/alert-workflows/bulk` | One transactional action across 1–50 unique alerts |

List filters include repeated `status` and `rule_level`, `assigned_to`, `unassigned`, rule, agent,
MITRE, time range, bounded search, and cursor. Sort values are `time_desc`, `time_asc`,
`severity_desc`, `severity_asc`, and `activity_desc`. Counts return total, actionable, unassigned,
and per-status values for the current alert-evidence filters.

The state machine is deliberately one-way:

- `NEW` → `ACKNOWLEDGED` or `FALSE_POSITIVE`
- `ACKNOWLEDGED` → `IN_PROGRESS`, `RESOLVED`, or `FALSE_POSITIVE`
- `IN_PROGRESS` → `RESOLVED` or `FALSE_POSITIVE`
- `RESOLVED` and `FALSE_POSITIVE` are terminal

Every mutation supplies `expected_version`. A stale write returns HTTP 409 and changes nothing.
Status, assignment, and note mutations update workflow history and the bounded security-audit log
in the same SQLite transaction. Assignment is restricted to an active assignable account.

Bulk requests use action `ACKNOWLEDGE`, `SET_STATUS`, or `ASSIGN` plus 1–50
`{alert_id, expected_version}` items. All selected items are validated before any write. If one
item is missing, stale, unauthorized, already unchanged, or violates the state machine, HTTP 409
returns item failures and the full operation is rolled back. Bulk operations never delete alerts.

## Notification endpoints

| Method and path | Purpose |
|---|---|
| `GET /api/v1/notifications?limit=25&unread_only=false` | Current analyst's newest bounded notifications and unread count |
| `PATCH /api/v1/notifications/{notification_id}/read` | Mark one owned notification read |
| `POST /api/v1/notifications/read-all` | Mark the current analyst's notifications read |

Critical/high alert ingestion and alert/incident assignment create deduplicated per-user records.
Storage is capped at the newest 500 records per analyst. Ownership is enforced in SQL; another
analyst's identifier is indistinguishable from a missing record. Read mutations are audited and
CSRF protected. Notification previews contain bounded summaries rather than raw telemetry.

## Errors and caching

Validation errors use HTTP 422. Missing resources use 404. Version/state/bulk conflicts use 409.
Authentication and authorization retain the shared 401/403 contracts. Authenticated workflow and
notification responses are not intended for shared proxy caching.
