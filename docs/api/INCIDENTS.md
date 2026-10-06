# Incident API Contract

Base path: `/api/v1/incidents`

Incident state is authoritative application data. It is changed only through deterministic API
operations; AI output cannot create incidents or mutate lifecycle state. Titles, descriptions,
notes, assignee names, and actor names are untrusted strings and clients must render them as text.

## Incident shape

Incident summaries contain:

- `incident_id`, `title`, `description`
- `severity`: `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`
- `status`: `NEW`, `TRIAGED`, `INVESTIGATING`, `RESOLVED`, or `FALSE_POSITIVE`
- nullable `assigned_to`, UTC `created_at` and `updated_at`, and `alert_count`

Detail responses add `alert_ids`, append-only `notes`, and ordered `history`. Related alerts are
referenced by ID instead of copied into incident storage.

## Endpoints

| Method | Path | Behavior |
|---|---|---|
| `POST` | `/api/v1/incidents` | Create a `NEW` incident, optionally with existing alert links and an assignee |
| `GET` | `/api/v1/incidents` | List summaries using deterministic keyset pagination |
| `GET` | `/api/v1/incidents/{incident_id}` | Read one incident with links, notes, and audit history |
| `PATCH` | `/api/v1/incidents/{incident_id}/status` | Apply one validated lifecycle transition |
| `POST` | `/api/v1/incidents/{incident_id}/alerts` | Link one existing alert; duplicate links return `409` |
| `POST` | `/api/v1/incidents/{incident_id}/notes` | Add an append-only analyst note |
| `PATCH` | `/api/v1/incidents/{incident_id}/assignment` | Assign or unassign an incident |

All routes require `soc:read`. Writes additionally require `incident:write`, an allowed `Origin`,
and `X-CSRF-Token`. Public write schemas contain no actor field. Audit actor ID and display text are
derived from the authenticated backend principal. The Wazuh key is never accepted here.

## Lifecycle

Allowed transitions are:

| From | To |
|---|---|
| `NEW` | `TRIAGED`, `FALSE_POSITIVE` |
| `TRIAGED` | `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE` |
| `INVESTIGATING` | `TRIAGED`, `RESOLVED`, `FALSE_POSITIVE` |
| `RESOLVED` | `INVESTIGATING` |
| `FALSE_POSITIVE` | `TRIAGED` |

Unsupported transitions and same-state updates return `409 invalid_status_transition`. Unknown
status or severity strings return the standard structured `422 invalid_request` response.

## List and pagination

`GET /api/v1/incidents` accepts repeatable `status` and `severity` filters, a case-insensitive exact
`assigned_to` filter, `limit` from 1–100, and an opaque `cursor`. Results are ordered by UTC
`created_at` descending and then `incident_id` descending. Clients must return cursors unchanged.

```json
{
  "items": [],
  "page": {
    "limit": 50,
    "next_cursor": null,
    "total": 0
  }
}
```

`total` counts all incidents matching the current filters, not only the visible page.

## Relationship and audit guarantees

- Alert links use foreign keys and never duplicate normalized or raw alert content.
- The same alert cannot be linked twice to one incident.
- Missing incidents and alerts return safe structured `404` responses.
- Initial links are explicit and analyst-directed; no opaque automatic correlation is performed.
- Creation, status changes, alert links, note additions, and assignment changes append audit events.
- Note content is stored once in the note record; audit details contain only its generated ID.
- No unlink, note-edit, audit-update, or audit-delete endpoint exists.

Legacy audit rows retain their original display text with a null stable actor ID. New rows record
both a stable `USR-...` analyst ID and a display snapshot.
