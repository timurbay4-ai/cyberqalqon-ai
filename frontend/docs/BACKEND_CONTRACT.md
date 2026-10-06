# Frontend Backend Contract

The FastAPI OpenAPI document and backend Pydantic schemas are authoritative. The frontend mirrors
them in `src/types` and validates response bodies in `src/api/contracts.ts`.

## System

- `GET /health` → `{ "status": "ok", "service": "cyberqalqon-backend" }`

## Human session

- `POST /api/v1/auth/login` accepts username/password, sets an opaque HttpOnly cookie, and returns
  `{ analyst, csrf_token }`.
- `GET /api/v1/auth/session` validates/restores the current session.
- `POST /api/v1/auth/logout` requires `X-CSRF-Token` and invalidates the session.
- Every request uses `credentials: include`; session identifiers are never visible to JavaScript.
- Any protected `401` returns the UI to the login boundary. `403` remains an operation error.

## Alerts

- `GET /api/v1/alerts`
  - Repeatable `rule_level` (0–16)
  - Exact case-insensitive `agent`
  - `mitre_mapped`, exact `mitre_id`, inclusive `start_time`/`end_time`, literal `search`
  - `limit` 1–100 and opaque `cursor`
  - Returns `{ items: NormalizedAlert[], page: { limit, next_cursor, total } }`
- `GET /api/v1/alerts/{alert_id}` → `NormalizedAlert`, or structured `404`

Alert optional fields may be absent or null. MITRE arrays may be empty. The raw Wazuh body is not
part of either response.

`POST /api/v1/alerts/ingest` is intentionally absent from the browser client. It is a
machine-to-machine route authenticated with `X-API-Key`.

Alert reads require `soc:read` on the authenticated human principal.

## Incidents

- `GET /api/v1/incidents`
  - Repeatable `status` and `severity`, exact case-insensitive `assigned_to`
  - `limit` 1–100 and opaque `cursor`
- `GET /api/v1/incidents/{incident_id}`
- `POST /api/v1/incidents`
- `PATCH /api/v1/incidents/{incident_id}/status`
- `POST /api/v1/incidents/{incident_id}/alerts`
- `POST /api/v1/incidents/{incident_id}/notes`
- `PATCH /api/v1/incidents/{incident_id}/assignment`

Statuses are exactly `NEW`, `TRIAGED`, `INVESTIGATING`, `RESOLVED`, and `FALSE_POSITIVE`.
Severities are exactly `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`.

Incident writes require `incident:write`. The client sends no `actor`; the backend records the
authenticated principal's stable analyst ID and display snapshot. Mutations include the in-memory
`X-CSRF-Token` and are accepted only from configured origins.

## Errors

```json
{
  "detail": {
    "code": "machine_readable_code",
    "message": "Safe analyst-facing message",
    "field": "optional.field"
  }
}
```

The client preserves HTTP status, code, message, and optional field in `ApiError`. Network failures,
malformed JSON, and schema mismatches are distinct failures and never trigger demo substitution.
