# CyberQalqon Backend Contract v2

Verified against `feature/backend-v2`. This document is the frontend and integration contract; no endpoint listed as implemented requires AI or an external service.

## Runtime and access

- Base URL: deployment-defined; local default `http://127.0.0.1:8000`.
- Content type: JSON unless the request has no body.
- Timestamp format: ISO 8601 UTC, for example `2026-09-30T16:00:00Z`.
- Nullable fields appear as JSON `null`; lists are present and may be empty.
- Error envelope: `{"error":{"code":"...","message":"..."}}`. Validation errors also include `details`.
- `API_ACCESS_TOKEN`: when configured, send `Authorization: Bearer <token>` to incident and review endpoints.
- `WAZUH_INGEST_TOKEN`: when configured, the Wazuh sender uses the same header for ingestion.
- Empty token settings disable the corresponding check for backward-compatible local development.
- `APP_ENV=production` fails startup unless both tokens are non-empty.

## Shared incident fields

Detail, ingestion, review, and current list items use this implemented schema:

| Field | Type | Nullable | Meaning |
|---|---|---:|---|
| `id` | string (UUID) | no | Stable CyberQalqon incident identifier |
| `alert_id` | string | yes | Original Wazuh alert ID |
| `event_timestamp` | ISO 8601 string | yes | Wazuh event time normalized to UTC |
| `created_at`, `updated_at` | ISO 8601 string | no | Backend persistence timestamps in UTC |
| `agent_id`, `agent_name`, `agent_ip` | string | yes | Wazuh agent evidence |
| `rule_id`, `rule_description` | string | yes | Wazuh rule evidence |
| `rule_level` | integer 0–15 | yes | Original Wazuh level |
| `rule_metadata` | object | no | Original Wazuh `rule` object |
| `mitre_ids`, `mitre_tactics`, `mitre_techniques` | string array | no | Wazuh-provided MITRE values |
| `source_ip`, `destination_ip` | string | yes | Extracted network evidence |
| `user`, `source_user`, `destination_user` | string | yes | Extracted identity evidence |
| `location` | string | yes | Wazuh location |
| `decoder` | object | yes | Decoder evidence |
| `full_log` | string | yes | Extracted log text |
| `raw_event` | object | no | Complete original received JSON; unknown fields retained |
| `severity` | `low` \| `medium` \| `high` \| `critical` | no | Display category derived from rule level |
| `priority_score` | integer 0–100 | no | Deterministic Investigation Priority Score |
| `repetition_count` | integer | no | Correlation count; exact retries do not increment it |
| `asset_importance` | string | no | Current scoring input; defaults to `normal` |
| `ai_status` | `not_configured` | no | AI is intentionally unavailable in this phase |
| `review_status` | `needs_review` \| `confirmed` \| `false_positive` | no | Current analyst state |
| `reviews` | review array | no | Append-only review history |

A review contains `id`, `status`, `analyst`, nullable `note`, and UTC `created_at`.

## Implemented endpoints

### Health

`GET /health` — no authentication, no parameters.

```json
{"status":"ok","service":"cyberqalqon-backend"}
```

`GET /ready` — no authentication. Verifies database access. Success is the same schema; database failure is `503 DATABASE_UNAVAILABLE`.

### Wazuh ingestion

`POST /api/v1/ingest/wazuh`

- Authentication: conditional `WAZUH_INGEST_TOKEN`.
- Body: one original Wazuh JSON object, maximum 1 MiB by default.
- First accepted delivery: `201` and full incident schema.
- Same Wazuh `id` retry: `200`, same incident ID, no duplicate row.
- Without Wazuh `id`: canonical complete JSON hash provides exact-payload deduplication.
- Unknown fields are retained only as evidence and never executed.

Relevant errors: `401 UNAUTHORIZED`, `413 REQUEST_TOO_LARGE`, `422 VALIDATION_ERROR`, `422 INVALID_WAZUH_ALERT`, `503 DATABASE_UNAVAILABLE`.

### Incident list

`GET /api/v1/incidents`

- Authentication: conditional `API_ACCESS_TOKEN`.
- `limit`: integer 1–200, default 50.
- `offset`: non-negative integer, default 0.
- `severity`: optional exact category.
- `agent`: optional exact `agent_name`, 1–256 characters.
- `mitre_id`: optional exact array membership, 1–128 characters.
- Ordering: priority descending, then creation time descending.

```json
{
  "total": 1,
  "limit": 50,
  "offset": 0,
  "items": [{"id":"...","severity":"high","raw_event":{},"reviews":[]}]
}
```

Each item currently uses the full incident schema. Frontend code should tolerate empty collections and `total: 0`.

### Incident statistics

`GET /api/v1/incidents/stats` — conditional `API_ACCESS_TOKEN`, no parameters.

```json
{
  "total": 3,
  "severity": {"low":1,"medium":0,"high":1,"critical":1},
  "review_status": {"needs_review":3,"confirmed":0,"false_positive":0}
}
```

All values are integer counts computed from stored incidents.

### Incident detail

`GET /api/v1/incidents/{incident_id}` — conditional `API_ACCESS_TOKEN`. Returns the full incident schema. Missing ID returns `404 INCIDENT_NOT_FOUND`.

### Analyst review

`POST /api/v1/incidents/{incident_id}/review` — conditional `API_ACCESS_TOKEN`.

```json
{"status":"confirmed","analyst":"analyst-1","note":"Evidence reviewed"}
```

- `status`: exactly `confirmed`, `false_positive`, or `needs_review`.
- `analyst`: trimmed string, 1–128 characters.
- `note`: optional trimmed string, maximum 4,000 characters.
- Unknown body properties are rejected.
- Success: `201` with the full incident and updated review history.
- Missing incident: `404 INCIDENT_NOT_FOUND`.

## Data availability and incomplete capabilities

Implemented: health/readiness, raw Wazuh ingestion, normalization, persistence, idempotency, incident list/detail, filters, pagination, database-derived statistics, analyst review history, optional shared-token access control, and AI-disabled status.

Not implemented: user accounts, roles, per-incident authorization, migrations, alert correlation beyond exact deduplication, AI analysis, active response, and a lightweight list representation. The list currently includes raw evidence; frontend clients should avoid unnecessarily retaining it in browser state.

## Backend audit findings

- P0: none after combined-baseline tests.
- P1 fixed: event APIs previously had no configurable access control.
- P2 fixed: old FastAPI resolved Starlette 0.46.2, which falls inside published affected-version ranges. The backend does not parse multipart forms, reducing exposure to the multipart advisory, but the dependency was still outdated. Runtime dependencies were updated to patched current versions. References: [GHSA-2c2j-9gv5-cj73](https://github.com/encode/starlette/security/advisories/GHSA-2c2j-9gv5-cj73) and [GHSA-86qp-5c8j-p5mr](https://github.com/advisories/GHSA-86qp-5c8j-p5mr).
- P2 fixed: SQLite discarded timestamp offsets and returned naive values.
- P2 fixed: required severity/review statistics were absent.
- P2 remaining: schema evolution uses `create_all`; no migration framework exists.
- P2 remaining: list responses include complete raw evidence and can be large.
- P2 integration issue outside backend ownership: `wazuh/scripts/send_fixture.py` opens JSON as plain UTF-8 while the committed `wazuh/samples/*.json` files contain a UTF-8 BOM, so the helper fails before sending them. Backend tests read those exact fixtures with `utf-8-sig` and confirm all four payloads are accepted. The Wazuh owner should align fixture encoding or loader behavior.
- P3 fixed: ingestion now emits outcome and incident ID without logging raw payloads.

No `shared/`, `wazuh/`, frontend, or cross-agent files were modified for this contract.
