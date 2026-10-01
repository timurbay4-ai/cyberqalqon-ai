# Backend API — Phase 2

Base URL examples use `http://127.0.0.1:8000`. JSON errors have the form:

```json
{"error":{"code":"INCIDENT_NOT_FOUND","message":"Incident not found"}}
```

## Authentication

`GET /health` and `GET /ready` are always public. Authentication for other endpoints is configuration-driven:

- If `WAZUH_INGEST_TOKEN` is non-empty, `POST /api/v1/ingest/wazuh` requires `Authorization: Bearer <token>`.
- If `API_ACCESS_TOKEN` is non-empty, incident list, statistics, detail, and review endpoints require `Authorization: Bearer <token>`.
- Empty settings keep local development backward-compatible and unauthenticated.
- `APP_ENV=production` requires both tokens and fails startup if either is absent.

Missing or invalid configured credentials return `401` with code `UNAUTHORIZED` and `WWW-Authenticate: Bearer`.

## System endpoints

### `GET /health`

Returns process liveness without inspecting dependencies.

```json
{"status":"ok","service":"cyberqalqon-backend"}
```

### `GET /ready`

Executes a minimal database query. A healthy response is identical to `/health`; database failures return a sanitized `503` error.

## `POST /api/v1/ingest/wazuh`

Accepts one raw Wazuh alert as a JSON object. The default request limit is 1 MiB. Common `timestamp`, `id`, `agent`, `rule`, `rule.mitre`, `data`, `location`, `decoder`, and `full_log` fields are extracted defensively. Optional omissions are accepted and remain `null` or empty; values are not fabricated. Unknown fields remain available under `raw_event`.

Example:

```json
{
  "timestamp": "2026-09-30T21:00:00+05:00",
  "id": "wazuh-example-001",
  "agent": {"id": "001", "name": "LAB-WIN-01", "ip": "192.0.2.10"},
  "rule": {
    "id": "5710",
    "level": 8,
    "description": "Synthetic authentication failure",
    "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]}
  },
  "data": {"srcip": "198.51.100.20", "srcuser": "test-user"},
  "location": "synthetic-auth.log"
}
```

The first ingestion returns `201`. A retry with the same Wazuh `id` returns `200` with the same incident and does not insert another row. When `id` is absent, canonical raw JSON is hashed for exact-delivery deduplication.

Abbreviated response:

```json
{
  "id": "450c94e4-3894-48d7-9af5-fc15b69263c3",
  "alert_id": "wazuh-example-001",
  "agent_name": "LAB-WIN-01",
  "rule_id": "5710",
  "rule_level": 8,
  "mitre_ids": ["T1110"],
  "source_ip": "198.51.100.20",
  "severity": "high",
  "priority_score": 40,
  "ai_status": "not_configured",
  "review_status": "needs_review",
  "raw_event": {"id": "wazuh-example-001"},
  "reviews": []
}
```

The actual response contains all normalized fields, timestamps, complete `raw_event`, preserved `rule_metadata`, and review history.

All returned timestamps are ISO 8601 UTC values such as `2026-09-30T16:00:00Z`. Incoming event timestamps must contain a timezone offset.

## `GET /api/v1/incidents`

Query parameters:

- `limit`: 1–200, default 50
- `offset`: non-negative, default 0
- `severity`: `low`, `medium`, `high`, or `critical`
- `agent`: exact agent-name match
- `mitre_id`: exact MITRE ID membership

Response:

```json
{"total":1,"limit":50,"offset":0,"items":[{"id":"...","ai_status":"not_configured"}]}
```

Items are ordered by descending priority, then newest creation time.

## `GET /api/v1/incidents/stats`

Returns counts derived from current database rows. It does not fabricate or estimate metrics.

```json
{
  "total": 3,
  "severity": {"low": 1, "medium": 0, "high": 1, "critical": 1},
  "review_status": {"needs_review": 3, "confirmed": 0, "false_positive": 0}
}
```

## `GET /api/v1/incidents/{incident_id}`

Returns the full incident representation, raw evidence, and review history. Unknown IDs return `404` with code `INCIDENT_NOT_FOUND`.

## `POST /api/v1/incidents/{incident_id}/review`

Appends a review and updates the incident's current `review_status`.

```json
{"status":"confirmed","analyst":"analyst-1","note":"Evidence reviewed"}
```

`status` is exactly one of `confirmed`, `false_positive`, or `needs_review`; analyst is 1–128 characters and note is optional up to 4,000 characters. Unknown properties are rejected. The `201` response is the complete incident including all review history.

## Scoring and severity

Investigation Priority Score is deterministic:

```text
round(clamp(rule_level, 0, 15) / 15 * 70)
+ min(max(repetition_count - 1, 0) * 5, 20)
+ asset points (low 0, normal 3, high 7, critical 10)
```

The result is clamped to 0–100 and is not a probability or AI confidence. Asset importance defaults to normal. Display severity boundaries are low 0–3, medium 4–7, high 8–11, and critical 12–15. Original Wazuh level is retained.

## Phase 2 limits

There is no user/role authorization, schema migration framework, active response, Wazuh installation, or AI analysis in this phase. SQLite schema is created on startup. Optional shared bearer tokens provide integration access control, but production deployments still require identity-aware authorization and managed migrations.
