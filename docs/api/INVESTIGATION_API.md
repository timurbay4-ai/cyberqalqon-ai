# Investigation Workbench API

## `POST /api/v1/investigations/workbench`

Builds one bounded, read-only investigation projection. POST is deliberate: sensitive entity
values and M11 finding context stay out of URLs. The operation itself performs no persistent write.

### Security

- authenticated host-only analyst session;
- trusted `Origin`;
- `X-CSRF-Token` from the current session;
- `soc:read` permission.

`VIEWER`, `ANALYST`, and `ADMIN` roles can read shared SOC evidence when their permission set
contains `soc:read`. Mutation buttons call their separate incident/case APIs and permissions. An
ingest key cannot authenticate this route.

### Request

```json
{
  "target_type": "EVENT",
  "target_id": "EVT-0123456789ABCDEF01234567",
  "relative_minutes": 1440,
  "related_limit": 25,
  "timeline_limit": 100,
  "sort": "oldest",
  "max_execution_ms": 1000
}
```

Targets are `EVENT`, `ALERT`, `INCIDENT`, `CASE`, `CORRELATION_GROUP`, `M11_FINDING`, and `ENTITY`.

- ordinary targets require `target_id` (1–255 characters);
- `ENTITY` requires `entity_type` and `entity_value` (1–2,048 characters);
- `M11_FINDING` requires `rule_id` (`DET-001` through `DET-009`) and its 64-character SHA-256
  `finding_key`;
- use either `relative_minutes` (15–44,640) or both timezone-aware `start_time`/`end_time`;
- an explicit range cannot exceed 31 days;
- `related_limit` is 1–100, `timeline_limit` is 1–200, and execution budget is 50–5,000 ms.

Entity types are `IPV4`, `IPV6`, `HOSTNAME`, `USERNAME`, `AGENT_ID`, `RULE_ID`, `PROCESS_NAME`,
`PROCESS_ID`, `FILE_HASH`, and `DOMAIN`. The backend never accepts SQL, field names, sort
expressions, or relationship definitions from the client.

### Response

The response contains:

- `primary_event`: normalized fields, redacted structured/raw evidence, alert/incident/case IDs;
- `summary`: observations, interpretation boundary, missing fields;
- `entities`: value, evidence field, sensitivity, and whether an indexed pivot is supported;
- `related_events`: bounded event summaries with one or more proven relationship labels;
- `links`: authoritative alert, incident, case, and M9 correlation references;
- `timeline`: stable typed items with event/action timestamp kind and future marker;
- `ioc_matches`: exact local active IOC matches and the mandatory non-proof caveat;
- `correlation_groups`: existing M9 keys, classification, confidence, window, evidence count, and
  linked incident;
- optional `detection_context`: actual M11 rule/finding contract, evaluated count, budget, and
  `side_effects=false`;
- `query`: effective window/limits/sort, latency, truncation, actual SQLite schema, and unavailable
  relationship types.

Schema-15 responses are supported. Missing schema-16 fields are null/empty and process
relationships are unavailable rather than inferred. Schema 17 adds process indexes but no M12
persistent entity.

### Errors

| HTTP | Code/condition | Meaning |
|---:|---|---|
| 401 | `authentication_required` | no valid session |
| 403 | origin/CSRF/permission error | request did not cross the protected boundary |
| 404 | `investigation_target_not_found` | no stored event resolves the requested target |
| 404 | `rule_not_found` / `finding_not_found` | M11 rule/key is absent in the bounded re-evaluation |
| 409 | `investigation_limit` / `evaluation_limit` | SQLite/M11 exceeded the declared budget |
| 422 | schema validation | malformed ID, value, timestamp, range, enum, or limit |

Errors do not echo raw evidence or construct diagnostic SQL. The generated FastAPI OpenAPI schema
is authoritative for the complete response shape.

## Owned mutation APIs reused by the UI

M12 does not wrap or duplicate mutations. It calls the existing endpoints for incident notes,
incident evidence pins, and versioned case references. Those endpoints remain responsible for
write permission, CSRF, optimistic concurrency, audit, and domain validation.
