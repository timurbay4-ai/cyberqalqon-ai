# SIEM v0.2 API

All analyst reads below require an HttpOnly authenticated session and `soc:read`. Cookie-backed
mutations additionally require an exact allowed `Origin` and `X-CSRF-Token`. Machine ingestion is
separate and accepts only the configured `X-API-Key`.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/events/ingest` | Normalize, redact, deduplicate, and retain one bounded Wazuh archive event |
| `GET` | `/api/v1/events` | Bounded Discover search with exact/FTS filters and opaque keyset pagination |
| `GET` | `/api/v1/events/coverage` | Evidence-backed telemetry coverage grouped by source/category/provider/channel |
| `GET` | `/api/v1/events/{event_id}` | Redacted structured/raw evidence and stored relationships |
| `GET` | `/api/v1/events/saved-searches` | List searches owned by the current analyst |
| `POST` | `/api/v1/events/saved-searches` | Create one owned validated search |
| `PATCH` | `/api/v1/events/saved-searches/{id}` | Replace one owned search |
| `DELETE` | `/api/v1/events/saved-searches/{id}` | Delete one owned search |
| `GET` | `/api/v1/overview` | Real bounded operational metrics for up to 31 days |
| `GET` | `/api/v1/sources` | Event-source freshness inventory |
| `GET` | `/api/v1/hosts` | Host evidence summary without claiming unknown connectivity |
| `GET` | `/api/v1/rules` | Read-only Wazuh/correlation catalog with latest evidence |
| `GET` | `/api/v1/reports/security-activity` | Filtered JSON report |
| `GET` | `/api/v1/reports/security-activity.csv` | Filtered, audited, formula-safe CSV report |
| `GET` | `/api/v1/audit-events` | `ADMIN`-only bounded security audit |

Discover accepts offset-aware `start_time`/`end_time`, IPv4/IPv6 endpoints, hostname, username,
operating system, provider, channel, process name, event identifier, rule, category, action,
outcome, severity range, source type, keyword, related alert, sort, cursor, and a limit of 1–100.
Explicit ranges and reports are capped at 31 days. The coverage endpoint defaults to 24 hours,
is capped at 31 days/100 groups, and returns only `OBSERVED` entries backed by `STORED_EVENTS`; it
does not claim that a configured-but-silent source is healthy. Report
filters are `severity_min`, `severity_max`, `host`, and `rule_id` and are returned in report
metadata. All SQL values are parameters; the API returns typed 4xx responses for malformed ranges,
filters, cursors, oversized bodies, retention violations, and conflicting identifiers.

Saved searches contain filter definitions only. They are capped at 50 per analyst and are never
shared. CSV responses use UTF-8 BOM, `no-store`, `nosniff`, a fixed filename, and prefix cells that
could be interpreted as spreadsheet formulas.
