# Threat hunting API

`GET /api/v1/threat-hunts` reuses the normalized `security_events` store. It supports bounded
filters for IP (source or destination), hostname, username, event category, rule ID, MITRE
technique, evidence text, sort order, and time. Presets are 15 minutes, one hour, one day, seven
days, or 30 days; an explicit offset-aware range may not exceed 31 days. Pages contain at most 100
events and use an opaque cursor.

Each event includes persisted alert and incident relationships where those relationships exist.
No relationship is inferred when the source event lacks a related alert ID. A hunt is read-only
and does not create workflow objects.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/v1/threat-hunts` | Run a bounded hunt |
| GET | `/api/v1/threat-hunts/saved` | List only the current analyst's saved hunts |
| POST | `/api/v1/threat-hunts/saved` | Save a validated query; maximum 50 per analyst |
| DELETE | `/api/v1/threat-hunts/saved/{saved_hunt_id}` | Delete an owned saved hunt |
| GET | `/api/v1/threat-hunts/export.csv` | Export at most 1,000 authorized results |

Reads and exports require `soc:read`; saved-hunt mutations require `alert:write`, CSRF, and trusted
origin validation. Ownership is enforced in SQL. CSV fields are neutralized against spreadsheet
formula injection, responses are `no-store`, and every export is audited. The
`X-Result-Truncated` response header states whether more authorized rows existed.

The UI stores complete hunt context only in browser history state. Shareable URL parameters are
limited to categorical rule, MITRE, category, and range values; IP, host, username, and evidence
text are deliberately excluded from the URL.
