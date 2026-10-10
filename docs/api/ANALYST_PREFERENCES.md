# Analyst preferences API contract

Base path: `/api/v1/preferences`

Preferences are isolated by the authenticated analyst ID. No route accepts another analyst ID.

| Method | Path | Behavior |
|---|---|---|
| `GET` | `/api/v1/preferences` | Return the current analyst's durable defaults |
| `PUT` | `/api/v1/preferences` | Replace the bounded preference set using `expected_version` |
| `POST` | `/api/v1/preferences/reset` | Restore documented defaults using `expected_version` |

Stored fields are dashboard range (`24h`, `7d`, `30d`), Discover/alert/incident page size
(`25`, `50`, `100`), table density, time display, default alert sort, and ordered Discover columns.
Columns are selected from `time`, `source`, `host`, `identity`, `rule`, and `event`; `time` and
`event` are mandatory, duplicates are rejected, and at most six columns are accepted.

Reads require `soc:read`. PUT/reset require the normal authenticated mutation boundary, including
allowed origin and CSRF token. Stale versions return `409 version_conflict`. Successful writes are
audited without recording secrets or cross-user values. Schema v11 backfills defaults only for
existing analysts; it does not create users or fabricate analyst actions.
