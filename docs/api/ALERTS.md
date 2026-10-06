# Alert API Contract

Base path: `/api/v1/alerts`

All alert strings are untrusted data. Consumers must render them as text, never executable HTML.
Read responses expose normalized alerts only; raw Wazuh event JSON remains private persistence data.

## Ingestion

`POST /api/v1/alerts/ingest` accepts one raw Wazuh JSON object and requires the machine-only
`X-API-Key` credential. This credential must never be sent to a browser or reused for analyst
authentication.

## List alerts

Requires an authenticated human principal with `soc:read`. An ingestion API key is not accepted.

```http
GET /api/v1/alerts?rule_level=14&rule_level=5&agent=host-01&mitre_mapped=true&mitre_id=T1110&start_time=2026-10-01T00:00:00Z&end_time=2026-10-07T00:00:00Z&search=authentication&limit=50&cursor=<opaque>
```

- `rule_level` is repeatable, accepts 0–16, and uses OR semantics.
- `agent` is a case-insensitive exact match against agent ID or name.
- `mitre_mapped` filters on whether the upstream `mitre.ids` array is non-empty.
- `mitre_id` is an exact validated ATT&CK technique ID.
- Time bounds are inclusive and require an ISO 8601 UTC offset.
- `search` performs literal case-insensitive matching over normalized fields; SQL wildcard
  characters have no special meaning.
- `limit` is 1–100 and defaults to 50.
- `cursor` is an opaque keyset cursor. Clients must return it unchanged.

Ordering is normalized UTC occurrence time descending, then alert ID descending.

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

`total` counts every item matching the filters, not only the current page.

## Alert detail

```http
GET /api/v1/alerts/{url-encoded-alert-id}
```

Returns one normalized alert, or `404` when the ID is absent.

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

The API does not return stack traces, SQL messages, secrets, or raw event content in structured
client errors.

## Authentication boundary

Alert list/detail routes require the human session cookie. Ingestion remains exclusively protected
by `X-API-Key`. CORS is credentialed only for explicitly configured origins; wildcard origins are
rejected by configuration.
