# Local threat intelligence API

The repository accepts manually curated IPv4, IPv6, FQDN, MD5, SHA1, and SHA256 indicators.
Values are normalized before a unique `(type, value)` constraint is applied. Records carry source,
confidence (0–100), optional description, optional offset-aware expiration, active state, and an
optimistic version.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/v1/iocs` | Filter/search up to 200 indicators |
| POST | `/api/v1/iocs` | Create one indicator |
| PUT | `/api/v1/iocs/{indicator_id}` | Versioned metadata or active-state update |
| POST | `/api/v1/iocs/import` | Transactionally import 1–100 validated definitions |
| GET | `/api/v1/iocs/matches?days=7&limit=500` | Match active, unexpired IOCs to bounded event evidence |
| GET | `/api/v1/iocs/export.json` | Export the complete bounded repository, at most 5,000 records |

Reads and exports require `soc:read`; writes require `alert:write`, CSRF, and trusted-origin
validation. Mutations and exports are audited. Imports skip normalized duplicates and return exact
created/duplicate counts. There is no hard delete: analysts deactivate an indicator so its history
and audit trail remain available.

Matching examines at most 200 newest active indicators and 5,000 newest events in a range of at
most 31 days. IPs match normalized source/destination fields. Domains and hashes match only
explicit structured fields whose names identify domain/host/FQDN or hash evidence; free-text
substring matching is intentionally excluded. Results do not create alerts, suppress detections,
or block traffic. No external feed is fetched automatically.
