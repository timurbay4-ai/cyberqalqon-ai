# Discover search guide

Discover issues server-side, parameterized queries. It is intentionally not an SPL implementation.
Choose a relative preset (15 minutes, 1 hour, 24 hours, or 7 days) or a custom offset-aware range,
then combine exact filters with one keyword search.

Supported filters:

- source and destination IP;
- hostname and username;
- internal event ID, Wazuh source ID, or event code;
- Wazuh rule ID;
- event category and outcome;
- minimum and maximum severity (0–16);
- source type;
- keyword across IDs, identities, endpoints, category, rule, message, and collector;
- newest or oldest ordering.

The API accepts at most 100 rows per page and a 31-day explicit range. The UI uses 25-row keyset
pages. Cursors are opaque and tied to the selected sort direction. Blank values, malformed IPs,
reversed or oversized ranges, invalid severities, and altered cursors return a typed 422 response.

Examples:

```text
rule_id=100111, source_type=network, severity_min=8
source_ip=127.0.0.1, keyword="port scan"
hostname=cyberqalqon-test-web, source_type=file_integrity
event_id=EVT-..., sort=oldest
```

Authenticated analysts can save up to 50 named searches. A saved search stores validated filter
values and either a relative preset or an explicit range; it does not store result rows, session
material, or credentials. Names are unique per analyst. Create, update, and delete require CSRF and
emit a security-audit record. Saved searches are never visible to another analyst.

Opening a row shows redacted structured and raw JSON evidence. Related alert and incident buttons
use stored relationships; absence of a button means the relationship is not known, not that none
exists outside the retained dataset.
