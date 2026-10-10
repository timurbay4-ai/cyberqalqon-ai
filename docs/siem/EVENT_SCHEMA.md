# Security event schema

`security_events` is a normalized investigation index, distinct from the authoritative `alerts`
table. Nullable columns remain null when Wazuh does not provide evidence.

| Field | Purpose |
|---|---|
| `event_id` | Internal `EVT-` identifier derived from the evidence fingerprint |
| `deduplication_id` | Full SHA-256 of canonical source evidence |
| `source_event_id` / `event_code` | Wazuh source ID and Windows/event code when present |
| `occurred_at` / `ingested_at` | Offset-aware UTC event and ingestion timestamps |
| `source_type` | Authentication, FIM, network, web, Windows event, Wazuh alert/archive |
| `hostname`, `agent_id`, `agent_name` | Observed host and Wazuh agent identity |
| source/destination IP and port | Nullable normalized network endpoints |
| `username`, category, action, outcome | Nullable event context |
| `rule_id`, `severity`, `message` | Detection context; severity is bounded to 0–16 |
| `structured_json` | Redacted structured evidence used by investigation views |
| `raw_event_json` | Redacted bounded source object, never returned by alert APIs |
| `ingestion_source` | Collector/projection identity |
| `related_alert_id` | Optional alert relationship |
| `raw_size_bytes`, `search_text` | Enforced source-size accounting and indexed search document |

## Evidence rules

- The request body and canonical stored event are bounded by `MAX_EVENT_INGEST_BYTES` (default
  262,144 bytes).
- Objects, arrays, numbers, booleans, and nulls are preserved. Keys containing password, token,
  secret, API key, authorization, cookie, credential, or session fragments are replaced with
  `[REDACTED]`. Common secret assignments inside strings are also masked.
- Internal IDs and deduplication are deterministic. Replaying identical evidence returns a
  duplicate result; an ID collision with different evidence is rejected.
- Alert backfill stores the already normalized alert document as event evidence; it does not claim
  that the unavailable historical raw archive object was recovered.
- FTS5 indexes the normalized search document. Exact filters use parameterized indexed columns.
