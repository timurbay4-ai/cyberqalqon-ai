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
| `operating_system` | Explicit agent OS evidence, or `windows` for a Windows EventChannel record |
| `event_provider`, `event_channel` | Source provider/channel when supplied by endpoint telemetry |
| `process_name`, `process_path`, `process_id` | Nullable observed process context |
| `command_line` | Nullable command/service image text after sensitive-assignment redaction |
| parent process name/path/ID | Nullable observed parent context |
| source/destination IP and port | Nullable normalized network endpoints |
| `username`, category, action, outcome | Nullable event context |
| `rule_id`, `severity`, `message` | Detection context; severity is bounded to 0–16 |
| `mitre_*_json` | Upstream-supplied ATT&CK IDs, tactics, and techniques; no local inference |
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
- Schema migration 16 adds endpoint context and MITRE arrays without rewriting old rows. Historical
  rows keep null endpoint fields and empty MITRE arrays unless that evidence was already normalized.
- Newly ingested endpoint-aware records use normalization schema `wazuh-event-v3`; existing
  `wazuh-event-v1`/`v2` evidence retains its original schema label.
- Event actions/outcomes are deterministic source semantics (for example Windows 4625 is
  `logon`/`failure`); they do not create an alert or claim malicious intent.

## M11 correlation field use

M11 reads indexed normalized identity, source, process, action/outcome, provider/channel, category,
and event-code columns first. Redacted `raw_event_json` supplies bounded event-specific context that
does not yet warrant a dedicated column, such as Windows logon ID/type, group SID, service metadata,
PowerShell script-block text, and Defender threat/remediation context. Matching never executes or
interpolates these values. Findings reference immutable event IDs and deliberately omit full command
or script text from their summaries.

The evaluator treats absent fields as unknown. Network logon and SSH correlation fails closed when
source identity is missing; Windows local interactive logons have a separately labelled
`local-no-ip` grouping path. Account, privileged-session, and Defender rules never manufacture
missing actor, logon, threat, or remediation evidence.
