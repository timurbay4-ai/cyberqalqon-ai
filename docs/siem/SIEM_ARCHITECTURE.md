# SIEM v0.2 architecture

CyberQalqon SIEM v0.2 is a lightweight, local-only subset of common SOC workflows. It does not
claim feature parity with Splunk Enterprise Security or Elastic Security. FastAPI, React, SQLite,
and the existing Wazuh manager remain the only runtime components. `AI_ENABLED=false` is supported
and is the validated demo configuration.

## Data paths

```text
Wazuh detections -> durable alert sender -> POST /api/v1/alerts/ingest
                                      |-> alerts -> deterministic M9 correlation -> incidents
                                      |-> normalized alert projection -> security_events

Wazuh archives.json -> allowlisted incremental event shipper
                    -> POST /api/v1/events/ingest
                    -> normalization + redaction + deduplication
                    -> security_events + FTS5

Authenticated browser -> Overview / Discover / Alerts / Incidents / Hosts / Rules / Reports / Administration
                      -> server-side bounded queries -> SQLite
```

The alert sender and event shipper are separate systemd services. The event shipper tails one
configured `archives.json` file with a durable device/inode/offset cursor. It selects only Wazuh
rule records, Nginx, FIM, CyberQalqon network telemetry, PAM/SSHD, and selected Windows security
event IDs. It never mirrors the archive without an allowlist.

## Trust boundaries

- Machine ingestion requires the existing `X-API-Key`; the key remains server-side.
- Human reads require an HttpOnly analyst session and `soc:read` permission.
- Mutations retain origin, CSRF, and role checks. SIEM read models do not bypass them.
- Saved searches are private to the owning analyst. Administration and security-audit reads require
  `ADMIN`; self-service password/session controls require an authenticated analyst plus CSRF.
- Untrusted event text is rendered as React text or escaped JSON, never executable HTML.
- Sensitive key names and common `key=value` secret fragments are redacted before persistence.
- CSV export is authenticated, bounded to 31 days, and neutralizes spreadsheet formulas.

## Storage and lifecycle

SQLite schema version 8 added `security_events`, a small state table, indexes, and optional FTS5.
Version 9 adds analyst-owned `saved_event_searches`, bounded append-only
`security_audit_events`, retention telemetry, and compound exact-filter indexes.
Version 15 adds authoritative agent inventory and Windows provenance. Version 16 adds nullable
endpoint execution context, OS evidence, and upstream MITRE arrays without rewriting historical
events.
The default event retention is 30 days and 100,000 records; both are configurable within validated
bounds. Age cleanup runs at most every five minutes during ingestion, while the record cap is
enforced on every new event. Events older than the configured retention window or more than 24
hours in the future are rejected with a typed response instead of being inserted and immediately
discarded. Existing alerts are preserved
and projected once into the event store as normalized evidence; original alert records remain
authoritative for alert investigation.

Agent connectivity is not inferred from old events. Inventory reports event-source `ACTIVE` or
`STALE` from a 15-minute last-seen threshold, while Wazuh agent status remains `UNKNOWN` until a
supported authenticated Wazuh agent-status API is configured.

Dashboard pipeline cards are delivery-activity evidence derived from stored ingest timestamps.
They do not claim that a Windows process or systemd unit is connected. Runtime service state is
validated separately by the local lab validator.
