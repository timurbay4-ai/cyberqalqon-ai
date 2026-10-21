# Telemetry coverage

This matrix records evidence actually verified in the authorized local v0.9.1
lab. Installed collectors, configuration, and fixtures are not represented as
live coverage unless an event completed the real pipeline.

| Source | Ingestion | Identity/status authority | v0.9.1 result |
| --- | --- | --- | --- |
| Kali `cyberqalqon-test-web` / Agent 001 | Wazuh Manager -> sender/shipper -> CyberQalqon | Wazuh API | PASS; Active and unchanged |
| Windows `windows-agent-002` / Agent 002 | Wazuh Agent -> local WSL relay chain -> Wazuh Manager -> shipper -> CyberQalqon | Wazuh API | PASS; Active with advancing keepalive |
| Windows Application / Provider `CyberQalqon-V091` / Event 100 | Same real Agent 002 path | Immutable event evidence plus Agent 002 authority | PASS; one unique Discover result, 0.447876-second measured ingestion latency |
| Windows Security/System/PowerShell/Defender | Normalization and configured-collector support | Wazuh event evidence required per source | PARTIAL; automated fixtures pass, but no new live v0.9.1 sample was claimed |
| Sysmon | Only when already installed and authorized | Wazuh event evidence | BLOCKED; Sysmon is not installed |
| Wazuh alert sender | Durable sender queue | Sender state database and service manager | PASS; pending, in-flight, terminal-blocked, and dead-letter counts zero |
| Wazuh archive shipper | Durable archive cursor | Shipper state and archive stat | PASS; cursor advancing and lag below the configured 8 MiB health threshold |
| Wazuh API inventory | Secure backend adapter | Wazuh API | PASS; custom CA, read-only reader, Agents 001 and 002 |

## Accepted Windows provenance

The accepted event is `EVT-EC38A419C81D709E27710058`, with Wazuh source event
ID `1791710035.26722760`. It preserves:

- Wazuh Agent `002` / `windows-agent-002`;
- computer `<windows-test-host>`;
- provider `CyberQalqon-V091`;
- channel `Application` and event ID `100`;
- timezone-aware occurred and ingested timestamps;
- normalization schema `wazuh-event-v2`;
- a raw evidence reference resolving to the immutable event record; and
- the original benign marker in raw evidence.

The archive shipper extension is intentionally exact: only
`Application/CyberQalqon-V091/100` is added to the established Windows event
allowlist. An unrelated provider/channel test is rejected. The accepted event
does not manufacture a rule, severity, or alert.

## Freshness versus connectivity

`SOURCE_ACTIVE`/`SOURCE_STALE` describe event time. `PIPELINE_DEGRADED` and
`PIPELINE_FAILED` describe transport/storage. `ONLINE`/`DISCONNECTED` require
Wazuh API authority. Some source-specific rows remain stale because no recent
event of that source type exists; this is not reported as a transport failure.

## v1.0 development coverage contract

`GET /api/v1/events/coverage` groups stored events by source type, normalized category, OS,
provider, and channel. An entry is always labelled `OBSERVED` with evidence `STORED_EVENTS` and
includes its first/last event time and last ingestion time. Absence from the report means no stored
evidence in the requested range; it does not prove collector failure or success.

M10 fixture tests now cover Windows process context plus Linux SSH and sudo normalization. These
tests do not change the live v0.9.1 rows above: no new live Windows Security, PowerShell, Defender,
System, auditd, or Sysmon acceptance is claimed.

## M11 detection readiness

The M11 catalog reports five independent facts per rule: parser support, eligible stored data,
recent eligible data, required-field sufficiency, and authoritative live configuration. Status is
`RECENTLY_OBSERVED`, `OBSERVED_STALE`, `PREREQUISITE_MISSING`, `NO_DATA`, or `UNKNOWN`. The current
API deliberately reports collector configuration as `UNKNOWN`; neither a fixture nor a historical
row proves current collection policy.

All `DET-001`–`DET-009` rules remain `DISABLED_BY_POLICY`. Sanitized isolated-database tests prove
normalization and evaluator behavior, not production coverage or acceptable noise. Windows Security,
PowerShell, System, Defender, Linux SSH, and sudo must each show representative live evidence and
measured false-positive volume before a separately reviewed activation design is considered.
