# Windows enrollment acceptance — v0.9.1

Status: **PASS** for the authorized local lab on 2026-10-11.

## Accepted identity

| Item | Verified value |
| --- | --- |
| Wazuh manager | 4.14.8, Ubuntu 24.04 WSL2 |
| Linux control agent | `001`, `cyberqalqon-test-web`, Active |
| Windows agent | `002`, `windows-agent-002`, Active |
| Windows OS | Windows 11 Pro `10.0.26300.9550` |
| Windows Wazuh version | 4.7.5 |
| Windows service | `WazuhSvc`, Running, Automatic, LocalSystem |
| Transport | `127.0.0.1:2514/tcp` through the local WSL relay chain |
| Event collection | Application EventChannel retained |

The existing manager identity `002` was recovered with Wazuh's supported key
management path and imported by an elevated, transactional PowerShell script.
No duplicate agent was created, Agent 001 was not changed, and no credential or
key value was written to source, command output, or this document.

The Windows transaction created an ACL-restricted rollback backup before
changing protected files:

`C:\ProgramData\CyberQalqon\backups\windows-agent002-v091-20261011T085215Z`

Manager-side backups remain in protected root-only directories. Their exact
runtime paths are intentionally excluded from source control.

After the protected files were installed, one controlled manager restart was
required to reload the pre-existing Agent 002 record into the manager database.
Both agents became Active on the first bounded poll, and Agent 002 keepalive
continued advancing. Manager database integrity remained healthy.

## Benign Windows event acceptance

The accepted marker was generated through the normal Windows Application log:

`CYBERQALQON-V091-WINDOWS-E2E-20261011T091355Z-505b6089`

| Field | Verified value |
| --- | --- |
| Windows record | `66687` |
| Provider | `CyberQalqon-V091` |
| Channel / Event ID | `Application` / `100` |
| Computer | `<windows-test-host>` |
| Wazuh agent | `002`, `windows-agent-002` |
| Wazuh source event ID | `1791710035.26722760` |
| CyberQalqon event ID | `EVT-EC38A419C81D709E27710058` |
| Occurred UTC | `2026-10-11T09:13:55.401000+00:00` |
| Ingested UTC | `2026-10-11T09:13:55.848876+00:00` |
| Measured ingestion latency | `0.447876` seconds |

The event was found once through the authenticated Discover API. Its detail and
raw evidence reference resolved successfully, the raw evidence contained the
marker, and the database contained one event row with one distinct deduplication
identifier. This benign event intentionally produced no detection alert.

The archive shipper now permits only the exact lab tuple
`Application/CyberQalqon-V091/100` in addition to the established Windows event
allowlist. Tests prove that unrelated providers and channels remain rejected.

## Security and recovery state

- Wazuh API 55000 remains loopback-only with verified TLS.
- Enrollment listeners 1515 and 2515 are closed; no enrollment credential is
  retained on Windows.
- Windows `client.keys` is non-empty and restricted by Windows ACLs.
- Reader access was extended only to Agent IDs 001 and 002; no manager mutation
  action was granted.
- Sender queue, in-flight, terminal-blocked, and dead-letter counts are zero.
- Rollback requires restoring the protected Windows backup, restarting only
  `WazuhSvc`, and confirming both manager identities. Never remove Agent 001.

## Decision

Windows enrollment, authoritative manager connectivity, CyberQalqon API
inventory, and benign Windows event delivery are **PASS**. Manual browser UAT
and production topology approval remain separate release gates; they do not
invalidate this local Windows integration acceptance.
