# M10 Windows Security Monitoring Validation

Validated on 2026-10-08. Baseline branch `main`, HEAD
`b07fdd50dc3df71976bf9467f8ecb98e68045926`. No commit or push was created.

## Result matrix

| Area | Result | Evidence |
|---|---|---|
| Windows Agent enrollment | BLOCKED | Empty key, stale manager IP, manager authd disabled, current shell not elevated |
| Windows Event collection | BLOCKED live / PASS artifact | Four exact-filter EventChannel configs parsed and tested; protected live config unchanged |
| Built-in Wazuh detection | BLOCKED runtime / PASS inspection | Installed rules 60106, 60122, 60204, 60109, 60111, 60113, 60117, 61138, 91815, 62123, 62124 verified |
| Custom Windows rules | PASS / not required | Built-ins cover requested semantics; no redundant rule added |
| CyberQalqon ingestion | PASS synthetic / BLOCKED live | Authenticated temp-DB ingest and retrieval passed; no enrolled Windows source exists |
| Dashboard/API | PASS component/API / BLOCKED live E2E | Typed API round-trip, search, and React rendering passed; no browser E2E claimed |
| M9 correlation | PASS | Windows fixture remained outside Kali incident; live dry-run inspected 12 alerts and performed zero writes |
| Performance | PASS measured / ingestion rate BLOCKED | See observations below |
| Existing lab health | PASS | Passive validator 7/7; manager, sender, relays, Kali agent/Nginx active; queue/dead letters zero |

## Performance observations

| Component | Observation |
|---|---|
| Windows Wazuh Agent | 3,031,040 bytes working set; 0.0 CPU seconds over 5 seconds while disconnected |
| Loopback relay | about 15.3 MiB worker plus 3.8 MiB venv launcher; 0.0156 CPU seconds over 5 seconds |
| Wazuh Manager | 295,116,800 bytes; 0.1491 CPU seconds over 5 seconds; active/running |
| Event logs | System 20,975,616 B; PowerShell 15,732,736 B; Defender 15,798,272 B; all circular |
| Wazuh JSON logs | alerts 1,352,896 B; archives 4,857,059 B |
| Live CyberQalqon SQLite | 249,856 B before any live Windows alert (none was inserted) |
| Temp SQLite API test | 74,000 B active-file growth for one alert including WAL overhead |
| Live Windows event rate | BLOCKED until enrollment |

The relay uses Python's standard library only, has no idle polling loop beyond the TCP server, caps
concurrent connections at eight, and writes no telemetry log. AI remains disabled; no LLM,
container, datastore, Sysmon, or additional daemon was installed.

## Regression evidence

- Backend: 142/142 PASS.
- Frontend: 53/53 PASS. Vitest reported a non-failing close timeout because two existing Vite
  servers remained active; TypeScript and the production build completed afterward.
- Wazuh sender and deployment: 115/115 PASS.
- TypeScript typecheck: PASS.
- Frontend production build: PASS.
- Passive local lab validator: 7/7 PASS.
- Both FastAPI listeners were restarted with the M10 code: localhost health/readiness HTTP 200,
  WSL bridge health HTTP 200, and live OpenAPI contains `WindowsEventContext`.
- SQLite `quick_check`: `ok`; 13 alerts and one existing incident retained.
- M9 live correlation dry-run: 12 alerts inspected, three candidate groups, zero writes.
- Kali evidence retained: rules 100101 (4 rows), 100111 (2), 100120 (3), 100130 (1), and
  100131 (2). Latest alert IDs remain `1791454461.789693`, `1791454461.788275`, and
  `1791454461.786522`.
- Ubuntu: `wazuh-manager`, `cyberqalqon-sender`, `cyberqalqon-backend-relay`, and
  `cyberqalqon-wazuh-manager-relay@1514` active.
- Kali: `wazuh-agent`, `nginx`, `cyberqalqon-wazuh-agent-relay`, and the bounded nftables monitor
  active; Nginx HTTP 200; Agent `001` active.
- Sender: queue 0, pending 0, in-flight 0, terminal-blocked 0, dead letters 0.

## Security and preservation

- Agent configuration and the empty key were backed up before any attempted repair under the
  Git-ignored, ACL-restricted `backups/m10-windows-agent/20261008T184532` directory.
- The protected live Windows agent files were not modified.
- Kali Agent `001` and all M9 uncommitted work were preserved.
- Authentication, CSRF, Wazuh TLS, and agent authentication were not weakened.
- The loopback relay rejects public/non-RFC1918 upstream discovery candidates and public bind
  addresses.
- Synthetic fixtures are clearly labeled and contain no malware or credential.
