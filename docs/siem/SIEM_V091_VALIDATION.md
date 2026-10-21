# CyberQalqon SIEM v0.9.1 validation

Observed on 2026-10-11 in the authorized local lab. This ledger distinguishes
verified local behavior from browser and production release gates.

## Acceptance summary

| Gate | Result | Evidence |
| --- | --- | --- |
| Implementation from v0.9 | PASS | Schema 15 and Agent Management preserved |
| Automated regression | PASS | Backend 203/203, frontend 100/100, Wazuh/AI/deployment/E2E 138/138 |
| Live Wazuh API | PASS | TLS 1.3, custom trusted CA, read-only reader, manager 4.14.8, Agents 001 and 002 Active |
| Windows enrollment | PASS | Existing Agent 002 imported through supported Wazuh mechanisms; no duplicate created |
| Windows telemetry E2E | PASS | Real Application event reached Wazuh, SQLite, and authenticated Discover in 0.447876 seconds |
| Browser UAT | BLOCKED | Login form/backend retry verified; authenticated 17-step UI run requires secure manual credential entry |
| Performance diagnostics | PASS | Bounded response and pipeline health checks completed |
| SQLite integrity | PASS | Schema 15, `quick_check=ok`, zero foreign-key violations |
| Production deployment | BLOCKED | Manual browser UAT and production topology approval remain open |

## Live runtime

- Frontend `http://127.0.0.1:5173/`, backend `/health`, and backend
  `/readiness` return HTTP 200.
- Wazuh Manager, Windows Agent 002, Kali Agent 001, the two local relay
  services, durable sender, and archive shipper are active.
- Agent 001 is `cyberqalqon-test-web`; Agent 002 is Windows
  `windows-agent-002`. Both are Active and Agent 002 keepalive advances.
- Wazuh API integration is `AVAILABLE`, `CUSTOM_CA`, read-only, and reports two
  authoritative agents.
- Sender pending, in-flight, terminal-blocked, and dead-letter counts are zero.
  The shipper cursor advances and observed lag remains below the 8 MiB health
  threshold.
- Enrollment listeners 1515 and 2515 are closed. Wazuh API 55000 and the
  Windows transport endpoint remain loopback-only.

Machine-readable local evidence is ignored by Git:

- `artifacts/runtime/windows-agent002-import-result.json`
- `artifacts/runtime/v091-windows-final-health.json`
- `artifacts/lab-validation/v091-windows-passive.json`

## Windows event evidence

The accepted marker
`CYBERQALQON-V091-WINDOWS-E2E-20261011T091355Z-505b6089` originated as
Application Event 100 from provider `CyberQalqon-V091` on
`<windows-test-host>`. Wazuh archived it as Agent 002 with source event ID
`1791710035.26722760`. CyberQalqon stored it once as
`EVT-EC38A419C81D709E27710058`, preserved its raw marker, and returned it from
the authenticated Discover API. A benign event correctly created no alert.

The first marker proved Wazuh delivery but exposed an exact allowlist gap in the
archive shipper. The final change adds only
`Application/CyberQalqon-V091/100`; positive and unrelated-provider negative
tests pass.

## Database

The final health snapshot at `2026-10-11T09:24:54.901084Z` observed a database
size of 120,967,168 bytes and 11,306 security events. Stable workflow counts
were 40 alerts, 3 incidents, 14 incident-alert relationships, 0 cases, 16
notifications, 21 audit events, two authoritative agent rows, and two
agent-health rows. `quick_check` returned `ok` and `foreign_key_check` returned
zero violations. The live database was not reset and the Windows event was not
inserted directly.

## Regression

- Backend pytest: 203 passed; one third-party deprecation warning.
- Frontend Vitest: 100 passed across 16 files.
- Wazuh sender/shipper plus AI tests: 114 passed.
- Deployment and HTTP E2E: 24 passed; two third-party WebSockets warnings.
- Combined post-change Wazuh/AI/deployment/E2E rerun: 138 passed.
- TypeScript, production build, Python compileall, `pip check`,
  `npm audit --audit-level=high`, and the passive validator passed.
- Passive validator: 9/9 PASS. No attack simulation or Nmap telemetry work was
  run.

The working tree remains intentionally dirty with preserved development work.
No reset, clean, rebase, commit, or push was performed.

## Remaining limitations

- The 17-step authenticated browser checklist is not complete. The in-app
  browser reached the protected login form and backend successfully after a
  retry, but the password was not placed in UI automation input or logs.
- The current local `soc-admin` credential was verified through the normal API
  login, but its original bootstrap value remains recoverable from earlier
  execution history. Rotate it through the supported application mechanism
  before production; rotation was outside this task's no-password-reset scope.
- Sysmon is absent, and no new live Security, PowerShell, Defender, or System
  channel sample was claimed.
- Production HTTPS/reverse-proxy/deployment topology has not been accepted.
