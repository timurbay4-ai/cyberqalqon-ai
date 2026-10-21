# CyberQalqon SIEM v0.9.1 release gate

Classification: **PARTIAL — local Windows integration accepted; production
release blocked**.

| Release gate | Status | Decision |
| --- | --- | --- |
| Source implementation | PASS | v0.9 implementation and schema 15 preserved |
| Automated regression | PASS | 203 backend, 100 frontend, 138 Wazuh/AI/deployment/E2E |
| Type/build/dependency checks | PASS | TypeScript/build/compileall/pip/npm checks pass |
| Passive local lab | PASS | 9/9; no attack simulation or Nmap telemetry |
| Live Wazuh API | PASS | Verified TLS, read-only reader, Agents 001 and 002 Active |
| Sender/shipper pipeline | PASS | Healthy; queue and dead-letter zero, cursor advancing within lag threshold |
| SQLite | PASS | Schema 15, quick check ok, zero FK violations |
| Windows enrollment | PASS | Existing Agent 002 reused; protected key/config backup and ACLs verified |
| Windows benign event E2E | PASS | Real Event 100 reached Wazuh, SQLite, and Discover in 0.447876 seconds |
| Human browser UAT | BLOCKED | Protected login is reachable; authenticated 17-step run needs manual credential entry |
| Production deployment | BLOCKED | Browser UAT and production topology approval remain open |

## Implemented in this acceptance window

- Identified the real Windows/WSL relay chain and kept every ingress endpoint
  loopback-only.
- Reused Agent `002` / `windows-agent-002` through supported Wazuh key management;
  no duplicate identity was created and Agent 001 remained Active.
- Created ACL-restricted Windows recovery material and root-only manager
  backups before changing protected configuration.
- Updated only the Windows manager endpoint, retained Application collection,
  restarted only `WazuhSvc`, and verified authoritative manager keepalive.
- Extended the existing read-only Wazuh reader only to exact Agent IDs 001 and
  002 and verified all Agent Management API surfaces.
- Delivered a uniquely marked real Windows Application event through the
  Wazuh archive pipeline into CyberQalqon Discover.
- Added a narrowly scoped shipper allowlist tuple for the lab event provider,
  with positive and unrelated-provider negative tests.
- Re-ran the complete regression and passive integrity gates without resetting
  live data.

## Remaining release blockers

1. A human operator must retrieve the CyberQalqon credential locally and run
   all 17 steps in `BROWSER_UAT_V091.md` through the normal login form. Do not
   send the password, cookie, or CSRF token through chat or automation logs.
2. Rotate the current local `soc-admin` bootstrap credential through the
   supported application mechanism before production because the original
   value remains in earlier execution history. No password reset or rotation
   was performed in this authorized Windows acceptance task.
3. Validate the intended production HTTPS/reverse-proxy and deployment
   topology. The accepted loopback lab is not a production deployment.

Sysmon remains absent, and this run did not claim new live Security,
PowerShell, Defender, or System channel samples.

No commit or push was created. The branch remains `main` at
`f6a59a923cc58cb768c1e4dd748bb529e5c01a43`; the existing uncommitted work and
the v0.9.1 acceptance changes are preserved.
