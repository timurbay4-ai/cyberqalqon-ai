# SIEM v0.6 telemetry and reliability validation

## Baseline

- Branch `main`; baseline HEAD `b07fdd50dc3df71976bf9467f8ecb98e68045926`.
- Dirty working tree from earlier milestones was preserved.
- Live baseline: schema 12, 40 alerts, 2,672 security events, 3 incidents, 1 analyst,
  `PRAGMA quick_check=ok`, and `AI_ENABLED=false`.
- Wazuh Manager 4.14.8 and Linux Agent 001 (`cyberqalqon-test-web`) were active.

## Implemented

- Schema 13 stores bounded component state and deduplicated issue/recovery transitions.
- One-shot read-only collector measures service state, sender queue, event-shipper cursor,
  parsing counters, SQLite integrity, Windows agent facts, and Wazuh API availability.
- Operational changes are audited and delivered as per-analyst notifications.
- `GET /api/v1/operations/overview` is protected by `soc:read`.
- Operations UI exposes loading, error, empty/partial states, evidence authority, metric detail,
  copy action, timezone-aware timestamps, and navigation to Hosts/Discover.
- Optional Wazuh API integration is HTTPS-loopback-only, verifies TLS, uses secret/file-backed
  credentials, has a three-second bounded timeout, follows no redirects, and implements no
  mutation methods.

## Authority model

| Signal | Authority | Meaning |
|---|---|---|
| Agent status/keepalive | Wazuh API only | `UNKNOWN` when API is unavailable |
| Manager process | systemd | Service active, not agent inventory |
| Sender queue/dead letter | sender SQLite status | Durable delivery state |
| Archive lag/parser counts | shipper cursor JSON + archive stat | Durable cursor state |
| Source freshness | CyberQalqon event DB | Observed telemetry only, never agent connectivity |
| Data integrity | SQLite `quick_check` | Application database integrity |

## Read-only Wazuh API finding

The manager API listens on `127.0.0.1:55000`/`::1:55000`. TLS verification rejects its self-signed
certificate with the default trust store, and an insecure diagnostic request returns HTTP 401
without a token. No approved read-only credential or trusted CA bundle exists. No credential was
created, extracted, bypassed, or stored. Authoritative inventory is therefore **BLOCKED** and the
product retains `UNKNOWN` agent states.

## Windows agent finding

- Wazuh agent 4.7.5; `WazuhSvc` automatic/running as LocalSystem.
- Configured manager is a stale private address on `1514/tcp`; the runtime value is
  intentionally redacted and connectivity failed.
- Agent name is `AD_client_1`; `client.keys` is empty, so enrollment is absent.
- Protected state/log reads require elevation. No firewall, service, config, or key was changed.
- Supported remediation remains the elevated, backup-first procedure in
  `docs/windows/WINDOWS_AGENT_CONNECTIVITY.md`; manager enrollment must be opened only for the
  bounded local enrollment window and disabled immediately afterward.

## Telemetry coverage

- Linux: Wazuh journald and dpkg collectors, Nginx access/error logs, FIM, and the existing
  authorized network telemetry are active. `/var/log/auth.log` is absent; SSH is inactive, so live
  SSH authentication remains blocked and only fixtures are valid.
- Windows: Security/System/PowerShell/Defender mappings and normalizer support exist, but live
  delivery is blocked by missing enrollment. Sysmon is not installed and was not added.
- Valid normalized events retain redacted raw evidence and a deterministic deduplication ID.
  Invalid timezone/malformed/oversized/delivery-rejected counts are exposed when the shipper can
  measure them. Duplicate attempts are explicitly `not measured`; malformed payload quarantine
  remains unsupported because retaining arbitrary corrupt input could preserve secrets without a
  reviewed retention policy.

## Backup and recovery evidence

- Online backup: `backups/cyberqalqon-pre-v06-20261009T164700Z.db` (Git-ignored).
- SHA-256: `0b6ce53a354ec5ea36bd3496d5d385ac44544a3dc7740b7eacba93968b229ce7`.
- Verification: schema 12, 11,476,992 bytes, checksum match.
- Disposable restore rehearsal: quick check `ok`, migrated schema 13, counts preserved at
  40/2,672/3/1.
- The WSL backend path was restored by binding a user-level backend to the current WSL virtual
  interface. No firewall or privileged configuration was changed; the shipper resumed from its
  durable cursor.

## Remaining blockers

- Wazuh API inventory needs an approved least-privilege read-only user plus trusted CA bundle.
- Windows enrollment needs an elevated, explicitly approved maintenance window.
- Authenticated visual E2E remains blocked in the Codex in-app browser if localhost API requests
  continue to be filtered; automated and host-side checks do not replace that visual claim.
- No always-on scheduler was added. Operators invoke the lightweight collector or schedule it via
  their approved local mechanism.

## Regression and performance

- Backend: 181 tests passed (including M9 correlation, alert workflows, investigations, hunting,
  IOC, dry-run, migrations, operational RBAC, cooldown, and Wazuh API contracts).
- Frontend: 94 tests passed; TypeScript and production build passed.
- Wazuh sender/shipper: 113 tests passed. Deployment/validator: 13 tests passed.
- Passive local validator: 8/8 passed; it now checks durable shipper cursor freshness/lag in
  addition to services, Agent 001, sender queue, HTTP, and SQLite.
- Operational overview repository: 50 local reads under active ingestion measured at 29.367 ms
  median and 181.810 ms max; serialized response was 6,246 bytes. These are point-in-time laptop
  measurements, not a capacity claim.
- Production bundle: JavaScript 473.38 kB (121.90 kB gzip), CSS 37.38 kB (8.29 kB gzip).
- Backend private memory was approximately 47.5 MiB on loopback and 63.8 MiB on the WSL gateway
  after backlog catch-up. No new always-on service or heavyweight dependency was introduced.
