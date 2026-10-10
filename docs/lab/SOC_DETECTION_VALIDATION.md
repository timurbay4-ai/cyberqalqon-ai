# CyberQalqon SOC Detection Validation

- Validation date: 2026-10-08
- Repository branch: `main`
- Baseline HEAD: `b07fdd50dc3df71976bf9467f8ecb98e68045926`

## Executive summary

The local defensive pipeline is operational. Five real detection scenarios were verified end to end in CyberQalqon: bounded TCP reconnaissance, existing web enumeration, sensitive-path probing, FIM file creation, and FIM file modification. Two SSH scenarios were validated with synthetic fixtures only. Four areas are blocked by missing safe telemetry or the browser environment, and three are not supported by installed sensors.

- Scenarios evaluated: 28
- New high-signal detection rules implemented: 4, plus one level-1 network seed rule
- Real detection scenarios verified end to end: 5
- Synthetic-only detection scenarios: 2
- Blocked scenarios: 4
- Not-supported sensor scenarios: 3
- Automated active validator: 13/13 PASS
- Sender queue: 0; dead letters: 0
- Database integrity: `ok`

## Detection and QA matrix

| Scenario | Telemetry | Rule / evidence | CyberQalqon | Type | Status |
|---|---|---|---|---|---|
| Bounded TCP connect scan | nftables → journald | `100111`, level 10, `1791454461.789693` | Stored | REAL_TELEMETRY | PASS |
| Single closed-port connection | nftables → journald | No `100111` | Not expected | REAL_TELEMETRY | PASS |
| Six-port slow scan, 42.11 s | nftables → journald | No new `100111` | Not expected | REAL_TELEMETRY | PASS |
| Directory enumeration | Nginx access log | `100101`, level 10, `1791454461.788275` | Stored | REAL_TELEMETRY | PASS |
| Ordinary `/` request | Nginx access log | No `100120` | Not expected | REAL_TELEMETRY | PASS |
| Sensitive-path probe | Nginx access log | `100120`, level 8, `1791454461.786522` | Stored | REAL_TELEMETRY | PASS |
| Lab config file added | Realtime FIM | `100130`, level 7, `1791453699.778702` | Stored | REAL_TELEMETRY | PASS |
| Lab config file modified | Realtime FIM | `100131`, level 9, `1791453718.780650` | Stored | REAL_TELEMETRY | PASS |
| Invalid SSH user | Fixture → `wazuh-logtest` | Built-in `5710`, level 5 | Not sent | SYNTHETIC_FIXTURE | PASS |
| Repeated invalid SSH users | Fixture → `wazuh-logtest` | Built-in `5712`, level 10 | Not sent | SYNTHETIC_FIXTURE | PASS |
| Real SSH authentication | SSH inactive | No safe isolated password service | No | BLOCKED | BLOCKED |
| Real web login attacks | Static Nginx only | No real auth endpoint | No | BLOCKED | BLOCKED |
| Windows authentication/PowerShell | Narrow config + loopback relay prepared | Enrollment needs elevation; no agent key | Synthetic API only | BLOCKED | BLOCKED |
| Sysmon process/network events | No Sysmon | Sensor absent | No | NOT_SUPPORTED | NOT_SUPPORTED |
| Linux process execution | No auditd | Sensor absent | No | NOT_SUPPORTED | NOT_SUPPORTED |
| DNS/outbound anomaly analytics | No flow/DNS sensor | Telemetry absent | No | NOT_SUPPORTED | NOT_SUPPORTED |
| Auth, session, CSRF, RBAC | Backend tests | 117 backend tests total | N/A | AUTOMATED_TEST | PASS |
| Alert and incident APIs | Backend tests | Included in 117 tests | N/A | AUTOMATED_TEST | PASS |
| Frontend components | Vitest | 50/50 on isolated rerun | N/A | AUTOMATED_TEST | PASS |
| Sender behavior/security | Pytest | 104/104 | N/A | AUTOMATED_TEST | PASS |
| Deployment artifacts | Pytest | 4/4 | N/A | AUTOMATED_TEST | PASS |
| Production frontend build | TypeScript + Vite | Build completed | N/A | BUILD_TEST | PASS |
| Backend restart | Host process restart | `/health` 200 | Pipeline recovered | REAL_OPERATION | PASS |
| Frontend restart | Vite restart | proxied `/health` 200 | N/A | REAL_OPERATION | PASS |
| Manager and Agent restart | systemd | both active; Agent 001 active | Pipeline recovered | REAL_OPERATION | PASS |
| Nginx and relay restarts | systemd | HTTP 200; relays active | Pipeline recovered | REAL_OPERATION | PASS |
| Sender queue persistence | Forced local backend outage | `1791454273.782117` survived sender restart | Stored after recovery | REAL_OPERATION | PASS |
| Authenticated visual dashboard | Codex in-app browser | Local `/api` blocked by browser client | Not visually verified | BROWSER_TEST | BLOCKED |

## End-to-end timing

The final automated active run observed:

| Rule | Occurred UTC | Ingested UTC | Approx. delivery latency |
|---|---|---|---:|
| `100120` | 10:14:21.696 | 10:14:22.608 | 0.91 s |
| `100101` | 10:14:21.696 | 10:14:22.940 | 1.24 s |
| `100111` | 10:14:21.847 | 10:14:23.358 | 1.51 s |

The deliberate backend outage retained alert `1791454273.782117` for about 41 seconds before successful delivery. Queue and dead-letter counts returned to zero.

## Preserved records

Both previously cited web enumeration alerts remain in the database:

- `1791441819.285749`: rule `100101`, level 10, Agent `cyberqalqon-test-web`
- `1791450861.342185`: rule `100101`, level 10, Agent `cyberqalqon-test-web`

No alert, incident, account, session, or audit record was deleted.

## Performance observations

- Windows backend health: one cold observation at 77.5 ms; subsequent observations 7.4-19.9 ms.
- Kali: 3.7 GiB visible memory, about 881 MiB used; root filesystem 3% used.
- Ubuntu: about 884 MiB used; root filesystem 1% used.
- Wazuh Manager memory: about 277 MiB.
- Sender memory: about 16 MiB.
- CyberQalqon SQLite size after tests: 200 KiB.
- Wazuh alerts log: about 1.27 MiB; archives log: about 4.33 MiB.

## Security result

- Firewall behavior remains accept-only; no default policy or packet-drop behavior changed.
- All active probes were bounded and targeted `127.0.0.1` only.
- Authentication and CSRF protections remained enabled.
- No real credential list, administrator brute force, malware, reverse shell, public scan, or external target was used.
- The former local ingest key that appeared in one diagnostic output was rotated immediately and is invalid. The current key was never printed.

## Remaining priority work

1. Complete the documented supported Windows Agent enrollment from an elevated shell; the narrow
   Security/System/PowerShell/Defender collection and dynamic-WSL relay are ready.
2. Provide a disposable loopback-only web authentication simulator or a dedicated isolated SSH namespace if real auth telemetry is required.
3. Add a lightweight process telemetry source only after an explicit sensor decision.
4. Re-run authenticated visual dashboard QA in a browser that permits localhost API calls.
