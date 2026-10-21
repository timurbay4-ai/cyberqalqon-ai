# M15 validation

Validation date: 2026-10-14. Browser UAT: **DEFERRED_BY_USER — NOT EXECUTED**.

| Area | Result |
|---|---|
| Backend | PASS — 256 tests |
| Frontend | PASS — 117 tests / 17 files |
| Wazuh sender/shipper | PASS — 124 tests |
| Deployment/validator code | PASS — 23 tests |
| Frontend TypeScript + production build | PASS |
| Golden datasets | PASS — 81 scenarios, 9 per rule |
| Quality framework | PASS — all applicable fixtures |
| Passive local validator | PARTIAL — 7/9; frontend unavailable after host restart and live shipper lag above threshold |
| Live SQLite | PASS — schema 17, quick check ok, FK 0 |
| Schema-18 rehearsal | PASS on fresh disposable backup; live apply blocked |
| Relay recovery | PASS — exact TCP 16000 path, loopback backend unchanged |
| Live backlog recovery | STABLE_AT_EQUILIBRIUM — 71,295 eligible remain across live and preserved rotated tails at final snapshot |
| `git diff --check` | recorded in final milestone handoff |

Security regression covers authentication, human-session enforcement, RBAC,
CSRF, trusted origins, lockout/session bounds, literal SQL metacharacters,
attacker-controlled HTML/shell/path values as inert data, secret-safe errors,
bounded evaluation/timeouts, SQLite busy fail-closed behavior, cross-host/account
fixtures, private notifications, authorized exports and shadow isolation.

The 10,000-event disposable benchmark preserved zero alerts, incidents and cases.
Single-rule evaluation p50/p95/max was 214.844/273.601/273.601 ms; nine-rule was
390.494/402.478/402.478 ms; shadow was 2,291.411/2,352.177/2,352.177 ms; bounded
query was 38.033/71.970/71.970 ms. Peak Python-tracked shadow allocation was
16,665,712 bytes. Synthetic insertion measured 2,522.3 events/s. Tests at 50k,
100k and 250k were not run because only 0.94 GiB host RAM was free; this is a
resource guard, not a capacity claim. The approved path is restored. A
4.5-minute observation held retry count at 491, kept shipper memory between
roughly 18 and 28 MiB, and showed live byte lag in a narrow 223-226 MB band while
new telemetry continued to arrive. This satisfies the operator's
stable-equilibrium stop condition without increasing batch size, CPU, RAM or
SQLite write pressure.

The final passive validator confirmed backend, Kali services, manager services,
relay, Wazuh agent, durable sender queue and database integrity. Its two honest
failures were the intentionally unstarted frontend after the host restart and
the live cursor lag above the 8 MiB warning threshold. Browser UAT was not run.
The final operational snapshot is `artifacts/runtime/m15-recovery-final.json`;
the passive validator report is
`artifacts/runtime/m15-passive-validation-final.json`.

On a disposable empty authenticated API, Operations overview p50/p95/max was
8.017/16.659/17.367 ms, the nine-rule quality catalog was
45.639/55.269/56.400 ms, and one rule-quality detail was
8.329/16.998/17.566 ms. These do not represent the live 1.49 GB database.

No live database migration, detection activation, Wazuh rule deployment,
notification generation, browser automation, Git commit or push was performed.
All DET-001 through DET-009 remain disabled by policy and shadow-only.
