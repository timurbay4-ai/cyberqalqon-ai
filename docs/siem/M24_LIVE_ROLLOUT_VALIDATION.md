# M24 conditional Operations live rollout validation

Date: 2026-10-21 (+05:00)
Decision: **BLOCKED — LIVE DEPLOYMENT NOT PERFORMED**

The operator granted a conditional rollout, but required every mandatory pre-deployment gate to pass. The WSL subsystem and relay gate did not pass, so the running backend was not restarted and the M24 Operations endpoint was not called against the live database.

## Pre-deployment results

| Gate | Result | Evidence |
| --- | --- | --- |
| Running source/version | PASS | PID 2176, loopback Uvicorn, application `0.9.0`; OpenAPI has the M23 measurement shape and no M24 deadline/completeness fields |
| Git/deployment configuration | PASS | `main`, HEAD `f6a59a923cc58cb768c1e4dd748bb529e5c01a43`, 272 pre-existing dirty entries preserved; startup keeps schema migration/batch/AI disabled and retention at 100,000 |
| Exact M23 rollback reconstruction | PASS | M24 transcript FileChange audit limited backend source changes to three Operations files; patches 48882, 48889, 48896 and 48903 were reversed in reverse order |
| Rollback archive verification | PASS | 108 payload entries were read from the zip and checked against the manifest; archive SHA-256 `c4ae69b929570b3897b6fc81ca4fc6a22f99bc0b3d2895e5aa999db884ee3cc6` |
| Rollback rehearsal | PASS | Disposable source restore, health 200, readiness 200, unauthenticated Operations 401, schema 17, `quick_check=ok`, FK=0, Python 3.11.9 |
| Live SQLite integrity | PASS | Read-only `quick_check=ok`, FK violations 0, schema 17 |
| Backend/frontend/gateway | PASS | Five samples each were HTTP 200; p95 134.006 / 75.130 / 56.102 ms |
| WSL relay | **FAIL** | Five `127.0.0.1:18000/health` probes timed out; direct Ubuntu probe failed with `Wsl/Service/0x8007274c` |
| Current forward state | **UNKNOWN** | WSL could not be read authoritatively; no service restart, manifest renewal, generation rebind or checkpoint write was attempted |
| Forward approval | EXPIRED | Exact prior expiry `2026-10-21 04:17:44 +05:00`; not renewed or bypassed |
| Passive validator | **FAIL / NOT_COMPLETED** | Unmodified validator stopped on its 30-second Kali WSL service probe with `subprocess.TimeoutExpired` |

The current M23 backend showed no lingering heavy Operations worker during a five-second diagnostic: process CPU delta was 0 ms and the observed threads were waiting. The old unbounded endpoint was not called.

## Rollback artifact

- Archive: `backups/m24-live-rollout/20261021T050551Z-m23-rollback.zip`
- SHA file: `backups/m24-live-rollout/20261021T050551Z-m23-rollback.zip.sha256`
- Archive SHA-256: `c4ae69b929570b3897b6fc81ca4fc6a22f99bc0b3d2895e5aa999db884ee3cc6`
- Reconstructed M23 Python tree SHA-256: `59c9db8e25df1e04b74cc052a2b1c1ac80c2fe949e008842335dfede15e3fd97`
- Manifest SHA-256: `37fb5b3be9ac7c842289548615ab2806ac8b5141c7ff408c5cfc110d38138f01`
- ACL: inheritance removed; only the current Windows user and `SYSTEM` have full access.

The restore procedure changes only the three Operations source files and preserves the production database, forward/legacy cursors, archives, firewall and portproxy configuration. A live restore was not executed because the deployment never began.

## Operations performance evidence

Live M24 cold/cached latency is **NOT_MEASURED** because M24 was not deployed. The already completed disposable schema-17 acceptance remains:

| Population | Cold p50 / p95 | Cached p50 / p95 | Cancellation |
| ---: | ---: | ---: | ---: |
| 10,000 | 7.175 / 14.955 ms | 0.100 / 0.129 ms | 31.275 ms |
| 50,000 | 10.050 / 56.699 ms | 0.145 / 0.746 ms | 31.317 ms |
| 100,000 | 7.217 / 47.841 ms | 0.091 / 1.187 ms | 26.751 ms |

The 100,000-row legacy scan reached its five-second disposable ceiling, while the M24 path used indexed/metadata reads. The machine-readable benchmark remains `artifacts/runtime/m24-operations-performance.json`, SHA-256 `38de78967aa6cf69af7535796a532e1009fd67679bca8456ba607f31f4c40128`.

## Current unchanged live state

- Backend PID 2176 remains the pre-rollout M23 process on `127.0.0.1:8000`.
- Frontend remains HTTP 200 on `127.0.0.1:5173`.
- Gateway/portproxy remains HTTP 200 on `172.19.240.1:16000`.
- Live DB is 2,015,412,224 bytes; observed WAL and SHM were 0 bytes.
- Backend working set was 20,738,048 bytes, private bytes 84,811,776, with 0 ms process CPU delta over the five-sample interval.
- Unauthenticated live Operations returned 401 before repository execution.
- No authenticated live M24 request, frontend restart, backend restart, forward/legacy shipper restart, schema migration, replay, batch activation, firewall/portproxy change, archive deletion, browser UAT, Git commit or push occurred.

The last known forward generation remains `e58aa9c7b9fbb04204f21d181dc1e6bdc2603d345ed120b7790c2df4fcb7da3a`, source device/inode `2096/33582586`. The last known legacy cursor/SHA remain `93438552` / `ef11626503c7af1c9a1d605ca7cfaf6abb01acbe0101817c1f5df22656260dde`. These values are **NOT_REVALIDATED_M24**, not a claim of current integrity.

Historical continuity remains **UNPROVEN**.

## WSL-restored recheck — 2026-10-21 10:48 +05:00

The operator restored basic WSL command execution and the mandatory preflight was repeated without changing production state. The rollout remains **BLOCKED / NOT_PERFORMED** for two newly authoritative reasons:

1. The current Windows WSL vEthernet interface GUID is `{20F93549-3239-4548-9B64-5B5980670EC1}`, while the scoped CyberQalqon TCP 16000 firewall rule remains bound to `{A1126C45-79ED-4355-A7D7-C18E73BA0CB0}`. Gateway `172.19.240.1`, WSL address `172.19.254.115`, remote scope and portproxy remain otherwise correct. WSL to gateway TCP 16000 and both bounded WSL HTTP probes fail. No firewall or portproxy change was made.
2. The active archive identity is now device/inode `2112/33582581`, not the approved generation identity `2096/33582586`. The current archive is 76,842,697 bytes while the durable forward checkpoint remains at cursor `1,143,132,931`, SHA-256 `2aae98473426a3ea7b49ee67021caf24cc6ec8fd413e3f0b20782422d42bc9ae`. This is an archive rotation/generation mismatch; no automatic rebind, offset change or activation was performed.

Authoritative unchanged evidence:

- generation ID `e58aa9c7b9fbb04204f21d181dc1e6bdc2603d345ed120b7790c2df4fcb7da3a`;
- forward approval `EXPIRED`, manifest SHA-256 `e521d7dff23df5029fb55d5f3201667edd372eaffcf0d29762a09e5fa219abb8`;
- forward service `inactive/dead`, main PID 0;
- legacy cursor `93438552` and legacy SHA-256 `ef11626503c7af1c9a1d605ca7cfaf6abb01acbe0101817c1f5df22656260dde` verified unchanged;
- accepted 46,054, duplicate acknowledgements 0, filtered 41,987, malformed 103, retry attempts 4, protocol errors 0, delivery rejected 0;
- no cursor progress and no archive growth during the 22.341-second observation.

The unmodified passive validator advanced farther after WSL recovery but still terminated with `TimeoutExpired` on `/var/ossec/bin/agent_control -lc` after 30 seconds. Thresholds were not changed and the failure was not hidden.

## Required next gate

The WSL service/relay must be restored through a separately authorized operational action without renewing the expired forward approval or activating the forward service. After authoritative read-only generation/checkpoint/legacy evidence is available and the unchanged passive validator completes, rerun the M24 preflight. Only then may the already approved, limited backend rollout proceed.

Remaining M24 work after that gate: controlled M24 backend restart, authenticated bounded Operations acceptance, live cold/cached/cancellation monitoring, post-restart integrity/RBAC validation, passive validator, and the still-deferred browser/diploma-demo checks.
