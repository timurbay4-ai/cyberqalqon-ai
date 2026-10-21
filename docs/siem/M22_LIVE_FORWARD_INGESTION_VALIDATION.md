# M22 conditional live forward-ingestion validation

Decision: **DEPLOYMENT PASS — RUNNING UNDER EXPIRING APPROVAL**.

Snapshot time: 2026-10-20 20:27 +05:00. Historical continuity remains
**UNPROVEN** and historical replay remains **NOT_STARTED**.

## Preflight and approval

- Backend, frontend, Windows portproxy/gateway and WSL relay returned HTTP 200.
- Live SQLite remained schema 17 with 100,000 events, `quick_check=ok` and zero
  foreign-key violations.
- Legacy cursor/device/inode remained `93,438,552` / `2096` / `33582396`.
- Legacy state SHA-256 remained
  `ef11626503c7af1c9a1d605ca7cfaf6abb01acbe0101817c1f5df22656260dde`.
- The root-only immutable backup remains in the protected M22 live-backup
  directory; its exact runtime path is excluded from source control.
- The backup and its checksum file have the Linux immutable attribute.
- Candidate source remained device/inode `2096/33582586`.
- Boundary `688001817`, prefix SHA-256
  `bd3d1ea52d7ae7ca42943e9710fcec50fd2121f3fb0666eaf50126429f26ccab`
  and generation
  `e58aa9c7b9fbb04204f21d181dc1e6bdc2603d345ed120b7790c2df4fcb7da3a`
  passed deep validation.
- Prepared live checkpoint SHA-256 was
  `810612ad1e86ebcafb33f41cfa32e0d78c8c8fa67aa96cc5966c3d24da9c6112`.
- Approval manifest validation returned `APPROVED`. Manifest SHA-256:
  `aea08b828c8e9314516411502baf2c4f3aa37a71a6e8985fa16d7299557126f7`.
- Approval window: 2026-10-20 20:17:53 through 2026-10-21 00:17:44 +05:00.

## Deployment isolation

The shared `/opt/cyberqalqon-sender` package and legacy service configuration
were not modified. The tested M22 package is isolated at
`/opt/cyberqalqon-forward-m22`, selected by a systemd-only `PYTHONPATH`
drop-in. The unit runs as `wazuh`, one worker, single-event delivery, read
limit 10, five records per second, batch protocol disabled and adaptive mode
disabled. It is static rather than boot-enabled.

The forward checkpoint is mode 0600 and owned by `wazuh:wazuh`. The approval
is mode 0640 and owned by `root:wazuh`. The payload-free audit is mode 0600
and owned by `wazuh:wazuh`.

## Bounded monitoring

Five consecutive samples over approximately 48 seconds all passed their
critical-stop checks:

| Metric | Result |
|---|---:|
| Archive growth average | 23,858.6 B/s |
| Forward cursor progress average | 47,741.9 B/s |
| Net backlog change average | -23,883.2 B/s |
| Initial sampled lag | 339,539,366 bytes |
| Final sampled lag | 338,382,178 bytes |
| Gateway HTTP statuses | 25/25 HTTP 200 |
| Relay HTTP statuses | 25/25 HTTP 200 |
| Restart count | 0 |
| Retry/rejection/protocol/malformed | 0/0/0/0 |

Observed steady gateway p95 was 4.56–11.21 ms after the initial sample; relay
p95 was 5.81–15.31 ms. Windows direct backend health later measured p50 5.814
ms and observed p95 36.191 ms. One authenticated operational-overview request
exceeded its 10-second client timeout; it was not an ingestion request, all
health probes stayed HTTP 200 and forward retry/protocol counters stayed zero.
The expensive request was not repeatedly retried.

## Final live snapshot

- Service: `active/running`; main PID 10901; restart count 0; warning journal
  entries 0.
- Forward cursor: `709662406` from start `688001817`.
- Current source size: `1041990037`; byte lag `332327631`, decreasing.
- Records: 4,084; unique insertions: 2,181; duplicate acknowledgements: 0;
  filtered: 1,903.
- Malformed, oversized, retry, protocol error and delivery rejection: all 0.
- Service memory: 50,294,784 bytes; cumulative CPU: 8.433 seconds.
- SQLite database size: 2,015,412,224 bytes. WAL was 144,245,352 bytes after
  the full integrity scan and active retention writes.
- Protected-reference consistency is covered by zero foreign-key violations;
  no protected evidence was deleted.
- Legacy cursor and SHA-256 were unchanged after deployment.
- No service-blocked or service-stop audit event was present.

## Passive validator

`artifacts/runtime/m22-live-passive-validation.json` reports 11 PASS, one
WARNING, one FAIL and one DEFERRED_BY_USER. The overall result remains FAIL
because the legacy shipper inode mismatch is intentionally unresolved. The
warning is retention at the 100,000-event cap; browser UAT remains deferred.
Release gates passed: schema 17, schema-18 disabled, `AI_ENABLED=false`, and
DET-001 through DET-009 remain `DISABLED_BY_POLICY/SHADOW_ONLY`.

## Remaining constraints

- Historical continuity is UNPROVEN; exactly-once historical recovery is not
  claimed.
- Historical replay has not started and old archives were not deleted.
- The approval expires at 2026-10-21 00:17:44 +05:00. The service revalidates
  it before every batch and will fail closed after expiry; renewal requires a
  new explicit operator approval.
- Schema 18, batch ingestion, detection enforcement, AI, browser UAT,
  firewall/portproxy changes, commit and push were not performed.
