# M18 live deployment gate

Status: **BLOCKED_PENDING_EXPLICIT_M18_CANARY_APPROVAL**.

## Pre-approval evidence

- Git: `main` at `f6a59a923cc58cb768c1e4dd748bb529e5c01a43`; dirty tree preserved.
- Backend and frontend: HTTP 200 after backup.
- WSL relay: active and HTTP 200.
- Scoped TCP 16000 mapping: passive validator PASS. A Windows loopback request
  to `127.0.0.1:16000` is not authoritative for the gateway-scoped mapping.
- Shipper: active, v3, one worker, backend reachable, protocol errors 0.
- Archive identity: device/inode `2096/33582396`, unchanged.
- Latest observed cursor/archive/lag: `36,728,683 / 201,640,137 /
  164,911,454` bytes.
- Database: schema 17, 100,000 events, quick_check ok, FK errors 0.
- Validator: 11 PASS, 2 WARNING, 0 FAIL, 1 DEFERRED_BY_USER.
- Safety gates: schema18 false, AI false, DET-001–DET-009
  DISABLED_BY_POLICY/SHADOW_ONLY.

Reference shipper-state backup:

`/var/lib/cyberqalqon-sender/backups/m18-precanary-state-20261015T051731Z.json`

SHA-256: `706fd8df7bd8294bdc21e3a47b9e918f6d91ab5e427ec8ff57502485da11c418`;
mode/owner: `0600 root:root`; captured cursor: 36,366,272.

Verified online SQLite backup:

`backups/cyberqalqon-pre-m18-canary-schema17-20261015T051731Z.db`

SHA-256: `a0b34f413ff6e826550f707f9c6cffe9be19ae922b636ea381c4782601635ca9`;
metadata sidecar has the same name plus `.json`.

The reference state is not a future rollback cursor. Because the live worker
continued, a separately approved canary must gracefully stop it and create a
fresh final state backup/checksum immediately before package/config changes.

## Proposed controlled rollout

Estimated delivery pause is 1–3 minutes; backend health interruption should be
under 30 seconds if a controlled backend restart is required. No schema change
is involved.

1. Recheck health, inode, cursor, disk/RAM and live retry/protocol counters.
2. Gracefully stop only the event shipper; confirm one worker is stopped.
3. Create and verify a fresh 0600 state backup. Do not change its cursor.
4. Deploy the already-tested backend and shipper package/config.
5. Restart the backend only through its existing controlled startup path.
6. Enable backend batch endpoint and shipper batch protocol at batch 10;
   adaptive mode remains false.
7. Start one shipper worker and observe several bounded intervals: 200/201
   split, cursor, latency, retry, busy, CPU/RAM, WAL, archive/cursor rates.
8. Consider batch 25 only after batch 10 is stable. Never enable 50/100 or a
   second worker in this canary.

## Rollback

- Before any acknowledged batch: disable both feature gates, restore the tested
  package/config if needed and restart single-event mode. A final state backup
  may be restored only when its cursor is still exactly authoritative.
- After any acknowledged batch: never restore an older cursor. Disable batch
  mode and continue the old single-event endpoint from the latest durable v3
  state; the new state fields are backward-compatible.
- Preserve all failed responses, state, DB/WAL/SHM and archive generations.
- Stop and leave services safe if integrity/FK, identity, acknowledgement or
  resource stop conditions trigger.
