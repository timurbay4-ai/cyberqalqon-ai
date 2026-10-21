# M20 optimized backend deployment gate

Decision: **BLOCKED_BEFORE_PHASE_7**. The optimized backend was not deployed.

## Completed evidence

- M19 retention review and schema-17 compatibility: PASS.
- Disposable restart/configuration rollback rehearsal: PASS.
- Single-event 201/200, crash/replay and evidence preservation: PASS.
- 100k one-writer/three-reader concurrency: PASS.
- Fresh live SQLite `quick_check=ok`, FK errors 0, schema 17.
- Fresh official online backup:
  `backups/cyberqalqon-pre-m20-backend-rollout-schema17-20261020T065715Z.db`.
- Backup size 2,014,007,296 bytes; SHA-256
  `d6c2358e98179c4794b7981babb08a5fd2a6f1a758032b92dd28f926d13c7cb8`;
  metadata integrity `ok` and schema 17.
- Current v3 state SHA-256, cursor and archive identities are recorded in
  `M20_BASELINE.md`.

## Blocking preconditions

1. Backend and frontend processes are absent.
2. WSL-to-gateway TCP 16000 is blocked by a stale Windows firewall interface
   binding; changing it requires explicit privileged-network approval.
3. The shipper is fail-closed on archive rotation. Cursor reconciliation must
   preserve the unread rotated generation; historical replay remains forbidden.
4. Current single-event production throughput/latency cannot be measured while
   those conditions persist.
5. Exact rollback to the old in-memory backend image is unavailable; rollback
   can preserve data and stop the new process, but cannot restore that process.

The reviewed `artifacts/runtime/repair-m20-host-firewall-interface.ps1`
preflights the exact old/new GUIDs and existing IP/port/Hyper-V/portproxy
scope, takes an ACL-restricted rule backup, changes only the named host rule,
uses a one-connection loopback TCP listener to prove the WSL portproxy path,
and restores the old interface filter on failure. It does not claim backend
health and must not run without the separate network approval.

The Phase-7 backend approval question has not yet been asked because relay
stability is a prerequisite. Firewall approval must be separate from backend
deployment approval, and batch-10 approval must be a later third decision.

After network repair and rotation reconciliation, re-run direct backend,
gateway, relay, frontend, state/inode, DB and passive-validator checks. Then
request exactly:

> CyberQalqon M19 optimized backend kodini mavjud single-event rejimini saqlagan
> holda live deploy qilishga ruxsat berasizmi?

If approved, keep batch disabled and one shipper worker. Observe at 0, 15, 30,
60 and 120 seconds, then a bounded 5-minute window. Stop on any schema drift,
integrity/FK error, cursor regression, unexpected duplicate row, protocol
error, repeated 5xx, readiness loss, protected-evidence risk, or resource
exhaustion.
