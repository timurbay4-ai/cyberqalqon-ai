# CyberQalqon local ingestion operations runbook

## M22 independent forward ingestion

1. Keep legacy and forward cursors separate. Never reset, copy, or rebind the
   legacy state merely to improve health output.
2. Use `forward status`, `forward validate --deep`, and `forward dry-run` before
   live work. These commands do not deliver or load sender credentials.
3. Confirm source identity/prefix, legacy SHA/cursor, backend/relay, schema 17
   integrity, retention pressure, RAM, and disk.
4. A `PENDING_EXPLICIT_USER_APPROVAL` template cannot run the service. Only a
   short-lived root-owned exact manifest after separate user approval can.
5. Start one worker at five records/s and read limit 10; do not enable the unit
   or raise rate automatically during initial observation.
6. Stop on identity/legacy change, protocol error, rejection, repeated retry,
   SQLite error, WAL/resource pressure, or retention anomaly. Preserve state and
   audit; never roll back acknowledged progress.
7. Historical replay is a different gate. Forward success does not change
   continuity from `UNPROVEN`.

See `M22_FORWARD_INGESTION_SERVICE.md` and `M22_DEPLOYMENT_GATE.md`.

## Safe read-only checks

Run from the repository root:

```powershell
python scripts/measure_m17_live_rates.py --seconds 60 --output artifacts/runtime/m17-live-rate-sample-new.json
python scripts/capture_operational_health.py --no-record --output artifacts/runtime/operational-health-check.json
python scripts/validate_local_lab.py --output artifacts/runtime/passive-validation.json
```

Do not use `--deep-shipper-audit` during sustained pressure. Byte lag is not an
eligible-record count. Treat v2 accepted history as mixed acknowledgements.

## v3 preflight

1. Confirm backend/relay health, archive identity, free RAM/disk and zero sender
   dead letters.
2. Run `event-state-upgrade` without `--apply` against the exact live state and
   archive.
3. Record state SHA-256, cursor, device/inode and planned backup path.
4. Obtain the explicit v3 deployment approval.
5. In the approved window, stop only the event shipper gracefully.
6. Re-plan because the cursor changed while the worker was active.
7. Create/verify the final backup and apply with both `--apply` and
   `--approve-live-state-upgrade`.
8. Deploy the tested package/config, start one worker and verify version 3,
   identity, cursor continuity, unique/duplicate counters, health and rate.

Never reuse a stale plan. If rotation changes inode, stop and reconcile the old
generation. Rollback is valid only before the first new v3 state write.

## Backpressure stop conditions

Pause a new deployment if backend health exceeds five seconds repeatedly,
SQLite reports busy/errors, WAL grows without bound, free RAM becomes critical,
retry/protocol-error counters rise, a delivery rejection terminal-blocks the
cursor, or archive identity changes. Do not reset the cursor or add workers.

## Historical replay

Replay is separate from live v3 deployment. Require a registered immutable
generation, stable live drain, database/retention headroom, explicit rate and
batch, and the separate replay approval. Begin with one small batch and observe
201 inserts, 200 duplicates, retention deletion, retry, WAL and resource use.
Pause rather than skipping a failed record.

## Recovery

- Network/server failure: leave cursor intact; verify relay and backend, then
  allow bounded retry/backoff.
- Protocol mismatch: preserve the response metadata, stop deployment and fix
  contract compatibility; do not coerce it to accepted.
- Permanent rejection: state remains `BLOCKED`; investigate the exact bounded
  record without putting raw payload into ordinary logs.
- Rotation: preserve the old inode/file, register it as an immutable
  generation and reconcile independently.
- SQLite integrity failure: stop writes, preserve DB/WAL/SHM and use the
  documented backup/restore process; never delete WAL by hand.

## M18 batch canary

M18 source adds an atomic `m18-batch-v1` protocol, but both backend and shipper
feature gates default to false. Never enable it from an ordinary health check.
Read `M18_DEPLOYMENT_GATE.md` and obtain the explicit canary approval first.

Start with one worker, network batch 10 and adaptive mode false. Verify the
backend endpoint is enabled before switching the shipper. A committed batch
must have a matching batch ID, ordered per-item results, `atomic=true`, and 201
with inserts or 200 with duplicates only. Any mismatch is unresolved and the
cursor must remain before the batch.

Run heavy live integrity/overview checks serially. Parallel read-only scans of
the 2 GB database can create avoidable I/O pressure and shipper retries. Use
bounded cached Operations metrics for routine refreshes.

On rollback after cursor progress, disable batch mode and continue single-event
delivery from the latest v3 state. Never copy the pre-canary state over a newer
acknowledged cursor. Re-run the passive validator, health checks and a bounded
rate sample before considering batch 25.

## M19 optimized batch deployment gate

M19 removes the expensive exact protected-count query from the write path and
adds bounded stage diagnostics. These source changes do not authorize a live
restart or canary. Review `M19_CANARY_READINESS.md` and obtain a fresh explicit
approval.

Before deployment, create and verify both a consistent SQLite backup and a
final stopped-shipper v3 state backup. Record SHA-256, cursor, archive
device/inode/size and current lag. Deploy the backend while batch remains off,
verify ordinary single-event 201/200 behavior, and inspect the new in-process
lock/commit/retention counters before any batch activation.

For an approved batch-10 observation, retain one worker and conservative fixed
batching. Stop automatically on a deadline violation, repeated 5xx, busy error,
protocol mismatch, cursor regression, integrity error, evidence-preservation
risk, unhealthy relay, or unacceptable lag growth. A timeout stage and numeric
timing may be logged; never log the payload, API key, event identifiers or SQL.

Operations `protected_records` is labelled `EXACT`, `LOWER_BOUND`, `CACHED` or
`NOT_MEASURED`. Do not present a lower bound as an exact count and do not restore
the removed global scan to a live dashboard path. FTS/evidence index changes
belong to a separate rehearsed migration; do not edit live triggers ad hoc.

## M20 backend restart gate

Do not run the general local startup script as an M20 backend deployment: it
also attempts a second gateway-bound backend and frontend startup. The reviewed
backend-only command is:

```powershell
Set-Location .\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Before requesting restart approval, verify the direct backend listener,
portproxy, WSL gateway TCP, relay HTTP, state/archive identity, schema/integrity,
backup SHA and single-event feature gates. If the firewall rule's interface
GUID differs from the current WSL adapter, stop: take a rule backup and obtain
separate privileged-network approval. Never broaden addresses or ports.
The M20 repair helper performs only a TCP path proof with a one-connection
loopback listener; `NOT_TESTED_BACKEND_ABSENT` must not be presented as HTTP
health.

After an approved restart, keep batch disabled and sample at 0, 15, 30, 60 and
120 seconds plus a bounded five-minute window. Verify direct health/readiness,
frontend proxy, gateway/relay, 201/200 semantics, cursor progression, retry,
WAL, memory and integrity. A slow SQLite readiness result must not prevent the
dependency-free liveness endpoint from responding; ingestion/readiness run in
the bounded threadpool.

If restart fails before new acknowledgements, stop the process and preserve the
current DB/WAL/SHM and shipper state. The exact old process image may not exist;
never improvise rollback from Git HEAD in a dirty multi-milestone tree. After
new acknowledgements, never restore an older database or cursor without a
proven reconciliation plan.

## M20 archive rotation stop condition

When state and active archive inodes differ, an `active` systemd status is not
healthy ingestion. Preserve the old generation and state hash. Do not edit the
inode/cursor to the new file, reset to zero, or report current-file byte lag as
total backlog. Registration/reconciliation and historical replay are distinct;
historical replay requires its own explicit approval.

## Future FTS migration

The schema-17 FTS trigger deletes by an `UNINDEXED` event ID. The rehearsed
rowid reverse map is a candidate for a new migration after schema 18, not an
operator command. Require a current backup, free-space check, map completeness,
insert/update/delete tests, integrity checks and explicit schema approval.

## M21 forensic reconciliation

Run reconciliation only against a fixed archive generation and a read-only
SQLite connection or the payload-free identity export. Keep its state outside
the production shipper namespace. Record device, inode, size, mtime and stored
SHA-256 before scanning. If any identity or digest changes, stop. A fingerprint
match proves presence in the retained database; a source-ID-only match is only
probable; absence is uncertain under retention.

Do not include raw archive payloads, API keys or database rows in ordinary
reports. Preserve malformed counts and the day-19 NUL artifact separately.

## M21 independent forward start gate

The M21 forward module has no production entry point. Do not add one or create
a service without explicit live approval. At the gate:

1. Revalidate the chosen device/inode and decoded prefix hash at the exact
   newline boundary.
2. Rehash the untouched legacy state and capture schema/integrity, DB/WAL,
   retention and relay health.
3. Create a new generation namespace under a separate state root. Never reuse
   or edit the legacy cursor.
4. Wire the existing authenticated single-event delivery client with one
   worker; keep batch off.
5. Observe 201 inserts and 200 duplicates separately. Retry/protocol errors do
   not advance; rejection blocks.
6. On rotation, verify the candidate start prefix and processed-record chain;
   rebind only with explicit approval.
7. After any acknowledgement, never roll back to an older independent state.

Forward start restores future processing only. Historical replay, continuity
claims and exactly-once claims remain separate approval and evidence problems.
# M23 operational checks

For read-only forward observation, run `scripts/observe_m23_live.py` as a user that can read the root-controlled evidence, writing only to a repository artifact path. It must never stop/restart services or modify manifests/checkpoints. Treat service active, approval valid, identity exact, cursor progress, and backlog trend as separate checks.

Generate future authority with `forward approval-proposal`; the output is a non-authorizing envelope. If the existing approval is expired, the result must be `ACTIVATION_PROPOSAL_REQUIRED`. Never convert the pending proposal to live authority without the explicit operator gate and normal root ownership/atomic-write procedure.

M23 rollout order is database/checkpoint/source backup, exact identity verification, backend source rollout, Operations validation, forward source rollout, bounded monitoring, and rollback on the stop conditions in `M23_DEPLOYMENT_GATE.md`. Do not combine this with renewal, rotation rebind, replay, schema migration, or batch activation.
