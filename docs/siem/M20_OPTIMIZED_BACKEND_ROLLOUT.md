# M20 optimized single-event backend rollout

Date: 2026-10-20
Decision: **BACKEND/FRONTEND PASS; ROTATION RECOVERY STILL GATED**

## Preflight and recovery

- Branch `main`, HEAD `f6a59a923cc58cb768c1e4dd748bb529e5c01a43`.
- Running source tree SHA-256:
  `5fae5718bf89af25b07f94560f1cebffef8dcc7fe62735c9ed1367a630bf72bf`
  across 92 backend Python files.
- Application/OpenAPI version: `0.9.0`.
- Full backend regression: 279 passed, 0 failed, one dependency deprecation
  warning.
- Fresh disposable rollout/restart/rollback rehearsal: PASS. Single-event
  create/duplicate was 201/200, disabled batch was 503, health stayed below
  16 ms during an isolated locked writer, schema stayed 17, and protected
  evidence survived.
- Exact pre-M19 source does not exist. The verified data-preserving rollback
  is therefore the exact pre-rollout state: stop only the new Uvicorn process,
  preserve live DB/state, and do not restore a stale DB or cursor. This stop
  path was exercised twice during startup-checker false negatives before the
  final successful start.
- ACL-protected recovery directory:
  `backups/m20-optimized-backend-rollout-20261020T085932Z`.
- Source recovery archive SHA-256:
  `705b08b6b8d7ac4bb7440b8a1679d35ca8080de87a08f0e6b708de0dd525c6ef`.
  It was read back without extraction and reproduced the exact source-tree
  hash above.
- Environment backup SHA-256:
  `c4bf0342ead6985d114b1bda22f8af478cf050749ad4a2bcbc3034b8c11d9811`.

## Fresh online SQLite backup

File:
`backups/m20-optimized-backend-rollout-20261020T085932Z/cyberqalqon-pre-m20-optimized-rollout-schema17-20261020T085932Z.db`

- Size: 2,014,007,296 bytes.
- SHA-256:
  `d6c2358e98179c4794b7981babb08a5fd2a6f1a758032b92dd28f926d13c7cb8`.
- Schema 17, complete migration history and `quick_check=ok`.
- The earlier pre-M20 backup remains present.
- A first startup-checker false negative caused a normal SQLite WAL close and
  checkpoint; live physical DB SHA became
  `07aa74354e3727bf1b0248ddeae8161285564d836c5235ac7e0665113528491b`.
  The live DB then passed `quick_check=ok`, FK=0 and unchanged logical counts.
  No backup was restored.

## Live runtime

Backend:

- State: running and healthy.
- PID: `24828`.
- Command: Python 3.11 Uvicorn `app.main:app --host 127.0.0.1 --port 8000`.
- Listener: only `127.0.0.1:8000`.
- `/health`: HTTP 200.
- `/readiness`: HTTP 200, `ready`.
- Batch gate: runtime HTTP 503 `batch_ingestion_disabled` with the valid local
  ingest key; no payload, key or event was logged.
- Schema-18 gate false, batch false, AI false, retention 30 days / 100,000.
- Five-interval 0/15/30/60/120-second results: health p95 about 51.4 ms,
  readiness p95 about 82.1 ms, frontend proxy p95 about 76.3 ms.
- Backend working set 14.2-22.5 MiB; private memory about 69 MiB; observed CPU
  increased by about 0.7 seconds. Final WAL size 0 bytes.
- Backend stdout/stderr contained zero `ERROR`/`Traceback` lines.

Frontend:

- State: running and healthy.
- PID: `26248`.
- Listener: only `127.0.0.1:5173` with strict port binding.
- Root and proxy health: HTTP 200.

Host free RAM ranged from approximately 451 to 891 MiB during observation.
This is a host-capacity warning, not backend growth: backend working memory
remained small and stable.

## Read-only/live-safe contract validation

- `soc-admin` exists, is active and has `ADMIN` role.
- Session endpoint without a cookie returned 401, proving authentication
  enforcement. A normal login was intentionally not performed because it
  would create a session and audit record outside the read-only validation
  requirement.
- Single-event ingestion without a key returned 401.
- Batch endpoint with the local key returned the expected disabled-gate 503.
- Event/session/audit counts were identical before and after the probes:
  100,000 / 3 / 99. No synthetic event was inserted.
- Current evidence-reference counts are zero for case events, incident event
  pins, case event references and alert-linked security events. Protected
  evidence behavior also passed regression and disposable retention tests.

## Relay, database and validator

- Windows portproxy and firewall scope were not changed.
- WSL gateway health: HTTP 200, final sample about 12.5 ms.
- WSL relay health: HTTP 200, final sample about 12.1 ms.
- SQLite: `quick_check=ok`, FK errors 0, schema 17, 100,000 events, 40 alerts.
- Passive validator: 11 PASS, 1 WARNING, 1 FAIL, 1 DEFERRED_BY_USER.
- The warning is the unchanged 100,000-event retention cap.
- The only failure is the intentional shipper archive-inode mismatch.
- Browser UAT remains deferred by the user.

## Preserved policy and shipper state

- Shipper was not restarted.
- Cursor remains `93,438,552`.
- State remains device/inode `2096 / 33582396`, SHA-256
  `ef11626503c7af1c9a1d605ca7cfaf6abb01acbe0101817c1f5df22656260dde`.
- Active archive remains device/inode `2096 / 33582586`.
- Accepted 7,007, duplicates 79, filtered 9,820, malformed 8, retries 592,
  protocol errors 0.
- Schema 18, archive replay, rotation recovery, cursor reset/skip and batch
  activation were not performed.
- DET-001 through DET-009 remain `DISABLED_BY_POLICY / SHADOW_ONLY` and
  `AI_ENABLED=false`.
- No Git commit or push was created.

Validator artifact:
`artifacts/lab-validation/m20-optimized-backend-rollout.json`, SHA-256
`2eb10f695cc7e621d8d0b3273c476900d5ba7f4f95edea78be30ddd52ef28e26`.
