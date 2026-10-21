# M20 backend rollout rehearsal

Status: **PASS in disposable isolation; not a live deployment**.

Artifact: `artifacts/runtime/m20-backend-rollout-rehearsal.json`. The rehearsal
used a temporary schema-17 SQLite database, an ephemeral loopback port and the
current source hash
`fb9ff2d6ef87325709534db033386e6077ccf3c89c9e9e8ee3c78b54d0a57f81`.
It did not open or modify the live database.

## Results

- Liveness/readiness after startup: HTTP 200/200.
- Near-cap retention: 100 retained rows with one alert-linked protected event.
- Single new event: HTTP 201; exact replay: HTTP 200.
- Restart and exact replay: HTTP 200, proving durable idempotency.
- Writer blocked by `BEGIN IMMEDIATE`: writer recovered with HTTP 201; five
  concurrent liveness probes stayed at 0-31 ms.
- Isolated batch-10: HTTP 201, 10 inserted, 0 duplicates, 78 ms.
- Configuration rollback: batch endpoint HTTP 503 while single-event remained
  HTTP 201.
- Final schema 17, `quick_check=ok`, zero FK errors, zero duplicate event-ID
  groups and protected evidence still present.

The test exercised four process starts and three stops, including state reuse,
batch-disabled to isolated-batch-enabled transition, and rollback to
batch-disabled single-event mode.

## Exact production startup and configuration

Run from `backend` with the existing restricted `.env`:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Required gates remain `ALLOW_M14_SCHEMA_MIGRATION=false`,
`EVENT_BATCH_INGEST_ENABLED=false`, `AI_ENABLED=false`, schema 17 and the
existing key-file authentication. Expected listener interruption is under 30
seconds after startup dependencies validate. Shipper retries preserve the
unacknowledged archive position; no cursor backup may overwrite newer progress.

## Rollback limitation

There is no running pre-M19 process or separately retained exact pre-M19
backend source package. The old in-memory image is unavailable. Consequently,
an approved restart can be rolled back safely to the current **backend stopped,
data preserved** state, but not to the unavailable old process image. Do not
use Git HEAD as an improvised rollback because the dirty tree contains multiple
authorized milestones. Database restore is reserved for proven database
damage and is forbidden after newer acknowledged writes unless reconciliation
proves it safe.

Stop conditions are startup/readiness failure, unexpected schema change,
repeated 5xx, protocol mismatch, integrity/FK error, protected-evidence loss,
cursor regression, duplicate rows or sustained resource exhaustion.
