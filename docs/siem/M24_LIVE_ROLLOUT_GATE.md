# M24 limited live rollout gate

Decision: **NOT READY TO EXECUTE / LIVE DEPLOYMENT NOT_PERFORMED**.

The M24 source and disposable validation pass, but live operations remain behind separate safety gates.

## Read-only live preflight

Captured 2026-10-21 at approximately 09:20 +05:00 without calling the Operations endpoint:

- backend `http://127.0.0.1:8000/health`: HTTP 200;
- backend `http://127.0.0.1:8000/readiness`: HTTP 200;
- frontend `http://127.0.0.1:5173/`: HTTP 200;
- Windows gateway/portproxy `http://172.19.240.1:16000/health`: HTTP 200;
- SQLite metadata: schema 17, durable retained count 100,000, DB 2,015,412,224 bytes, WAL 68,441,472 bytes;
- running backend process was not restarted and therefore still runs the previously loaded M23 code;
- live M24 Operations request: deliberately NOT_PERFORMED;
- browser UAT: `DEFERRED_BY_USER`.

The latest M23 evidence recorded generation `e58aa9c7b9fbb04204f21d181dc1e6bdc2603d345ed120b7790c2df4fcb7da3a`, source device/inode `2096/33582586`, legacy cursor `93438552`, and legacy SHA-256 `ef11626503c7af1c9a1d605ca7cfaf6abb01acbe0101817c1f5df22656260dde`. M24 did not modify those files. This is last-known evidence, not a claim that the current WSL checkpoint was re-read.

## Blocking gates

1. The forward approval expired at **2026-10-21 04:17:44 +05:00**. At the M24 preflight the local time was after 09:20 +05:00. It was not renewed and must not be combined with M24 backend approval.
2. The bounded WSL service/checkpoint probe did not return a current authoritative service state. Current generation/inode/checkpoint SHA therefore remain **NOT_REVALIDATED_M24**, even though the Windows gateway is healthy.
3. Current live SQLite `quick_check` was not repeated because it is a multi-minute, full-database operation on the 2.0 GB production file and would contradict the P0 resource-safety objective. The latest M23 passive validator reported `quick_check=ok`, FK=0, schema 17; the M24 disposable matrix independently passed integrity at all sizes. A rollout preflight must choose a bounded maintenance window for a fresh live integrity check.
4. An exact standalone M23 source rollback bundle was not present in the workspace before M24 edits. The existing running process is not a recoverable source artifact. A verified source rollback package must be reconstructed or supplied before restart-based deployment. Falling back to the old unbounded Operations scan is not an acceptable emergency behavior; fail-closed typed 503 is safer.

Because these are release gates, operator approval alone must not trigger a deployment until they are cleared.

## Expected restart behavior

The M24 code requires no schema change. A controlled backend restart would load the new read-only Operations repository and typed response. Existing 127.0.0.1 binding, single-event ingestion, machine authentication, human sessions/RBAC/CSRF, schema 17, retention 100,000, forward checkpoint and legacy state must remain unchanged. Frontend assets may be rebuilt/restarted after backend readiness; the parser retains M23 response compatibility.

## Stop conditions

Abort or roll back/fail closed on any of:

- backend/readiness or gateway not HTTP 200;
- generation, inode, legacy cursor/SHA or durable checkpoint mismatch;
- expired/missing approval while a forward service continuation is required;
- SQLite integrity/FK failure or schema other than 17;
- repeated 5xx, request p95 above the bounded budget, SQLite busy growth, or ingestion degradation;
- cancellation not interrupting work;
- unexpected event loss, duplicate semantics change, retention/protected-evidence regression;
- any requirement for schema migration, batch activation, replay, firewall/portproxy change, or detection/AI activation.

## Required independent approvals

- A fresh forward activation/renewal, if the expired service gate must be reactivated, bound to the authoritative current checkpoint and generation.
- A separate M24 limited backend rollout approval after the current checkpoint, integrity and rollback blockers above are cleared.

Historical continuity remains **UNPROVEN**.
