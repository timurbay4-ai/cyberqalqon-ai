# M23 factual baseline

Snapshot: **2026-10-20 22:24:29 +05:00**. Scope: read-only live observation plus repository audit. No live source, manifest, checkpoint, schema, firewall, portproxy, or detection setting was changed.

## Repository and processes

- Branch/HEAD: `main` / `f6a59a923cc58cb768c1e4dd748bb529e5c01a43`.
- The pre-existing dirty tree was preserved; no reset, clean, commit, push, or rebase occurred.
- Backend: `127.0.0.1:8000`, PID 24828, Python 3.11/uvicorn, HTTP 200.
- Frontend: `127.0.0.1:5173`, PID 26248, Vite, HTTP 200.
- The running processes predate M23 source changes. M23 code is **not deployed** and its exact loaded Git revision is not exposed by the health contract.
- WSL capacity: 12 logical CPUs, 3,826,896 KiB RAM, 2,640,700 KiB available, 1,009,915,432,960 bytes free on the forward-state filesystem.

## Forward and approval state

| Evidence | Value |
| --- | --- |
| Service | active/running; PID 10901; restart count 0 |
| Generation | `e58aa9c7b9fbb04204f21d181dc1e6bdc2603d345ed120b7790c2df4fcb7da3a` |
| Source device/inode | `2096/33582586`; rotation absent |
| Source size | 1,219,734,039 bytes |
| Cursor / current-generation lag | 961,924,702 / 257,809,337 bytes |
| Accepted / duplicate / filtered / malformed | 27,622 / 0 / 25,610 / 103 |
| Retry / protocol / rejected | 0 / 0 / 0 |
| Checkpoint SHA-256 | `830f15754fc9ab2eef16d5df070039f97b70f9a287dac187381aa6f3f4da6786` |
| Approval | VALID until 2026-10-21 04:17:44 +05:00 |
| Approval SHA-256 | `e521d7dff23df5029fb55d5f3201667edd372eaffcf0d29762a09e5fa219abb8` |

Legacy remained cursor `93438552`, inode `33582396`, SHA-256 `ef11626503c7af1c9a1d605ca7cfaf6abb01acbe0101817c1f5df22656260dde`. Historical continuity remains **UNPROVEN**.

## Database and safety gates

Passive validation observed schema 17, 100,000 events, `quick_check=ok`, zero foreign-key violations, and retention at its configured cap. `AI_ENABLED=false`, schema-18 activation is disabled, and DET-001..DET-009 remain `DISABLED_BY_POLICY/SHADOW_ONLY`. Browser UAT remains `DEFERRED_BY_USER`.

Evidence: `artifacts/runtime/m23-live-observation.json` and `artifacts/runtime/m23-passive-validation.json`.
