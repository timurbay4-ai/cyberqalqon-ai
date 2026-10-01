# Backend Stabilization Milestone 1 — Lightweight Incident List

## Scope and integration dependency

This stabilization branch, `feature/backend-stabilization-v1`, originates from
AI-inclusive commit `9ea630b`; the integration baseline is `279f5e7`. Merging
the branch directly into `integration/phase3` would therefore also introduce
the intervening AI commits. Integration must isolate the Milestone 1 commits
(for example, by reviewing and cherry-picking them onto the intended baseline).

AI development remains suspended for this milestone. No model, provider,
prompt, download, or AI interface was changed.

## API and frontend integration

`GET /api/v1/incidents/summary` uses the same bearer authentication, filters,
ordering, and limit/offset pagination as `GET /api/v1/incidents`. Its explicit
SQL projection contains only list-view metadata. It does not select
`raw_event`, `full_log`, `decoder`, `rule_metadata`, or review history.

The legacy list and detail routes remain unchanged and compatible. Dashboard,
Incident Explorer, and Alert Explorer consume the summary endpoint. Dashboard
continues to use `/api/v1/incidents/stats` for counts. Alert Explorer calls the
detail endpoint only after expansion, caches successful detail responses for
the component lifetime, displays request failures, and supports retry.

## Reproducible benchmark

Run from `backend`:

```powershell
.venv\Scripts\python.exe scripts\benchmark_incident_summary.py
```

Reference run on 2026-10-01 used in-memory SQLite, 1,000 synthetic incidents,
20,000 characters in each large evidence field, `severity=high`, page size 50,
5 warm-ups, and 30 measured repetitions:

| Measurement | Legacy list | Summary list |
|---|---:|---:|
| Response payload | 4,044,795 bytes | 22,395 bytes |
| Endpoint median / p95 | 154.772 / 231.735 ms | 47.340 / 63.963 ms |
| Repository median / p95 | 193.046 / 240.065 ms | 26.268 / 36.062 ms |
| Serialization median / p95 | 34.053 / 42.715 ms | 1.736 / 2.501 ms |
| SQL SELECT statements | 3 | 2 |
| Large evidence columns selected | yes | no |

Times are environment-specific and should be compared only under the printed
conditions. The SQL capture is the primary proof that the optimization avoids
loading large evidence; payload reduction alone is not treated as proof.
Memory was not reported because process-level measurements would be unreliable
with the in-process TestClient and shared Python allocator.

## Verification commands

```powershell
cd backend
.venv\Scripts\python.exe -m pytest -q tests\integration\test_incident_summary.py
.venv\Scripts\python.exe -m pytest -q

cd ..\frontend
npm test -- --run
npm run build
npm run lint
```

The reference verification passed 10 targeted backend tests, 83 total backend
tests, 75 frontend tests, and the production build. Lint completed with no
errors and eight pre-existing warnings. Pytest reports one upstream
Starlette/httpx deprecation warning.

## Remaining limitations and Milestone 2

- Summary pagination remains offset-based, matching the legacy contract.
- SQLite remains the current database and migration tooling is intentionally
  outside this milestone.
- The detail cache is component-local and is cleared on page unmount.

Milestone 2 should begin only after explicit approval. First create an
integration-safe branch from the intended baseline, bring over only the
Milestone 1 commits, then design and review the Alembic migration plan before
making schema changes. Do not carry unfinished AI work into the integration
branch implicitly.
