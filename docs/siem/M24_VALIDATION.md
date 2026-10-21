# M24 Operations validation

Status: engineering PASS; live deployment NOT_PERFORMED.

## Automated regression

| Suite | Result |
| --- | ---: |
| Backend full suite | 291 passed |
| Frontend full suite | 126 passed in 17 files |
| Wazuh forward/shipper suite | 226 passed |
| Deployment, validator and HTTP E2E suite | 29 passed |
| M24 focused Operations backend suite | 24 passed (included in backend total) |
| M24 focused frontend contract/page suite | 28 passed (included in frontend total) |
| TypeScript typecheck | PASS |
| Frontend production build | PASS |
| Python compileall (`backend/app`, sender, scripts) | PASS |
| `git diff --check` | PASS; line-ending warnings only |

Counts above are not added together when describing a parent suite; focused tests are subsets.

The Python suites emitted only dependency deprecation warnings for Starlette/AnyIO and the E2E WebSockets stack. No flaky retry or test rerun was used.

## M24 failure-injection coverage

- read-only SQLite progress handler reaches a hard deadline;
- explicit cancellation interrupts a disposable long query;
- typed retryable 503 on timeout with `Retry-After`;
- one computation for five equivalent concurrent cold callers;
- verified stale snapshot while refresh is running;
- verified stale snapshot after injected refresh timeout;
- cache has a hard eight-entry bound;
- request SQL contains no `COUNT/MIN/MAX` aggregate over `security_events`;
- frontend validates fresh/cached/stale/unknown and preserves the M23 rollback shape;
- frontend exposes stale and unknown values without inventing totals.

## Non-regression gates

- Schema remains 17; no migration or backfill was added.
- Retention remains 100,000.
- Single-event ingestion path is unchanged; batch activation was not enabled.
- Machine API authentication, analyst RBAC, CSRF, durable checkpoint and generation validation code are unchanged.
- Disposable concurrent reads plus production `EventRepository.ingest()` preserved retained count, protected evidence, `quick_check=ok`, and zero FK errors.
- `AI_ENABLED=false` and DET-001–DET-009 policy were not changed.
- Historical replay was not started.
- Browser UAT remains `DEFERRED_BY_USER`.
- Git commit/push was not performed.

## Modified files

- `backend/app/db/operations.py`
- `backend/app/api/routes/operations.py`
- `backend/app/schemas/operations.py`
- `backend/tests/test_operations.py`
- `frontend/src/types/operations.ts`
- `frontend/src/api/contracts.ts`
- `frontend/src/pages/operations-page.tsx`
- `frontend/src/test/fixtures.ts`
- `frontend/src/api/contracts.test.ts`
- `frontend/src/pages/operations-page.test.tsx`
- `scripts/benchmark_m24_operations.py`
- `docs/siem/M24_OPERATIONS_ROOT_CAUSE.md`
- `docs/siem/M24_OPERATIONS_PERFORMANCE.md`
- `docs/siem/M24_LIVE_ROLLOUT_GATE.md`
- `docs/siem/M24_VALIDATION.md`

Generated evidence:

- `artifacts/runtime/m24-operations-performance.json`
- `artifacts/runtime/m24-benchmark-console.log`

The repository was already dirty before M24. Existing unrelated and earlier milestone changes were preserved.
