# M18 validation

## Automated results

| Suite | Result |
|---|---:|
| Backend full regression | 272/272 PASS |
| Wazuh sender/shipper/state/archive | 158/158 PASS |
| Deployment and validator tests | 24/24 PASS |
| Frontend Vitest | 118/118 PASS |
| Frontend TypeScript | PASS |
| Frontend production build | PASS |
| M18 backend/security/operations focused | 61/61 PASS |
| M18 stage/full disposable benchmark integrity | PASS |
| `git diff --check` | PASS (line-ending warnings only) |
| Browser UAT | DEFERRED_BY_USER |

The backend suite includes M11 advanced detection, M12 workbench, M14 shadow
evaluation, M15 detection quality, retention/idempotency/atomicity and backup
coverage. The Wazuh suite includes v3 state, archive recovery/rotation,
deterministic batch replay, retry-gap preservation and adaptive bounds.

## Batch fault/security matrix

- missing/wrong machine key: 401;
- feature disabled: typed retryable 503;
- malformed/partial/non-object JSON and media type: rejected;
- strict protocol/envelope/extra fields: rejected;
- oversized body/event/batch: bounded 413/422;
- invalid middle event: atomic rollback and NOT_PROCESSED peers;
- duplicate subset/full batch: deterministic 201/200 outcomes;
- conflicting event ID: atomic 409 rollback;
- SQLite busy/deadline/internal DB error: typed retryable failure;
- simulated crash before commit: no rows;
- lost response after commit: idempotent full replay, cursor remains safe;
- SQL text/nested evidence: data only, parameterized writes and bounded
  normalization;
- protocol mismatch or malformed success: no cursor advancement;
- partial tail, bad UTF-8/JSON, truncation and inode change: fail-closed v3
  behavior preserved.

## Live passive result

`artifacts/runtime/m18-passive-validation.json`: 11 PASS, 2 WARNING, 0 FAIL,
1 DEFERRED_BY_USER. Warnings are active archive lag and retention at the exact
100,000-event cap. Live M18 code/protocol was not deployed, so live throughput
optimization is BLOCKED pending approval and backlog recovery is WARNING.
