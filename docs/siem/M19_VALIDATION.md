# M19 validation

Status: **PASS for source engineering / WARNING for live readiness**

## Engineering evidence

- Same-backup before/after profiling: PASS.
- Normal 50k/90k/99k/100k benchmark: PASS with measured variance.
- 100k oldest-1,000-protected benchmark: PASS.
- One-writer/three-reader concurrency: PASS.
- Targeted M18/M19/security-event/operations tests: 66 PASS.
- SQLite quick/FK checks on all benchmark variants: PASS.
- Browser UAT: `DEFERRED_BY_USER`.
- Live batch deployment: `BLOCKED_PENDING_EXPLICIT_APPROVAL`.

## Full regression

| Suite | Result |
|---|---|
| Backend full regression | 277 PASS, 0 FAIL |
| Wazuh sender/shipper, v3 state, archive recovery | 158 PASS, 0 FAIL |
| Deployment/validator | 24 PASS, 0 FAIL |
| Frontend Vitest | 118 PASS in 17 files, 0 FAIL |
| TypeScript typecheck | PASS |
| Frontend production build | PASS |
| New script/source compile | PASS |
| `git diff --check` | PASS; line-ending warnings only |

Total automated tests: **577 PASS, 0 FAIL**. Browser UAT was not run.

## Passive live validation

The first passive run returned 10 PASS, 2 WARNING, 1 FAIL and 1
DEFERRED_BY_USER because one WSL relay health request timed out. That result is
retained at `artifacts/lab-validation/m19-passive.json`; it is not hidden.
Five immediate read-only relay probes then returned HTTP 200 in 0.096–0.672
seconds. A clean validator rerun returned 11 PASS, 2 WARNING, 0 FAIL and 1
DEFERRED_BY_USER at
`artifacts/lab-validation/m19-passive-rerun.json`.

The two warnings are the 100,000-event cap and growing byte backlog. The final
15-second sample recorded cursor 87,547,597, archive 346,809,373 and lag
259,261,776 bytes, with net lag growth 11,820.4 B/s. It also saw a relay health
timeout at the end after HTTP 200 at the start, so intermittent five-second
relay/backend latency remains a live warning despite the clean validator
rerun. Database state remained 100,000 events, schema 17, `quick_check=ok`, and
zero foreign-key errors.

## Safety state

- Live shipper: active, v3, one task, single-event protocol, cursor not reset.
- Backend/frontend: HTTP 200; relay service active; TCP 16000 scoped mapping present.
- Schema 18: not applied; historical replay: not started.
- DET-001–DET-009: `DISABLED_BY_POLICY / SHADOW_ONLY`.
- `AI_ENABLED=false`.
- Browser UAT: `DEFERRED_BY_USER`.
- Optimized source: not deployed; no service restart was performed.
- Git: branch `main`, HEAD `f6a59a923cc58cb768c1e4dd748bb529e5c01a43`,
  pre-existing dirty tree preserved, no commit/push.

Synthetic tests are not classified as live acceptance. Another canary remains
blocked pending a fresh backup/state preflight and explicit user approval.
