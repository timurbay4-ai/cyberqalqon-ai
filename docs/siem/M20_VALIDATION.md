# M20 validation

Overall: **PARTIAL — engineering PASS, live pipeline FAIL, approvals pending**.

## Newly executed automation

| Suite | Result |
|---|---|
| Backend | 279 PASS, 0 FAIL |
| Wazuh sender/shipper/recovery | 158 PASS, 0 FAIL |
| Deployment/validator | 24 PASS, 0 FAIL |
| Frontend Vitest | 118 PASS in 17 files, 0 FAIL |
| TypeScript typecheck | PASS |
| Production build | PASS |
| Python compileall | PASS |
| `git diff --check` | PASS; line-ending warnings only |

Total automated tests: **579 PASS, 0 FAIL**. A targeted run first exposed one
Windows scheduler-tick flake where a 100 ms synthetic sleep measured 94 ms; the
test was given a 50 ms timing margin without changing the product deadline, and
the full suite then passed.

## Passive live validator

Artifact: `artifacts/lab-validation/m20-preapproval-passive.json`.

- PASS 8, WARNING 1, FAIL 4, DEFERRED_BY_USER 1.
- FAIL: backend unavailable, frontend unavailable, relay HTTP failure and
  shipper inode/cursor mismatch.
- WARNING: 100,000-row retention cap.
- PASS: manager/Kali services, Wazuh agent, sender queue, malformed audit,
  database integrity, safety gates and configured portproxy scope.
- The validator's portproxy PASS validates configuration/listener scope; a
  direct WSL-origin TCP probe still timed out and is authoritative for path
  reachability.

## Safety assertions

- Optimized backend deployment: **NOT EXECUTED**.
- Live batch-10/batch-25: **NOT EXECUTED**.
- Schema 18/historical replay: **NOT EXECUTED**.
- Firewall/portproxy change: **NOT EXECUTED**.
- DET-001–DET-009: `DISABLED_BY_POLICY / SHADOW_ONLY`.
- `AI_ENABLED=false`.
- Browser UAT: `DEFERRED_BY_USER`.
- Git commit/push: **NOT EXECUTED**.
