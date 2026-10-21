# M23 validation

Overall engineering result: **PASS WITH WARNINGS**. Live M23 deployment: **NOT PERFORMED**.

## Newly executed suites

| Suite | Result |
| --- | --- |
| Backend | 283/283 PASS; one dependency deprecation warning |
| Frontend stable pool | 124/124 PASS |
| Wazuh sender/shipper/forward | 226/226 PASS |
| Deployment/validator tests | 27/27 PASS; one dependency deprecation warning |
| Unique automated tests | **660/660 PASS** |
| TypeScript typecheck + production build | PASS |
| Python compileall | PASS |
| `git diff --check` | PASS; line-ending notices only |
| Passive live validator | 11 PASS, 1 WARNING, 1 FAIL, 1 DEFERRED_BY_USER |

Two default-worker frontend full runs each exposed a different timing-sensitive test failure; both failed tests passed alone, and the complete suite passed with Vitest `vmThreads`. This remains a test-runner stability WARNING, not hidden as a clean default-pool result.

The passive FAIL is the known legacy archive inode mismatch. The warning is retention at 100,000. Browser UAT is deferred. Database integrity, security gates, active forward generation, approval validity, relay/gateway health, and live cursor progress passed.

No old result is included in the 660-test aggregate. Targeted tests and disposable benchmarks are reported separately to avoid double counting.
