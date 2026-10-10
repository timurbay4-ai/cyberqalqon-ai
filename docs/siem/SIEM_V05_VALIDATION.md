# SIEM v0.5 validation — 2026-10-09

## 1. Features implemented — PASS

- consolidated deployed/observed Wazuh and M9 correlation inventory with provenance;
- local declarative rule drafts, validation, bounded historical dry-run, immutable versions,
  optimistic updates, rollback-as-new-version, audit, and explicit manual-deployment readiness;
- dedicated Threat Hunting workspace with relationships, saved hunts, safe history state, and CSV;
- truthful MITRE coverage and deterministic false-positive/noise/disposition analytics;
- local IPv4/IPv6/domain/hash repository with normalization, deduplication, provenance, confidence,
  expiration, active state, import/export, audit, and bounded event matching;
- responsive, keyboard-accessible pages with loading, empty, error, pagination, copy, drill-down,
  timezone-aware time, read-only roles, and explanatory trust labels.

No AI runtime, external feed, external scan, automatic suppression, or automatic Wazuh rule change
was added.

## 2. Database changes — PASS

The Git-ignored verified backup is `backups/cyberqalqon-pre-v05-20261009T093000Z.db`, SHA-256
`2b2ad61f81ff354c95ecbb02905044547e24a803d22fb0949a1c032419a84126`. Migration was rehearsed
against `backups/cyberqalqon-v05-migration-rehearsal.db` before live application.

Schema 12 additively creates `detection_rule_drafts`, `detection_rule_versions`, `saved_hunts`, and
`ioc_indicators` plus bounded indexes. Rehearsal and live databases finished with
`PRAGMA quick_check=ok`, 40 alerts, 2,672 security events, three incidents, and one analyst. All
four new live tables started at zero rows; no historical analyst action was fabricated.

## 3. API endpoints — PASS

Twenty authenticated paths with 24 HTTP operations cover rule inventory/detail/coverage/analytics; draft CRUD,
validation, dry-run, versions, rollback, and readiness confirmation; hunts, per-user saved hunts,
and CSV; plus IOC list/create/update/import/matches/JSON export. Exact contracts and bounds are in
`docs/api/DETECTION_ENGINEERING.md`, `THREAT_HUNTING.md`, and `THREAT_INTELLIGENCE.md`.

## 4. UI changes — PASS, authenticated browser inspection BLOCKED

Navigation now exposes Detection Rules as the detection engineering workspace, Threat Hunting, and
Threat Intelligence. Component-level user-flow and XSS rendering tests pass. The unauthenticated
login surface rendered correctly in the Codex in-app browser, but that browser reported the known
localhost API block, so an authenticated visual pass of the three pages is BLOCKED. Authentication
and CSRF were not weakened to bypass the browser restriction.

## 5. Detection coverage — PASS

Live inventory contains ten rules: six read-only Wazuh/observed rules and four local M9 correlation
rules. Three rules have explicit mappings and seven are unmapped. Current mapped evidence is:

| Technique | Mapped | Enabled | Triggered | Tested | Alerts | State |
|---|---:|---:|---:|---:|---:|---|
| T1046 | 1 | 0 | 1 | 0 | 11 | TRIGGERED |
| T1565.001 | 1 | 0 | 1 | 0 | 2 | TRIGGERED |
| T1595.002 | 1 | 0 | 1 | 0 | 13 | TRIGGERED |

Enabled is zero because Wazuh enablement is not authoritative without the management API; it is
not inferred from historical triggers. All three mapped techniques are explicit validation gaps
because no authoritative deployed-rule test record exists. This is not a claim of full ATT&CK
coverage.

## 6. Dry-run results — PASS

An isolated schema-12 copy of the real lab data evaluated the newest 1,000 events over a 30-day
window using the declarative condition `rule_id EQUALS 100111`. It returned 17 event IDs, did not
truncate IDs, and measured 44.411 ms. Alerts, incidents, and analyst notifications remained
40 / 3 / 0 before and after. The returned contract explicitly reported `side_effects=false`.

## 7. Security tests — PASS

- backend: 175/175 PASS, including RBAC, CSRF/origin, audit, stale-version conflicts, injection
  resistance, IOC/schema validation, request/resource limits, saved-hunt ownership isolation,
  export authorization, deduplication, and concurrent IOC creation;
- frontend: 91/91 PASS, including inert untrusted markup, safe hunt URLs, read-only controls,
  truthful coverage labels, and explicit manual-deployment consent;
- Wazuh sender/shipper: 113/113 PASS;
- deployment/validator contracts: 13/13 PASS;
- TypeScript typecheck and production build: PASS;
- passive local validator: 7/7 PASS.

## 8. Performance — PASS for the bounded local dataset

Twenty-run isolated measurements produced p95 values of 1.907 ms for inventory, 0.020 ms for
coverage, 1.621 ms for a 100-row 30-day rule hunt, 27.226 ms for 30-day analytics, and 2.393 ms
for seven-day IOC matching. The production bundle is 459.86 kB JavaScript (119.28 kB gzip) and
37.25 kB CSS (8.26 kB gzip). The live loopback backend used 45.57 MiB private memory and Vite used
215.69 MiB at the point-in-time snapshot. These are laptop observations, not capacity guarantees.

## 9. Known limitations — PARTIAL

- live Wazuh rules remain intentionally read-only; readiness confirmation is not deployment;
- authoritative Wazuh enabled/version/test state and agent management API data are unavailable;
- hunts cover normalized allowlisted telemetry, not every raw archive field;
- hunt export is capped at 1,000 rows; IOC matching inspects 200 indicators and 5,000 events;
- domains/hashes require explicitly named structured fields; no DNS feed or network blocking exists;
- tuning suggestions need five terminal dispositions and never suppress alerts;
- authenticated visual inspection remains blocked only in the Codex in-app localhost browser.

## 10. Git and runtime status — PASS

Branch remains `main` at `b07fdd50dc3df71976bf9467f8ecb98e68045926`. No commit, push, reset,
rebase, or clean was performed; all pre-existing dirty changes were preserved. `git diff --check`
passes. Backend/readiness/frontend return HTTP 200, AI remains disabled, Wazuh Manager and agent
`001` (`cyberqalqon-test-web`) are active, supporting services are active, and sender queue,
pending, in-flight, terminal-blocked, and dead-letter counts are zero.
