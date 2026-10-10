# SIEM v0.4.1 validation — 2026-10-09

## Migration safety

The verified Git-ignored pre-migration backup is
`backups/cyberqalqon-pre-v041-20261009T082737Z.db` (SHA-256
`77ffd33564518e2f37a7f1462d41ef4e34e1541c07fcb77a93f51f598f687930`). Migration was rehearsed
against `backups/cyberqalqon-v041-migration-rehearsal.db` before live startup.

Both rehearsal and live database finished with `PRAGMA quick_check=ok`, schema version 11, 40
alerts, 40 alert workflows, three incidents, and 2,672 security events. The additive migration
created zero checklist items, evidence pins, or investigation activities and exactly one default
preference row for the existing analyst. AI remained disabled.

## Feature result

| Capability | Result | Evidence |
|---|---|---|
| Persistent incident checklist | PASS | Ordered create/edit/assign/complete/reopen/reorder with versions, RBAC, CSRF, audit, and read-only viewer behavior |
| Evidence pins and annotations | PASS | Existing-ID validation, incident-link validation, immutable source ID, duplicate rejection, versioned annotation, confirmed unpin |
| Unified investigation timeline | PASS | Existing incident history plus investigation activity, action/source timestamps, deterministic bounded pagination |
| Per-user defaults | PASS | Analyst isolation, validation, optimistic update/reset, audited mutations |
| Configurable Discover columns | PASS | Persisted order/visibility/density, mandatory time/event columns, keyboard controls, restore defaults |
| Source health | PARTIAL | Persisted delivery time/lag and honest `ACTIVE`/`STALE`/`EMPTY`; runtime queue/cursor signals unavailable and agent state `UNKNOWN` without authoritative feeds |
| Administration productivity | PASS | Preference controls plus security-audit text/action/target/outcome filters; existing user/session controls retained |
| Browser E2E | BLOCKED | The embedded app browser blocks localhost API traffic; authentication and CSRF were not weakened to bypass it |

Source-stale/ingest-failure notifications were not fabricated: no authoritative transition
scheduler or runtime failure feed exists. The lab validator and systemd remain the service-health
source of truth.

## Verification

- backend: 170/170 PASS;
- frontend: 86/86 PASS (bounded to one worker for stable execution on the local laptop);
- Wazuh sender/normalizer: 113/113 PASS;
- deployment/validator contract: 13/13 PASS;
- frontend TypeScript and production build: PASS;
- passive local lab validator: 7/7 PASS;
- readiness, health, and frontend health proxy: HTTP 200;
- AI: `false`.

The production bundle is 411.83 kB JavaScript (109.82 kB gzip) and 35.34 kB CSS (7.91 kB gzip).
Repository latency and memory measurements are recorded in `PERFORMANCE.md`. No commit or push was
created, and pre-existing dirty worktree changes were preserved.
