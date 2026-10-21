# M15 schema 18 migration gate

Live migration status: **BLOCKED_PENDING_SEPARATE_APPROVAL**.
`ALLOW_M14_SCHEMA_MIGRATION=false` remains required.

| Item | Result |
|---|---|
| Live schema | 17 |
| Target | 18 (`advanced_detection_readiness`) |
| Live integrity | `quick_check=ok`, foreign keys 0 |
| Preserved counts | 80,176 events; 40 alerts; 3 incidents; 0 cases; 1 analyst |
| Fresh online backup | `backups/cyberqalqon-pre-m15-schema17-20261013T055900Z.db` |
| Backup size | 1,490,481,152 bytes |
| SHA-256 | `22c0cc6fa6b7e28f55c386003e49da1ae7220c82d46286b19e1a434873b6f7d1` |
| Rehearsal copy | `tmp/m15-schema18-rehearsal-20261013T060200Z.db` |
| First migration | PASS, 0.056 s |
| Second application | PASS/idempotent, 0.073 s |
| Rehearsal integrity | `quick_check=ok`, foreign keys 0, counts preserved |
| Interruption rollback | PASS in automated migration test |

Schema 18 adds advanced-detection rule state, versioned configurations,
lifecycle history, correlation state/processed-event dedupe, isolated shadow
runs/findings, diagnostics and their bounded indexes. It does not enable rules
or create production detections.

The ingestion backlog is active, so the safest order is relay recovery, bounded
backlog stabilization, a final pre-migration backup, then a separately approved
maintenance window. Expected database migration time from rehearsal is under one
second, but service downtime should allow pre/post validation and rollback.

Rollback is service stop, preserve the failed database as evidence, restore the
checksum-verified online backup, start the schema-17-compatible application, and
verify counts, FK, `quick_check`, authentication and ingestion cursor continuity.
Never reverse individual DDL statements in the live file. Post-migration checks
must verify schema/user_version 18, migrations 1-18 exactly once, all new tables
and indexes, unchanged data counts, auth, read APIs and shadow isolation.
