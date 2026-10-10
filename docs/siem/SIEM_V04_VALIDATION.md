# SIEM v0.4 validation record

Validated on 2026-10-09 against the authorized local Windows/WSL CyberQalqon lab. The checkout
remained on `main` at `b07fdd50dc3df71976bf9467f8ecb98e68045926`; no commit, push, history
rewrite, auth bypass, or source reset was performed. No LLM/Ollama runtime was installed or
started, and `AI_ENABLED=false` was verified after migration.

## Migration and rollback evidence

Before applying schema v10, the existing online backup was verified again:

- database: `backups/cyberqalqon-pre-v04-20261008T163334Z.db`
- metadata: the adjacent `.db.json` file
- schema: 9; bytes: 10,801,152
- SHA-256: `9461d9d34928450d7b14052c4ebe5811ca9592ca8dfb65f04c19fe601e5a0a0a`

Migration was first rehearsed against an ignored copy. Live application then produced schema 10
with `PRAGMA quick_check=ok`: 40 alerts, 40 workflows, 2,672 security events, three incidents, and
one analyst. Every alert had exactly one workflow. Historical workflows were `NEW`; notes,
history, assignments, and notifications remained empty rather than being fabricated.

Rollback is restore-based: stop the backend, verify the pre-v0.4 backup and metadata with
`python -m app.cli.backup verify`, preserve the current DB for forensics, restore the verified
backup with the supported restore CLI, and start the matching schema-v9 application build. Do not
edit `schema_migrations`, decrement `PRAGMA user_version`, or partially drop v10 tables.

## Functional and security results

| Area | Result | Evidence |
|---|---|---|
| Durable workflow | PASS | Five statuses, one-way transitions, assignment, notes, last activity, history, filter/sort/count contracts |
| Optimistic concurrency | PASS | Required versions; stale status/assignment/note/bulk writes return 409 without changes |
| Bulk triage | PASS | 1–50 unique items, confirmation UI, acknowledge/assign/status, full prevalidation, transactional rollback, item failures |
| RBAC and CSRF | PASS | `ADMIN`/`ANALYST` receive `alert:write`; `VIEWER` mutation rejected; normal session/origin/CSRF boundary retained |
| Audit | PASS | Individual and bulk mutations append actor/time/target/outcome evidence in the same transaction; log remains capped at 10,000 |
| Notifications | PASS | Per-user critical/high and assignment records, dedupe, 500/user cap, unread/read-one/read-all, ownership isolation, navigation |
| Alert UX | PASS | Persisted queue, status/assignee/unassigned/sort filters, 50-item selection cap, bulk confirmation, detail workflow panel |
| Existing workflows | PASS | Dashboard, Discover, incidents, hosts/sources, rules, reports, admin, saved searches, deep links, copy and time formatting retained |
| AI/M8 | PASS | Unchanged and disabled (`AI_ENABLED=false`) |

## Automated and live gates

| Gate | Result |
|---|---|
| Backend | 166/166 PASS |
| Frontend | 81/81 PASS; one CPU-contention timeout was isolated and the clean rerun passed |
| TypeScript and production build | PASS |
| Deployment/validator contracts | 13/13 PASS |
| Wazuh sender/shipper/rule tests | 113/113 PASS |
| Passive local validator | 7/7 PASS |
| Backend, readiness, frontend, frontend proxy | HTTP 200 / ready |
| Wazuh Manager and agent 001 | Active; `cyberqalqon-test-web` enrolled and active |
| Sender durability | Queue 0, pending 0, in-flight 0, terminal blocked 0, dead letters 0 |
| SQLite | `quick_check=ok`, schema 10 |
| Diff whitespace | PASS (line-ending notices only) |

The passive validator intentionally generated no attack traffic and no analyst actions. Its latest
machine-readable output is `artifacts/lab-validation/latest.json`.

## Scope classification

The highest-priority durable SOC workflow phases are implemented and verified: alert triage,
bounded bulk actions, and persisted per-user notifications. Existing incidents, saved searches,
reports, source freshness, administration, and audit views were integrated rather than replaced.
The broader v0.4 product prompt remains **PARTIAL** because incident checklist/pinned evidence,
configurable Discover columns/user preferences, source-stale notifications, and a richer dedicated
investigation workspace are intentionally not fabricated in this iteration.

Authenticated visual browser E2E remains blocked by the Codex in-app browser's localhost `/api`
restriction. Component/API/build validation is reported separately and is not mislabeled as a
visual browser pass.
