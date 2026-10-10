# SIEM v0.5 feature coverage

| Workflow | State | Implemented behavior |
|---|---|---|
| Security Overview | Implemented | Real bounded timelines/top lists, event rate, incident status, source freshness, delivery activity, retention, and DB size |
| Discover | Implemented | FTS/exact search, chips, safe URL/history state, deep links, saved-search rename, 25/50/100 keyset pages, safe JSON/copy, relationships, and persisted reorderable columns/density |
| Security event store | Implemented | v12 SQLite schema, dedupe, redaction, compound indexes, FTS5 fallback, age and hard-cap retention |
| Real event ingestion | Implemented | Allowlisted durable Wazuh archive cursor plus alert projection |
| Alerts | Implemented | Durable `NEW`/`ACKNOWLEDGED`/`IN_PROGRESS`/`RESOLVED`/`FALSE_POSITIVE` workflow, active-analyst assignment, notes, activity history, optimistic concurrency, filtering/sorting, counts, copy/deep links, and related evidence |
| Bulk alert triage | Implemented | Explicit confirmation, maximum 50 selected alerts, acknowledge/assign/status actions, version checks, transactional all-or-nothing behavior, per-item rejection details, and audit evidence |
| Incidents | Implemented | Existing M9 lifecycle plus durable ordered checklist, evidence pins/annotations, unified action/source-time investigation timeline, optimistic concurrency, and per-user assignment notifications |
| Hosts and log sources | Partial | Search/filter/detail, event/alert counts, platform evidence, persisted delivery time/lag, `ACTIVE`/`STALE`/`EMPTY` pipeline health, explicit unavailable queue/cursor metrics, and `UNKNOWN` agent state without Wazuh API auth |
| Detection engineering | Implemented | Consolidated deployed/observed Wazuh and M9 inventory, truthful metadata provenance, local declarative drafts, validation, bounded dry-run, versions, rollback-as-new-version, audit, and manual-only deployment readiness |
| Threat hunting | Implemented | Dedicated bounded IP/host/user/category/rule/MITRE/time/evidence hunts, persisted relationships, safe deep links, per-analyst saved queries, and audited CSV export |
| MITRE coverage | Implemented | Explicit mappings with mapped, enabled, triggered, and tested facts kept separate; gaps mean missing test evidence only within the mapped set |
| Detection analytics | Implemented | Alert/false-positive trends, top rules/IPs/hosts, MITRE and IOC summaries, terminal analyst dispositions, and deterministic tuning candidates without suppression |
| Local threat intelligence | Implemented | Validated/normalized/deduplicated IPv4, IPv6, domain and hash records with provenance, confidence, expiration, audit, import/export, and bounded event matching |
| Reports | Implemented | Authenticated 31-day custom/preset JSON/CSV downloads with progress, severity/host/rule filters, metadata, audit, and spreadsheet escaping |
| Navigation/accessibility | Implemented | Breadcrumbs, URL/deep-link history, keyboard shortcuts, standardized copy announcements and clipboard error feedback |
| Administration/audit | Implemented | Self-service password/session controls, admin account inventory, bounded security audit, and action/target/outcome/text audit filters |
| Wazuh online/offline status | Blocked | No supported authenticated Wazuh agent-status API credential is configured |
| PDF reports | Planned | CSV/JSON chosen to avoid a new heavyweight runtime |
| Arbitrary SPL/KQL/EQL | Planned | v0.5 uses validated bounded filters and a declarative rule schema, not an unrestricted query language |
| AI analysis | Disabled | No model was installed or started; SIEM workflows operate with `AI_ENABLED=false` |
| Notification center | Implemented | Persisted per-user critical/high alert and alert/incident assignment notifications, unread count, mark-one/all-read, bounded reads/storage, dedupe, ownership isolation, navigation, RBAC, CSRF, and audit |
| Analyst preferences | Implemented | Isolated versioned defaults for dashboard range, page sizes, table density, alert sort, time-display preference, and Discover columns; reset is authenticated and audited |

Live Wazuh rule editing remains disabled. v0.5 local drafts are versioned, validated, tested against
historical normalized events, and explicitly marked for separate manual operator review; the app
never writes or reloads Wazuh rules.
Source-stale and ingest-failure notifications remain future work because the local lab has no
authoritative transition scheduler or runtime failure feed. Existing incident evidence, host
inventory, source freshness, reports, saved searches, and audit views are reused rather than
duplicated.
