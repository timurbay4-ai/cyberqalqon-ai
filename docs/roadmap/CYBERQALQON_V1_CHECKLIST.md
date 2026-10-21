# CyberQalqon SIEM v1.0 implementation checklist

Legend: `[x]` verified in the current development work; `[~]` implemented but broader regression or
live evidence is pending; `[ ]` not yet implemented; `[!]` requires operator authorization or an
external acceptance environment.

## Repository and architecture

- [x] Inspect v0.9.1 backend, frontend, migrations, normalizers, Wazuh integration, tests, and docs.
- [x] Record v1.0 gap analysis and dependencies.
- [x] Preserve existing uncommitted work and live data.
- [x] Keep `AI_ENABLED=false`; add no AI runtime or feature.
- [x] Keep Browser UAT and production HTTPS as separate open gates.

## M10 — Endpoint telemetry

### Normalization

- [x] Windows provider/channel/event ID/host/agent provenance.
- [x] Windows event action/outcome semantics for 4624, 4625, 4634, 4648, 4672, 4688, 4720,
  4726, 4732, 4103, 4104, 7045, 1116, and 1117.
- [x] Defender failure/protection-change event semantics for selected bounded IDs.
- [x] OS, process path, redacted command line, parent process path, and upstream MITRE context.
- [x] Linux SSH, PAM, sudo, auditd, service, account/group, and scheduled-task categories.
- [x] Representative sanitized Windows process, Linux SSH, and Linux sudo fixtures.
- [x] Invalid nested types and MITRE IDs fail closed.

### Collection and prerequisites

- [x] Expand repository EventChannel fragment and supported installer definitions.
- [x] Expand archive shipper allowlist without mirroring full channels.
- [x] Document Security/PowerShell/Defender audit prerequisites.
- [!] Apply new Windows collector/audit policy to a live endpoint.
- [!] Produce live Security, PowerShell, System, and Defender evidence.
- [!] Install or enable Sysmon (not part of this milestone without approval).

### Storage and API

- [x] Additive schema migration 16.
- [x] Preserve historical records with nullable/default fields.
- [x] OS/time and action/time indexes; reuse provider/channel/time index.
- [x] Exact OS/provider/channel/process/action filters.
- [x] Saved-search request/response support for new filters.
- [x] Evidence-backed `/api/v1/events/coverage` report.
- [x] Coverage states only `OBSERVED` with `STORED_EVENTS` evidence.
- [x] Focused backend tests: 42 passing at the first M10 checkpoint.

### Frontend

- [x] TypeScript event contract includes endpoint context and MITRE.
- [x] Discover exposes OS/provider/channel/process/action filters.
- [x] Event detail renders endpoint execution and MITRE context.
- [x] Targeted runtime-contract/Discover tests: 19 passing.
- [x] TypeScript typecheck passes.
- [x] Production frontend build passes.

### Documentation

- [x] v1.0 roadmap and checklist.
- [x] Update event schema, SIEM API, Windows collection, and telemetry coverage docs.
- [x] Publish M10 development validation report with automated regression totals.

## M11 — Advanced detection and correlation

- [x] Extend the existing authorized draft/dry-run mechanism with M10 endpoint context fields.
- [x] Verify an endpoint process/provider/command/parent-path draft against stored fixture evidence
  with no alert, incident, notification, or live Wazuh side effect.
- [x] Inventory existing M9/Wazuh rules against nine required detections.
- [x] Define stable IDs, prerequisites, severity, ATT&CK, window, threshold, group-by, and dedupe.
- [x] Implement repeated Windows failed-logon rule (`DET-001`).
- [x] Implement failed→successful authentication sequence (`DET-002`).
- [x] Implement suspicious privileged-logon pattern (`DET-003`).
- [x] Implement privileged account/group change rule (`DET-004`).
- [x] Implement suspicious PowerShell indicators (`DET-005`).
- [x] Implement unexpected service-install rule (`DET-006`).
- [x] Implement repeated SSH failure/failure→success rule (`DET-007`).
- [x] Implement unusual sudo activity rule (`DET-008`).
- [x] Integrate relevant Defender detection/remediation state (`DET-009`).
- [x] Add positive/negative/boundary/dedupe/expiry and missing-prerequisite tests.
- [x] Add authenticated catalog/detail/dry-run API with RBAC, CSRF, audit, and hard bounds.
- [x] Add frontend filters, prerequisite/availability status, detail, tuning notes, explanation,
  evidence links, and dry-run results.
- [x] Keep every M11 rule disabled pending approval, live telemetry acceptance, and tuning.
- [x] Publish `M11_ADVANCED_DETECTION_VALIDATION.md` and update API, correlation, event-schema,
  coverage, feature, limitation, roadmap, and checklist documentation.

## M12 — Analyst workbench

- [x] Consolidate alert entity context and related events.
- [x] Add detection explanation and prerequisite visibility.
- [x] Consolidate incident asset/user/evidence/timeline projections.
- [x] Preserve alert/incident/case mutation ownership boundaries.
- [x] Add safe deep links and navigation tests.
- [x] Verify RBAC, CSRF, optimistic concurrency, and audit for every mutation.
- [x] Do not add unsupported automatic closure.

## M13 — Performance and reliability

- [ ] Establish event-ingestion and search benchmark baselines.
- [ ] Add queue saturation/backpressure thresholds and summaries.
- [ ] Verify sender/shipper crash recovery and cursor rotation.
- [ ] Verify dead-letter behavior without data loss.
- [ ] Add safe FTS reindex/recovery procedure if measurements justify it.
- [ ] Run integrity, retention, backup, and restore regression.
- [ ] Document capacity limits and infrastructure decision thresholds.

## M14 — Security and deployment hardening

- [ ] Audit authentication, RBAC, CSRF, input validation, and error redaction.
- [ ] Verify TLS certificate validation and restrictive bindings.
- [ ] Verify secret, database, cursor, queue, and backup permissions.
- [ ] Document supported `soc-admin` rotation process.
- [!] Rotate bootstrap credentials before production.
- [!] Validate HTTPS topology in the target environment.
- [ ] Confirm Wazuh API and SQLite are never publicly exposed.

## M15 — v1.0 release candidate

- [ ] Freeze v1.0 API and migration contracts.
- [ ] Update architecture and migration documentation.
- [ ] Publish telemetry coverage matrix and detection catalog.
- [ ] Publish analyst, operations, backup, and security runbooks.
- [ ] Publish known limitations and versioned release notes.
- [ ] Run complete backend/frontend/Wazuh/deployment regression.
- [ ] Validate upgrade from a copied v0.9.1 database.
- [ ] Run separate authenticated Browser UAT.
- [!] Complete production HTTPS acceptance.
- [!] Obtain explicit authorization before commit, tag, push, or deployment.
