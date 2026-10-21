# CyberQalqon SIEM v1.0 development plan

Status: active development
Baseline: v0.9.1 working tree at `f6a59a9` plus preserved uncommitted work
Target: an evidence-driven, local, enterprise-oriented v1.0 release candidate

## Ground rules

- Existing FastAPI, React, SQLite, Wazuh sender/shipper, RBAC, cases, alerts, incidents, and
  correlation components are extended rather than duplicated.
- `AI_ENABLED=false` is the v1.0 development baseline. No Ollama or speculative AI work belongs
  to this roadmap.
- Additive, transactional migrations preserve all historical alerts, incidents, cases, events,
  evidence, and audit records.
- Live endpoint policy changes, software installation, credential rotation, firewall changes, and
  production deployment require separate operator approval.
- A configured collector is not proof of coverage. Coverage is reported as observed only when
  stored event evidence exists.
- Browser UAT and production HTTPS acceptance remain independent open release gates.

## Gap analysis

| Area | Existing capability to reuse | v1.0 gap | Planned milestone |
|---|---|---|---|
| Endpoint events | Bounded event store, Wazuh archive shipper, Windows provenance fields | Incomplete Windows ID coverage, Linux semantics, process/command/MITRE context | M10 |
| Search | FTS5, exact filters, keyset pagination, saved searches | Missing OS/provider/channel/process/action filters | M10 |
| Coverage | Static validation matrix and overview counts | No evidence-backed coverage API | M10 |
| Detection | Wazuh catalog, local drafts, dry-run, M9 correlation | Required endpoint correlation rules and quality metadata incomplete | M11 |
| Investigation | Alerts, incidents, cases, evidence pins, timelines, notes | Entity context and cross-object reasoning need consolidation | M12 |
| Reliability | Durable sender/shipper, cursor, retry, dead letter, operational snapshots | Backpressure thresholds and unified lag/saturation summaries need hardening | M13 |
| Security | Argon2id auth, CSRF, RBAC, audit, TLS-capable deployment | Bootstrap rotation gate and production evidence remain open | M14 |
| Release | Versioned docs and validation scripts | Coherent v1.0 contracts, release notes, and acceptance report missing | M15 |

## Technical debt and dependencies

1. The root README and several version-labelled documents describe older schema or release
   baselines. They must be updated only as each v1.0 capability is verified.
2. The event model and alert model overlap but have different authority: raw/archive evidence is
   authoritative in `security_events`; alert conclusions remain authoritative in `alerts`.
   M10 preserves this boundary.
3. SQLite FTS search documents are denormalized. New rows index v1.0 fields immediately; historical
   rows are not silently rewritten. A deliberate, idempotent reindex operation may be added in M13.
4. Windows Security, PowerShell, System, and Defender collection prerequisites are endpoint policy
   dependencies. Code and exact collector fragments may be prepared without applying them.
5. Detection enablement depends on real telemetry volume. No noisy correlation rule is globally
   enabled from fixture-only evidence.
6. Agent status comes from the read-only Wazuh API, while source freshness comes from stored
   telemetry. These states must remain separate in API and UI language.
7. The live database stays untouched during migration development. Migration validation uses
   isolated temporary databases until an operator schedules an application upgrade.

## M10 — Windows and Linux telemetry expansion

### 1. Objective

Provide consistent endpoint event context, bounded collection, evidence-backed coverage, and
analyst-friendly Discover rendering for the required Windows and Linux security sources.

### 2. Existing components to reuse

- `event_normalizer.py`, `EventRepository`, schema migrations, FTS5, and event APIs.
- Wazuh archive shipper allowlist and persistent cursor.
- Existing Windows EventChannel configuration/installer fragments.
- Discover filters, saved searches, event detail, runtime API validation, and preferences.
- v0.9.1 agent inventory and read-only Wazuh API integration.

### 3. Features to implement

- Windows events 4624, 4625, 4634, 4648, 4672, 4688, 4720, 4726, 4732, 4103, 4104, 7045,
  Defender detection/remediation, and selected protection-state changes.
- Linux SSH/PAM, sudo, account/group, service, scheduled-task, and auditd categories when present.
- OS, provider, channel, process path, redacted command line, parent process, action/outcome, and
  upstream MITRE context.
- Exact OS/provider/channel/process/action filters and improved endpoint detail rendering.
- An authenticated coverage report that says only `OBSERVED` from `STORED_EVENTS`.
- Sanitized Windows/Linux fixtures and focused tests.

### 4. Architecture changes

- Add schema migration 16 with nullable endpoint columns and JSON MITRE arrays.
- Retain the existing event identity/fingerprint and raw-evidence reference model.
- Keep collector filters exact and bounded; do not mirror entire Windows channels or archives.
- Do not create alerts from archive evidence in the normalizer.

### 5. Backend tasks

- Extend normalization and redaction-safe extraction.
- Add query fields to request, saved-search, repository, and response contracts.
- Add evidence-backed telemetry coverage aggregation.
- Reject malformed nested values and invalid MITRE IDs without partial persistence.

### 6. Frontend tasks

- Extend runtime contracts and types.
- Add Discover filters for OS, provider, channel, process, and action.
- Render endpoint execution context and upstream MITRE evidence in event detail.
- Preserve loading, empty, unavailable, and untrusted-text behavior.

### 7. Database changes

- Additive schema v16 only; no table drops or historical rewrites.
- Add indexes for OS/time and action/time; reuse the existing provider/channel/time index.
- Store MITRE arrays as validated JSON.

### 8. Security considerations

- Redact command lines before normalized persistence.
- Do not store credentials, session material, or unbounded payloads.
- Keep event reads behind `soc:read`; coverage is also authenticated.
- Applying Windows audit policy remains an operator-approved action.

### 9. Acceptance criteria

- All listed Windows semantics are deterministic and fixture-tested.
- Representative Linux SSH and sudo fixtures normalize correctly.
- Exact filters execute server-side and migration 15→16 preserves rows.
- Frontend typecheck, focused UI tests, and production build pass.
- Coverage output never represents unobserved configured sources as live.

### 10. Dependencies

- Existing Wazuh EventChannel decoder fields.
- Audit policy/channel enablement for live validation.
- Current event-store retention and size limits.

### 11. Risks

- 4624 and 4688 can be high volume; exact endpoint policy and post-deployment measurement are
  required.
- Command lines may contain secrets; redaction is mandatory and imperfect free-text patterns remain
  a documented limitation.
- Fixture success is not live telemetry acceptance.

## M11 — Advanced detection and correlation

### 1. Objective

Implement explainable endpoint detections on the existing M9/Wazuh architecture without creating
a competing rule engine.

### 2. Existing components to reuse

M9 correlation, Wazuh rule inventory, declarative drafts, validation, bounded dry-run, alert
deduplication, incident correlation, MITRE coverage, and audit history.

### 3. Features to implement

Stable rules for repeated Windows failures, failure→success, privileged logon, privileged account
change, suspicious PowerShell, service install, repeated SSH failures, unusual sudo, and Defender
detections. Every rule records prerequisites, scope, window, threshold, grouping, dedupe, false
positives, evidence, and analyst guidance.

### 4. Architecture changes

Extend the current declarative rule schema with event-code/provider/action predicates and bounded
sequence/threshold correlation. Reuse existing state and alert/incident persistence.

### 5. Backend tasks

Add rule validation, correlation state expiry, deterministic dedupe keys, error isolation, dry-run
explanations, and audit events for authorized enable/disable actions.

### 6. Frontend tasks

Show prerequisites, current telemetry sufficiency, test evidence, false-positive notes, and dry-run
matches. Do not imply enabled/triggered/tested are equivalent.

### 7. Database changes

Add versioned rule metadata and bounded correlation state only if the existing tables cannot carry
the fields. Migration must be additive and rollback-safe.

### 8. Security considerations

Rule mutation remains RBAC/CSRF/audit protected. Raw commands and unrestricted expressions are not
accepted. Fixture-only rules default disabled.

### 9. Acceptance criteria

Each required detection has positive, negative, boundary, dedupe, expiry, and missing-prerequisite
tests. No benign single event triggers a threshold rule.

### 10. Dependencies

M10 normalized fields, observed telemetry, existing M9 state management, and Wazuh rule metadata.

### 11. Risks

Low-volume lab evidence may hide false positives. Production enablement requires measured tuning.

### Development completion status

The repository now contains versioned `DET-001`–`DET-009` definitions, explicit prerequisites,
the shared deterministic event-time evaluator, bounded authenticated dry-run APIs, telemetry
availability gating, analyst explanations/evidence, frontend catalog/detail/filtering, and isolated
positive/negative/boundary/dedupe/expiry/missing-field tests. All rules are
`DISABLED_BY_POLICY`; M9 remains the only live automatic incident correlation path. No live database
migration, Wazuh rule change, Windows policy change, alert, incident, case, or notification was
created for M11 development. Production enablement remains outside this milestone.

## M12 — SOC analyst workbench

### 1. Objective

Make alert and incident investigation coherent across related events, entities, cases, and audit
history while retaining one source of truth for each state.

### 2. Existing components to reuse

Alert workflow, incident workspace, cases, evidence pins, comments, timelines, assignments, SLA,
notifications, and reports.

### 3. Features to implement

Entity context, related-event navigation, consolidated timeline, detection explanation, MITRE
context, affected asset/user summaries, priority reasoning, case references, and status history.

### 4. Architecture changes

Introduce read-only investigation projections over existing records; mutations continue through
the owning alert/incident/case service.

### 5. Backend tasks

Bounded relationship queries, timeline merge ordering, entity aggregation, and authoritative link
metadata with no automatic closure.

### 6. Frontend tasks

Compact workbench panels, safe deep links, clear provenance, and actionable empty states.

### 7. Database changes

Prefer indexes and projections. New link/history tables require immutable IDs and foreign keys.

### 8. Security considerations

Every mutation is authenticated, authorized, CSRF-protected, version-checked, and audited.

### 9. Acceptance criteria

An analyst can move from alert to source event, related incident, and case without losing context;
parallel edits fail safely.

### 10. Dependencies

M10 evidence fields and M11 explanations.

### 11. Risks

Duplicated workflow state could diverge; projections must remain read-only.

### 12. Implementation status (2026-10-12)

Implemented as one bounded read-only projection and a dedicated frontend workbench. Existing
incident/case services retain mutation ownership. Schema-15 compatibility is tested; optional
schema-17 process indexes were added to migration source but not applied to the live database.
Automated regression passed; authenticated browser UAT and live schema-17 process pivots remain
blocked and are not claimed as complete.

## M13 — Performance and reliability

### 1. Objective

Keep the local stack recoverable under bounded load and make lag, queue pressure, and search cost
visible.

### 2. Existing components to reuse

Sender spool, event cursor, retries, dead letters, retention, FTS5, keyset pagination, backups,
health snapshots, and validators.

### 3. Features to implement

Backpressure thresholds, queue saturation status, retry/error summaries, startup recovery checks,
coverage/search benchmarks, safe reindexing, and restoration runbooks.

### 4. Architecture changes

No Kafka/Redis/Elasticsearch/PostgreSQL without measured evidence. Add bounded metrics and indexes
inside the present components.

### 5. Backend tasks

Instrument lag/queue/search timing, cap expensive queries, improve structured errors, and add
readiness checks that do not expose secrets.

### 6. Frontend tasks

Expose freshness, saturation, last-success, and degraded states without conflating process status
with telemetry evidence.

### 7. Database changes

Measured index changes, idempotent FTS rebuild support, integrity checks, and documented backup
compatibility.

### 8. Security considerations

Metrics omit credentials and raw payloads. Recovery never silently discards queued events.

### 9. Acceptance criteria

Crash/restart, queue persistence, cursor rotation, dead-letter, retention, backup/restore, and
bounded search tests pass with recorded measurements.

### 10. Dependencies

M10 schema and realistic fixture volume.

### 11. Risks

SQLite write contention and FTS growth; thresholds must be measured before infrastructure changes.

## M14 — Security and deployment hardening

### 1. Objective

Close application and single-node deployment controls without claiming external production
acceptance.

### 2. Existing components to reuse

Argon2id, sessions, RBAC, CSRF/origin checks, audit trail, secret redaction, TLS reverse proxy,
non-root containers, private listeners, and backup verification.

### 3. Features to implement

Supported bootstrap rotation runbook, certificate-validation checks, listener review, file/backup
permission verification, error redaction tests, and deployment security checklist.

### 4. Architecture changes

Keep browser/API same-origin behind HTTPS; Wazuh API and SQLite remain private.

### 5. Backend tasks

Review every mutation dependency, tighten validation, verify audit coverage, and add secret/error
regression tests.

### 6. Frontend tasks

Preserve role-aware controls and safe session-expiry behavior; never store credentials or tokens in
browser-accessible persistence.

### 7. Database changes

Only audited security metadata if required. Password rotation uses the supported account mechanism,
not direct database editing.

### 8. Security considerations

Credential rotation, privileged OS changes, and production deployment require explicit approval.

### 9. Acceptance criteria

Security regression passes, no secrets appear in tracked files/logs, HTTPS topology is validated in
the target environment, and bootstrap credentials are rotated by an authorized operator.

### 10. Dependencies

Stable M10–M13 contracts and deployment environment access.

### 11. Risks

Local lab success cannot substitute for target TLS, DNS, certificate, permission, or recovery
evidence.

## M15 — v1.0 release candidate

### 1. Objective

Integrate M10–M14 into a truthful, versioned v1.0 release candidate.

### 2. Existing components to reuse

Release gates, validation scripts, CI, changelog, architecture docs, API docs, and known limitations.

### 3. Features to implement

Final architecture, API/migration documentation, coverage matrix, detection catalog, analyst and
operations runbooks, security checklist, release notes, and readiness report.

### 4. Architecture changes

Freeze public contracts and migration sequence for the candidate; record compatibility boundaries.

### 5. Backend tasks

Full automated regression, migration upgrade tests, backup/restore compatibility, and clean OpenAPI
generation.

### 6. Frontend tasks

Full test/build and separate authenticated Browser UAT.

### 7. Database changes

No release-time destructive changes. Validate upgrade from the supported v0.9.1 schema on a copy.

### 8. Security considerations

Secret scan, dependency review, credential rotation evidence, TLS evidence, and least-privilege
deployment review.

### 9. Acceptance criteria

All automated gates pass; live telemetry claims have evidence; Browser UAT and production HTTPS
gates are explicitly PASS or remain OPEN. No commit/tag/push occurs without authorization.

### 10. Dependencies

Stable completion evidence from M10–M14.

### 11. Risks

Late contract drift, incomplete live telemetry, or open security gates delay the release rather than
being waived.

## Sequence

1. Complete and stabilize M10 code/contracts/docs.
2. Implement M11 rules disabled-by-default where live prerequisites are absent.
3. Build M12 projections and investigation UI.
4. Measure and harden M13.
5. Close authorized M14 controls.
6. Assemble M15 and run independent Browser UAT/production acceptance gates.
