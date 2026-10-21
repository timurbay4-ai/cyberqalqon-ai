# M14 advanced detection readiness architecture

## Safety boundary

M14 prepares `DET-001` through `DET-009` for controlled evaluation. It does not
create a live evaluator or attach any M11 finding to alert, incident, case,
notification, or Wazuh output paths. Every rule retains `enabled=false` and
`runtime_activation_state=DISABLED_BY_POLICY`; `AI_ENABLED=false` is unchanged.

The subsystem reuses the deterministic M11 evaluator and adds four isolated
layers:

1. Versioned declarative configuration and lifecycle state.
2. Transactional, restart-safe correlation replay state.
3. Operator-triggered historical tuning and shadow evaluation.
4. Rule-specific telemetry evidence, diagnostics, and canary-readiness blockers.

The existing Detection Engineering workspace exposes Overview, Configuration,
Test, Shadow, Tuning, Readiness, and Diagnostics views. M12 can open historical
dry-run and shadow findings through its existing evidence contract. No frontend
control can activate a rule.

## Storage and API

Prepared schema 18 adds `advanced_detection_*` tables for rule state, immutable
configuration versions, lifecycle history, correlation state, processed-event
hashes, shadow runs/findings, and bounded diagnostics. Shadow tables contain no
foreign key or adapter to production alerts, incidents, or cases.

Readers require `soc:read`. Shadow, tuning, and correlation replay require
`alert:write`. Configuration and lifecycle mutations require ADMIN. Existing
session, Origin, CSRF, audit, and optimistic-concurrency controls remain in
force. Configuration accepts only typed fields, bounded identifiers, numeric
limits, and allowlisted exclusions—never Python, shell, SQL, or arbitrary query
text.

## Schema gate

The live database remains schema 17. Schema 18 was applied only to a disposable
copy of the verified schema-17 online backup. A future live migration requires
separate explicit approval and a fresh online backup. The runtime default
`ALLOW_M14_SCHEMA_MIGRATION=false` caps automatic migration at schema 17; a
normal backend restart therefore remains ready without applying schema 18. The
one-shot flag may be set true only for an explicitly approved start.
