# M14 activation and rollback safety

M14 has no activation endpoint, live worker, Wazuh writer, or production alert
adapter. Database constraints allow only
`runtime_activation_state=DISABLED_BY_POLICY`, API models reject `ACTIVE`, and
the lifecycle service hard-blocks the transition. A frontend toggle can never
authorize production behavior.

Schema activation is independently gated. `ALLOW_M14_SCHEMA_MIGRATION=false`
is the default and keeps an existing live schema-17 database unchanged across
backend restart. A schema-17 runtime reports M14 storage APIs as
`schema_approval_required` while all pre-M14 SIEM paths remain ready.

A future milestone must separately verify telemetry, historical evaluation,
configuration review, resource budget, false-positive baseline, locked version,
allowlisted host/rule scope, explicit start/end, maximum alert/evaluation rate,
operator approval, expiry, monitoring, and rollback triggers. M14 deliberately
reports target scope and approval as false and activation path as disabled.

Fail-closed conditions include invalid/stale configuration, missing telemetry,
timeouts, abnormal bounded volume, duplicates, SQLite busy, restart,
state-version mismatch, upstream loss, and resource exhaustion. Database-busy
mutations return a bounded 503 response; shadow failure cannot affect ingestion.

Rollback rehearsal uses disposable databases. Configuration restore creates an
audited new version. A live rollback, schema change, Wazuh reload, or canary
activation requires fresh evidence and explicit user approval; none occurred in
M14.
