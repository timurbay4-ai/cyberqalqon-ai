# M10 endpoint telemetry v1.0 development validation

Date: 2026-10-11
Scope: unprivileged software development and automated tests
Live endpoint changes: none

## Implemented

- Additive SQLite schema migration 16 for OS, process path, redacted command line, parent path, and
  upstream MITRE arrays.
- New records use normalization schema `wazuh-event-v3`; historical schema labels are preserved.
- Windows normalization semantics for required authentication, process, account/group,
  PowerShell, service, and Defender events.
- Linux normalization categories for SSH/PAM, sudo, auditd, service, account/group, and scheduled
  task evidence when present.
- Exact server-side OS/provider/channel/process/action filters, including saved-search contracts.
- Evidence-backed `GET /api/v1/events/coverage`; every returned row is `OBSERVED` from
  `STORED_EVENTS`.
- Discover filters and endpoint detail rendering with safe command-line copy and MITRE provenance.
- Exact bounded EventChannel definitions and archive allowlist updates. These files were not
  deployed to Agent 002 during this work.

## Database safety

- Migration 16 only adds columns and indexes.
- An isolated schema-15 upgrade test preserved the original event message and raw JSON, left new
  unknown fields null/empty, and reached the current schema version.
- No live database was opened for migration, rewritten, deleted, or pruned.

## Automated evidence

| Suite | Result | Notes |
|---|---:|---|
| Backend full regression | 221 passed | Full suite after M10 application changes |
| Backend migration regression | 11 passed | Includes the final schema-15 preservation test added after the full run |
| Backend final affected regression | 50 passed | Events, migrations, and detection-engineering dry-run after `v3` schema labeling |
| Frontend full regression | 100 passed | Re-run with one worker after a parallel-load-only shortcut-test timeout |
| Frontend focused M10 contracts/Discover | 19 passed | New filters and endpoint/MITRE rendering included |
| Frontend focused M11 foundation | 16 passed | Endpoint draft fields and runtime contracts |
| Frontend production build | PASS | TypeScript no-emit check plus Vite production build |
| Wazuh sender/shipper | 117 passed | Includes expanded Windows allowlist |
| Deployment/validator | 22 passed | Includes exact EventChannel and schema-16 validator assertions |
| Diff whitespace validation | PASS | `git diff --check`; only existing Windows LF→CRLF notices |

The initial parallel frontend run produced one timing failure in the keyboard-shortcuts test. The
test passed alone and the complete 100-test suite passed when re-run serially. No product code was
changed to mask the timing result.

## Live evidence status

- Existing v0.9.1 Windows Application event evidence remains valid and unchanged.
- No new live Windows Security, PowerShell, System, or Defender event was generated or claimed.
- No live Linux auditd evidence was generated or claimed.
- Sysmon remains absent.
- Windows auditing/module/script-block policy prerequisites were documented but not applied.

## Security notes

- Extracted command lines use the redacted payload, preventing common password/token/secret
  assignments from bypassing persistence redaction.
- Invalid nested execution identifiers and invalid MITRE technique IDs fail closed.
- Coverage remains authenticated with `soc:read` and never converts configured/silent sources into
  a health claim.
- Authentication, CSRF, RBAC, agent keys, credentials, and service state were not changed.

## Remaining M10 acceptance work

1. Operator-authorized Windows audit-policy verification and collector deployment, if desired.
2. Real Security, PowerShell, System, and Defender samples through Agent 002.
3. Optional real Linux auditd validation when auditd is installed/configured.
4. Application restart/upgrade window to apply migration 16 to the live database, followed by
   `quick_check`, foreign-key, count-preservation, and rollback-backup verification.

These are live acceptance tasks, not grounds to claim the implemented software tests failed.
