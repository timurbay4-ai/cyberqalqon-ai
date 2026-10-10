# Changelog

All notable CyberQalqon SIEM changes are recorded here. The project uses
semantic version identifiers for application and image metadata. A version entry
does not by itself mean that production acceptance has been granted.

## 0.8.1-rc1 - 2026-10-10

### Corrected

- Preserved the native browser `fetch` receiver so real Chromium/Edge requests
  no longer fail with `Illegal invocation`.
- Accepted an omitted terminal-page cursor as the API's documented `null`
  cursor, keeping Discover results usable on the final page.
- Aligned GitHub Actions image inspection with the 0.8.1 backend/web tags and
  added a regression check for release metadata drift.

### Verified

- Completed the 20-step authenticated Edge UAT against a disposable restored
  database, including case evidence, playbook, reports, audit, and logout.
- Verified ADMIN, ANALYST, and VIEWER boundaries, CSRF rejection, and real
  short-TTL session expiration without weakening authentication.
- Kept AI disabled and preserved the live evidence database and local Wazuh
  telemetry pipeline throughout release-gate testing.

## 0.8.0-rc1 - 2026-10-10

### Stabilized

- Bounded Vitest to one non-parallel worker so the full frontend suite remains
  reproducible while the local Wazuh lab is running.
- Added route-level React lazy loading and a bounded page error state. The main
  production JavaScript chunk fell from 512.85 kB to 317.73 kB before gzip.
- Bound Vite development and preview servers to the documented IPv4 loopback,
  avoiding Windows `localhost` resolving only to `::1`.
- Added `127.0.0.1:5173` to the default development Origin allowlist while
  preserving exact-origin, CSRF, and credentialed-CORS enforcement.
- Converted incomplete HTTP request bodies into a bounded client error instead
  of allowing a client disconnect traceback through the ingestion route.
- Extended the passive lab validator to verify the complete WSL backend relay
  path, not only the systemd unit state.
- Updated backend, frontend, image, deployment, and CI version metadata to 0.8.0.

### Verified

- Schema 14 and all v0.1-v0.7 data were preserved; no v0.8 migration was needed.
- Supported online backup and disposable restore rehearsal completed.
- Authentication, trusted Origin, CSRF, RBAC, machine-key, evidence, report, and
  audit regression coverage remains enabled.
- Wazuh shipper backlog recovered from its durable cursor after the documented
  WSL-interface backend listener returned; no queue or dead-letter data was
  deleted.

### Known release gates

- Authenticated real-browser UAT remains blocked in the available automation
  environments. The in-app browser loads the frontend but cannot reach its local
  auth API; the Windows browser helper cannot activate Chrome. Manual Chrome or
  Edge execution is required before release approval.
- Authenticated Wazuh API inventory is unavailable because read-only credentials
  are not configured. Event ingestion and agent 001 remain healthy.
- The Windows Wazuh Agent service runs, but supported enrollment is incomplete.

## 0.7.0 - 2026-10-09

- Added SOC case management, evidence digests and custody history, deterministic
  playbooks, SLA evaluation and analytics, and JSON/CSV/PDF case reports.

## 0.1.0-0.6.0

- Established normalized alert ingestion, authentication, incident correlation,
  SIEM event search, analyst workflow, investigations, detection engineering,
  Windows monitoring, telemetry operations, and reliability controls.
