# CyberQalqon SIEM v0.8 repository inventory

Inventory checkpoint: 2026-10-10 (Asia/Yekaterinburg). This document records the
pre-change state used for the v0.8 stabilization work. No tracked source file was
modified before this checkpoint was assembled.

## Repository identity

- Repository: `cyberqalqon-ai-lead-dev`
- Branch: `main`
- HEAD: `b07fdd50dc3df71976bf9467f8ecb98e68045926`
- Git status: 177 entries: 62 tracked unstaged files and 115 untracked paths
- Staged files: 0
- Visible, non-ignored files: 311
- Existing work from v0.1-v0.7 is intentionally uncommitted and must be preserved.

The largest visible source areas are `backend` (105 files), `frontend` (86),
`docs` (47), `wazuh` (48), `tests` (6), and `scripts` (5). The repository also
contains one empty, untracked directory whose literal name is ``. It is not
part of an application path and was not deleted because the stabilization brief
forbids speculative cleanup.

## Working-tree classification

| Class | Current state | Release treatment |
| --- | --- | --- |
| Source | Backend, frontend, sender, scripts, shared schemas | Review and stage explicitly |
| Tests | Backend, frontend, Wazuh, deployment and E2E | Review and stage explicitly |
| Documentation | API, architecture, lab, SIEM and Windows docs | Review and stage explicitly |
| Configuration templates | `.env*.example`, Compose, Nginx, Wazuh units/rules | Review; never substitute live values |
| Runtime data | SQLite DB/WAL/SHM, logs, validator output | Keep ignored; do not stage |
| Backups | Milestone and rehearsal databases | Keep ignored; do not stage |
| Secrets | `.env`, `secrets/`, key/certificate formats | Keep ignored; never stage |
| Generated output | `frontend/dist`, caches, `tmp`, PDF validation output | Rebuild for verification; do not stage unless explicitly selected as a release artifact |

## Generated and runtime artifacts

- `backups/`: approximately 134.74 MiB and ignored.
- `backend/`: approximately 113.47 MiB including the virtual environment and
  the ignored live database.
- `frontend/`: approximately 105.26 MiB including `node_modules` and build output.
- `.pytest_cache/`, `logs/`, `tmp/`, `artifacts/lab-validation/`, local SQLite
  files, `frontend/dist/`, `.env`, and `secrets/` are ignored.
- The existing `output/pdfs/cyberqalqon-case-report-validation.pdf` is a v0.7
  synthetic validation artifact, not production evidence.

## Secret and credential exposure review

- The live `.env` is ignored. Only environment variable names were inspected.
- `secrets/local-lab-wazuh-ingest.key` is ignored.
- The exact local ingest-key value was not found in any visible source,
  documentation, configuration template, test, or deliverable.
- No PEM private-key header was found in visible repository files.
- Credential-shaped strings are limited to configuration handling, redacted
  examples, and test fixtures; no verified live credential exposure was found.
- Production Compose uses a mounted secret file and the Nginx image uses mounted
  TLS files. Runtime databases and key formats are covered by `.gitignore`.

## Code and dependency inventory

- Python dependency integrity: `pip check` passed.
- Python import/bytecode compilation passed for backend, sender, and scripts.
- Frontend dependency tree is internally consistent (`npm ls --depth=0`).
- TypeScript type checking passed.
- Exact duplicate-content scanning found only intentionally empty Python
  `__init__.py` package markers.
- No verified duplicate implementation module or unused direct dependency was
  identified at this checkpoint.
- No `eval`, `exec`, `shell=True`, unsafe YAML loading, browser storage of
  sessions, or React raw-HTML injection was found.

## Database and migration inventory

- Live database: `backend/data/cyberqalqon-local-lab.db`
- SQLite schema: 14; migrations 1 through 14 are present in order.
- Tables: 46
- `PRAGMA quick_check`: `ok`
- `PRAGMA foreign_key_check`: 0 violations
- Journal mode: WAL
- Baseline records at inventory time: 4,266 security events, 40 alerts,
  3 incidents, 1 analyst, 6 sessions, and 0 cases.
- Repository connection helpers enable foreign keys and a 5-second busy timeout.
  A plain standalone SQLite connection reports foreign keys disabled by default;
  this is SQLite client behavior, not the application connection policy.
- A supported online backup was created and verified before stabilization:
  `backups/cyberqalqon-pre-v08-20261010T084500Z.db`, schema 14, SHA-256
  `d4f644b2baa4cda97743f81f589ad6914bff6a1af4e45e5aa48232a5e99eb371`.
- Restore rehearsal succeeded only against
  `tmp/v08-restore-rehearsal-20261010.db`: schema 14, quick check `ok`, zero
  foreign-key violations, 40 alerts, 3 incidents, and 4,266 security events.
  The restore utility intentionally invalidated six copied sessions. The live
  database was not replaced.

## Baseline validation

| Check | Result |
| --- | --- |
| Backend | 190 passed, one upstream Starlette/AnyIO deprecation warning |
| Wazuh sender + deployment | 126 passed |
| Frontend typecheck | Passed |
| Frontend production build | Passed; one 512.85 kB JS chunk (129.40 kB gzip) |
| Frontend tests, default runner | Failed to start 11 fork workers under concurrent laptop load; 30 executed tests passed |
| Frontend tests, one worker | 97 passed in 27.79 seconds |

The default Vitest worker fan-out is therefore a verified low-resource release
reproducibility defect. The single production bundle is also a verified
performance issue and code-splitting candidate.

## Functional coverage and test gaps

All advertised top-level pages exist and are wired into the application shell:
Overview, Operations, Discover, Threat Hunting, Alerts, Incidents, Cases, Hosts,
Detection Rules, Threat Intelligence, Reports, and Administration. Notifications
and preferences are integrated components rather than standalone routes.

Dedicated page test files exist for Administration, Alerts, Cases, Discover,
Incidents, and Operations. Dashboard, Hosts, Reports, Detection Rules, Threat
Hunting, and Threat Intelligence rely on broader application/experience suites
rather than one test file per page. Browser back/forward handling exists in
`App.tsx`, but authenticated real-browser execution still requires a usable test
session or dedicated test account.

## Security posture inventory

- Argon2id uses fixed reviewed parameters and dummy verification for unknown users.
- Login lockout, opaque hashed session tokens, bounded session count, expiry,
  HttpOnly/SameSite cookies, production Secure cookies, trusted Origin checks,
  CSRF tokens, RBAC, and audit events are implemented.
- CORS rejects wildcard origins and permits only enumerated methods/headers.
- Production Nginx defines HSTS, CSP, frame denial, MIME sniffing prevention,
  referrer policy, and restrictive permissions policy.
- SQL access uses parameterized statements in reviewed repositories. No verified
  path-traversal surface or arbitrary evidence-file access was identified.
- `AI_ENABLED=false` in the local environment. No LLM installation is present or
  required for the stabilization work.

## Telemetry inventory

- Ubuntu WSL: Wazuh Manager, sender, event shipper, backend relay, and manager
  relay are active/running.
- Wazuh agent `001` (`cyberqalqon-test-web`) is Active.
- Kali: Wazuh Agent, Nginx, and agent relay are active/running; the bounded
  nftables monitor is active/exited as designed.
- Windows `WazuhSvc` is Running with automatic startup.
- No attack traffic was generated for this inventory.

## Documentation and release gaps

- Existing deployment, backup/restore, operations, demo, API, architecture, and
  limitation documents are present.
- Application and frontend version metadata still identify v0.7.0.
- A v0.8 changelog/release note, consolidated environment reference, release
  checklist, browser UAT evidence, explicit hardware guidance, and reviewed Git
  staging proposal do not yet exist.
- CI runs the complete major suites, but its default `npm test` command inherits
  the verified worker fan-out instability until the test configuration is bounded.

## Initial stabilization priorities

1. Make frontend test execution deterministic on a low-resource laptop.
2. Split page-level frontend code so the initial production bundle is bounded.
3. Execute a route-by-route functional audit and add coverage for verified gaps.
4. Run authenticated browser UAT if a supported existing session is available;
   otherwise publish a precise manual UAT checklist and mark execution blocked.
5. Verify API/query performance, telemetry durability, and report rendering.
6. Update version/release metadata and consolidate release documentation without
   committing or pushing the dirty working tree.
