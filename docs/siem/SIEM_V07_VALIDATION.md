# CyberQalqon SIEM v0.7 validation

## Phase 0 baseline and migration safety

- Branch: `main`; baseline HEAD: `b07fdd50dc3df71976bf9467f8ecb98e68045926`.
- Existing dirty working tree was preserved; no reset, clean, rebase, commit, or push was run.
- `AI_ENABLED=false` remained configured.
- Baseline schema: v13; SQLite `quick_check=ok`.
- Baseline live counts: 40 alerts, 3 incidents, 1 analyst, 3,608 security events, 4 analyst
  notifications, 4 operational events, and 6 operational component-state rows.
- Baseline alert-list SQLite query (30 runs): p50 0.085 ms; maximum 0.942 ms.
- Baseline `/health` (20 local requests): p50 15.207 ms; p95 82.922 ms; maximum 381.277 ms.
- Verified online backup:
  `backups/cyberqalqon-pre-v07-20261009T175837Z.db` (Git-ignored), SHA-256
  `d5e14babec7a1a80fc23b7a19d5a628c0cef9b32a079726875fd112ae23f20d3`.
- Backup sidecar verification passed at schema v13 and 15,872,000 bytes.
- Migration rehearsal reached schema v14 with `quick_check=ok` and unchanged baseline counts; the
  new `soc_cases` table started empty.
- Live migration reached schema v14 with `quick_check=ok`; 40 alerts, 3 incidents, 1 analyst, and 4
  notifications remained. Security events had naturally advanced to 3,675 during live ingestion.

Rollback remains restore-based: stop the backend, verify the named backup and metadata with the
supported backup CLI, preserve the current database, restore the selected backup with the supported
restore CLI, and run the matching schema-v13 application. No destructive rollback was performed.

## Implemented controls

1. Durable cases with explicit manual/alert/incident creation, strict state transitions, owner,
   priority, severity, resolution/closure fields, timestamps, optimistic concurrency, and related
   alerts/incidents/events.
2. Assignment, handoff comments, append-only collaboration and activity, per-owner case
   notifications, cursor pagination, literal search, filters, sorting, audit records, and deep links.
3. Reference-only evidence manifests with SHA-256 acquisition digests, source/acquisition metadata,
   immutable digest, verification state, and append-only custody history. No file-path ingestion.
4. Five deterministic playbooks with ordered steps, evidence requirements, administrator approval
   gates, progress/history, and no command execution or active response primitive.
5. Explicit `LOCAL_CASE_SLA_V1` targets, computed pending/met/overdue state, deduplicated owner
   escalation notifications, workload analytics, aging, MTTA/MTTR, and embedded definitions.
6. Bounded/redacted JSON, formula-safe CSV, and A4 PDF reports with no-store/nosniff headers,
   report digest/history, and security audit evidence.
7. A dedicated responsive Cases workspace with create/list/detail, filters, search, sort, cursor
   pagination, permission-aware controls, loading/empty/error states, copy actions, quick actions,
   keyboard navigation (`g` then `c`), confirmation before closure, and URL deep links.

## Security and reliability evidence

- Case mutations reuse session authentication, trusted-origin enforcement, CSRF validation, and
  `incident:write`; reads require `soc:read`.
- Viewer tests prove read access without mutation/export access.
- Stale `expected_version` tests return conflict rather than overwriting analyst work.
- Missing and duplicate related/evidence references fail atomically.
- Evidence verification tests detect a changed authoritative stored event and append `MISMATCH`.
- Playbook tests enforce sequence, evidence gates, and administrator approval.
- Report tests prove secret-assignment redaction, CSV formula neutralization, JSON/CSV/PDF media
  types, PDF signature, no-store headers, and report audit history.
- SLA evaluation tests prove per-owner notices are deduplicated.
- Schema migration tests pass on fresh and populated databases.

## Test results

- Backend full suite: 190/190 PASS; focused final v0.7 case plus migration suite: 19/19 PASS.
- Frontend full suite: 97/97 PASS.
- Frontend TypeScript plus production build: PASS. Output at validation time: JS 512.74 kB
  (129.39 kB gzip), CSS 42.62 kB (9.17 kB gzip). Vite reports the single JS chunk above 500 kB as
  a non-blocking optimization warning.
- PDF validation artifact: one-page A4, unencrypted, no JavaScript; visual inspection passed after
  correcting literal line-break markup. Secret-assignment text is visibly redacted.

## Pipeline health snapshot

- Backend `/health`: HTTP 200; `/readiness`: HTTP 200.
- Frontend listener: `127.0.0.1:5173`; backend listener: `127.0.0.1:8000`.
- Ubuntu WSL: Wazuh Manager, sender, event shipper, backend relay, and manager relay active.
- Kali WSL: Wazuh Agent, Nginx, agent relay, and bounded nftables telemetry unit active.
- Wazuh agent `001` (`cyberqalqon-test-web`): Active.
- Sender SQLite: `quick_check=ok`, queue 0, dead letters 0.
- Event shipper: archive inode matches, lag 0 bytes, state age approximately 3 seconds at snapshot.
- Windows Wazuh service: Running/Automatic. Its known stale enrollment configuration was not changed.

## Truthful limitations

- No legal-grade forensic custody certification is claimed.
- SLA targets are local operational definitions and are evaluated explicitly; no background scheduler
  or external paging integration is claimed.
- Safe playbooks document human work only; they do not block, isolate, scan, or execute commands.
- Case exports intentionally omit raw evidence and cap included collections.
- The frontend remains a single Vite chunk slightly above 500 kB; code-splitting is deferred.
- Wazuh API credentials remain unavailable, so API-derived inventory is not fabricated.
- Windows agent enrollment remains blocked by the previously documented missing supported key channel.
