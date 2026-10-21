# M21 validation

Date: 2026-10-20
Live recovery: **NOT EXECUTED**
Browser UAT: **DEFERRED_BY_USER**

## Automated results

| Suite | Result |
|---|---|
| Backend full regression | 279/279 PASS; one dependency deprecation warning |
| Wazuh sender/shipper/recovery/state/M21 | 187/187 PASS |
| M21 focused continuity and forward state | 24/24 PASS (included in 187) |
| Frontend full regression, conservative one-worker rerun | 118/118 PASS |
| Frontend `App.test.tsx` isolation | 11/11 PASS |
| TypeScript `tsc --noEmit` | PASS |
| Production Vite build | PASS, 65 modules transformed |
| Deployment/validator tests | 24/24 PASS; one dependency deprecation warning |
| M20 forensic disposable self-test | PASS |
| `git diff --check` | PASS; line-ending warnings only |

The first default-pool frontend run completed 107 tests but Vitest reported one
fork-worker startup timeout. It was not hidden. The affected file passed 11/11
alone, and the complete conservative rerun passed 118/118 with no unhandled
error.

M21 disposable coverage includes matching-prefix/mismatching-suffix, missing
inode, plain-to-gzip rotation, valid/invalid boundaries, equal ledger/different
payload, timestamp gaps, duplicates, retention eviction, exact/probable/unknown
fingerprints, 305 NUL bytes, truncated JSON, invalid UTF-8, unavailable source,
interrupted scan, independent restart, identity mismatch, backend retry,
duplicate acknowledgement, lost response after commit, immutable legacy state,
same filename/different generation and atomic-save crash.

## Live read-only checks

- Backend `127.0.0.1:8000/health`: HTTP 200.
- Frontend `127.0.0.1:5173/` and `/health`: HTTP 200.
- WSL relay `127.0.0.1:18000/health`: HTTP 200.
- SQLite: schema 17, quick check `ok`, foreign-key errors 0, events 100,000,
  alerts 40, WAL 0 bytes.
- Passive validator: 14 checks — 11 PASS, 1 WARNING, 1 FAIL,
  1 DEFERRED_BY_USER; overall FAIL.

The validator FAIL is intentionally retained: `event_shipper_cursor` reports
legacy cursor `93,438,552`, active archive identity mismatch and increasing
generation-separated bytes. `retention_capacity` is WARNING because the store
is at 100,000/100,000. All other pipeline checks, including portproxy/relay,
manager/agent, queue and release safety gates, passed.

## Safety verification

- Legacy state hash and cursor remained unchanged.
- Schema 18 was not applied; retention remained 100,000.
- Historical replay and forward live ingestion were not started.
- Batch ingestion remained disabled.
- `AI_ENABLED=false`; DET-001–DET-009 remained
  `DISABLED_BY_POLICY / SHADOW_ONLY`.
- No Chrome/Edge UAT, firewall/portproxy change, commit or push occurred.

Final M21 engineering outcome: **PASS** for source implementation and offline
validation; **UNPROVEN** for exact historical continuity; **BLOCKED** at the
live forward-ingestion approval gate.
