# M22 runtime baseline

Captured 2026-10-20. This baseline is read-only with respect to live services,
archives, cursors, SQLite rows, schema, firewall, and portproxy.

## Runtime

| Item | Evidence | Result |
|---|---|---|
| Backend | `http://127.0.0.1:8000/health` | HTTP 200 |
| Frontend | `http://127.0.0.1:5173/` | HTTP 200 |
| WSL gateway | `http://172.19.240.1:16000/health` | HTTP 200 |
| WSL relay | `http://127.0.0.1:18000/health` | HTTP 200 |
| Wazuh Manager / sender / legacy shipper | systemd | active / active / active |
| Forward shipper | systemd | inactive; unit not installed |
| Forward approval | `/etc/cyberqalqon/forward-approval.json` | absent |
| Live forward state root | `/var/lib/cyberqalqon-forward` | absent |

The legacy shipper process is active but fail-closed. Its active inode does not
match its durable cursor identity, and its journal records repeated batch
failures. “active” is not reported as healthy ingestion.

## Archive and legacy checkpoint

| Field | Value |
|---|---:|
| Active source | `/var/ossec/logs/archives/archives.json` |
| Device / inode | `2096 / 33582586` |
| Size at staged checkpoint registration | `888,786,144` bytes |
| Legacy stored device / inode | `2096 / 33582396` |
| Legacy cursor | `93,438,552` |
| Legacy state SHA-256 | `ef11626503c7af1c9a1d605ca7cfaf6abb01acbe0101817c1f5df22656260dde` |
| Historical continuity | **UNPROVEN** |

The active file is append-only during observations; later sizes are expected to
be larger. Identity and the verified start prefix, not a mutable full-file hash,
bind the proposed forward generation.

## SQLite and resource headroom

- Live DB: schema 17, 100,000 events, 2,014,007,296 bytes, WAL 0 bytes.
- Read-only `quick_check`: `ok`; `foreign_key_check`: 0 errors.
- Windows C: free space: 172,372,258,816 bytes.
- Host free RAM sample: 581,580 KiB of 8,020,492 KiB: **WARNING**.
- Retention is already at the 100,000-row limit; new inserts can evict the
  oldest unprotected events.

## Safety state

- `AI_ENABLED=false`.
- DET-001–DET-009 remain `DISABLED_BY_POLICY / SHADOW_ONLY`.
- Batch protocol and adaptive batching are not enabled for forward ingestion.
- Schema 18 was not applied; historical replay was not started.
- Chrome/Edge UAT remains `DEFERRED_BY_USER`.
- Git branch `main`, HEAD `f6a59a923cc58cb768c1e4dd748bb529e5c01a43`;
  the pre-existing dirty tree is preserved and no commit/push was made.
