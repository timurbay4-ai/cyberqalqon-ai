# M21 immutable forensic baseline

Date: 2026-10-20
Mode: read-only evidence capture
Outcome: **PASS WITH UNPROVEN HISTORICAL CONTINUITY**

No live state, cursor, archive, database row, service, firewall, schema, feature
gate, or Git history was changed. Large archives were hashed in place and were
not copied.

## Authoritative current state

The state file is
`/var/lib/cyberqalqon-sender/event-shipper-state.json`. Its file inode is
`33581562`; the source identity stored inside it is device/inode
`2096/33582396`. These values must not be confused.

| Field | Value |
|---|---:|
| State version | 3 |
| Legacy cursor | 93,438,552 |
| Stored source device/inode | 2096 / 33582396 |
| State SHA-256 | `ef11626503c7af1c9a1d605ca7cfaf6abb01acbe0101817c1f5df22656260dde` |
| Accepted after v3 accounting | 7,007 |
| Duplicate acknowledgements | 79 |
| Legacy mixed successful acknowledgements | 269 |
| Filtered / malformed | 9,820 / 8 |
| Protocol errors / delivery rejections | 0 / 0 |
| Last failure category | `retry` |

The process is `active/running`, but ingestion is operationally **FAIL-CLOSED**
because the active archive is device/inode `2096/33582586`.

## Archive inventory

All hashes below cover stored bytes. Gzip decoded-content hashes and sidecar
matches remain recorded in the M20 continuity manifest.

| Generation | Form | Stored bytes | Current file inode | Stored SHA-256 | Confidence |
|---|---|---:|---:|---|---|
| day 15 | gzip | 29,762,778 | 33581558 | `8c379d3e4352407f3a052f58301bfa910dbb311e778f2632bc9a36c93bfd1cb1` | PROVEN current content; Wazuh decoded sum PASS |
| day 16 | plain | 933,199,640 | 33582371 | `69500d816651dd382b7ba56bd79bff0a57814c8ce9b3383bd98ae7e12edf83d4` | PROVEN current content; no historical sidecar |
| day 17 | gzip | 31,528,939 | 33582598 | `7d57990225a5391e156240dd4fd6d87a0607b2ea0ed19fccba48918e047123c9` | PROVEN current content; Wazuh decoded sum PASS |
| day 18 | gzip | 39,304,254 | 33582692 | `c21601feb38ac8905e768187ecf3f27216c5eb7e56f7b5d1a36ba38810b244a2` | PROVEN current content; Wazuh decoded sum PASS |
| day 19 | plain | 163,373,056 | 33582589 | `920932131e089c7f7acd40a2de9e74186a70b6a09d69aad1f92ae03b4c8a972d` | PROVEN current content; no historical sidecar |

The active day-20 archive was still growing. Its exact captured prefix was
`0..688,001,817`, SHA-256
`bd3d1ea52d7ae7ca42943e9710fcec50fd2121f3fb0666eaf50126429f26ccab`,
on inode `33582586`. The prefix ends exactly on a newline at timestamp
`2026-10-20T16:32:01.560+0500`; the captured partial-tail length is zero. This
is a prefix binding, not a full-file checksum.

## Checkpoints, acknowledgements, and manifests

- 72 files under sender `state-backups`, `backups`, and
  `deployment-backups` were inventoried by exact path, metadata, mode, and
  SHA-256. The manifest contains hashes only, not secret contents.
- Sender database `/var/lib/cyberqalqon-sender/sender.db` was hashed read-only.
- The retained backend identity export still hashes to
  `5195987ccbab17cb00eca33e68bade00c049bdda1d1e4b7033d0d18f6d4984cf`.
- M20 manifest hashes were reverified and did not change.

## Live SQLite baseline

`backend/data/cyberqalqon-local-lab.db` was opened with SQLite `mode=ro` and
`query_only=ON`.

| Check | Result |
|---|---|
| Main DB SHA-256 | `07aa74354e3727bf1b0248ddeae8161285564d836c5235ac7e0665113528491b` |
| Main DB size | 2,014,007,296 bytes |
| WAL | present, 0 bytes, empty SHA-256 |
| `quick_check` | `ok` |
| Foreign-key errors | 0 |
| Schema | 17 |
| Events / alerts | 100,000 / 40 |

The main-file hash is valid because DB metadata remained stable and the WAL was
empty during capture. It is not a permanent history ledger.

## New payload-free evidence

| Artifact | SHA-256 |
|---|---|
| `artifacts/runtime/m21-forensic-baseline.json` | `2094fc9785a3975277bcd000a9226b1f8e1fc44c0e386d0a742cb9c5dacd4722` |
| `artifacts/runtime/m21-live-database-baseline.json` | `7f8624fe75d28767d61d9f67b477fddcb08a03548c688b8e5f2c1a0bce9e9ea6` |
| `artifacts/runtime/m21-active-snapshot-boundary.json` | `52d4ba8d5cdf2181fb82890867e5948587bd7ee433b3d906f1f8d225f20d9b1c` |

These hashes establish the bytes observed on 2026-10-20. They do not create a
signed historical chain of custody.
