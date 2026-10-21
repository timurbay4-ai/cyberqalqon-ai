# M20 scoped firewall repair

Date: 2026-10-20
Decision: **FIREWALL REPAIR PASS / SERVICE RESTORE BLOCKED BY SEPARATE GATES**

## Authorized change

Only `CyberQalqon-M15-WSL-Relay-TCP16000-Host` was changed. Its stale
interface filter resolved from `{739FB153-C045-408A-989C-4E33D30A5A97}` to
the current `vEthernet (WSL (Hyper-V firewall))` adapter, GUID
`{A1126C45-79ED-4355-A7D7-C18E73BA0CB0}`.

The rule remains enabled, inbound, allow, profile `Any`, TCP 16000, local
address `172.19.240.1`, and remote address `172.19.254.115`. Portproxy remains
`172.19.240.1:16000 -> 127.0.0.1:8000`. The Hyper-V rule remains enabled and
scoped to the same IPs and port. All three Windows Firewall profiles remain
enabled. No new allow rule was created and neither portproxy nor Hyper-V
firewall was changed.

The host rule still reports `EnforcementStatus=NotApplicable`; this field is
not hidden. Functional evidence is authoritative for this repair: the
pre-change WSL gateway TCP probe timed out at about 2,004 ms, while the
post-change probe connected in about 5.2 ms. The elevated repair also used an
isolated one-connection loopback listener and proved the complete
WSL-to-portproxy-to-loopback TCP path before reporting success.

## Backup and integrity

- Backup directory:
  `C:\ProgramData\CyberQalqon\backups\m20-firewall-interface-20261020T084032Z`
- Manifest:
  `C:\ProgramData\CyberQalqon\backups\m20-firewall-interface-20261020T084032Z\sha256-manifest.json`
- Manifest SHA-256:
  `e3780feb0ce4697d936b9950397a4b523d2b582afbf311b709d124000902f450`
- ACL inheritance: disabled; the recorded SDDL matches the live backup ACL.
- Rule, port, address, interface, Hyper-V, portproxy, ACL and preflight files:
  all hashes revalidated after the repair.
- Machine-readable result:
  `artifacts/runtime/m20-host-firewall-interface-result.json`, SHA-256
  `236d0d64cd3c4da9ad69139402b48170b19734cd15068708f133e8f7501e8b6e`.

## Connectivity and service state

| Check | Before | After |
|---|---|---|
| Windows to portproxy TCP 16000 | PASS | PASS, about 5.4 ms |
| WSL to gateway TCP 16000 | FAIL, timeout | PASS, about 5.2 ms |
| WSL local relay TCP 18000 | PASS | PASS, about 0.7 ms |
| Windows backend `127.0.0.1:8000` | absent | absent |
| Frontend `127.0.0.1:5173` | absent | absent |
| Gateway and relay HTTP health | timeout | timeout: upstream backend absent |

The current working tree contains the M19/M20 optimized backend source. No
exact pre-M19 process/source snapshot exists in the searched backups or
runtime artifacts. Starting the current source would therefore be the
explicitly excluded optimized backend rollout. The backend was not started.
The reviewed frontend starter refuses to start unless backend health is HTTP
200, so the frontend was also left stopped. This preserves the approval
boundary and does not misrepresent TCP repair as application health.

## Archive generation and cursor safety

- Shipper state version: 3.
- Cursor: `93,438,552`, unchanged.
- State device/inode: `2096 / 33582396`, unchanged.
- State SHA-256:
  `ef11626503c7af1c9a1d605ca7cfaf6abb01acbe0101817c1f5df22656260dde`,
  unchanged.
- Active archive device/inode: `2096 / 33582586`.
- Shipper service: active but fail-closed with `ArchiveCursorStateError`.
- Counters remain accepted 7,007, duplicate acknowledgements 79, filtered
  9,820, malformed 8, retries 592 and protocol errors 0.

The rotation occurred at midnight on 2026-10-16 local time: the last record in
`ossec-archive-15.json.gz` is timestamped at that boundary, and the first
`ArchiveCursorStateError` followed at 00:00:05. The gzip passes CRC/size
validation and has SHA-256
`8c379d3e4352407f3a052f58301bfa910dbb311e778f2632bc9a36c93bfd1cb1`.
It expands to 1,167,573,927 bytes. The preserved cursor is exactly on a newline
boundary, the next record is valid JSON, and 1,074,135,375 bytes remain after
the cursor.

Compression replaced the original filesystem inode, so a cryptographic inode
link from `33582396` to the gzip cannot be proven from retained metadata alone.
The date/timestamp and cursor evidence make it the corresponding generation
with high confidence, but not enough to authorize cursor reassignment or
replay. No state, cursor, archive or service configuration was changed or
restarted. Safe recovery therefore remains a separate approval gate.

## Passive validator

Artifact: `artifacts/lab-validation/m20-scoped-firewall-repair.json`
SHA-256: `9f7da153bfa66bec83aca0bc993498848c7336668d183f9efb1552f04630bf80`

- 8 PASS, 1 WARNING, 4 FAIL, 1 DEFERRED_BY_USER.
- PASS: WSL portproxy, manager/Kali services, agent enrollment, sender queue,
  archive malformed audit, database integrity and release safety gates.
- WARNING: retention is at the unchanged 100,000-event cap.
- FAIL: backend health, frontend proxy health, relay HTTP health, and the
  intentional archive identity fail-closed condition.
- Database: `quick_check=ok`, foreign-key violations 0, schema 17, 100,000
  events, 40 alerts.
- Schema 18 remains blocked, retention remains unchanged, `AI_ENABLED=false`,
  and DET-001 through DET-009 remain `DISABLED_BY_POLICY / SHADOW_ONLY`.
- Browser UAT remains `DEFERRED_BY_USER`.

No historical replay, batch canary, optimized backend deployment, cursor
reset, archive deletion, Git commit or Git push was performed.
