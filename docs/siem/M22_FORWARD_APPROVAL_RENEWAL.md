# M22 forward-ingestion approval renewal

Decision: **RENEWAL PASS — SERVICE RUNNING**.

Final snapshot: 2026-10-20 20:59:43 +05:00. Historical continuity remains
**UNPROVEN** and historical replay remains **NOT_STARTED**.

## Expiry and manifest

The previous manifest was still valid when renewal began. Its deadline was
2026-10-21 00:17:44 +05:00 and SHA-256 was
`aea08b828c8e9314516411502baf2c4f3aa37a71a6e8985fa16d7299557126f7`.

The renewal was issued at epoch `1792511674.1444283` and has the exact approved
deadline 2026-10-21 04:17:44 +05:00 (`1792538264.7977576`). New manifest
SHA-256:

`e521d7dff23df5029fb55d5f3201667edd372eaffcf0d29762a09e5fa219abb8`

The manifest was written through a same-directory temporary file, fsynced,
atomically replaced and followed by a directory fsync. It is owned by
`root:wazuh`, mode `0640`. Runtime validation returned `APPROVED`. No automatic
or indefinite renewal mechanism was installed.

The previous manifest was preserved, mode `0400`, root-owned and immutable in
the protected M22 renewal backup directory. Its exact runtime path is excluded
from source control.

## Generation and checkpoint integrity

- Generation:
  `e58aa9c7b9fbb04204f21d181dc1e6bdc2603d345ed120b7790c2df4fcb7da3a`.
- Source device/inode: `2096/33582586`; rotation was not detected.
- Start boundary: `688001817`; prefix SHA-256 remained
  `bd3d1ea52d7ae7ca42943e9710fcec50fd2121f3fb0666eaf50126429f26ccab`.
- Initial renewal-preflight cursor/SHA: `741423806` /
  `47ac510ab60268d54bdb2eadf84c8e28a10aa92276a9ecd709667f3a1625bda0`.
- Authoritative activation checkpoint cursor/SHA: `745144297` /
  `625c569d2fdfe17396479db868a20de366c8dbf43fdde90e1f4008148b36a628`.
- Final live cursor/SHA: `749699565` /
  `106050c01d6c5ebd0ecea542cfe00b0331f23b2b357e4d5fee220ae63f276b09`.

The cursor was never reset to `736007869` and did not regress. Deep prefix and
record-chain validation passed for the authoritative checkpoint. Its immutable
copy remains in the protected root-only M22 renewal backup directory.

## Legacy state

Legacy cursor remained `93438552`. Legacy SHA-256 remained
`ef11626503c7af1c9a1d605ca7cfaf6abb01acbe0101817c1f5df22656260dde`.
No legacy mutation, reset or rebind occurred.

## Service and post-renewal observation

The service stayed `active/running` on PID 10901 with restart count 0. Renewal
did not restart it. The durable state can report `PAUSED` between completed
batches while systemd remains active; it was not terminal-blocked.

Five monitoring samples over 48.914 seconds showed:

| Metric | Result |
|---|---:|
| Cursor | `746101746 → 746895940` |
| Cursor delta | `+794194` bytes |
| Unique insertions | `5737 → 5817` (`+80`) |
| Duplicate acknowledgements | 0 |
| Retry / protocol / rejection / malformed | `0 / 0 / 0 / 0` |
| Archive growth average | 21,703.234 B/s |
| Cursor progress average | 16,237.530 B/s |
| Net backlog average | **+5,465.704 B/s** |
| Byte lag | `339507787 → 339775047` |
| Gateway probes | 25/25 HTTP 200 |
| Relay probes | 25/25 HTTP 200 |

Backlog growth was substantially lower than the pre-renewal continuity window
of approximately +21,475 B/s, but it was still positive. Renewal does not
change throughput settings, so this difference is observational rather than a
causal performance claim. No batch activation or rate increase was made.

## Application and database health

- Backend, frontend, scoped Windows gateway/portproxy and WSL relay: HTTP 200.
- SQLite schema: 17; `quick_check=ok`; foreign-key violations: 0.
- Retained events: 100,000; retention limit remained 100,000.
- WAL observed during the monitoring window: 144,245,352 bytes.

The post-renewal passive validator at
`artifacts/runtime/m22-renewal-post-passive-validation.json` reports 11 PASS,
one WARNING, one FAIL and one DEFERRED_BY_USER. Overall remains FAIL only
because the known legacy archive-inode mismatch remains unresolved. The
warning is retention at the configured cap. Browser UAT remains deferred.
Release gates passed: schema-18 disabled, `AI_ENABLED=false`, and DET-001
through DET-009 remain `DISABLED_BY_POLICY/SHADOW_ONLY`.

## Restrictions preserved

No historical replay, legacy reset/rebind, schema migration, archive deletion,
batch-10/25 activation, retention change, detection/AI activation, browser UAT,
firewall/portproxy change, Git commit or push was performed. The service was
left running under the new finite approval deadline.
