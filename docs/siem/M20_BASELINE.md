# M20 authoritative baseline

Captured: 2026-10-20. Status: **FAIL for current live ingestion / PASS for
data preservation**.

## Repository and runtime

- Branch `main`, HEAD `f6a59a923cc58cb768c1e4dd748bb529e5c01a43`.
- The pre-existing dirty tree was preserved; 202 paths are currently modified
  or untracked. No commit, push, reset, clean or rebase was run.
- The M19/M20 source exists on disk, but no Windows Uvicorn process is running.
  Therefore no claim is made that the optimized source is live.
- Windows listeners `127.0.0.1:8000` and `127.0.0.1:5173` are absent. Direct
  backend, readiness and frontend requests are refused.
- The WSL relay and event shipper systemd units are active with one process
  each. The installed shipper source SHA-256 is
  `07375518fba0a1ebbb2cd5b4122625b8a200d9494a64ec8a0931c27f58648023`.
  Batch protocol/adaptive variables are absent, so the deployed protocol is
  single-event; `current_batch_size=25` is the local read bound, not a network
  batch activation.

## Durable shipper and archive state

| Field | Value |
|---|---:|
| State version | 3 |
| Durable cursor | 93,438,552 |
| State device/inode | 2096 / 33582396 |
| Current archive device/inode | 2096 / 33582586 |
| Accepted | 7,007 |
| Duplicate acknowledgements | 79 |
| Filtered | 9,820 |
| Malformed JSON | 8 |
| Retry attempts | 592 |
| Protocol errors | 0 |
| Consecutive retries | 409 |
| Last success | 2026-10-15T07:11:43.423192Z |
| State SHA-256 | `ef11626503c7af1c9a1d605ca7cfaf6abb01acbe0101817c1f5df22656260dde` |

The archive rotated while the state still names the old inode. The shipper is
fail-closed with repeated `ArchiveCursorStateError`; it did not reset or
silently skip the old generation. The old inode is no longer present as an
uncompressed file in the archive tree. Rotated gzip evidence exists, but
reconciliation/replay was not started because historical replay is prohibited.

Three ten-second windows measured current-file growth at 26,809.50,
22,383.56 and 22,382.55 bytes/s while cursor progress remained 0 bytes/s.
Total eligible backlog is **UNKNOWN**: subtracting an old-generation cursor
from the current generation size would be invalid.

## Network and service path

- Portproxy remains `172.19.240.1:16000 -> 127.0.0.1:8000`.
- Current WSL source IP is `172.19.254.115`; gateway is `172.19.240.1`.
- The Hyper-V rule is scoped to those two IPs and TCP 16000 and reports
  `EnforcementStatus=OK`.
- The host firewall rule retains the same IP/port scope but is bound to stale
  interface GUID `{739FB153-C045-408A-989C-4E33D30A5A97}`. The current adapter
  GUID is `{A1126C45-79ED-4355-A7D7-C18E73BA0CB0}` and the rule reports
  `EnforcementStatus=NotApplicable`.
- WSL relay TCP accept is fast (0.46-2.53 ms), while WSL-to-gateway TCP and both
  gateway/relay HTTP probes timed out at about 2 seconds.

No firewall, Hyper-V or portproxy setting was changed.

## SQLite and host resources

- Live database: `backend/data/cyberqalqon-local-lab.db`.
- Size 2,014,007,296 bytes; WAL 28,263,232 bytes at baseline.
- Schema 17; 100,000 security events; 40 alerts; 3 incidents.
- `quick_check=ok` in 39.593 seconds; foreign-key errors 0.
- Retention remains 30 days / 100,000 rows. Latest bounded audit reports zero
  protected records; no exact global evidence scan was introduced.
- Free disk was 175,291,797,504 bytes. Free host RAM was approximately 892 MiB
  of 7.65 GiB, so memory headroom is a warning, not a proven timeout cause.
- Relay memory was about 2.4 MiB and shipper memory about 16.7 MiB; neither
  showed a restart loop.

## Safety state

Schema 18 was not applied, historical replay was not started, retention was
not changed, DET-001 through DET-009 remain
`DISABLED_BY_POLICY / SHADOW_ONLY`, and `AI_ENABLED=false`. Browser UAT is
`DEFERRED_BY_USER`.
