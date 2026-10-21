# M22 operational continuity preflight

Decision: **PREFLIGHT PASS — RENEWAL REQUIRES EXPLICIT OPERATOR APPROVAL**.

Final live snapshot: 2026-10-20 20:46:29 +05:00. The existing approval was not
extended, its expiry check was not bypassed, and the service gate was not
changed. Historical continuity remains **UNPROVEN**; historical replay remains
**NOT_STARTED**.

## Live forward service and source generation

- `cyberqalqon-forward-ingestion.service` is `active/running`, PID 10901,
  restart count 0 and main status 0.
- Generation ID is
  `e58aa9c7b9fbb04204f21d181dc1e6bdc2603d345ed120b7790c2df4fcb7da3a`.
- Source is `/var/ossec/logs/archives/archives.json`, device/inode
  `2096/33582586`. The observed size was `1,072,223,919` bytes.
- The source generation is unchanged. No automatic rebind or new start
  boundary was selected.
- The 20:46:29 +05:00 durable checkpoint snapshot was cursor `736,007,869`,
  byte lag `336,216,050`, and SHA-256
  `5104bde390d6f0a7db7f12c238308d4270027ba209ca96478509a378e345d620`.
  This SHA is a point-in-time value and changes after acknowledged progress.
- At that snapshot the counters were 4,807 unique insertions, zero duplicate
  acknowledgements, 4,213 filtered, and zero malformed, retry, protocol-error
  or delivery-rejection records.
- The durable JSON reports `PAUSED` between completed batches while systemd
  remains `active/running`; it is not terminal-blocked and progress continued.

## Approval expiry

The root-controlled active manifest SHA-256 is
`aea08b828c8e9314516411502baf2c4f3aa37a71a6e8985fa16d7299557126f7`.
It expires at epoch `1792523864.7977576`, or 2026-10-21 00:17:44 +05:00.
At system epoch `1792511046.6731052` (2026-10-20 20:44:06 +05:00),
`12,818.125` seconds remained, approximately 3 hours 33 minutes 38 seconds.

The service validates the manifest before every batch. At expiry it will fail
closed before another batch, retain the last acknowledged durable cursor and
write a payload-free blocked/stop audit entry. Systemd may make its bounded
restart attempts, but an expired manifest cannot pass validation. The static
unit is not boot-enabled. Expiry does not authorize a skip, reset, rebind or
historical replay.

A read-only check through the same non-deep per-batch validation path returned
`APPROVED` for the exact generation/source/boundary and unchanged manifest.
An additional external deep check raced with an active atomic checkpoint write
and correctly failed closed with `state changed during validation`; the stable
immutable backup then passed deep prefix and record-chain validation using the
service venv. No gate was bypassed.

## Legacy checkpoint preservation

- Legacy cursor: `93,438,552`, unchanged.
- Legacy state SHA-256:
  `ef11626503c7af1c9a1d605ca7cfaf6abb01acbe0101817c1f5df22656260dde`,
  unchanged.
- The independent forward checkpoint did not write to the legacy state.

## Health and integrity

| Check | Result |
|---|---:|
| Backend `127.0.0.1:8000` | HTTP 200 |
| Frontend `127.0.0.1:5173` | HTTP 200 |
| Windows scoped gateway/portproxy `172.19.240.1:16000` | HTTP 200 |
| WSL to gateway relay | HTTP 200 |
| SQLite schema | 17 |
| SQLite `quick_check` | `ok` |
| SQLite foreign-key violations | 0 |
| Retained events | 100,000 |
| Database / WAL | 2,015,412,224 / 144,245,352 bytes |

The full read-only SQLite integrity pass took 147,047.255 ms. The retention
limit remains 100,000. No synthetic live event was inserted.

The fresh passive validator at
`artifacts/runtime/m22-continuity-passive-validation.json` reports 11 PASS,
one WARNING, one FAIL and one DEFERRED_BY_USER. Overall remains FAIL; the
failure is the known legacy archive-inode mismatch and was not hidden. The
warning is retention at its configured cap. Release safety gates passed:
schema 17, schema-18 disabled, `AI_ENABLED=false`, and DET-001 through DET-009
remain `DISABLED_BY_POLICY/SHADOW_ONLY`.

## Verified forward-checkpoint backup

A service-safe stable read produced a protected root-only checkpoint copy. Its
exact runtime path is excluded from source control.

- Cursor: `723,769,421`.
- SHA-256:
  `36966cc9869783e1ab23ea8c05295fd87572a234b61b1ecfc6ce8a776cbb97bb`.
- Counters: 6,739 records; 3,605 unique; zero duplicate; 3,134 filtered.
- Deep prefix and record-chain validation: PASS.
- Binding to the unchanged legacy state: PASS.
- Ownership/mode: `root:root`, `0400`; Linux immutable attribute set.

The backup is a verified recovery/audit checkpoint. It is not a replacement
instruction for an evolved live checkpoint and must never be restored blindly
after later acknowledgements.

## Fresh backlog trend

Five bounded samples over approximately 50.5 seconds produced:

| Metric | Average |
|---|---:|
| Archive growth | 36,937.261 B/s |
| Forward cursor progress | 15,462.386 B/s |
| Net backlog change | **+21,474.876 B/s** |

Lag increased from `330,433,555` to `331,534,909` bytes. All five intervals
kept the service active with zero restarts, retries, protocol errors, delivery
rejections and malformed records; gateway and relay probes were HTTP 200.
Unlike the earlier post-deployment draining window, this short continuity
window shows backlog growth. That is an operational risk, not permission to
raise the rate or enable batch ingestion.

## Renewal proposal and safe-stop gate

The non-active proposal is
`artifacts/runtime/m22-forward-renewal-proposal.json`. It is bound to the same
generation, source device/inode, start boundary/prefix, verified checkpoint
backup, legacy cursor/SHA and single-event-only policy. It proposes a four-hour
extension of the existing deadline, through 2026-10-21 04:17:44 +05:00.
The proposal SHA-256 is
`455b2d3a8f8c0c9c28374c72ab5c41b2dab8f29e41047bcb40edbf4c0ac114d1`.

Activation requires a separate explicit operator approval. Once approved,
the controlled activation needs approximately 5–10 minutes. Approval should
arrive at least 30 minutes before the current 00:17:44 deadline so there is
time to recheck the source identity, deep-validate the evolved checkpoint,
confirm the legacy state, atomically install the root-controlled manifest and
observe multiple successful batches.

Safe-stop conditions include: expiry or manifest mismatch; source/generation
change; legacy-state change; checkpoint/prefix/chain validation failure;
cursor regression; retry/protocol/rejection errors; repeated backend or relay
failure; SQLite integrity/busy pressure; resource floors; or any unapproved
archive rotation. The proposal has status
`PENDING_EXPLICIT_OPERATOR_APPROVAL`, `accepts_unproven_history=false`, and
was not copied to `/etc/cyberqalqon`.

## Restrictions preserved

No legacy reset/rebind, historical replay, schema migration, batch activation,
retention change, AI/detection activation, browser UAT, firewall/portproxy
change, archive deletion, Git commit or push was performed.
