# M20 rotation recovery readiness

Date: 2026-10-20
Scope: read-only production forensics and isolated disposable recovery validation
Decision: **BLOCKED_RECOVERY_NOT_PROVEN**

No production shipper restart, live replay, cursor edit, archive edit, database
write, backend/frontend restart, schema migration, browser UAT, commit or push was
performed.

## 1. Root cause and supporting evidence

The durable v3 shipper state still identifies device/inode `2096/33582396` at
offset `93,438,552`. At the 2026-10-16 day boundary Wazuh changed
`archives.json` to a new inode. The shipper detected the identity mismatch at
00:00:05 local time and has refused to read since then.

This is a new-inode daily rotation, followed by gzip replacement, not
copy-truncate:

- The current `archives.json` and dated day-20 JSON are two hard links to inode
  `33582586` (`st_nlink=2`).
- State was last persisted at 23:59:05 on day 15; the first
  `ArchiveCursorStateError` occurred at 00:00:05 on day 16.
- `ossec-archive-15.json.gz` was created at 00:00:17 and completed at 00:00:35.
- Old inode `33582396` no longer identifies archive evidence. It was reused at
  00:00:48 for `ossec-alerts-15.json.sum`.
- The systemd process is technically `active/running`, with zero systemd
  restarts, but it is operationally fail-closed and logs
  `ArchiveCursorStateError` every two seconds. It has not advanced the cursor.

## 2. Previous archive generation found

**YES, as a content-validated candidate; original inode ancestry is UNKNOWN.**

Candidate:
`/var/ossec/logs/archives/2026/Oct/ossec-archive-15.json.gz`

| Property | Result |
|---|---:|
| Compressed size | 29,762,778 bytes |
| Compressed SHA-256 | `8c379d3e4352407f3a052f58301bfa910dbb311e778f2632bc9a36c93bfd1cb1` |
| Uncompressed size | 1,167,573,927 bytes |
| Uncompressed SHA-256 | `6a1f029362bd2a12cfd2ff4f7a1020e220e68ea09e9f4ad6588f4d2b28ac05b7` |
| Wazuh `.sum` SHA-256 match | PASS |
| Gzip CRC/stream validation | PASS |
| JSON lines | 210,128 |

The Wazuh checksum sidecar cryptographically verifies the candidate's
uncompressed content. It does not bind that content to the state inode
`33582396`, because the original uncompressed inode was removed and has since
been reused.

## 3. Cursor continuity

**UNPROVEN.**

Inside the candidate, offset `93,438,552` is exactly after a newline. The
preceding line is valid JSON, and the record starting at that offset is valid
JSON with line SHA-256
`7303d2b606950b0bd9ff9fb1fd1c4e2b0fb891b3e1e06191f4b8cf89fbd09d72`.
There are `1,074,135,375` uncompressed bytes after the cursor.

Existing backups establish a monotonic state lineage on inode `33582396`:

`3,258,960 -> 36,366,272 -> 42,723,427 -> 44,749,863 -> 93,438,552`.

They do not contain a prefix/content hash that binds inode `33582396` to the
candidate gzip. A matching day, timestamp, size range and valid record boundary
are high-confidence circumstantial evidence, not positive identity proof.

## 4. Actual production data continuity

**UNPROVEN.**

All date-named archive files from day 15 through day 20 are present, but the
recovery chain is larger than only the day-15 tail:

| Day | Form | Integrity evidence | Important observation |
|---|---|---|---|
| 15 | gzip | gzip PASS; Wazuh SHA-256 match | Cursor candidate; inode ancestry unproven |
| 16 | JSON | bounded SHA-256 captured | No Wazuh checksum sidecar |
| 17 | gzip | gzip/Wazuh SHA-256 match | Starts at 10:27 after day-16 ended 23:31 |
| 18 | gzip | gzip/Wazuh SHA-256 match | Valid stream |
| 19 | JSON | bounded SHA-256 captured | Ends with a 305-byte non-newline partial record |
| 20 | active JSON | live device/inode `2096/33582586` | Continues growing |

No date filename is missing in this range, but timestamp gaps and the partial
day-19 tail mean source telemetry continuity cannot be asserted. The original
day-15 inode-to-content link is also absent.

## 5. Disposable recovery validation

The isolated test uses only temporary files and a fake delivery client. It
simulates a gzip rotated generation, starts from a verified newline checkpoint,
pauses, restarts, and completes without redelivering the acknowledged prefix.

Validated behavior:

- immutable generation registration and mutation detection;
- resume from a verified checkpoint;
- missing-generation failure;
- truncated gzip failure without checkpoint creation;
- corrupt JSON checkpoint failure;
- negative, beyond-EOF and mid-record checkpoint failure;
- restart/idempotency and completed-state stability;
- accepted versus duplicate acknowledgement accounting;
- retry/protocol/permanent-rejection no-advance behavior;
- filtered, malformed, oversized and partial record handling;
- same-size/same-mtime content mutation detection before delivery.

Results:

- Focused recovery/state/shipper suite: **59/59 PASS**.
- Full Wazuh sender suite: **163/163 PASS**.
- Deployment recovery test: **1/1 PASS**.

These results prove the local recovery algorithm against controlled evidence.
They do not prove that the production candidate is the file formerly named by
inode `33582396`.

## 6. Regression and production invariants

- Backend: **279/279 PASS**; one dependency deprecation warning.
- Live SQLite: schema 17, `quick_check=ok`, foreign-key errors 0.
- Counts remained 100,000 events, 40 alerts, 3 analyst sessions and 99 audit
  events. No synthetic production event was written.
- Backend, frontend, relay and portproxy health: PASS.
- Passive validator: 11 PASS, 1 WARNING, 1 FAIL, 1 DEFERRED_BY_USER. The sole
  FAIL is the unchanged archive identity mismatch; the warning is the unchanged
  100,000-row retention cap.
- Production cursor remains `93,438,552`; state SHA-256 remains
  `ef11626503c7af1c9a1d605ca7cfaf6abb01acbe0101817c1f5df22656260dde`.
- Schema 18 remains blocked; single-event ingestion remains enabled; batch
  ingestion remains disabled; `AI_ENABLED=false`; DET-001 through DET-009
  remain `DISABLED_BY_POLICY / SHADOW_ONLY`.

## 7. Duplicate and loss risks

- Starting at `93,438,552` on a wrongly identified generation could skip or
  duplicate an unbounded region.
- Replaying day 15 from byte zero avoids that specific skip risk but repeats an
  acknowledged prefix. Because retention is capped, old idempotency rows may no
  longer exist; replay could reinsert historical events and evict other data.
- Recovering only day 15 would skip days 16 through 19.
- The day-19 partial tail cannot be treated as a successfully delivered event
  and may represent source-level loss.
- A rotation during catch-up could create another unregistered generation.
- The current CLI can register/replay a generation, but it has no
  operator-gated command to import the live checkpoint provenance or perform a
  final active-generation cutover safely.

## 8. Code changes

Local source only; nothing was installed or deployed:

- `archive_recovery.py` now verifies the registered digest before each replay
  batch and refuses negative, beyond-EOF, mid-record and inconsistent COMPLETE
  checkpoints.
- `test_archive_recovery.py` adds disposable rotated-generation resume,
  restart/idempotency, corrupt-offset and same-identity mutation tests.

The local `archive_recovery.py` SHA-256 is
`d1485c194be7c82c8d4c66af6e4b1f448bd816cc2d2c07e6818cdc64b3087592`.
The installed production module remains a different, unchanged build with
SHA-256
`bfde6949dbc52f132d23a4a25d960aebf185f4d50e89be645f029f8c538b620c`.

## 9. Exact remaining blockers

1. No cryptographic/provenance link binds stored inode `33582396` to the
   candidate day-15 gzip.
2. Day-16 and day-19 uncompressed generations lack Wazuh checksum sidecars.
3. Day-19 ends with a partial record, and observed timestamp gaps prevent a
   claim of complete source telemetry.
4. Recovery must process the day-15 tail and every later immutable generation
   in order before active day-20 cutover.
5. No reviewed, operator-gated checkpoint-import and active-cutover mechanism
   exists in the current CLI.
6. The fail-closed service process remains active and noisy; stopping it is a
   live operation prohibited by this investigation.

## 10. Proposed live recovery steps requiring separate approval

1. Keep replay and cursor changes blocked until either immutable backup/snapshot
   evidence positively binds inode `33582396` to the day-15 content, or the
   operator explicitly accepts the residual provenance risk.
2. Review and test an operator-gated checkpoint-import/cutover command. It must
   record source-state SHA-256, old device/inode, generation digest, newline
   boundary and imported offset without modifying the active cursor.
3. On separate approval, gracefully stop only the fail-closed shipper and take
   new immutable checksummed copies of state and generations 15 through 20.
4. Register but do not deliver each immutable generation. Verify all digests,
   ordering, first/last records and the day-19 partial-tail audit.
5. If provenance is proven, initialize day 15 at offset `93,438,552`, then use
   separately approved bounded replay for the day-15 tail and days 16 through
   19 in order. Never count malformed/partial records as delivered.
6. Freeze/snapshot the active day-20 boundary, finish historical catch-up, and
   perform an atomic active-generation cutover that cannot skip concurrent
   writes or restore an older acknowledgement.
7. Monitor insert/duplicate/retry/rejection, retention impact, database
   integrity and cursor monotonicity. Pause without advancement on any failure.

Final decision: **BLOCKED_RECOVERY_NOT_PROVEN**
