# M20 rotated-generation recovery gate

Status: **PREPARED, NOT EXECUTED**.

The optimized backend and frontend are healthy. The remaining ingestion
blocker is independent: event-shipper state names inode `33582396` at cursor
`93,438,552`, while the active archive is inode `33582586`. The worker remains
active but fail-closed with `ArchiveCursorStateError`.

## Preserved old generation

- Candidate generation:
  `/var/ossec/logs/archives/2026/Oct/ossec-archive-15.json.gz`.
- Compressed SHA-256:
  `8c379d3e4352407f3a052f58301bfa910dbb311e778f2632bc9a36c93bfd1cb1`.
- Compressed size: 29,762,778 bytes.
- Validated uncompressed size: 1,167,573,927 bytes.
- Gzip CRC/size validation: PASS.
- Cursor is exactly on a newline boundary; the next record is valid JSON.
- Preserved bytes after the cursor: 1,074,135,375.
- Timeline linkage: the generation ends at 2026-10-16 00:00 local time and
  the first `ArchiveCursorStateError` follows at 00:00:05.

Compression replaced the original filesystem inode, so the retained evidence
does not cryptographically prove that gzip inode ancestry equals state inode
`33582396`. Date, boundary and timeline evidence provide high confidence, but
not enough to rewrite the live state automatically.

## Required separate recovery operation

1. Keep current backend/frontend and relay health stable.
2. Stop only the event shipper gracefully and capture a new final state
   checksum/cursor backup.
3. Take an immutable, checksummed copy of the candidate gzip and record its
   validated uncompressed identity.
4. Register the old generation without changing the active-generation cursor.
5. Prove the recovery reader begins at byte `93,438,552`, on the recorded line
   boundary, and cannot skip or overwrite acknowledgements.
6. Keep the active archive and later rotated generations preserved.
7. Historical delivery/replay requires its own bounded rate, retention-impact
   analysis and explicit approval; registration alone must not send events.
8. Never copy an older state over a newer acknowledged cursor and never bind
   the two inode values by assertion.

No step in this recovery gate was executed during the backend rollout.
