# M21 provenance reconstruction

Final classification: **UNPROVEN_REQUIRES_EXPLICIT_RISK_DECISION**.

## Findings by confidence

### PROVEN

- The current legacy state bytes hash to `ef116265...60dde`; it records cursor
  `93,438,552` and source device/inode `2096/33582396`.
- The decoded day-15 candidate has a valid record boundary at that cursor and a
  decoded-prefix SHA-256 of `fefc860f...71739`.
- Its first `59,462,466` decoded bytes hash to the value recorded in the M17
  preflight: `9480a82b...734b9`.
- The prefix contains 17,183 segments. Current selection finds 7,356 eligible,
  9,819 filtered and 8 malformed. The durable ledger contains the same total,
  but allocates one record differently: 7,355 acknowledged, 9,820 filtered and
  8 malformed.
- Exactly 7,355 prefix fingerprints are present in the retained backend export.
- Day-19 offsets `163,372,751..163,373,056` are 305 NUL bytes with SHA-256
  `c25637e3...84bb`; they are not a JSON object or cross-generation fragment.

These statements prove properties of the evidence currently present. They do
not by themselves authenticate the history of the deleted original inode.

### STRONGLY_CORROBORATED

- M17 captured device/inode `2096/33582396` while recording the
  `59,462,466`-byte prefix hash. The candidate day-15 gzip reproduces that
  decoded prefix exactly.
- Root-only backups show monotonic checkpoints
  `3,258,960 -> 36,366,272 -> 42,723,427 -> 44,749,863 -> 93,438,552`.
- The last 1,000 eligible records before the cursor all have retained exact
  fingerprints; the first 1,000 after it have none.
- State time, first identity-mismatch time, gzip creation, archive coverage and
  Wazuh journal lifecycle are mutually consistent with normal day-15 rotation.

The evidence is strong, but the historical manifests are unsigned and not
externally timestamped.

### CONSISTENT_BUT_UNPROVEN

- Bytes from `59,462,466` through the final cursor appear to extend the same
  append-only day-15 stream.
- Day-16 and day-19 names, metadata and record windows fit the sequence.
- The current active generation follows day 19 and starts when Wazuh resumed on
  day 20.

No authenticated historical hash covers the first interval through the exact
cursor, and day 16/day 19 have no Wazuh checksum sidecar.

### CONTRADICTED

- Full uninterrupted telemetry is contradicted by WSL boot gaps and explicit
  Wazuh stop/start journal entries.
- Exactly-once recovery is contradicted as a proven claim: retained backend
  rows are capped at 100,000 and do not form a permanent acknowledgement log.
- The active inode cannot be treated as the legacy generation; the identities
  differ.

### UNKNOWN

- Security activity that occurred while WSL/Wazuh collection was unavailable.
- A signed exact-cursor hash for original inode `33582396`.
- Whether day-16/day-19 current bytes can be authenticated to their creation
  time beyond filesystem/journal consistency.
- Historical new-versus-duplicate split for the 269 legacy acknowledgements.

## Decision

The additional M21 capture strengthens current content integrity but provides
no new authoritative historical anchor at cursor `93,438,552`. Exact-cursor
ancestry remains **UNPROVEN**. Numerical agreement was not promoted to
cryptographic proof, and live recovery was not performed.
