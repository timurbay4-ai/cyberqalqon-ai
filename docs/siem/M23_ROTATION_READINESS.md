# M23 rotation readiness

Rotation behavior remains fail-closed and generation-specific.

- Device/inode mismatch blocks the current worker.
- A candidate must preserve the registered start prefix and the complete processed record chain through the durable cursor.
- Source truncation behind the cursor is rejected.
- Gzip sources require an immutable stored SHA-256.
- Partial final records remain WAITING and do not advance the cursor.
- Checkpoint locks prevent concurrent workers.
- A rebind requires the explicit rotation flag and leaves the state paused; live rebind still needs separate operator approval.
- Legacy state is never used as the forward generation's mutable cursor.

M21/M22/M23 suites cover inode change, prefix mismatch, truncation, gzip identity, partial tails, lock contention, state corruption, acknowledgement/checkpoint failure, and rotation approval boundaries. No live rotation or new generation enrollment occurred in M23.

Current observation: source remained `2096/33582586`; `rotation_detected=false` across all six samples.
