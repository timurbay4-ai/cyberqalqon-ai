# M22 checkpoint isolation

- Legacy, immutable for M22:
  `/var/lib/cyberqalqon-sender/event-shipper-state.json`
- Staged, non-live checkpoint:
  `artifacts/runtime/m22-forward-checkpoint-staging/m22-forward/`
- Planned live checkpoint:
  `/var/lib/cyberqalqon-forward/m22-forward/e58aa9c7b9fbb04204f21d181dc1e6bdc2603d345ed120b7790c2df4fcb7da3a.json`

The staged checkpoint SHA-256 is
`17aabe42098ead5c22b404bacc7125e0ed36278221b30f722f450e4c36fe5295`.
It starts at offset `688,001,817`, has zero processed records, and records the
exact legacy SHA/cursor inventory. It is not under `/var/lib` and cannot be
consumed by current services.

## Guarantees

- Atomic JSON uses file fsync, `os.replace`, and POSIX directory fsync.
- A per-checkpoint OS lock prevents concurrent managed readers.
- Every batch revalidates source identity and legacy state SHA/cursor.
- Cursor advances only after a classified record is acknowledged or safely
  filtered/malformed and the checkpoint is persisted.
- Retry/protocol errors do not advance; permanent rejection blocks terminally.
- Partial records do not advance. Oversized records are streaming-hashed and
  never accumulated whole in memory.
- Deep verification recomputes the prefix and processed-record chain.
- Rotation rebind verifies the chain and requires explicit approval.

Tests cover crash-before-checkpoint, acknowledgement loss then duplicate,
corrupt counters/digests, source replacement, legacy mutation, partial tails,
oversized records, lock contention, restart, and rotation.
