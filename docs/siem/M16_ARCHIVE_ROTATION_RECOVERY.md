# M16 archive rotation recovery

## Observed generations

| Generation | Identity / state |
|---|---|
| Rotated 2026-10-13 archive | generation `11b2f7a89af8848ca3bcf22ffa54e3c1286cacd3dbe44a058c8fe4d5dd6ea62d`; device 2112; inode 33582223; compressed size 23,169,852 bytes; uncompressed size 903,384,951 bytes |
| Active archive final snapshot | device 2096; inode 33582042; generation `457a5b13428217b03df44139194e161518550ea0ee6d96acf3cc4e99349499ea` at the final 2026-10-14 health capture |

The root-only manifest is
`/var/lib/cyberqalqon-sender/m16/archive-generations.json`. Registration is
idempotent for the same immutable identity and refuses a changed file at the same
path. Device/inode are not treated as globally unique: size, nanosecond mtime and
full content digest also participate in the stable generation identity.

## Recovery implementation

`ArchiveGenerationManifest` supports plain and gzip archives. The separate
`HistoricalArchiveReplayer` uses an atomic, mode-0600 state file per generation
and stores uncompressed offsets. It validates file identity before reading and a
full digest at EOF. Missing, replaced, corrupt or truncated generations fail
closed. Partial final records, malformed JSON, invalid UTF-8 and oversized lines
are separately counted. Retry does not advance the acknowledged offset.

The live shipper cursor is never reused by the historical reader. Active archive
auditing reads only the already-acknowledged prefix and verifies device/inode and
the cursor bound before and after the scan.

## Audited inventory

| Scope | Valid JSON | Eligible | Filtered | Malformed |
|---|---:|---:|---:|---:|
| Rotated archive from offset 482 | 164,670 | 72,524 | 92,146 | 154 |
| Rotated unread tail from 228,463,941 | 123,350 | 53,748 | 69,602 | 74 |
| Active acknowledged prefix snapshot | 27,714 | 11,326 | 16,388 | 8 |

The active archive continues to grow, so its cursor, byte lag and unread eligible
count are point-in-time values rather than a fixed queue size.
