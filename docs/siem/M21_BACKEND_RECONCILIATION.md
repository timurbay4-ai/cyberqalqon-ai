# M21 offline backend reconciliation

Outcome: **PASS for bounded read-only classification; PARTIAL for history**.

## Implementation

`wazuh/cyberqalqon_sender/reconciliation.py` adds:

- immutable archive generation capture using device, inode, size, mtime and
  stored SHA-256;
- read-only SQLite identity loading or payload-free M20 export loading;
- canonical JSON SHA-256 fingerprints rather than timestamp-only identity;
- bounded, resumable scans with atomic payload-free checkpoints;
- explicit malformed, filtered, exact, probable, absent-from-retained-window,
  and unclassifiable counters;
- fail-closed source identity, digest and cursor-boundary validation.

The scanner never writes to an archive or backend database. Its only output is
an operator-selected reconciliation state/report.

## Day-15 result

Source generation ID:
`f8c0a3a32e8b232e195b819ff2492bb24d8f946d9ef13648ae941d6965fbeef2`.

| Classification | Count |
|---|---:|
| Physical segments | 210,128 |
| Valid JSON | 210,078 |
| Filtered | 116,951 |
| Proven already ingested by exact fingerprint | 7,355 |
| Probable duplicate, not proven (source ID only) | 1 |
| Present in archive but absent from retained DB | 85,771 |
| Unable to classify | 0 |
| Malformed/incomplete | 50 |
| Invalid UTF-8 / invalid JSON | 48 / 2 |

The 85,771 records are **not** labelled “never ingested.” SQLite retains only
100,000 events under the 30-day/cap policy; older idempotency evidence can be
evicted. The one source-ID-only match is not promoted because source IDs repeat
extensively.

Payload-free artifacts:

- `m21-day15-reconciliation-report.json`, SHA-256
  `f273f863cf6db67413e7a789d0c16eec7c230a507cf853900a1d03b91ba5269a`;
- `m21-day15-reconciliation-state.json`, SHA-256
  `eee2ac041a96676a9fd46faea4ddee315f9490e059e587fa0063d61fa1251f80`.

No event was reconstructed or written to the live database.
