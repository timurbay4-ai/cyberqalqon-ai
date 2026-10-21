# M16 data preservation

M16 uses three distinct preservation layers:

1. Wazuh JSON archives remain read-only evidence sources. No archive was deleted,
   truncated, rewritten, or moved by M16.
2. The live schema-17 event store keeps bounded normalized/searchable events.
3. Investigation references and the security audit preserve analyst decisions and
   prevent referenced event eviction.

## Protected database evidence

An event is excluded from age and FIFO deletion when it is linked by a case,
stored as an event evidence pin/reference, or linked to an existing alert.
Incidents that contain that alert therefore retain the projected event as well.
The current ingest is also protected from its own cleanup transaction.

Protected pressure is fail-safe: the store may exceed `SIEM_EVENT_MAX_RECORDS`,
reports the exact excess, and writes an aggregated retention audit. It does not
silently sever an investigation reference.

Analyst audit history, alerts, incidents, cases, and evidence metadata are not
members of the `security_events` FIFO and are not deleted by this policy.

## Archive evidence

The rotated archive registered for M16 is held in its original root-owned WSL
location and identified by a manifest containing device, inode, size, mtime and
SHA-256. The manifest and audit outputs are mode 0600 under a mode 0700 directory.
Malformed audits record only generation ID, byte offsets, line hash and failure
category; `contains_raw_payload=false` is enforced.

## Actions intentionally not performed

- No live historical replay.
- No cursor reset or durable shipper-state overwrite.
- No live retention-limit or retention-days change.
- No archive purge or malformed-record reclassification as delivered.
- No schema-18 migration.
- No second production ingestion worker.

The live 100,000-row store is already at its configured budget. Historical
replay therefore remains blocked pending a separate capacity/retention decision
and explicit operator approval.
