# M14 persistent correlation state

Correlation replay is an isolated, non-alert-producing path over normalized
security events. Input is sorted by event time and immutable event ID. Stable
processed-event hashes prevent replay duplicates. Correlation keys include the
rule, host, account, source identity, and packaged grouping fields, so host and
account boundaries cannot merge.

Only normalized fields needed by M11 plus an allowlisted subset of Windows event
data are persisted. Full raw evidence is not copied. Each key keeps at most 200
event snapshots; requests accept at most 5,000 events, 200 findings, a 31-day
window, and a 5-second execution budget. Expiry is configuration-bound and old
state/processed hashes are deleted transactionally.

State update, watermark, processed hashes, and diagnostics share SQLite
transactions. A simulated interruption rolls back both state and dedupe rows.
Restart replay recovers persisted state; duplicate input produces zero newly
processed events. A state-schema mismatch fails closed instead of attempting a
best-effort conversion. Out-of-order input is deterministic because evaluation
uses event time, not arrival order.

Recovery procedure: stop only the isolated evaluation request, inspect the
schema/version mismatch, preserve the database, restore or migrate a disposable
copy, and retry after review. Never delete production evidence or reset an
ingestion cursor to repair M14 correlation state.
