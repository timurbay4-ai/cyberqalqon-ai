# M22 independent forward-ingestion service

The implementation reuses `EventDeliveryClient` and `select_archive_event`; it
does not introduce another backend protocol. Delivery remains one authenticated
HTTP request per eligible event.

## CLI

`cyberqalqon-sender forward` supports `inspect`, `status`, `validate --deep`,
`dry-run`, `prepare`, `approval-template`, `approval-check`, explicit
`rebind-rotated`, and approval-gated `run`. Offline inspection does not load
sender credentials. The approval template is deliberately non-authorizing.

Live execution requires an expiring, root-owned, non-writable manifest bound to
the exact generation, source, boundary, legacy hash/cursor, and prepared state
hash. It must accept `UNPROVEN` history while denying historical replay and
legacy mutation.

## Service

Template: `wazuh/configs/cyberqalqon-forward-ingestion.service`.

It is not installed, enabled, or started and has no `[Install]` section. It runs
as `wazuh`, has one worker, single-event delivery, conservative read/rate limits,
exclusive checkpoint ownership, payload-free fsynced JSONL audit, bounded retry
wait, and systemd filesystem/capability hardening. Static
`systemd-analyze verify` found no unit-specific errors after copying it at mode
0644; unrelated distro alias warnings remain.

An inode change stops before cursor advancement. The service never guesses a
rotated filename. Preserve both generations, deep-verify the candidate chain,
approve the paused rebind, and then restart. Safe stop preserves checkpoint,
audit, approval evidence, legacy state, and archives. Never restore the initial
forward state after acknowledged progress.
