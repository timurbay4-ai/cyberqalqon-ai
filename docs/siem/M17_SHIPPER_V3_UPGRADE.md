# M17 shipper v3 upgrade

Status: **READY_FOR_APPROVAL; NOT DEPLOYED**.

The v3 reader now fails closed on v1/v2 and forward versions. A legacy state
can only change through `event-state-upgrade` with an explicit apply flag and
operator approval. The procedure validates archive device/inode and cursor,
verifies the source SHA-256, writes a mode-0600 backup, atomically replaces the
state after file `fsync`, and syncs the parent directory on POSIX.

v2 `accepted` is preserved as `legacy_successful_acknowledgements`. v3
`accepted` and `duplicate_attempts` start at zero. Historic unique insert and
duplicate values remain `UNKNOWN`; no counter is fabricated.

## Disposable real-state rehearsal

A root-readable copy of the actual v2 state was upgraded and rolled back in a
temporary directory. Live state was not modified.

- source/target: 2 -> 3
- device/inode: 2096 / 33582042
- rehearsed cursor: 447,801,988, unchanged
- backup SHA verification: PASS
- exact-byte rollback before new v3 writes: PASS
- legacy acknowledgement preservation: PASS
- historic unique/duplicate counts: `UNKNOWN` / `UNKNOWN`

Unit tests also cover changed-state refusal, unsupported forward versions and
an interrupted `os.replace` that leaves the original state intact.

## Live approval evidence

| Item | Value at capture |
|---|---|
| State | `/var/lib/cyberqalqon-sender/event-shipper-state.json` |
| State version | 2 |
| Active archive | `/var/ossec/logs/archives/archives.json` |
| Archive identity | device 2096, inode 33582042 |
| Captured cursor / archive / lag | 447,969,672 / 968,004,028 / 520,034,356 bytes |
| Preflight backup | `/var/lib/cyberqalqon-sender/state-backups/m17/event-shipper-state.v2-preflight-20261014T172712Z.json` |
| Preflight backup SHA-256 | `8e2fad963f5d0e8500fc3e2afc645d2bb6a98d44e8a394463fed5908f2911758` |

Because the live shipper continues to advance, the maintenance procedure must
stop it gracefully, re-read identity/cursor, and create a second final backup.
Rollback is allowed only if the v3 state hash still equals the just-converted
hash; after any v3 write, rolling back would discard acknowledged progress and
is refused.

Expected interruption is one short shipper maintenance window. The backend,
sender and Wazuh Manager need not be stopped. If archive rotation occurs after
planning or before conversion, identity validation refuses the upgrade. If
deployment fails before a v3 write, restore the verified final v2 backup; after
a v3 write, preserve both states and reconcile instead of rolling back.
