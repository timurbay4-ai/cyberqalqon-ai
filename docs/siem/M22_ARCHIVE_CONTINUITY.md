# M22 archive continuity

Verdict: **UNPROVEN**. M22 validates a future start point; it does not repair or
reinterpret history.

| Segment | Availability | Delivery knowledge | M22 action |
|---|---|---|---|
| Legacy cursor generation | original identity mismatch | UNKNOWN | Preserve; no rebind/reset |
| Retained day 15–19 | independently inventoried | UNKNOWN | Separate reconciliation/replay gate |
| Day-19 305-byte NUL tail | malformed evidence | Not deliverable | Count and preserve |
| Day-20 prefix through `688001817` | prefix hash proven | UNKNOWN | Exclude from immediate forward delivery |
| Day-20 after boundary | same inode | NOT STARTED | Proposed forward source |
| WSL/Wazuh offline intervals | no archive evidence | UNPROVEN | Not reconstructible from archives |

Event IDs regress and repeat, retention removes old database rows, offline
intervals have no source records, and no signed end-to-start chain proves that
legacy cursor `93,438,552` is an ancestor of active inode `33582586`.
Historical replay remains `NOT_STARTED` and outside the forward approval gate.
