# M23 approval lifecycle

## Security model

- **Who authorizes:** a human operator; code can only prepare a pending proposal.
- **What:** single-event forward ingestion for one exact generation/start boundary and unchanged legacy inventory.
- **Duration:** minimum 60 seconds, hard maximum 86,400 seconds.
- **Cursor movement:** allowed forward within the approved generation when the processed chain validates; rewind is never authorized.
- **Rotation:** changes generation identity and requires separate approval; authority never transfers automatically.
- **Expiry:** service validation fails closed; an expired manifest produces a `FRESH_ACTIVATION` proposal, not a renewal.
- **Audit:** proposal includes old manifest SHA, current checkpoint SHA, generation, device/inode, legacy SHA/cursor, reason code, requested expiry, and no raw payload.

`forward approval-proposal` writes a durable proposal envelope only. Its nested manifest remains `PENDING_EXPLICIT_USER_APPROVAL`, `accepts_unproven_history=false`, replay=false, and legacy mutation=false. Existing output is never overwritten.

Idempotency returns `ALREADY_APPROVED` when the existing valid window already covers the requested expiry. Clock regression, invalid duration, wrong generation/inode/cursor, changed boundary prefix, corrupt checkpoint, insecure permissions, or unauthorized security scope fail closed.

39 combined M22/M23 lifecycle tests passed. The current live approval was neither rewritten nor extended during M23.
