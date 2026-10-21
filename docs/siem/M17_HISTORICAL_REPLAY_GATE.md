# M17 historical replay gate

Live status: **BLOCKED_CAPACITY_AND_LIVE_BACKLOG; NOT STARTED**.

The source replayer is one bounded, explicitly selected generation worker with
an independent durable checkpoint, rate limit, pause/resume, gzip support,
identity validation and EOF SHA-256 validation. State persistence now uses
file and directory sync. Retry/protocol errors pause without advancing;
permanent rejection blocks without skipping. Disposable authenticated tests
verify 201 insert, 200 duplicate and idempotent one-row storage.

Current readiness:

- five rotated gzip files exist, but only archive `13` is registered;
- the registered unread tail has 53,748 eligible records;
- current active eligible backlog is `UNKNOWN`;
- the live normalized store is at its 100,000-row cap;
- active archive byte lag is growing, not draining;
- host free RAM is constrained;
- live v3 accounting and backpressure are not deployed.

Consequently no meaningful replay duration range can be produced and no live
replay approval is requested yet. The remaining four archives must be
registered/audited without mutation, capacity must stabilize, and live backlog
must demonstrate sustained positive drain before replay can be proposed.

When those prerequisites pass, the request must name the generation, rate,
batch, pause thresholds, retained-row expectations and monitoring interval, and
must ask exactly:

`Cheklangan tezlikdagi historical archive replay’ni live muhitda boshlashga ruxsat berasizmi?`
