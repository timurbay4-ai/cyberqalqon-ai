# M21 forward-ingestion approval gate

Decision now: **BLOCKED PENDING EXPLICIT LIVE APPROVAL**.

No state directory was created under `/var/lib`, no production package or unit
was changed, and no event was delivered.

## Proposed candidate boundary

| Gate item | Candidate |
|---|---|
| Source | `/var/ossec/logs/archives/archives.json` |
| Captured device/inode | `2096/33582586` |
| Explicit start boundary | decoded/plain offset `688,001,817` |
| Boundary | complete newline; partial-tail length 0 |
| Last excluded record | timestamp `2026-10-20T16:32:01.560+0500` |
| Prefix SHA-256 | `bd3d1ea52d7ae7ca42943e9710fcec50fd2121f3fb0666eaf50126429f26ccab` |
| Proposed independent state root | `/var/lib/cyberqalqon-sender/forward/m21/` |
| Legacy state | unchanged at SHA-256 `ef116265...60dde` |

This candidate excludes all older bytes: the unread day-15 suffix, days 16–19,
the day-19 NUL artifact, and day-20 bytes before the boundary. They remain on
disk for separate reconciliation/replay. Accepting this boundary restores
forward delivery; it does **not** accept or prove historical continuity.

## Mandatory revalidation before any live start

1. Recheck source device/inode and prove that the captured prefix SHA is still
   identical. If rotation occurred, stop and submit the rotated candidate for
   prefix/record-chain verification.
2. Rehash the legacy state and confirm cursor `93,438,552` is unchanged.
3. Capture free disk/RAM, DB/WAL/integrity, backend/relay health and retention
   capacity. Current DB is already at the 100,000-row cap.
4. Review package diff and explicitly wire one new service/namespace to the
   existing authenticated `EventDeliveryClient`; do not add a second ingestion
   implementation.
5. Begin with one worker and conservative single-event delivery. Batch remains
   disabled.
6. Record 201 and 200 separately; stop on identity change, protocol error,
   repeated 5xx, rejection, SQLite error, unbounded WAL, or resource pressure.
7. Preserve all generations and both state namespaces. Never modify the legacy
   cursor as part of this rollout.

## Resource and production-impact budget

At the final read-only sample, Windows had 710,598,656 bytes free RAM out of
8,212,983,808 and 173,569,769,472 bytes free on `C:`. WSL reported
2,834,124,800 bytes available RAM and 1,010,942,713,856 bytes available in its
virtual filesystem; the latter is not a guarantee of equal physical host
capacity. The low host-RAM margin is a **WARNING**.

The forward design streams one bounded line at a time, uses one worker, creates
only a small JSON state file, and does not copy archives. A live gate must still
reserve WAL/temporary headroom, run heavy integrity scans serially and stop on
memory pressure. Historical replay has a different, much larger budget and is
not covered by forward approval.

New accepted events can evict older rows under the unchanged 100,000-event cap
and can drive the existing normal alert/correlation paths. AI remains false and
DET-001–DET-009 remain shadow/disabled; this does not mean all ordinary Wazuh
alerts are suppressed. Retention deletion, alert volume and evidence links are
mandatory live observations.

## Approval must explicitly acknowledge

- exact-cursor ancestry remains unproven;
- WSL/Wazuh downtime gaps cannot be replayed;
- the chosen start intentionally leaves older eligible records outside the
  forward pipeline;
- retention may evict other rows as new events arrive;
- forward success is not exactly-once historical recovery.

If any gate fails, remain fail-closed. Live start, package deployment, service
creation and historical replay each remain separate operator actions.
