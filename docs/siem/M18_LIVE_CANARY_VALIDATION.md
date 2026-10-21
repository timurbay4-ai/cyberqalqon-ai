# M18 limited live canary validation

Status: **CANARY FAILED SAFETY GATE — ROLLED BACK SAFELY**
Authorization: `APPROVED_M18_LIMITED_CANARY_BATCH_10`
Date: 2026-10-15
Protocol tested: `m18-batch-v1`
Live batch size: 10
Workers: 1

Batch 25 was not enabled and remains blocked. Batch 50/100, schema migration,
historical replay, AI, detection enforcement, browser UAT and Git commit/push
were not performed.

## Executive decision

The batch-10 protocol preserved acknowledgement and database integrity, and it
increased acknowledged-event throughput. It did not pass the live reliability
gate:

- 5 of 23 batch requests returned HTTP 503 because processing crossed the
  15-second pre-commit deadline;
- three 503 responses occurred consecutively;
- the latency distribution was censored by the timeout, with p95 at least
  15,000 ms and a final observed request latency of 15,020.169 ms;
- backlog growth worsened from the pre-canary `+17,318.58 B/s` to an observed
  `+29,891.06 B/s` during an active-canary sample window;
- a relay health sample timed out while the database path was saturated,
  although later relay checks returned HTTP 200.

The mandatory repeated-5xx rollback condition therefore triggered. The latest
acknowledged v3 state was preserved; no old cursor was restored.

## Safety preflight and backups

All health checks were HTTP 200 before deployment: Windows backend, frontend,
gateway-scoped TCP 16000 portproxy, and the WSL backend relay. The archive
device/inode stayed `2096/33582396` throughout the canary.

| Evidence | Path | SHA-256 |
|---|---|---|
| Verified schema-17 SQLite backup | `backups/cyberqalqon-pre-m18-canary-schema17-20261015T051731Z.db` | `a0b34f413ff6e826550f707f9c6cffe9be19ae922b636ea381c4782601635ca9` |
| Reference pre-canary state | `/var/lib/cyberqalqon-sender/backups/m18-precanary-state-20261015T051731Z.json` | `706fd8df7bd8294bdc21e3a47b9e918f6d91ab5e427ec8ff57502485da11c418` |
| Final deployment-start state | `/var/lib/cyberqalqon-sender/backups/m18-live-canary-20261015T053032Z/event-shipper-state.v3.json` | `45751dc999debcc466348731137747ecd178bc624bae3ec000728d3f004d6e` |
| Pre-canary sender environment | `/var/lib/cyberqalqon-sender/backups/m18-live-canary-20261015T053032Z/sender.env.pre-canary` | `61924fa691d74107d9501740d804d9beae7444d5925b49cdfbcfa947b4f6cb5d` |
| Pre-canary sender package | `/var/lib/cyberqalqon-sender/backups/m18-live-canary-20261015T053032Z/sender-package.pre-canary.tar.gz` | `4da48d01025480b35efea2c0e8169da88b5773e803b273ebfe0a71bec84b1257` |
| Pre-canary backend environment | `backups/m18-live-canary-20261015T053032Z/backend.env.pre-canary` | `c4bf0342ead6985d114b1bda22f8af478cf050749ad4a2bcbc3034b8c11d9811` |
| Failed-canary final state | `/var/lib/cyberqalqon-sender/backups/m18-failed-canary-20261015T054215Z/event-shipper-state.final-v3.json` | `a2627acc44927431aac2cab306a7aec8ece762c9d567e341f4b5001eeb8c14d1` |

The WSL backup directories are `0700 root:root`; their files are `0600
root:root`. The sender environment remains `0640 root:wazuh`. The backend
environment backup is local, Git-ignored, and access-restricted.

The user-specified control cursor `36,728,683` was recorded in the earlier
deployment gate. Because the authorized live worker continued before the
canary stop, the authoritative deployment-start cursor was `42,723,427`.
Restoring the older control cursor would have replayed already acknowledged
data, so it was correctly not used as a rollback state.

## Canary configuration

| Setting | Live value |
|---|---:|
| Protocol | `m18-batch-v1` |
| Network batch | 10 |
| Local read batch | 25 |
| Adaptive batching | false |
| Adaptive min/max safety bound | 10 / 10 |
| Worker count | 1 |
| Maximum request body | 2,097,152 bytes |
| Backend batch limit | 10 events |
| Processing deadline | 15 seconds |

The sender package was staged, compiled and hash-compared before its package
directory was atomically swapped. The deployed `event_shipper.py` SHA-256 was
`777f14eee61a98d90fb1ff7e782e7c78be6e77f9ed1fde7e72fdf6c81b1a12b4`.

## Live results

The shipper ran from epoch `1792042684.140267` to `1792042898.372107`, a
214.232-second live interval.

| Metric | Start | Stop | Delta |
|---|---:|---:|---:|
| Cursor | 42,723,427 | 44,749,863 | +2,026,436 bytes |
| Unique insert acknowledgements | 2,876 | 3,031 | +155 |
| Duplicate acknowledgements | 45 | 55 | +10 |
| Filtered records | 5,338 | 5,512 | +174 |
| Malformed JSON | 8 | 8 | 0 |
| Delivery rejection | 0 | 0 | 0 |
| Retry attempts | 152 | 158 | +6 |
| Protocol errors | 0 | 0 | 0 |
| Batch HTTP requests | 0 | 23 | +23 |
| Batch events acknowledged | 0 | 165 | +165 |

HTTP outcomes:

| HTTP outcome | Requests | Meaning |
|---|---:|---|
| 201 | 17 | Batch contained newly inserted events |
| 200 | 1 | Idempotent duplicate acknowledgement |
| 4xx | 0 | No permanent client/data rejection |
| 503 | 5 | Retryable pre-commit processing timeout |

The 165 acknowledged items reconcile exactly to 155 new inserts plus 10
duplicate acknowledgements. The ten duplicates formed one idempotent batch
acknowledgement following retries; they were not ten duplicate database rows.
Post-canary SQL validation found zero duplicate `event_id` groups and zero
duplicate `deduplication_id` groups.

Historical v2 acknowledgement uniqueness remains `UNKNOWN`; the preserved
historical count is 269 and was not reclassified.

### Throughput and backlog

- Pre-canary state-reported delivery rate: 0.496541 records/s.
- Full-canary unique insertion rate: 0.723515 records/s.
- Full-canary acknowledged-event rate: 0.770194 records/s.
- A bounded active-canary sample measured cursor progress at 11,134.51 B/s,
  archive growth at 41,025.58 B/s, and net lag growth at 29,891.06 B/s.
- The preceding M18 observation measured cursor progress near 4,749 B/s,
  archive growth near 22,067 B/s, and lag growth at 17,318.58 B/s.
- The observed live-canary lag-growth rate was therefore 72.60% worse, despite
  higher delivery throughput.

The first and late active-canary sample lags were 184,388,304 and 189,160,084
bytes. A later backup-time lag is not used as a canary rate endpoint because
the archive continued growing after the worker had been stopped.

### Latency and resources

The process did not retain a full per-request latency histogram after rollback.
Because 5/23 requests crossed the configured 15-second deadline, nearest-rank
p95 is safely reported as a censored `>=15,000 ms`, not as a fabricated exact
number. Observed state samples ranged from 2,650.469 ms to 15,020.169 ms.

- Shipper: one task, approximately 22 MiB peak memory, 2.261 seconds total CPU
  during the canary.
- Backend sample: approximately 72 MiB working set.
- Post-rollback WAL: 16,780,792 bytes.
- No SQLite busy/lock exception, protocol error, terminal block or delivery
  rejection was recorded.

## Rollback execution

Rollback began immediately after confirming repeated HTTP 503 responses.

1. The event shipper was stopped and MainPID was confirmed as zero.
2. The latest state at cursor `44,749,863` was copied to a new root-only
   evidence directory and fsynced.
3. The pre-canary sender package was restored. Its `event_shipper.py` SHA-256
   is `07375518fba0a1ebbb2cd5b4122625b8a200d9494a64ec8a0931c27f58648023`.
4. The sender environment was restored with batch protocol absent/disabled.
5. The backend environment was restored with batch ingestion disabled, then
   the existing loopback-only Uvicorn startup command was restarted.
6. The old single-event worker was started using the latest cursor. No state
   backup was copied over the live state.

After a short retry/recovery interval, single-event ingestion returned to
HTTP 201/200 responses. A post-rollback sample showed cursor `45,943,104`, last
latency 649.261 ms, zero consecutive retries, one worker/task, and HTTP 200 for
backend, frontend, portproxy and WSL relay.

## Integrity and validation

Passive validator result: **WARNING**, with 11 PASS, 2 WARNING, 0 FAIL and 1
DEFERRED_BY_USER.

- SQLite `quick_check`: `ok`
- Foreign-key violations: 0
- Schema: 17 (`TARGET`)
- Security events: 100,000
- Alerts: 40
- Duplicate event IDs: 0
- Duplicate deduplication IDs: 0
- Archive identity: unchanged
- Active-file malformed count: 8
- Rotated malformed audit count: 154
- Total malformed audit count: 162
- Canary malformed delta: 0; malformed records were never counted as delivered
- Delivery rejection: 0
- Backend/frontend/portproxy/relay: HTTP 200
- Pre-canary full regression: backend 272/272, Wazuh 158/158, deployment
  24/24, frontend 118/118, TypeScript and production build PASS
- Targeted post-rollback regression: 53 passed, 0 failed

The two expected validator warnings are the large event-shipper backlog and the
database operating at its unchanged 100,000-event retention cap. Browser UAT
remains `DEFERRED_BY_USER`.

Validator artifact:
`artifacts/lab-validation/m18-live-canary-rollback.json`.

## Policy state and remaining blockers

- Live schema remains 17; schema-18 migration was not started.
- Historical replay was not started.
- Retention remains 30 days / 100,000 events.
- `DET-001` through `DET-009` remain
  `DISABLED_BY_POLICY / SHADOW_ONLY`.
- `AI_ENABLED=false`.
- Browser UAT remains deferred.
- Existing dirty working tree was preserved.
- No Git commit or push was created.
- Firewall and portproxy configuration were not changed.

The blocking issue for another batch canary is the intermittent batch
transaction crossing the 15-second pre-commit deadline while the database is at
the retention cap. Instrumentation must identify whether retention/protected
evidence work, lock acquisition, or another transaction phase dominates those
timeouts. Batch 25 must not be attempted until batch 10 can run without repeated
5xx and with a non-worsening backlog trend under comparable archive input.
