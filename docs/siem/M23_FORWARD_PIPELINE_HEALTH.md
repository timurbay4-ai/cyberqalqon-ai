# M23 forward pipeline health

The pipeline was evaluated as independent dimensions, not one green badge.

| Dimension | Result | Evidence |
| --- | --- | --- |
| Backend liveness | PASS | Windows HTTP 200 |
| Ingestion route reachability | PASS | gateway and relay 6/6 HTTP 200 |
| Forward service | PASS | active, PID 10901, zero restarts |
| Approval validity | PASS | exact root-controlled manifest, finite expiry, SHA recorded |
| Generation identity | PASS | exact generation and `2096/33582586` |
| Delivery progress | PASS | cursor advanced 2,239,555 bytes in 50.237 seconds |
| Delivery errors | PASS | retries/protocol/rejections remained zero |
| Current backlog trend | PASS for sampled window | all five intervals drained; average −18,912.874 B/s |
| Legacy provenance | FAIL/UNPROVEN | legacy inode differs from active source; intentionally preserved |
| Historical replay | NOT_CONFIGURED | no replay started |

The authoritative acknowledgement boundary is HTTP 201/200 followed by immediate durable checkpoint persistence. M23 coalesces only local filtered/malformed cursor updates; it does not defer acknowledged-event persistence.

Stage analysis:

1. Archive reader: inode-stable, bounded line reader, no rotation detected.
2. Filter/JSON: 181 filtered and 229 accepted during the sample; 103 cumulative malformed records are not successful deliveries.
3. HTTP client: one persistent `httpx.Client`; no per-event client construction.
4. Relay/gateway: p95 20.399/69.205 ms in the six-sample window.
5. FastAPI/SQLite: single-event mode, schema 17, retention cap 100,000.
6. Checkpoint: current-generation chain and source identity remain separate from the immutable legacy state.

The 3.79-hour catch-up estimate in the artifact is reported only because every measured interval drained; it must not be treated as an SLA or historical-backlog estimate.
