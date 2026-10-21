# M20 relay stability and health diagnosis

Status: **current NETWORK TIMEOUT proven; previous intermittent BACKEND
QUEUEING strongly supported; remediation not live**.

## Correlated evidence

The present outage is not an ambiguous five-second application delay:

| Probe | Result |
|---|---|
| Windows `127.0.0.1:8000/health` | connection refused; no backend listener |
| WSL `172.19.240.1:16000` TCP | three timeouts, about 2,002-2,006 ms |
| WSL gateway HTTP | three timeouts, about 2,003-2,028 ms |
| WSL `127.0.0.1:18000` TCP | accepted in 0.46-2.53 ms |
| WSL relay HTTP | three timeouts, about 2,003 ms |

The relay process is scheduled and accepting locally. Its HTTP timeout is an
upstream symptom. The portproxy entry and Hyper-V rule have correct current
addresses, but the ordinary Windows firewall rule is bound to the prior WSL
adapter GUID while the current adapter has a new GUID. This explains the
persistent gateway SYN timeout. Changing that privileged rule requires new
explicit approval because the prior authorization required stopping when the
recorded GUID became stale.

## Previous intermittent five-second timeouts

The old backend source used one Uvicorn event loop and called synchronous
`sqlite3` single/batch ingestion directly inside `async` routes. A 5-15 second
retention transaction therefore queued dependency-free `/health` requests on
the same event loop. `/health` itself performs no database, archive or Wazuh
operation; `/readiness` performs a schema/SQLite check with a five-second busy
timeout.

M20 moves ingestion and readiness database calls to Starlette's bounded worker
threadpool. An isolated locked-writer rehearsal then returned five liveness
responses in 0-31 ms while the writer waited 359 ms and eventually committed.
The response body and `/health` contract did not change.

The shipper uses one persistent `httpx.Client`, so keep-alive is enabled. Fresh
TCP probes also fail in the current outage, excluding a stale pooled connection
as the present root cause. Before the outage, the code-level event-loop block
matches the observed timeout duration and M18/M19 long transactions; exact
per-request historical attribution remains unavailable.

## Classification

- `NETWORK TIMEOUT`: **PROVEN CURRENTLY** — stale host firewall interface
  binding plus current TCP SYN timeouts.
- `RELAY TIMEOUT`: **SYMPTOM**, not root cause — local listener is responsive.
- `BACKEND QUEUEING`: **HIGH CONFIDENCE HISTORICALLY** — synchronous SQLite on
  the event loop; fixed and tested in source only.
- `BACKEND APPLICATION TIMEOUT`: **NOT CURRENTLY TESTABLE** because no process
  is running.
- `DATABASE-RELATED STALL`: **INDIRECT HISTORICAL CONTRIBUTOR** through the old
  event-loop execution model, not a dependency of liveness itself.
- `RESOURCE STARVATION`: **WARNING/UNPROVEN** — low free RAM, no correlated CPU
  or relay scheduling evidence.
- `UNKNOWN`: exact allocation between old network jitter and backend queueing
  for each retained historical timeout.

No timeout was increased and no failure was suppressed.
