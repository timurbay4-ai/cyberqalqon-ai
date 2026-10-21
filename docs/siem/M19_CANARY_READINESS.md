# M19 canary readiness

Decision: **BLOCKED — fresh live deployment approval required**

Source remediation and isolated batch-10/batch-25 evidence satisfy the
engineering gate: representative transactions remain below 15 seconds,
atomicity/idempotency pass, protected rows survive, and schema-17 integrity is
preserved. They do not authorize or prove a production improvement.

The final passive rerun passed the relay check, but the first validator run and
the end of the final rate sample each observed a five-second relay health
timeout. That intermittent latency and the still-growing backlog must be stable
inside the future preflight/observation window; they are not waived by the
isolated benchmark.

Before a new canary, an operator must:

1. review M19 validation and the retained per-503 uncertainty;
2. verify backend, relay, portproxy and shipper health;
3. run passive database integrity checks;
4. create and hash a consistent SQLite backup;
5. stop the shipper in a controlled manner and hash its latest v3 state;
6. record cursor, archive device/inode/size and eligible backlog;
7. deploy the reviewed backend source without enabling batch yet;
8. verify single-event regression and the new bounded metrics;
9. define a short batch-10 observation window and preserve one worker;
10. obtain a new explicit user approval before activation.

Automatic stop conditions remain: any unexpected duplicate/event loss, cursor
regression, protocol error, repeated 5xx, deadline violation, SQLite integrity
error, retention evidence risk, unhealthy relay/shipper, or worsening backlog
without adequate throughput. Rollback must preserve the newest acknowledged v3
cursor; an older backup must never overwrite forward progress.

Batch 25 is not automatically authorized. The FTS and dense-evidence index
recommendations are a separate schema gate. Schema 18, historical replay,
detection enforcement and AI remain blocked.
