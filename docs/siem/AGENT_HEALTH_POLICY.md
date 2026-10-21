# Agent and pipeline health policy

CyberQalqon records only supported observations and keeps their authorities
visible.

## State sources

- `WAZUH_API`: authoritative enrollment and connection state.
- `TELEMETRY_EVIDENCE`: source presence and freshness only.
- `OS_SERVICE_MANAGER`: local/manager service state, not agent connectivity.
- `DURABLE_SENDER_STATE` and `DURABLE_SHIPPER_STATE`: queue/cursor health.
- `APPLICATION_DATABASE`: SQLite integrity and ingestion timestamps.

A running Windows service is not `CONNECTED`. A recent event is not `ONLINE`.
Only an active server-side agent record or Wazuh API result can establish that
connection state.

## Transitions and notifications

Agent disconnect/reconnect history is written only from Wazuh API observations.
The first observation establishes state without notifying. A later transition
creates one history row, one credential-free audit event, and per-active-analyst
notifications. Repeated disconnect notices have a 15-minute cooldown; recovery
is emitted once per actual transition. Global history is bounded by
`AGENT_HEALTH_HISTORY_MAX_RECORDS`.

The one-shot collector applies the same principles to API unavailable/recovery,
queue/dead-letter/delivery failures, shipper backlog, and source stale/recovery.
Equal or older observations are ignored; equal state does not emit a transition;
recent repeated issue notifications are suppressed. Operational history is
capped at 1,000 and security audit history at 10,000.

Default thresholds:

| Condition | Default |
| --- | ---: |
| Sender queue warning | 100 items |
| Sender queue bytes warning | 64 MiB |
| Oldest pending warning | 60 seconds |
| Shipper lag warning | 8 MiB |
| Source stale | 900 seconds |

Thresholds are environment-configurable. Collection remains an operator-run
one-shot job; v0.9 adds no daemon or aggressive frontend polling.

## Recovery policy

Resolve the underlying authority first, run the bounded collector again, and
confirm a recovery transition. Never mark a component healthy by editing the
database. Stale cached inventory remains labeled stale until a new provider
observation succeeds.
