# Agent management

CyberQalqon v0.9 exposes an authenticated, read-only agent workspace. It
combines Wazuh API inventory with telemetry relationships without treating the
two as equivalent.

## Architecture and identity

```text
Wazuh API (authority) ----> bounded cache ----> namespaced inventory/history
                                                   |
Wazuh event ingestion ----> security_events -------+----> /api/v1/agents
                                                        -> Agents workspace
```

The durable key is a SHA-256-derived opaque identifier over provider, manager
identity, and provider agent ID. The visible Wazuh ID remains available for
operations, but it is never the database primary key. This prevents ID `001`
from different managers from colliding. A telemetry-only identity uses an
`observed_` key and remains distinct until an authoritative provider record can
be matched unambiguously.

Hostname or IP changes update attributes of an authoritative manager-scoped
identity; they do not define identity. Unknown manager scope is kept explicit.

## Supported states

| Field | Values | Authority |
| --- | --- | --- |
| Connection | `ONLINE`, `DISCONNECTED`, `NEVER_CONNECTED`, `UNKNOWN` | Wazuh API only; telemetry-only rows are always `UNKNOWN` |
| Enrollment | `ENROLLED`, `UNKNOWN` | Wazuh API inventory or unavailable |
| Data freshness | `ACTIVE`, `STALE`, `NO_DATA` | Last security-event timestamp |
| Pipeline health | `ACTIVE`, `STALE`, `EMPTY` | Last ingestion timestamp |
| Status authority | `WAZUH_API`, `TELEMETRY_EVIDENCE` | Returned on every row |

An event received recently means only that data was observed. It never changes
connection state to `ONLINE`.

## API

All routes require a human session with `soc:read` and preserve normal session,
Origin, and RBAC controls.

- `GET /api/v1/agents` supports search, OS/status/version/manager/source and
  last-seen filters, safe sorting, and offset pagination.
- `GET /api/v1/agents/{agent_key}` returns metadata, source relationships,
  recent event IDs, related alert/incident IDs, and troubleshooting guidance.
- `GET /api/v1/agents/{agent_key}/health` returns bounded authoritative history.
- `GET /api/v1/integrations/wazuh/status` exposes availability, observation
  time, cache age/staleness, TLS mode, and read-only status.

The UI contains no restart, configuration, enrollment, upgrade, or removal
control. These actions require a separately approved and audited workflow.

## v0.9.1 live acceptance

The local Wazuh API is available through a custom trusted CA and a read-only
reader scoped to the two accepted identities:

| Wazuh ID | Name | Platform | Authoritative state |
| --- | --- | --- | --- |
| `001` | `cyberqalqon-test-web` | Linux | `ONLINE`, `ENROLLED` |
| `002` | `windows-agent-002` | Windows 11 Pro | `ONLINE`, `ENROLLED` |

Authenticated calls to the integration-status, agent-list, Agent 002 detail,
and Agent 002 health endpoints returned HTTP 200. The Agent 002 response used
`WAZUH_API` authority and showed fresh Windows telemetry. A benign Application
event from Agent 002 was also discoverable through the authenticated event API;
that event did not alter its authoritative connection state.

## Cache and failure behavior

Inventory refresh uses a non-blocking in-process lock and a configurable TTL
(`WAZUH_INVENTORY_CACHE_SECONDS`, default 60). Provider outage leaves the
integration `UNAVAILABLE`. Cached observation timestamps and stale state are
shown; stale data is not represented as current. History is capped by
`AGENT_HEALTH_HISTORY_MAX_RECORDS` (default 10,000).

## Troubleshooting

1. Check `/api/v1/integrations/wazuh/status` before acting on a connection badge.
2. If unavailable, verify the CA, credential files, loopback path, and least-
   privilege role described in `docs/wazuh/WAZUH_API_INTEGRATION.md`.
3. If an agent is `UNKNOWN` but has fresh data, treat that as telemetry evidence,
   not proof of connection.
4. If a provider row and observed row remain separate, verify manager identity
   and provider agent ID; do not merge by mutable hostname or IP.
