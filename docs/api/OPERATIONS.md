# Operational diagnostics API

`GET /api/v1/operations/overview` requires an authenticated analyst with `soc:read`.
It is read-only and accepts only `event_limit=1..100`. No runtime file path, service name,
command, or Wazuh endpoint can be supplied by the caller.

The response separates evidence sources:

- `WAZUH_API` is the only authority for Wazuh agent connection status. If its read-only
  credential or trusted CA is absent, inventory is `UNAVAILABLE` and agent status remains
  `UNKNOWN`.
- `OS_SERVICE_MANAGER` proves only that a process/service is active. It does not prove agent
  enrollment or event delivery.
- `DURABLE_SENDER_STATE` reports queue depth, in-flight items, retries, dead letters, and the
  last safe delivery result. The local warning threshold is 100 queued items or a 60-second
  oldest pending item; any dead letter or terminal-blocked record is unhealthy immediately.
- `DURABLE_SHIPPER_STATE` reports archive cursor, byte lag, parsing counters, and delivery
  retry blockage.
- `APPLICATION_DATABASE` reports SQLite integrity and normalized-event quality counts.

Operational state is populated by the one-shot collector:

```powershell
backend\.venv\Scripts\python.exe scripts\capture_operational_health.py
```

The collector has bounded subprocess/network timeouts, writes a sanitized Git-ignored JSON
snapshot, and records only newer observations. It never restarts services, edits Wazuh config,
changes firewall rules, or enrolls an agent.

State transitions are persisted and deduplicated. An initial unhealthy state produces one issue;
repeated identical observations produce none; a transition back to healthy produces one recovery.
Non-recovery notices have a per-component 15-minute cooldown to contain flapping, while every
recovery is delivered. Each transition is audited and allowed notices are fanned out through the
existing per-analyst notification table.
Mark-read mutations continue to require the normal Origin and CSRF protections.
