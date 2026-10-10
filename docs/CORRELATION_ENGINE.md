# Deterministic Incident Correlation

CyberQalqon evaluates persisted Wazuh alerts synchronously after ingest. The alert commit completes
first; correlation then runs in a separate short-lived `BEGIN IMMEDIATE` transaction. A correlation
failure is logged with a one-way alert identifier digest and never rolls back or hides the alert.
There is no worker, queue, model, or background service.

## Rules

| Rule | Required chronological evidence | Classification | Severity | Confidence |
|---|---|---|---|---|
| `CORR-001` | `100111` → `100101` → `100120` | `MULTI_STAGE_RECONNAISSANCE` | HIGH | `EXACT_MATCH` |
| `CORR-002` | two related `100101` alerts | `REPEATED_WEB_ENUMERATION` | HIGH | `STRONG_MATCH` |
| `CORR-003` | `100101` → `100120` | `WEB_RECONNAISSANCE_ESCALATION` | HIGH | `STRONG_MATCH` |
| `CORR-004` | `100130` → `100131` | `FILE_INTEGRITY_SEQUENCE` | MEDIUM | `EXACT_MATCH` |

Rules are deterministic and do not infer compromise, exfiltration, or maliciousness from severity.
`CORR-001` takes precedence over partial reconnaissance rules. An open partial incident is upgraded
when delayed evidence completes the sequence.

## Identity and time matching

Network rules require a valid normalized source IP, the same agent ID, compatible explicit
destination IPs, and chronological evidence inside `CORRELATION_WINDOW_SECONDS`. IPv4-mapped IPv6
is folded to IPv4 and IPv6 is compressed. Source identity is always agent-scoped, including
loopback and private addresses: `agent:<id>|source:<ip>`. Explicit destinations augment the target
identity; conflicting destinations fail closed.

FIM correlation requires the exact normalized `syscheck.path` and agent ID. Missing source or file
identity preserves the individual alert but creates no automatic incident. Agent names and alert
severity are never identity keys.

## Lifecycle and atomicity

- Automatic metadata is stored separately from analyst-owned incident state.
- Analyst-created incidents, notes, assignments, severity decisions, and history are not changed.
- Alerts already belonging to a manual incident fail closed for automatic grouping.
- `RESOLVED` and `FALSE_POSITIVE` automatic incidents are never reopened or duplicated.
- A unique automatic-membership constraint and one SQLite write transaction prevent concurrent
  duplicate incidents or inconsistent links.
- System changes append ordinary `CREATED` and `ALERT_LINKED` audit rows as
  `system:correlation`; they never impersonate an analyst.

Migration 6 adds `incident_correlations` and `auto_correlation_alerts`; migration 7 adds the
agent/time/order candidate index. Neither rewrites alerts or existing incidents.

## Bounds and resource use

| Setting | Default | Meaning |
|---|---:|---|
| `CORRELATION_ENABLED` | `true` | Enable post-ingest deterministic evaluation |
| `CORRELATION_WINDOW_SECONDS` | `900` | Maximum evidence span |
| `CORRELATION_MAX_CANDIDATES` | `200` | Maximum indexed alert rows inspected per ingest |
| `CORRELATION_MAX_LINKS` | `50` | Maximum automatic links in one plan |
| `CORRELATION_RETRY_ATTEMPTS` | `1` | SQLite busy retries; maximum accepted value is 3 |

Candidate lookup uses `(agent_id, occurred_at, alert_id, rule_id)` and is bounded by time, supported rule IDs,
agent, and row limit. Detail timeline retrieval is one ordered join, not one query per alert. Idle
CPU and memory overhead are zero beyond loaded Python code. Configuration validation caps the window
at 24 hours, candidates at 5,000, links at 100, and retries at 3.

## Historical dry-run

Startup never backfills. This read-only command opens SQLite with `mode=ro`, sets `query_only`,
prints candidate groups, and performs no writes:

```powershell
cd backend
$env:PYTHONPATH='.'
.venv\Scripts\python.exe -m app.cli.correlate_alerts --limit 1000
```

Use `--database-url sqlite:///...` and `--window-seconds ...` for explicit evaluation. The command
has no apply mode; historical incidents require a separate reviewed operator decision.

## Extending and testing

Add a bounded rule to `build_correlation_plan`, define its identity requirements and precedence,
then add positive, missing-field, cross-identity, window-boundary, delayed-delivery, lifecycle,
rollback, and concurrency tests in `backend/tests/test_incident_correlation.py`. Never execute event
content, perform network calls, or introduce probability scores into this engine.
