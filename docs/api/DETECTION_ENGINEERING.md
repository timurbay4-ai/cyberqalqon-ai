# Detection engineering API

All endpoints require an authenticated analyst with `soc:read`. Draft mutations additionally
require `alert:write`, the session CSRF header, and the configured trusted origin. Optimistic
mutations use `expected_version`; stale writes return `409`.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/v1/detection-engineering/rules` | Consolidated Wazuh, observed, and M9 correlation inventory |
| GET | `/api/v1/detection-engineering/rules/{rule_id}` | Rule detail |
| GET | `/api/v1/detection-engineering/coverage` | Explicit MITRE mappings and distinct enabled/triggered/tested counts |
| GET | `/api/v1/detection-engineering/advanced-rules?days=30` | Disabled M11 catalog with prerequisites and evidence-backed telemetry availability |
| GET | `/api/v1/detection-engineering/advanced-rules/{rule_id}` | Complete `DET-001`–`DET-009` rule metadata and validation contract |
| POST | `/api/v1/detection-engineering/advanced-rules/{rule_id}/dry-run` | Run the shared sequence/threshold evaluator over at most 1,000 events and 31 days |
| GET | `/api/v1/detection-engineering/analytics?days=30` | Bounded trends, top entities, dispositions, IOC and false-positive summaries |
| GET/POST | `/api/v1/detection-engineering/drafts` | List or create local declarative drafts |
| GET/PUT | `/api/v1/detection-engineering/drafts/{draft_id}` | Read or version a draft |
| POST | `/api/v1/detection-engineering/drafts/{draft_id}/validate` | Validate the allowlisted schema |
| POST | `/api/v1/detection-engineering/drafts/{draft_id}/dry-run` | Evaluate at most 1,000 historical events over at most 31 days |
| POST | `/api/v1/detection-engineering/drafts/{draft_id}/confirm-manual-deployment` | Record explicit readiness for separate operator review |
| GET | `/api/v1/detection-engineering/drafts/{draft_id}/versions` | Immutable version snapshots |
| POST | `/api/v1/detection-engineering/drafts/{draft_id}/rollback` | Copy an earlier snapshot into a new `DRAFT` version |

Draft conditions are an AND-list of one to eight allowlisted normalized event fields. Operators
are `EQUALS`, `CONTAINS`, and `STARTS_WITH`; values are always bound parameters. SQL, Python,
regular expressions, shell expressions, and arbitrary field names are not accepted.

The v1.0 endpoint allowlist includes OS, provider, channel, process name/path, redacted command
line, and parent process name/path in addition to the existing identity, network, event, outcome,
rule, and message fields. Partial matching remains restricted to textual fields; IPs and categorical
fields require exact matching. Command-line dry-runs warn that results depend on endpoint audit
policy and the redacted text actually collected.

Lifecycle is `DRAFT → VALIDATED → TESTED → READY_FOR_MANUAL_DEPLOYMENT`. Updating or rolling back
creates a new `DRAFT` version. Dry-run records only test metadata and audit evidence; it never
creates alerts, incidents, or notifications. The confirmation endpoint returns
`live_wazuh_modified=false` and `deployment_mode=MANUAL_REVIEW_ONLY`. CyberQalqon does not write,
reload, or restart live Wazuh configuration.

External Wazuh rule versions and enabled state remain unavailable when no authoritative Wazuh API
is configured. The API reports `UNKNOWN`/`UNAVAILABLE` rather than deriving those facts from a
stored alert. An observed alert proves only that a rule triggered at least once.

## M11 advanced rules

`DET-001` through `DET-009` are packaged, versioned definitions for Windows authentication,
privilege/account changes, PowerShell, service installation, Linux SSH/sudo, and Defender
lifecycle evidence. Every definition exposes its source/event prerequisites, required fields,
conditions, grouping, event-time window, threshold, deterministic dedupe policy, severity, justified
MITRE mappings, false-positive notes, evidence contract, analyst guidance, version, and validation
notes. Every rule returns `enabled=false` and `activation_state=DISABLED_BY_POLICY`; the API has no
enable endpoint.

The advanced dry-run sorts bounded candidate events by source timestamp and stable event ID, then
uses the same evaluator intended for a future live caller. It returns explained finding groups,
the contributing event IDs, threshold, grouping values, evidence summaries, dedupe key, severity,
and telemetry availability. Full command/script text is not copied into finding summaries.
`max_events` is capped at 1,000, `max_findings` at 100, the range at 31 days, and
`max_execution_ms` at 5,000 (default 1,000). SQLite progress interruption and a post-evaluation
deadline check fail the request with `evaluation_limit` if the wall-clock budget is exceeded. The
call is RBAC/CSRF protected and audited, but creates no alert, incident, case, notification, or
Wazuh change.

Availability is deliberately split into parser support, stored data observed, recently observed,
required-field sufficiency, and live configuration status. Stored evidence never proves a live
collector is configured; configuration remains `UNKNOWN` until an authoritative management source
is added.
