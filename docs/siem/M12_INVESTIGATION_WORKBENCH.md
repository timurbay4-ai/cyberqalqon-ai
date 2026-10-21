# M12 Analyst Investigation Workbench

Status: implemented in source; live schema migration and authenticated browser UAT not performed.

## Purpose

M12 provides one evidence-first workspace over existing CyberQalqon records. It does not introduce
a second correlation engine or a new investigation datastore. The projection resolves an event,
alert, incident, case, M9 correlation group, M11 dry-run finding, or supported entity to a primary
stored security event and composes context from the existing owners:

`security_events -> alerts -> incidents/correlations -> cases -> analyst activity`

M11 findings are re-evaluated by the existing deterministic evaluator. They remain transient,
disabled, and side-effect free.

## Reused components

- M10 normalized event and redacted evidence fields;
- M9 incident/correlation tables and explanations;
- M11 rule catalog, evaluator, finding evidence, thresholds, ordering, dedupe key, prerequisites,
  ATT&CK rationale, and execution metadata;
- existing alert, incident, case, evidence-pin, note, IOC, audit, RBAC, Origin, session, and CSRF
  services;
- Discover filters, keyset pagination, event detail, safe history state, and user preferences.

No workflow state is copied into an M12 table. Mutations continue through their owning API.

## Investigation targets

| Analyst target | Resolution |
|---|---|
| Event | Exact immutable event ID |
| Alert | Earliest stored event carrying the alert/source ID |
| Incident | Earliest event linked through `incident_alerts` |
| Case | Direct event, alert, or incident reference |
| Correlation group | Existing M9 correlation key/incident, never a new correlation |
| M11 finding | Exact SHA-256 dedupe key from a bounded server-side re-evaluation |
| Host, user, IP, destination, agent, rule, process | Exact normalized indexed entity |
| Domain or file hash | Exact token in the bounded event FTS document |
| IOC match | Entity investigation plus exact active local IOC context |

Sensitive values such as usernames, IP addresses, domains, hashes, and evidence are carried in
browser history state and a CSRF-protected POST body. They are not written to the URL.

## Relationship definitions

Time proximity alone is never a relationship. Related events must share at least one real field or
persisted ownership link:

- `SAME_SOURCE_IP`, `SAME_DESTINATION_IP` — normalized endpoint equality;
- `SAME_HOST`, `SAME_ACCOUNT`, `SAME_AGENT`, `SAME_RULE` — exact normalized identity;
- `SAME_PROCESS_NAME`, `SAME_PROCESS_ID` — exact endpoint context and M12 schema-17 index present;
- `SAME_INCIDENT` — alerts are linked to the same existing incident;
- `SAME_CASE` — direct event, alert, or incident references resolve to the same case;
- `SAME_CORRELATION_GROUP` — events belong to the existing M9-correlated incident.

Each source query is bounded, merged by immutable event ID, and labels every proven relationship.
An event with the same timestamp remains a separate item. `related_truncated` tells the UI that the
snapshot hit its cap; Discover remains the full keyset-paginated event explorer.

## Unified timeline

The projection merges security events, alerts, an optional M11 finding, incident history and notes,
case activity/comments, and evidence actions. Sorting is stable on timestamp and immutable item ID.
`EVENT_TIME` and `ANALYST_ACTION_TIME` are explicit, future timestamps are marked, duplicate item
keys are suppressed without merging distinct events, and the UI provides type, severity, local-time,
and direction filters plus expand/collapse controls.

## Deterministic summary and explanation

Summary text uses explicit templates and stored facts. Observations identify time, source, host,
account, rule, and linked records when present. Missing fields are listed. Every projection carries
the boundary that suspicious facts do not establish attacker intent or confirmed compromise.

For an M11 target, the page shows the catalog rule, disabled state, severity, family, matched
conditions and evidence, threshold, window, event-time order, grouping keys, dedupe key, ATT&CK
rationale, prerequisite/availability evidence, and dry-run budget. No explanation is synthesized
outside the evaluator contract. `DET-009` therefore retains its supported Defender lifecycle
explanation without inventing a blanket ATT&CK mapping.

## Analyst actions and ownership

The workbench exposes only existing, authorized actions:

- copy immutable IDs and redacted evidence;
- open event, alert, incident, case, or rule detail;
- pin an event to an existing linked incident;
- add a note to an existing linked incident;
- associate the event with an explicitly supplied existing case using its current version.

The last three call existing audited APIs. M12 never silently creates an alert, incident, case,
notification, note, or evidence record. Read-only users do not see mutation controls, and the
backend still enforces permission, Origin, CSRF, version, and validation requirements.

## Schema compatibility

The live database remains schema 15. M12 aliases absent schema-16 endpoint fields to honest null or
empty defaults and reports the actual schema version. Process pivots are disabled and listed as
unavailable until schema 17 adds only these optional indexes:

- `idx_security_events_process_name_time`;
- `idx_security_events_process_id_time`.

No live migration was run. Isolated tests cover schema 15 and schema 17. A future live upgrade still
requires the normal backup, copied rehearsal, explicit approval, migration, integrity check, and
rollback procedure.

## Query/resource limits

- investigation range: 15 minutes through 31 days;
- related events: 1–100;
- timeline items: 1–200;
- execution budget: 50–5,000 ms;
- M11 re-evaluation: unchanged 1,000 events and 100 findings;
- entities: 50; IOC response: 50; correlation groups: 20;
- SQLite connection is `query_only` and explicitly closed after every projection.

No polling loop, cache service, model, Docker service, or external threat-intelligence request was
added.
