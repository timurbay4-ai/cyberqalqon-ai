# SOC investigation guide

## Start an investigation

1. In Discover, set the smallest useful time range and filters.
2. Open the stored event and review normalized fields plus the redacted source envelope.
3. Select **Open Investigation Workbench**.
4. Read **Observed facts**, **Interpretation boundary**, and **Unavailable fields** before forming a
   conclusion.
5. Use entity pivots and relationship labels to expand only evidence-backed context.
6. Use **Return to results** or browser Back. Discover restores applied filters, sort, cursor stack,
   selected evidence, and non-sensitive URL state.

Sensitive user/IP/host/domain/hash pivots remain in local history state and a protected POST body.
Do not copy raw browser state into tickets or shared URLs.

## Read the primary event

Compare original event time with ingestion time, then review source type, agent/host, event/rule ID,
severity, endpoints, account, process context, normalized fields, and redacted raw evidence.
`Unavailable` means the field is absent or the live schema cannot serve the indexed relationship;
it does not mean a negative fact. Copy only the redacted JSON offered by the UI.

## Follow related activity

Every card states why it is related. Shared source/destination IP, host, account, agent, rule,
process, incident, case, or M9 correlation group are supported. Two records close in time are not
declared related unless they also share a supported field or persisted link. Open a result in
Discover for the regular keyset-paginated view, or investigate it as a new primary event.

## Interpret an M11 dry-run finding

Run a bounded dry-run from Detection Engineering and open a returned finding. Confirm:

- rule ID/name/family and `DISABLED_BY_POLICY` state;
- prerequisite and telemetry availability evidence;
- matched conditions and evidence IDs;
- threshold, evaluation window, event-time order, grouping keys, and dedupe key;
- ATT&CK mapping rationale, including any intentionally unmapped branch;
- evaluated count, execution budget, and `side_effects=false`.

For `DET-002`, the evidence must show the scoped 4625 failures before the 4624 success in event
time and within the declared window. Arrival order is not proof of sequence. For `DET-009`, use the
actual Defender detection/remediation/protection lifecycle explanation; do not add an unsupported
blanket ATT&CK technique.

Opening a finding re-evaluates its exact dedupe key in the requested bounded range. It does not
persist the finding or create an alert, incident, case, or notification.

## Use the timeline

Timeline items retain immutable IDs even when timestamps match. Filter by type, minimum severity,
and local From/Until time; switch chronological direction; expand details; and note whether the
timestamp is `EVENT_TIME` or `ANALYST_ACTION_TIME`. A future timestamp is explicitly marked and
should be validated against endpoint clock configuration. Missing timestamps are not fabricated.

## Use IOC context

IOC context comes only from CyberQalqon's local repository. It is an exact match against an
extracted IPv4, IPv6, domain, or file hash and includes source, confidence, expiration, and evidence
field. It never contacts an external service or blocks traffic. An IOC match is context, not proof
of compromise.

## Take analyst actions

If authorized, the workbench can pin the event to an already-linked incident, add an incident note,
or associate it with an explicitly named existing case. These use existing audited workflows and
never create a new container silently. Case association first reads the current case version;
concurrent changes fail safely through the owning API. Read-only analysts see no mutation controls.

Prefer short factual notes with event IDs and observed timestamps. Do not paste secrets or
unredacted evidence into notes. Continue status, assignment, evidence annotation, playbook, and case
closure work in the owning incident/case workspace.

## Known operational boundary

The live lab database is still schema 15. Host/user/IP/rule/agent pivots work, while process
relationship pivots remain unavailable until an explicitly approved schema-17 upgrade. M11 remains
dry-run only. Authenticated real-browser UAT is separate from automated frontend tests and must not
be claimed until executed.
