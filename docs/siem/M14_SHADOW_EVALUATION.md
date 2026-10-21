# M14 shadow evaluation and tuning

Shadow evaluation is explicitly operator-triggered and reads existing
`security_events`. It records a run ID, rule/configuration version, time range,
source availability, evaluated/matched/duplicate/missing counts, truncation,
wall/CPU measurements, outcome, and bounded findings. Findings use the
`SHADOW` namespace and expose `production_alert_id`, `production_incident_id`,
and `production_case_id` only as enforced `null` values.

Limits are: 31 days, 5,000 input events, 200 stored findings, and 5,000 ms.
Timeout, database-busy, invalid configuration, and future-window conditions fail
closed. A failed shadow run never blocks ordinary ingestion. There is no
scheduled or always-on shadow worker.

Tuning compares two to five declarative threshold/window candidates over the
same bounded evidence. Results show matches/findings, duplicates, missing-field
impact, repeated findings, and top source/host/user counts. The interpretation
explicitly states that fewer findings do not mean better detection quality and
unlabeled events are neither true nor false positives. No automatic suppression
or deployment follows a comparison.

M12 opens an exact shadow finding by POST body, preserving sensitive-URL rules.
It reuses existing supporting-event, correlation sequence, entity, incident,
and evidence contracts and never fabricates relationships.
