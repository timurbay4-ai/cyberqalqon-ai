import { useEffect, useState, type FormEvent } from "react";

import { INCIDENT_SEVERITIES, INCIDENT_STATUSES, type IncidentSeverity, type IncidentStatus } from "../types/incidents";
import { humanize } from "../utils/format";

export interface IncidentFilterValues {
  status: IncidentStatus | "";
  severity: IncidentSeverity | "";
  assignedTo: string;
}

export const EMPTY_INCIDENT_FILTERS: IncidentFilterValues = { status: "", severity: "", assignedTo: "" };

export function IncidentFilters({ values, onApply }: { values: IncidentFilterValues; onApply(values: IncidentFilterValues): void }) {
  const [draft, setDraft] = useState(values);
  useEffect(() => setDraft(values), [values]);
  const submit = (event: FormEvent) => { event.preventDefault(); onApply(draft); };
  return (
    <form className="filters filters--compact" aria-label="Incident filters" onSubmit={submit}>
      <label className="field"><span>Status</span><select value={draft.status} onChange={(event) => setDraft({ ...draft, status: event.target.value as IncidentStatus | "" })}><option value="">All statuses</option>{INCIDENT_STATUSES.map((status) => <option value={status} key={status}>{humanize(status)}</option>)}</select></label>
      <label className="field"><span>Severity</span><select value={draft.severity} onChange={(event) => setDraft({ ...draft, severity: event.target.value as IncidentSeverity | "" })}><option value="">All severities</option>{INCIDENT_SEVERITIES.map((severity) => <option value={severity} key={severity}>{humanize(severity)}</option>)}</select></label>
      <label className="field field--grow"><span>Assigned to</span><input value={draft.assignedTo} maxLength={128} placeholder="Exact analyst identifier" onChange={(event) => setDraft({ ...draft, assignedTo: event.target.value })} /></label>
      <div className="filter-actions"><button className="button button--primary" type="submit">Apply filters</button><button className="button button--ghost" type="button" onClick={() => { setDraft(EMPTY_INCIDENT_FILTERS); onApply(EMPTY_INCIDENT_FILTERS); }}>Reset</button></div>
    </form>
  );
}
