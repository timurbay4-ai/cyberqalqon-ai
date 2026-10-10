import { useEffect, useState, type FormEvent } from "react";

import { ALERT_WORKFLOW_STATUSES, type AlertAssignee, type AlertWorkflowSort, type AlertWorkflowStatus, type SeverityBand } from "../types/alerts";
import { SEVERITY_BANDS, severityLabel, severityRange } from "../utils/severity";

export interface AlertFilterValues {
  search: string;
  ruleId: string;
  agent: string;
  severityBands: SeverityBand[];
  mitreMode: "any" | "mapped" | "unmapped";
  mitreId: string;
  startTime: string;
  endTime: string;
  status: AlertWorkflowStatus | "";
  assignedTo: string;
  unassigned: boolean;
  sort: AlertWorkflowSort;
}

export const EMPTY_ALERT_FILTERS: AlertFilterValues = {
  search: "",
  ruleId: "",
  agent: "",
  severityBands: [],
  mitreMode: "any",
  mitreId: "",
  startTime: "",
  endTime: "",
  status: "",
  assignedTo: "",
  unassigned: false,
  sort: "time_desc",
};

export function AlertFilters({ values, assignees = [], onApply }: { values: AlertFilterValues; assignees?: AlertAssignee[]; onApply(values: AlertFilterValues): void }) {
  const [draft, setDraft] = useState(values);
  useEffect(() => setDraft(values), [values]);

  const toggleBand = (band: SeverityBand) => setDraft((current) => ({
    ...current,
    severityBands: current.severityBands.includes(band)
      ? current.severityBands.filter((item) => item !== band)
      : [...current.severityBands, band],
  }));

  const submit = (event: FormEvent) => {
    event.preventDefault();
    onApply(draft);
  };

  return (
    <form className="filters" aria-label="Alert filters" onSubmit={submit}>
      <label className="field field--grow"><span>Search</span><input type="search" value={draft.search} maxLength={200} placeholder="Rule, asset, user, IP or MITRE" onChange={(event) => setDraft({ ...draft, search: event.target.value })} /></label>
      <label className="field"><span>Rule ID</span><input value={draft.ruleId} maxLength={128} placeholder="Exact rule ID" onChange={(event) => setDraft({ ...draft, ruleId: event.target.value })} /></label>
      <label className="field"><span>Agent</span><input value={draft.agent} maxLength={255} placeholder="Exact ID or name" onChange={(event) => setDraft({ ...draft, agent: event.target.value })} /></label>
      <label className="field"><span>Workflow status</span><select value={draft.status} onChange={(event) => setDraft({ ...draft, status: event.target.value as AlertWorkflowStatus | "" })}><option value="">All statuses</option>{ALERT_WORKFLOW_STATUSES.map((value) => <option value={value} key={value}>{value.replaceAll("_", " ")}</option>)}</select></label>
      <label className="field"><span>Assignee</span><select value={draft.assignedTo} disabled={draft.unassigned} onChange={(event) => setDraft({ ...draft, assignedTo: event.target.value })}><option value="">Any assignee</option>{assignees.map((assignee) => <option value={assignee.analyst_id} key={assignee.analyst_id}>{assignee.display_name} ({assignee.username})</option>)}</select></label>
      <label className="field field--checkbox"><span>Assignment</span><span><input type="checkbox" aria-label="Unassigned only" checked={draft.unassigned} onChange={(event) => setDraft({ ...draft, unassigned: event.target.checked, assignedTo: event.target.checked ? "" : draft.assignedTo })} /> Unassigned only</span></label>
      <label className="field"><span>Sort</span><select value={draft.sort} onChange={(event) => setDraft({ ...draft, sort: event.target.value as AlertWorkflowSort })}><option value="time_desc">Newest alert</option><option value="time_asc">Oldest alert</option><option value="severity_desc">Highest severity</option><option value="severity_asc">Lowest severity</option><option value="activity_desc">Latest activity</option></select></label>
      <label className="field"><span>MITRE mapping</span><select value={draft.mitreMode} onChange={(event) => setDraft({ ...draft, mitreMode: event.target.value as AlertFilterValues["mitreMode"] })}><option value="any">Any</option><option value="mapped">Mapped</option><option value="unmapped">Unmapped</option></select></label>
      <label className="field"><span>MITRE ID</span><input value={draft.mitreId} maxLength={9} placeholder="T1110" onChange={(event) => setDraft({ ...draft, mitreId: event.target.value.toUpperCase() })} /></label>
      <label className="field"><span>From</span><input type="datetime-local" value={draft.startTime} onChange={(event) => setDraft({ ...draft, startTime: event.target.value })} /></label>
      <label className="field"><span>To</span><input type="datetime-local" value={draft.endTime} onChange={(event) => setDraft({ ...draft, endTime: event.target.value })} /></label>
      <fieldset className="severity-fieldset">
        <legend>Severity</legend>
        <div className="filter-chips">
          {SEVERITY_BANDS.map((band) => <button className={`filter-chip filter-chip--${band}${draft.severityBands.includes(band) ? " is-selected" : ""}`} type="button" aria-pressed={draft.severityBands.includes(band)} onClick={() => toggleBand(band)} key={band}>{severityLabel(band)} <span>{severityRange(band)}</span></button>)}
        </div>
      </fieldset>
      <div className="filter-actions">
        <button className="button button--primary" type="submit">Apply filters</button>
        <button className="button button--ghost" type="button" onClick={() => { setDraft(EMPTY_ALERT_FILTERS); onApply(EMPTY_ALERT_FILTERS); }}>Reset</button>
      </div>
    </form>
  );
}
