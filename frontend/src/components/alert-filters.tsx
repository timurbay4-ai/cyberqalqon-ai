import { useEffect, useState, type FormEvent } from "react";

import type { SeverityBand } from "../types/alerts";
import { SEVERITY_BANDS, severityLabel, severityRange } from "../utils/severity";

export interface AlertFilterValues {
  search: string;
  agent: string;
  severityBands: SeverityBand[];
  mitreMode: "any" | "mapped" | "unmapped";
  mitreId: string;
  startTime: string;
  endTime: string;
}

export const EMPTY_ALERT_FILTERS: AlertFilterValues = {
  search: "",
  agent: "",
  severityBands: [],
  mitreMode: "any",
  mitreId: "",
  startTime: "",
  endTime: "",
};

export function AlertFilters({ values, onApply }: { values: AlertFilterValues; onApply(values: AlertFilterValues): void }) {
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
      <label className="field"><span>Agent</span><input value={draft.agent} maxLength={255} placeholder="Exact ID or name" onChange={(event) => setDraft({ ...draft, agent: event.target.value })} /></label>
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
