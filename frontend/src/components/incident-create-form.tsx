import { useState, type FormEvent } from "react";

import { INCIDENT_SEVERITIES, type IncidentCreate, type IncidentSeverity } from "../types/incidents";
import { humanize } from "../utils/format";

export function IncidentCreateForm({ busy, error, onCancel, onCreate }: { busy: boolean; error: string | null; onCancel(): void; onCreate(payload: IncidentCreate): Promise<void> }) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<IncidentSeverity>("MEDIUM");
  const [assignedTo, setAssignedTo] = useState("");
  const [alertId, setAlertId] = useState("");
  const submit = (event: FormEvent) => {
    event.preventDefault();
    void onCreate({ title, description, severity, assigned_to: assignedTo.trim() || null, alert_ids: alertId.trim() ? [alertId.trim()] : [] });
  };
  return (
    <section className="panel create-panel" aria-label="Create incident">
      <header className="panel__header"><div><span className="eyebrow">Deterministic workflow</span><h2>Create incident</h2></div><button className="icon-button" type="button" aria-label="Close create incident" onClick={onCancel}>×</button></header>
      <form className="form-grid" onSubmit={submit}>
        <label className="field field--wide"><span>Title</span><input required maxLength={255} value={title} onChange={(event) => setTitle(event.target.value)} /></label>
        <label className="field"><span>Severity</span><select value={severity} onChange={(event) => setSeverity(event.target.value as IncidentSeverity)}>{INCIDENT_SEVERITIES.map((item) => <option value={item} key={item}>{humanize(item)}</option>)}</select></label>
        <label className="field"><span>Assign to (optional)</span><input maxLength={128} value={assignedTo} onChange={(event) => setAssignedTo(event.target.value)} /></label>
        <label className="field"><span>Initial alert ID (optional)</span><input maxLength={255} value={alertId} onChange={(event) => setAlertId(event.target.value)} /></label>
        <label className="field field--wide"><span>Description</span><textarea maxLength={4096} rows={4} value={description} onChange={(event) => setDescription(event.target.value)} /></label>
        {error && <p className="form-message form-message--error" role="alert">{error}</p>}
        <div className="form-actions"><button className="button button--primary" disabled={busy} type="submit">{busy ? "Creating…" : "Create incident"}</button><button className="button button--secondary" disabled={busy} type="button" onClick={onCancel}>Cancel</button></div>
      </form>
    </section>
  );
}
