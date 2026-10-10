import { useEffect, useState, type FormEvent } from "react";

import { ALLOWED_STATUS_TRANSITIONS, type IncidentDetail as IncidentDetailModel, type IncidentStatus } from "../types/incidents";
import { formatTimestamp, humanize } from "../utils/format";
import { IncidentSeverityBadge, IncidentStatusBadge } from "./incident-badges";
import { AIAnalysisPanel } from "./ai-analysis-panel";
import type { BackendApi } from "../types/api";
import { CopyButton } from "./copy-button";
import { InvestigationWorkspace } from "./investigation-workspace";

interface IncidentDetailProps {
  incident: IncidentDetailModel;
  busy: boolean;
  error: string | null;
  success: string | null;
  canMutate: boolean;
  api: BackendApi;
  onClose(): void;
  onOpenAlert?(alertId: string): void;
  onOpenEvent?(eventId: string): void;
  onStatus(status: IncidentStatus): Promise<boolean>;
  onLink(alertId: string): Promise<boolean>;
  onNote(body: string): Promise<boolean>;
  onAssignment(assignedTo: string | null): Promise<boolean>;
}

export function IncidentDetail({ incident, api, busy, error, success, canMutate, onClose, onOpenAlert = () => undefined, onOpenEvent = () => undefined, onStatus, onLink, onNote, onAssignment }: IncidentDetailProps) {
  const transitions = ALLOWED_STATUS_TRANSITIONS[incident.status];
  const [nextStatus, setNextStatus] = useState<IncidentStatus>(transitions[0]);
  const [alertId, setAlertId] = useState("");
  const [note, setNote] = useState("");
  const [assignedTo, setAssignedTo] = useState(incident.assigned_to ?? "");

  useEffect(() => {
    setNextStatus(ALLOWED_STATUS_TRANSITIONS[incident.status][0]);
    setAssignedTo(incident.assigned_to ?? "");
  }, [incident.assigned_to, incident.status]);

  const submit = (operation: () => Promise<boolean>, clear?: () => void) => async (event: FormEvent) => {
    event.preventDefault();
    if (await operation()) clear?.();
  };

  return (
    <aside className="detail-panel incident-detail" aria-label="Incident detail">
      <header className="detail-panel__header"><div><span className="eyebrow">Authoritative incident</span><h2>{incident.title}</h2><span className="mono subtle">{incident.incident_id}</span></div><button className="icon-button" type="button" aria-label="Close incident detail" onClick={onClose}>×</button></header>
      <div className="detail-panel__body">
        <div className="detail-hero"><IncidentSeverityBadge severity={incident.severity} /><IncidentStatusBadge status={incident.status} /></div>
        <div className="copy-actions"><CopyButton value={incident.incident_id} label="Copy incident ID" />{incident.alert_ids.length > 0 && <CopyButton value={incident.alert_ids.join("\n")} label="Copy alert references" />}</div>
        <p className="incident-description">{incident.description || "No description supplied."}</p>
        <dl className="metadata-grid"><div><dt>Assigned to</dt><dd>{incident.assigned_to ?? "Unassigned"}</dd></div><div><dt>Updated</dt><dd>{formatTimestamp(incident.updated_at)}</dd></div><div><dt>Created</dt><dd>{formatTimestamp(incident.created_at)}</dd></div><div><dt>Linked alerts</dt><dd>{incident.alert_count}</dd></div></dl>

        {incident.correlation && <section className="detail-section correlation-summary" aria-label="Correlation summary">
          <div className="section-heading"><h3>Automatic correlation</h3><span className="correlation-badge">{incident.correlation.correlation_rule}</span></div>
          <p>{incident.correlation.explanation}</p>
          <dl className="metadata-grid">
            <div><dt>Classification</dt><dd>{humanize(incident.correlation.classification)}</dd></div>
            <div><dt>Confidence</dt><dd>{humanize(incident.correlation.confidence)}</dd></div>
            <div><dt>Scoped source</dt><dd className="mono">{incident.correlation.source_identity}</dd></div>
            <div><dt>Target identity</dt><dd className="mono">{incident.correlation.target_identity}</dd></div>
            <div><dt>First seen</dt><dd>{formatTimestamp(incident.correlation.first_seen)}</dd></div>
            <div><dt>Last seen</dt><dd>{formatTimestamp(incident.correlation.last_seen)}</dd></div>
          </dl>
        </section>}

        <section className="detail-section"><h3>Alert timeline</h3>{incident.timeline.length ? <ol className="timeline alert-timeline">{incident.timeline.map((alert) => <li key={alert.alert_id}>
          <div><strong>Rule {alert.rule_id} · Level {alert.rule_level}</strong><time>{formatTimestamp(alert.occurred_at)}</time></div>
          <p>{alert.rule_description}</p>
          <p className="timeline-evidence">Agent: {alert.agent_name} ({alert.agent_id}) · Source: {alert.source_ip ?? "not available"} · Destination: {alert.destination_ip ?? incident.correlation?.target_identity ?? "not available"}</p>
          {alert.mitre_ids.length > 0 && <p>MITRE ATT&amp;CK: {alert.mitre_ids.join(", ")}</p>}
          <button className="text-link mono text-link--button" type="button" onClick={() => onOpenAlert(alert.alert_id)}>Open alert {alert.alert_id}</button>
        </li>)}</ol> : <p className="muted">No linked alert evidence.</p>}</section>

        <section className="detail-section mutation-section">
          <h3>{canMutate ? "Authenticated analyst action" : "Read-only access"}</h3>
          <p className="trust-note">{canMutate ? "Audit identity is supplied by the authenticated backend session." : "Your Viewer role cannot modify incidents."}</p>
          {error && <p className="form-message form-message--error" role="alert">{error}</p>}
          {success && <p className="form-message form-message--success" role="status">{success}</p>}
        </section>

        {canMutate && <section className="detail-section"><h3>Lifecycle</h3><form className="inline-form" onSubmit={submit(() => onStatus(nextStatus))}><label className="field"><span>Allowed transition</span><select aria-label="Allowed transition" value={nextStatus} onChange={(event) => setNextStatus(event.target.value as IncidentStatus)}>{transitions.map((status) => <option value={status} key={status}>{humanize(status)}</option>)}</select></label><button className="button button--primary" disabled={busy} type="submit">{busy ? "Saving…" : "Update status"}</button></form></section>}

        {canMutate && <section className="detail-section"><h3>Assignment</h3><form className="inline-form" onSubmit={submit(() => onAssignment(assignedTo.trim() || null))}><label className="field"><span>Analyst identifier</span><input maxLength={128} value={assignedTo} onChange={(event) => setAssignedTo(event.target.value)} placeholder="Blank to unassign" /></label><button className="button button--secondary" disabled={busy} type="submit">Save assignment</button></form></section>}

        <section className="detail-section"><h3>Linked alerts</h3>{incident.alert_ids.length ? <ul className="id-list">{incident.alert_ids.map((id) => <li className="mono" key={id}>{id}</li>)}</ul> : <p className="muted">No alerts linked.</p>}{canMutate && <form className="inline-form" onSubmit={submit(() => onLink(alertId), () => setAlertId(""))}><label className="field"><span>Existing alert ID</span><input required maxLength={255} value={alertId} onChange={(event) => setAlertId(event.target.value)} /></label><button className="button button--secondary" disabled={busy} type="submit">Link alert</button></form>}</section>

        <section className="detail-section"><h3>Analyst notes</h3>{incident.notes.length ? <ol className="timeline notes-list">{incident.notes.map((item) => <li key={item.note_id}><div><strong>{item.author}</strong><time>{formatTimestamp(item.created_at)}</time></div><p>{item.body}</p></li>)}</ol> : <p className="muted">No notes recorded.</p>}{canMutate && <form className="stack-form" onSubmit={submit(() => onNote(note), () => setNote(""))}><label className="field"><span>New note</span><textarea required maxLength={4096} rows={3} value={note} onChange={(event) => setNote(event.target.value)} /></label><button className="button button--secondary" disabled={busy} type="submit">Add note</button></form>}</section>

        <section className="detail-section"><InvestigationWorkspace api={api} incidentId={incident.incident_id} canMutate={canMutate} onOpenAlert={onOpenAlert} onOpenEvent={onOpenEvent} /></section>

        <section className="detail-section"><h3>Audit history</h3><ol className="timeline audit-list">{incident.history.map((event) => <li key={event.event_id}><div><strong>{humanize(event.event_type)}</strong><time>{formatTimestamp(event.occurred_at)}</time></div><p>Actor: {event.actor}</p><code>{JSON.stringify(event.details)}</code></li>)}</ol></section>
        <AIAnalysisPanel api={api} targetType="incident" targetId={incident.incident_id} />
      </div>
    </aside>
  );
}
