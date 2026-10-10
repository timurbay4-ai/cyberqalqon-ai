import { useEffect, useState, type FormEvent } from "react";

import { ALERT_WORKFLOW_STATUSES, type AlertAssignee, type AlertWorkflowDetail, type AlertWorkflowStatus } from "../types/alerts";
import { formatTimestamp } from "../utils/format";

const NEXT_STATUSES: Record<AlertWorkflowStatus, AlertWorkflowStatus[]> = {
  NEW: ["ACKNOWLEDGED", "FALSE_POSITIVE"],
  ACKNOWLEDGED: ["IN_PROGRESS", "RESOLVED", "FALSE_POSITIVE"],
  IN_PROGRESS: ["RESOLVED", "FALSE_POSITIVE"],
  RESOLVED: [],
  FALSE_POSITIVE: [],
};

export function AlertWorkflowPanel({ workflow, assignees, canMutate, busy, error, success, onStatus, onAssignment, onNote }: {
  workflow: AlertWorkflowDetail;
  assignees: AlertAssignee[];
  canMutate: boolean;
  busy: boolean;
  error: string | null;
  success: string | null;
  onStatus(status: AlertWorkflowStatus): void;
  onAssignment(analystId: string | null): void;
  onNote(body: string): void;
}) {
  const [status, setStatus] = useState<AlertWorkflowStatus | "">("");
  const [assignee, setAssignee] = useState(workflow.assignee?.analyst_id ?? "");
  const [note, setNote] = useState("");
  useEffect(() => setAssignee(workflow.assignee?.analyst_id ?? ""), [workflow.assignee?.analyst_id]);

  const submitNote = (event: FormEvent) => {
    event.preventDefault();
    const body = note.trim();
    if (!body) return;
    onNote(body);
    setNote("");
  };
  const changeStatus = () => {
    if (!status) return;
    if ((status === "RESOLVED" || status === "FALSE_POSITIVE") && !window.confirm(`Change this alert to ${status.replaceAll("_", " ")}? This terminal state cannot be reopened.`)) return;
    onStatus(status);
    setStatus("");
  };

  return (
    <section className="detail-section workflow-panel">
      <div className="section-title-row"><h3>Analyst workflow</h3><span className={`workflow-badge workflow-badge--${workflow.status.toLowerCase()}`}>{workflow.status.replaceAll("_", " ")}</span></div>
      <dl className="metadata-grid"><div><dt>Assignee</dt><dd>{workflow.assignee ? `${workflow.assignee.display_name} (${workflow.assignee.username})` : "Unassigned"}</dd></div><div><dt>Last activity</dt><dd>{formatTimestamp(workflow.last_activity_at)}</dd></div><div><dt>Version</dt><dd>{workflow.version}</dd></div><div><dt>Notes</dt><dd>{workflow.note_count}</dd></div></dl>
      {error && <p className="inline-error" role="alert">{error}</p>}
      {success && <p className="inline-success" role="status">{success}</p>}
      {!canMutate && <p className="trust-note">Your role has read-only access to alert workflow data.</p>}
      {canMutate && <div className="workflow-controls">
        <label className="field"><span>Next status</span><select value={status} disabled={busy || NEXT_STATUSES[workflow.status].length === 0} onChange={(event) => setStatus(event.target.value as AlertWorkflowStatus | "")}><option value="">Select transition</option>{NEXT_STATUSES[workflow.status].map((value) => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}</select></label>
        <button className="button button--primary" type="button" disabled={busy || !status} onClick={changeStatus}>Update status</button>
        <label className="field"><span>Assign analyst</span><select value={assignee} disabled={busy} onChange={(event) => setAssignee(event.target.value)}><option value="">Unassigned</option>{assignees.map((item) => <option key={item.analyst_id} value={item.analyst_id}>{item.display_name} ({item.username})</option>)}</select></label>
        <button className="button button--ghost" type="button" disabled={busy || assignee === (workflow.assignee?.analyst_id ?? "")} onClick={() => onAssignment(assignee || null)}>Save assignment</button>
      </div>}
      {canMutate && <form className="workflow-note-form" onSubmit={submitNote}><label className="field"><span>Add analyst note</span><textarea value={note} maxLength={4096} rows={3} disabled={busy} onChange={(event) => setNote(event.target.value)} placeholder="Record investigation evidence or next steps" /></label><button className="button button--ghost" type="submit" disabled={busy || !note.trim()}>Add note</button></form>}
      <div className="workflow-activity"><h4>Activity history</h4>{workflow.history.length === 0 ? <p className="muted-copy">No analyst activity has been recorded.</p> : <ol>{[...workflow.history].reverse().map((event) => <li key={event.event_id}><div><strong>{event.event_type.replaceAll("_", " ")}</strong><span>{event.actor_display}</span></div><time dateTime={event.occurred_at}>{formatTimestamp(event.occurred_at)}</time><small>Version {event.version}</small></li>)}</ol>}</div>
      {workflow.notes.length > 0 && <div className="workflow-notes"><h4>Analyst notes</h4>{[...workflow.notes].reverse().map((item) => <article key={item.note_id}><p>{item.body}</p><footer>{item.author_display} · {formatTimestamp(item.created_at)}</footer></article>)}</div>}
      <span className="sr-only">Available workflow statuses: {ALERT_WORKFLOW_STATUSES.join(", ")}</span>
    </section>
  );
}
