import { useCallback, useEffect, useState, type FormEvent } from "react";

import type { BackendApi } from "../types/api";
import type { AlertAssignee } from "../types/alerts";
import type { ChecklistItem, EvidencePin, EvidenceType, InvestigationTimelinePage, InvestigationWorkspace as Workspace } from "../types/investigations";
import { formatTimestamp, humanize } from "../utils/format";
import { CopyButton } from "./copy-button";
import { StatePanel } from "./state-panel";

function failure(reason: unknown): string {
  return reason instanceof Error ? reason.message : "The investigation action failed.";
}

function ChecklistRow({ item, assignees, busy, canMutate, onUpdate, onToggle }: {
  item: ChecklistItem;
  assignees: AlertAssignee[];
  busy: boolean;
  canMutate: boolean;
  onUpdate(body: string, assignedTo: string | null): void;
  onToggle(): void;
}) {
  const [body, setBody] = useState(item.body);
  const [assignedTo, setAssignedTo] = useState(item.assigned_to?.analyst_id ?? "");
  useEffect(() => { setBody(item.body); setAssignedTo(item.assigned_to?.analyst_id ?? ""); }, [item]);
  return <div className={`checklist-item${item.is_completed ? " is-complete" : ""}`}>
    <label className="checklist-item__toggle"><input type="checkbox" checked={item.is_completed} disabled={!canMutate || busy} onChange={onToggle} /><span>{item.is_completed ? "Completed" : "Open"}</span></label>
    <input aria-label="Checklist item text" maxLength={1024} value={body} readOnly={!canMutate} onChange={(event) => setBody(event.target.value)} />
    <select aria-label="Checklist assignee" value={assignedTo} disabled={!canMutate || busy} onChange={(event) => setAssignedTo(event.target.value)}><option value="">Unassigned</option>{assignees.map((assignee) => <option value={assignee.analyst_id} key={assignee.analyst_id}>{assignee.display_name}</option>)}</select>
    {canMutate && <button className="button button--secondary" type="button" disabled={busy || !body.trim()} onClick={() => onUpdate(body.trim(), assignedTo || null)}>Save item</button>}
    <small>Created {formatTimestamp(item.created_at)} by {item.created_by_display}{item.completed_at ? ` · completed ${formatTimestamp(item.completed_at)}` : ""}</small>
  </div>;
}

function EvidenceRow({ pin, busy, canMutate, onAnnotate, onUnpin, onOpen }: {
  pin: EvidencePin;
  busy: boolean;
  canMutate: boolean;
  onAnnotate(annotation: string): void;
  onUnpin(): void;
  onOpen(): void;
}) {
  const [annotation, setAnnotation] = useState(pin.annotation);
  useEffect(() => setAnnotation(pin.annotation), [pin]);
  return <article className="evidence-pin">
    <header><span className="source-pill">{humanize(pin.evidence_type)}</span><strong className="mono">{pin.evidence_id}</strong></header>
    <p>Evidence time {formatTimestamp(pin.source_timestamp)} · pinned {formatTimestamp(pin.pinned_at)} by {pin.pinned_by_display}</p>
    <textarea aria-label={`Annotation for ${pin.evidence_id}`} maxLength={4096} rows={2} value={annotation} readOnly={!canMutate} onChange={(event) => setAnnotation(event.target.value)} />
    <div className="filter-actions"><button className="button button--secondary" type="button" onClick={onOpen}>View source</button><CopyButton value={pin.evidence_id} label="Copy evidence ID" />{canMutate && <><button className="button button--secondary" type="button" disabled={busy} onClick={() => onAnnotate(annotation.trim())}>Save annotation</button><button className="button button--ghost" type="button" disabled={busy} onClick={onUnpin}>Unpin</button></>}</div>
  </article>;
}

export function InvestigationWorkspace({ api, incidentId, canMutate, onOpenAlert, onOpenEvent }: {
  api: BackendApi;
  incidentId: string;
  canMutate: boolean;
  onOpenAlert(id: string): void;
  onOpenEvent(id: string): void;
}) {
  const [workspace, setWorkspace] = useState<Workspace | null>(null);
  const [timeline, setTimeline] = useState<InvestigationTimelinePage | null>(null);
  const [assignees, setAssignees] = useState<AlertAssignee[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [itemBody, setItemBody] = useState("");
  const [itemAssignee, setItemAssignee] = useState("");
  const [evidenceType, setEvidenceType] = useState<EvidenceType>("EVENT");
  const [evidenceId, setEvidenceId] = useState("");
  const [annotation, setAnnotation] = useState("");

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const [nextWorkspace, nextTimeline, nextAssignees] = await Promise.all([
        api.getInvestigation(incidentId), api.getInvestigationTimeline(incidentId), api.listAlertAssignees(),
      ]);
      setWorkspace(nextWorkspace); setTimeline(nextTimeline); setAssignees(nextAssignees);
    } catch (reason) { setError(failure(reason)); }
    finally { setLoading(false); }
  }, [api, incidentId]);

  useEffect(() => { void load(); }, [load]);

  const mutate = async (operation: () => Promise<Workspace>, success: string) => {
    setBusy(true); setError(null); setMessage(null);
    try {
      setWorkspace(await operation());
      setTimeline(await api.getInvestigationTimeline(incidentId));
      setMessage(success);
      return true;
    } catch (reason) { setError(failure(reason)); return false; }
    finally { setBusy(false); }
  };

  const createItem = async (event: FormEvent) => {
    event.preventDefault();
    if (await mutate(() => api.createChecklistItem(incidentId, { body: itemBody.trim(), assigned_to: itemAssignee || null }), "Checklist item created.")) {
      setItemBody(""); setItemAssignee("");
    }
  };
  const pin = async (event: FormEvent) => {
    event.preventDefault();
    if (await mutate(() => api.pinEvidence(incidentId, { evidence_type: evidenceType, evidence_id: evidenceId.trim(), annotation: annotation.trim() }), "Evidence pinned.")) {
      setEvidenceId(""); setAnnotation("");
    }
  };
  const move = (index: number, direction: -1 | 1) => {
    if (!workspace) return;
    const next = [...workspace.checklist_items];
    const target = index + direction;
    if (target < 0 || target >= next.length) return;
    [next[index], next[target]] = [next[target], next[index]];
    void mutate(() => api.reorderChecklist(incidentId, { items: next.map((item) => ({ checklist_item_id: item.checklist_item_id, expected_version: item.version })) }), "Checklist reordered.");
  };
  const loadMore = async () => {
    if (!timeline?.next_cursor) return;
    setBusy(true); setError(null);
    try {
      const next = await api.getInvestigationTimeline(incidentId, timeline.limit, timeline.next_cursor);
      setTimeline({ ...next, items: [...timeline.items, ...next.items] });
    } catch (reason) { setError(failure(reason)); }
    finally { setBusy(false); }
  };

  if (loading && !workspace) return <StatePanel kind="loading" title="Loading investigation" message="Reading persisted checklist and evidence…" />;
  if (!workspace) return <StatePanel kind="error" title="Investigation unavailable" message={error ?? "No workspace response."} actionLabel="Retry" onAction={() => { void load(); }} />;

  return <section className="investigation-workspace" aria-label="Investigation workspace">
    <div className="section-heading"><div><h3>Investigation checklist</h3><p>{workspace.checklist_completed} of {workspace.checklist_total} complete</p></div></div>
    {error && <p className="form-message form-message--error" role="alert">{error}</p>}
    {message && <p className="form-message form-message--success" role="status">{message}</p>}
    {workspace.checklist_items.length === 0 ? <p className="muted-copy">No checklist items yet.</p> : <div className="checklist-list">{workspace.checklist_items.map((item, index) => <div className="checklist-row" key={item.checklist_item_id}><div className="checklist-order"><button type="button" aria-label={`Move ${item.body} up`} disabled={!canMutate || busy || index === 0} onClick={() => move(index, -1)}>↑</button><button type="button" aria-label={`Move ${item.body} down`} disabled={!canMutate || busy || index === workspace.checklist_items.length - 1} onClick={() => move(index, 1)}>↓</button></div><ChecklistRow item={item} assignees={assignees} busy={busy} canMutate={canMutate} onToggle={() => { void mutate(() => api.updateChecklistItem(incidentId, item.checklist_item_id, { is_completed: !item.is_completed, expected_version: item.version }), item.is_completed ? "Checklist item reopened." : "Checklist item completed."); }} onUpdate={(body, assignedTo) => { void mutate(() => api.updateChecklistItem(incidentId, item.checklist_item_id, { body, assigned_to: assignedTo, expected_version: item.version }), "Checklist item updated."); }} /></div>)}</div>}
    {canMutate && <form className="inline-form investigation-create" onSubmit={createItem}><label className="field"><span>New checklist item</span><input required maxLength={1024} value={itemBody} onChange={(event) => setItemBody(event.target.value)} /></label><label className="field"><span>Assign to</span><select value={itemAssignee} onChange={(event) => setItemAssignee(event.target.value)}><option value="">Unassigned</option>{assignees.map((item) => <option value={item.analyst_id} key={item.analyst_id}>{item.display_name}</option>)}</select></label><button className="button button--primary" disabled={busy || !itemBody.trim()} type="submit">Add item</button></form>}

    <div className="section-heading"><div><h3>Pinned evidence</h3><p>Immutable source identifiers with analyst annotations.</p></div></div>
    {workspace.evidence_pins.length === 0 ? <p className="muted-copy">No evidence pinned.</p> : <div className="evidence-list">{workspace.evidence_pins.map((evidence) => <EvidenceRow key={evidence.evidence_pin_id} pin={evidence} busy={busy} canMutate={canMutate} onAnnotate={(value) => { void mutate(() => api.annotateEvidence(incidentId, evidence.evidence_pin_id, value, evidence.version), "Evidence annotation updated."); }} onUnpin={() => { if (window.confirm(`Unpin evidence ${evidence.evidence_id}? The activity history will remain.`)) void mutate(() => api.unpinEvidence(incidentId, evidence.evidence_pin_id, evidence.version), "Evidence unpinned."); }} onOpen={() => evidence.evidence_type === "EVENT" ? onOpenEvent(evidence.evidence_id) : onOpenAlert(evidence.evidence_id)} />)}</div>}
    {canMutate && <form className="stack-form evidence-form" onSubmit={pin}><div className="inline-form"><label className="field"><span>Evidence type</span><select value={evidenceType} onChange={(event) => setEvidenceType(event.target.value as EvidenceType)}><option value="EVENT">Security event</option><option value="ALERT">Wazuh alert</option><option value="INCIDENT_EVIDENCE">Linked incident evidence</option></select></label><label className="field"><span>Immutable evidence ID</span><input required maxLength={255} value={evidenceId} onChange={(event) => setEvidenceId(event.target.value)} /></label></div><label className="field"><span>Annotation</span><textarea maxLength={4096} rows={2} value={annotation} onChange={(event) => setAnnotation(event.target.value)} /></label><button className="button button--secondary" disabled={busy || !evidenceId.trim()} type="submit">Pin evidence</button></form>}

    <div className="section-heading"><div><h3>Unified activity</h3><p>Incident decisions and investigation actions in truthful action-time order.</p></div></div>
    {!timeline || timeline.items.length === 0 ? <p className="muted-copy">No investigation activity.</p> : <ol className="timeline audit-list">{timeline.items.map((item) => <li key={item.activity_id}><div><strong>{humanize(item.activity_type)}</strong><time>{formatTimestamp(item.action_at)}</time></div><p>{item.actor_display} · {item.entity_type} <span className="mono">{item.entity_id}</span></p>{item.source_timestamp && <p>Evidence occurred {formatTimestamp(item.source_timestamp)}</p>}<code>{JSON.stringify(item.details)}</code></li>)}</ol>}
    {timeline?.next_cursor && <button className="button button--secondary" type="button" disabled={busy} onClick={() => { void loadMore(); }}>Load older activity</button>}
  </section>;
}
