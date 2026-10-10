import { FormEvent, useEffect, useMemo, useRef, useState } from "react";

import { ApiError } from "../api/client";
import { CopyButton } from "../components/copy-button";
import { Pagination } from "../components/pagination";
import { StatePanel } from "../components/state-panel";
import type { AlertAssignee } from "../types/alerts";
import type { BackendApi, CaseListResponse } from "../types/api";
import {
  CASE_PRIORITIES,
  CASE_SEVERITIES,
  CASE_STATUSES,
  CASE_TRANSITIONS,
  type CaseAnalytics,
  type CaseCreate,
  type CaseDetail,
  type CasePriority,
  type CaseSeverity,
  type CaseStatus,
  type EvidenceReferenceType,
  type PlaybookTemplate,
} from "../types/cases";
import { formatTimestamp, humanize } from "../utils/format";

function errorMessage(reason: unknown): string {
  if (reason instanceof ApiError) return `${reason.message} [${reason.code}]`;
  return reason instanceof Error ? reason.message : "The case operation failed.";
}

function badgeClass(value: string) { return `status-badge status-badge--${value.toLowerCase().replaceAll("_", "-")}`; }

export function CasesPage({ api, canMutate, openCaseId = null, onOpenAlert, onOpenIncident, onOpenEvent }: {
  api: BackendApi;
  canMutate: boolean;
  openCaseId?: string | null;
  onOpenAlert(alertId: string): void;
  onOpenIncident(incidentId: string): void;
  onOpenEvent(eventId: string): void;
}) {
  const [searchDraft, setSearchDraft] = useState("");
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState<CaseStatus | "">("");
  const [severity, setSeverity] = useState<CaseSeverity | "">("");
  const [priority, setPriority] = useState<CasePriority | "">("");
  const [ownerId, setOwnerId] = useState("");
  const [sort, setSort] = useState<"newest" | "oldest" | "updated" | "priority">("updated");
  const [pageSize, setPageSize] = useState(25);
  const [cursor, setCursor] = useState<string | undefined>();
  const [cursorStack, setCursorStack] = useState<Array<string | undefined>>([]);
  const [data, setData] = useState<CaseListResponse | null>(null);
  const [analytics, setAnalytics] = useState<CaseAnalytics | null>(null);
  const [assignees, setAssignees] = useState<AlertAssignee[]>([]);
  const [templates, setTemplates] = useState<PlaybookTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(openCaseId);
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [busy, setBusy] = useState(false);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [create, setCreate] = useState<CaseCreate>({ title: "", description: "", severity: "MEDIUM", priority: "MEDIUM", source_type: "MANUAL" });
  const [statusDraft, setStatusDraft] = useState<{ status: CaseStatus | ""; resolution: string; closureReason: string }>({ status: "", resolution: "", closureReason: "" });
  const [assignment, setAssignment] = useState({ ownerId: "", note: "" });
  const [comment, setComment] = useState("");
  const [related, setRelated] = useState<{ kind: "alert" | "incident" | "event"; id: string }>({ kind: "alert", id: "" });
  const [evidence, setEvidence] = useState<{ type: EvidenceReferenceType; id: string; annotation: string }>({ type: "ALERT", id: "", annotation: "" });
  const [playbookKey, setPlaybookKey] = useState("");
  const [stepNotes, setStepNotes] = useState<Record<string, string>>({});
  const selectedRef = useRef(selectedId);
  selectedRef.current = selectedId;

  useEffect(() => setSelectedId(openCaseId), [openCaseId]);
  useEffect(() => {
    const restore = () => setSelectedId(new URLSearchParams(window.location.search).get("case"));
    window.addEventListener("popstate", restore);
    return () => window.removeEventListener("popstate", restore);
  }, []);
  useEffect(() => {
    const close = () => { const url = new URL(window.location.href); url.searchParams.delete("case"); window.history.replaceState(window.history.state, "", url); setSelectedId(null); };
    window.addEventListener("cyberqalqon:escape", close);
    return () => window.removeEventListener("cyberqalqon:escape", close);
  }, []);

  const query = useMemo(() => ({
    statuses: status ? [status] : undefined, severities: severity ? [severity] : undefined,
    priorities: priority ? [priority] : undefined, ownerId: ownerId || undefined, search: search || undefined,
    sort, limit: pageSize, cursor,
  }), [cursor, ownerId, pageSize, priority, search, severity, sort, status]);

  useEffect(() => {
    const controller = new AbortController(); let active = true; setLoading(true); setError(null);
    Promise.all([api.listCases(query, controller.signal), api.getCaseAnalytics(30, controller.signal)])
      .then(([cases, metrics]) => { if (active) { setData(cases); setAnalytics(metrics); } })
      .catch((reason: unknown) => { if (active && !(reason instanceof DOMException && reason.name === "AbortError")) setError(errorMessage(reason)); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [api, query, revision]);

  useEffect(() => {
    const controller = new AbortController();
    Promise.all([api.listAlertAssignees(controller.signal), api.listPlaybookTemplates(controller.signal)])
      .then(([owners, available]) => { setAssignees(owners); setTemplates(available); setPlaybookKey((current) => current || available[0]?.key || ""); })
      .catch(() => { /* non-blocking: case reads still work */ });
    return () => controller.abort();
  }, [api]);

  useEffect(() => {
    if (!selectedId) { setDetail(null); setDetailError(null); return; }
    const controller = new AbortController(); let active = true; setDetailLoading(true); setDetailError(null); setMutationError(null); setSuccess(null);
    api.getCase(selectedId, controller.signal)
      .then((item) => { if (active) { setDetail(item); setAssignment({ ownerId: item.owner?.analyst_id ?? "", note: "" }); } })
      .catch((reason: unknown) => { if (active) setDetailError(errorMessage(reason)); })
      .finally(() => { if (active) setDetailLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [api, selectedId]);

  const resetPage = () => { setCursor(undefined); setCursorStack([]); };
  const selectCase = (caseId: string) => { const url = new URL(window.location.href); url.searchParams.set("view", "cases"); url.searchParams.set("case", caseId); window.history.pushState({}, "", url); setSelectedId(caseId); };
  const closeCase = () => { const url = new URL(window.location.href); url.searchParams.delete("case"); window.history.replaceState({}, "", url); setSelectedId(null); };
  const mutate = async (operation: () => Promise<CaseDetail>, message: string) => {
    const target = selectedId; setBusy(true); setMutationError(null); setSuccess(null);
    try { const updated = await operation(); if (selectedRef.current === target) setDetail(updated); setRevision((value) => value + 1); setSuccess(message); }
    catch (reason) { if (selectedRef.current === target) setMutationError(errorMessage(reason)); }
    finally { setBusy(false); }
  };
  const createCase = async (event: FormEvent) => {
    event.preventDefault(); setBusy(true); setMutationError(null);
    try { const created = await api.createCase({ ...create, source_id: create.source_type === "MANUAL" ? null : create.source_id?.trim() }); setShowCreate(false); setCreate({ title: "", description: "", severity: "MEDIUM", priority: "MEDIUM", source_type: "MANUAL" }); selectCase(created.case_id); setDetail(created); setRevision((value) => value + 1); }
    catch (reason) { setMutationError(errorMessage(reason)); }
    finally { setBusy(false); }
  };
  const download = async (format: "json" | "csv" | "pdf") => {
    if (!detail) return; setBusy(true); setMutationError(null);
    try { const file = await api.downloadCaseReport(detail.case_id, format); const href = URL.createObjectURL(file.blob); const anchor = document.createElement("a"); anchor.href = href; anchor.download = file.filename; anchor.click(); URL.revokeObjectURL(href); setSuccess(`${file.filename} downloaded.`); const refreshed = await api.getCase(detail.case_id); setDetail(refreshed); }
    catch (reason) { setMutationError(errorMessage(reason)); }
    finally { setBusy(false); }
  };
  const evaluateSla = async () => {
    setBusy(true); setMutationError(null); setSuccess(null);
    try { const result = await api.evaluateCaseSla(); setSuccess(`SLA evaluated for ${result.evaluated_cases} owned cases; ${result.notifications_created} new notifications.`); setRevision((value) => value + 1); }
    catch (reason) { setMutationError(errorMessage(reason)); }
    finally { setBusy(false); }
  };

  return <div className="page-grid cases-workspace">
    <section className="page-column">
      <header className="page-header"><div><span className="eyebrow">Durable investigations</span><h1>SOC cases</h1><p>Owned work, evidence integrity, deterministic playbooks, SLA state, and auditable reports.</p></div><div className="header-actions"><div className="page-header__metric"><strong>{data?.total ?? "—"}</strong><span>matching cases</span></div>{canMutate && <button className="button button--secondary" disabled={busy} type="button" onClick={() => void evaluateSla()}>Evaluate SLA</button>}{canMutate && <button className="button button--primary" type="button" onClick={() => setShowCreate((value) => !value)}>Create case</button>}</div></header>
      {success && !selectedId && <p className="form-message form-message--success" role="status">{success}</p>}
      {analytics && <div className="metric-grid case-metrics"><article className="metric-card"><span>Open</span><strong>{analytics.open_cases}</strong></article><article className="metric-card"><span>Response overdue</span><strong>{analytics.overdue_response}</strong></article><article className="metric-card"><span>Resolution overdue</span><strong>{analytics.overdue_resolution}</strong></article><article className="metric-card"><span>MTTA</span><strong>{analytics.mtta_minutes == null ? "—" : `${analytics.mtta_minutes}m`}</strong><small>Creation to first triage/investigation</small></article><article className="metric-card"><span>MTTR</span><strong>{analytics.mttr_minutes == null ? "—" : `${analytics.mttr_minutes}m`}</strong><small>Creation to resolution</small></article></div>}
      {showCreate && canMutate && <form className="panel case-create" onSubmit={createCase}><header className="panel__header"><h2>New SOC case</h2><span>Cases are created only by this explicit action.</span></header><div className="case-form-grid"><label className="filter-field"><span>Title</span><input required maxLength={255} value={create.title} onChange={(event) => setCreate((current) => ({ ...current, title: event.target.value }))} /></label><label className="filter-field"><span>Severity</span><select value={create.severity} onChange={(event) => setCreate((current) => ({ ...current, severity: event.target.value as CaseSeverity }))}>{CASE_SEVERITIES.map((value) => <option key={value}>{value}</option>)}</select></label><label className="filter-field"><span>Priority</span><select value={create.priority} onChange={(event) => setCreate((current) => ({ ...current, priority: event.target.value as CasePriority }))}>{CASE_PRIORITIES.map((value) => <option key={value}>{value}</option>)}</select></label><label className="filter-field"><span>Owner</span><select value={create.owner_id ?? ""} onChange={(event) => setCreate((current) => ({ ...current, owner_id: event.target.value || null }))}><option value="">Unassigned</option>{assignees.map((item) => <option key={item.analyst_id} value={item.analyst_id}>{item.display_name}</option>)}</select></label><label className="filter-field"><span>Source</span><select value={create.source_type} onChange={(event) => setCreate((current) => ({ ...current, source_type: event.target.value as CaseCreate["source_type"], source_id: "" }))}><option value="MANUAL">Manual</option><option value="ALERT">Alert</option><option value="INCIDENT">Incident</option></select></label>{create.source_type !== "MANUAL" && <label className="filter-field"><span>{humanize(create.source_type ?? "source")} ID</span><input required maxLength={255} value={create.source_id ?? ""} onChange={(event) => setCreate((current) => ({ ...current, source_id: event.target.value }))} /></label>}<label className="filter-field case-form-grid__wide"><span>Description</span><textarea maxLength={8192} value={create.description ?? ""} onChange={(event) => setCreate((current) => ({ ...current, description: event.target.value }))} /></label></div><div className="form-actions"><button className="button button--secondary" type="button" onClick={() => setShowCreate(false)}>Cancel</button><button className="button button--primary" disabled={busy} type="submit">{busy ? "Creating…" : "Create case"}</button></div></form>}
      <form className="panel case-filters" onSubmit={(event) => { event.preventDefault(); setSearch(searchDraft.trim()); resetPage(); }}><label className="filter-field case-filter-search"><span>Search</span><input aria-label="Search cases" maxLength={200} placeholder="Case ID, title, description" value={searchDraft} onChange={(event) => setSearchDraft(event.target.value)} /></label><label className="filter-field"><span>Status</span><select value={status} onChange={(event) => { setStatus(event.target.value as CaseStatus | ""); resetPage(); }}><option value="">All</option>{CASE_STATUSES.map((value) => <option key={value}>{humanize(value)}</option>)}</select></label><label className="filter-field"><span>Severity</span><select value={severity} onChange={(event) => { setSeverity(event.target.value as CaseSeverity | ""); resetPage(); }}><option value="">All</option>{CASE_SEVERITIES.map((value) => <option key={value}>{humanize(value)}</option>)}</select></label><label className="filter-field"><span>Priority</span><select value={priority} onChange={(event) => { setPriority(event.target.value as CasePriority | ""); resetPage(); }}><option value="">All</option>{CASE_PRIORITIES.map((value) => <option key={value}>{humanize(value)}</option>)}</select></label><label className="filter-field"><span>Owner</span><select value={ownerId} onChange={(event) => { setOwnerId(event.target.value); resetPage(); }}><option value="">All</option>{assignees.map((item) => <option key={item.analyst_id} value={item.analyst_id}>{item.display_name}</option>)}</select></label><label className="filter-field"><span>Sort</span><select value={sort} onChange={(event) => { setSort(event.target.value as typeof sort); resetPage(); }}><option value="updated">Recently updated</option><option value="newest">Newest</option><option value="oldest">Oldest</option><option value="priority">Priority / due</option></select></label><button className="button button--secondary" type="submit">Apply search</button></form>
      {mutationError && !selectedId && <p className="form-message form-message--error" role="alert">{mutationError}</p>}
      {loading && !data && <StatePanel kind="loading" title="Loading cases" message="Reading the durable case queue…" />}
      {error && <StatePanel kind="unavailable" title="Cases unavailable" message={error} actionLabel="Retry" onAction={() => setRevision((value) => value + 1)} />}
      {!loading && !error && data?.items.length === 0 && <StatePanel kind="empty" title="No matching cases" message="Create an explicit case or adjust the filters." />}
      {!error && data && data.items.length > 0 && <><div className="table-wrap"><table className="data-table cases-table"><thead><tr><th>Case</th><th>Status</th><th>Priority</th><th>Owner</th><th>SLA</th><th>Updated</th></tr></thead><tbody>{data.items.map((item) => <tr key={item.case_id} className={selectedId === item.case_id ? "is-selected" : undefined} onClick={() => selectCase(item.case_id)}><td><button className="table-link" type="button" onClick={() => selectCase(item.case_id)}><strong>{item.title}</strong><span>{item.case_id}</span></button></td><td><span className={badgeClass(item.status)}>{humanize(item.status)}</span></td><td><span className={badgeClass(item.priority)}>{item.priority}</span><small>{item.severity}</small></td><td>{item.owner?.display_name ?? "Unassigned"}</td><td><span className={item.sla.escalation_state === "NONE" ? "muted-copy" : "stale-warning"}>{humanize(item.sla.escalation_state)}</span></td><td>{formatTimestamp(item.updated_at)}</td></tr>)}</tbody></table></div><Pagination visible={data.items.length} total={data.total} hasPrevious={cursorStack.length > 0} hasNext={Boolean(data.next_cursor)} loading={loading} pageSize={pageSize} onPageSizeChange={(value) => { setPageSize(value); resetPage(); }} onPrevious={() => { setCursor(cursorStack[cursorStack.length - 1]); setCursorStack((current) => current.slice(0, -1)); }} onNext={() => { if (data.next_cursor) { setCursorStack((current) => [...current, cursor]); setCursor(data.next_cursor); } }} /></>}
    </section>
    {selectedId && detailLoading && !detail && <aside className="detail-panel detail-panel--state"><StatePanel kind="loading" title="Loading case" message="Reading case work and evidence manifest…" /></aside>}
    {selectedId && detailError && <aside className="detail-panel detail-panel--state"><StatePanel kind="error" title="Case unavailable" message={detailError} actionLabel="Close" onAction={closeCase} /></aside>}
    {detail && selectedId === detail.case_id && <aside className="detail-panel case-detail" aria-label={`Case ${detail.case_id}`}><header className="detail-panel__header"><div><span className="eyebrow">SOC case · version {detail.version}</span><h2>{detail.title}</h2><div className="case-id-line"><code>{detail.case_id}</code><CopyButton value={detail.case_id} label="Copy case ID" /></div></div><button className="icon-button" type="button" aria-label="Close case detail" onClick={closeCase}>×</button></header><div className="detail-panel__body">
      <div className="case-summary-strip"><span className={badgeClass(detail.status)}>{humanize(detail.status)}</span><span className={badgeClass(detail.priority)}>{detail.priority} priority</span><span>{detail.severity} severity</span><span>{detail.owner?.display_name ?? "Unassigned"}</span></div>
      {detail.sla.escalation_state !== "NONE" && <p className="stale-warning" role="status">SLA escalation: {humanize(detail.sla.escalation_state)}. Response due {formatTimestamp(detail.sla.response_due_at)}; resolution due {formatTimestamp(detail.sla.resolution_due_at)}.</p>}
      <p>{detail.description || "No description supplied."}</p>
      {mutationError && <p className="form-message form-message--error" role="alert">{mutationError}</p>}{success && <p className="form-message form-message--success" role="status">{success}</p>}
      <section className="case-section"><header><h3>Quick actions</h3></header><div className="case-report-actions"><button className="button button--secondary" disabled={busy || !canMutate} type="button" onClick={() => void download("json")}>Export JSON</button><button className="button button--secondary" disabled={busy || !canMutate} type="button" onClick={() => void download("csv")}>Export CSV</button><button className="button button--primary" disabled={busy || !canMutate} type="button" onClick={() => void download("pdf")}>Export PDF</button></div>{!canMutate && <p className="muted-copy">Your role can read cases but cannot change or export them.</p>}</section>
      {canMutate && <section className="case-section"><header><h3>Lifecycle and handoff</h3></header><form className="case-action-form" onSubmit={(event) => { event.preventDefault(); if (!detail || !statusDraft.status) return; if (statusDraft.status === "CLOSED" && !window.confirm("Close this case? Closed cases cannot transition further.")) return; void mutate(() => api.updateCaseStatus(detail.case_id, { status: statusDraft.status as CaseStatus, expected_version: detail.version, resolution: statusDraft.resolution || undefined, closure_reason: statusDraft.closureReason || undefined }), `Case moved to ${statusDraft.status}.`); }}><label className="filter-field"><span>Next status</span><select required value={statusDraft.status} onChange={(event) => setStatusDraft((current) => ({ ...current, status: event.target.value as CaseStatus | "" }))}><option value="">Choose transition</option>{CASE_TRANSITIONS[detail.status].map((value) => <option key={value}>{value}</option>)}</select></label>{statusDraft.status === "RESOLVED" && <label className="filter-field"><span>Resolution</span><textarea required maxLength={8192} value={statusDraft.resolution} onChange={(event) => setStatusDraft((current) => ({ ...current, resolution: event.target.value }))} /></label>}{statusDraft.status === "CLOSED" && <label className="filter-field"><span>Closure reason</span><textarea required maxLength={4096} value={statusDraft.closureReason} onChange={(event) => setStatusDraft((current) => ({ ...current, closureReason: event.target.value }))} /></label>}<button className="button button--secondary" disabled={busy || !statusDraft.status} type="submit">Apply transition</button></form><form className="case-action-form" onSubmit={(event) => { event.preventDefault(); void mutate(() => api.updateCaseAssignment(detail.case_id, { owner_id: assignment.ownerId || null, handoff_note: assignment.note || undefined, expected_version: detail.version }), "Case owner updated."); }}><label className="filter-field"><span>Owner</span><select value={assignment.ownerId} onChange={(event) => setAssignment((current) => ({ ...current, ownerId: event.target.value }))}><option value="">Unassigned</option>{assignees.map((item) => <option key={item.analyst_id} value={item.analyst_id}>{item.display_name}</option>)}</select></label><label className="filter-field"><span>Handoff note</span><textarea maxLength={4096} value={assignment.note} onChange={(event) => setAssignment((current) => ({ ...current, note: event.target.value }))} /></label><button className="button button--secondary" disabled={busy} type="submit">Update owner</button></form></section>}
      <section className="case-section"><header><h3>Related records</h3><span>{detail.alert_count + detail.incident_count + detail.event_count} linked</span></header><div className="related-chips">{detail.alert_ids.map((id) => <button type="button" key={id} onClick={() => onOpenAlert(id)}>Alert {id}</button>)}{detail.incident_ids.map((id) => <button type="button" key={id} onClick={() => onOpenIncident(id)}>Incident {id}</button>)}{detail.event_ids.map((id) => <button type="button" key={id} onClick={() => onOpenEvent(id)}>Event {id}</button>)}</div>{canMutate && <form className="case-inline-form" onSubmit={(event) => { event.preventDefault(); if (!related.id.trim()) return; void mutate(() => api.linkCaseReference(detail.case_id, related.kind, related.id.trim(), detail.version), `${humanize(related.kind)} linked.`); }}><select aria-label="Related record type" value={related.kind} onChange={(event) => setRelated((current) => ({ ...current, kind: event.target.value as typeof related.kind }))}><option value="alert">Alert</option><option value="incident">Incident</option><option value="event">Event</option></select><input aria-label="Related record ID" required maxLength={255} value={related.id} onChange={(event) => setRelated((current) => ({ ...current, id: event.target.value }))} /><button className="button button--secondary" disabled={busy} type="submit">Link</button></form>}</section>
      <section className="case-section"><header><h3>Evidence manifest</h3><span>Application-level SHA-256 change detection</span></header><p className="muted-copy">References point to existing stored telemetry; this is not a legal-grade forensic acquisition claim.</p>{detail.evidence.length === 0 ? <p className="empty-inline">No evidence references.</p> : <div className="case-evidence-list">{detail.evidence.map((item) => <article key={item.evidence_ref_id}><div><strong>{item.source_label}</strong><span className={badgeClass(item.integrity_status)}>{item.integrity_status}</span></div><div className="case-digest"><code>{item.digest}</code><CopyButton value={item.digest} label="Copy evidence digest" /></div><small>Acquired {formatTimestamp(item.acquired_at)} · verified {formatTimestamp(item.last_verified_at)} · {item.custody.length} custody events</small>{canMutate && <button className="button button--ghost" disabled={busy} type="button" onClick={() => void mutate(() => api.verifyCaseEvidence(detail.case_id, item.evidence_ref_id, item.version), "Evidence verification recorded.")}>Verify now</button>}</article>)}</div>}{canMutate && <form className="case-action-form" onSubmit={(event) => { event.preventDefault(); if (!evidence.id.trim()) return; void mutate(() => api.acquireCaseEvidence(detail.case_id, { reference_type: evidence.type, reference_id: evidence.id.trim(), annotation: evidence.annotation, expected_version: detail.version }), "Evidence reference acquired."); }}><label className="filter-field"><span>Reference type</span><select value={evidence.type} onChange={(event) => setEvidence((current) => ({ ...current, type: event.target.value as EvidenceReferenceType }))}><option>ALERT</option><option>EVENT</option><option>INCIDENT</option></select></label><label className="filter-field"><span>Reference ID</span><input required maxLength={255} value={evidence.id} onChange={(event) => setEvidence((current) => ({ ...current, id: event.target.value }))} /></label><label className="filter-field"><span>Annotation</span><input maxLength={4096} value={evidence.annotation} onChange={(event) => setEvidence((current) => ({ ...current, annotation: event.target.value }))} /></label><button className="button button--secondary" disabled={busy} type="submit">Acquire reference</button></form>}</section>
      <section className="case-section"><header><h3>Safe playbooks</h3><span>No commands, scans, blocking, or isolation actions</span></header>{detail.playbooks.map((playbook) => <article className="case-playbook" key={playbook.playbook_id}><header><strong>{playbook.name}</strong><span>{playbook.completed_steps}/{playbook.total_steps} · {playbook.status}</span></header>{playbook.steps.map((step) => <div className={`playbook-step ${step.status === "COMPLETED" ? "is-complete" : ""}`} key={step.step_id}><div><strong>{step.sequence + 1}. {step.title}</strong><span>{step.step_type} · {step.status}</span><p>{step.description}</p></div>{step.status === "PENDING" && canMutate && <form onSubmit={(event) => { event.preventDefault(); const note = stepNotes[step.step_id]?.trim() ?? ""; const evidenceId = step.step_type === "EVIDENCE" ? detail.evidence[0]?.evidence_ref_id : undefined; void mutate(() => api.updateCasePlaybookStep(detail.case_id, playbook.playbook_id, step.step_id, { status: "COMPLETED", expected_version: step.version, completion_note: note, evidence_ref_id: evidenceId }), "Playbook step completed."); }}><input aria-label={`Completion note for ${step.title}`} required maxLength={2048} placeholder="Completion note" value={stepNotes[step.step_id] ?? ""} onChange={(event) => setStepNotes((current) => ({ ...current, [step.step_id]: event.target.value }))} /><button className="button button--secondary" disabled={busy || (step.step_type === "EVIDENCE" && detail.evidence.length === 0)} type="submit">Complete</button></form>}</div>)}</article>)}{detail.playbooks.length === 0 && <p className="empty-inline">No playbook instantiated.</p>}{canMutate && <form className="case-inline-form" onSubmit={(event) => { event.preventDefault(); if (playbookKey) void mutate(() => api.startCasePlaybook(detail.case_id, playbookKey, detail.version), "Safe playbook instantiated."); }}><select aria-label="Playbook template" value={playbookKey} onChange={(event) => setPlaybookKey(event.target.value)}>{templates.map((item) => <option value={item.key} key={item.key}>{item.name}</option>)}</select><button className="button button--secondary" disabled={busy || !playbookKey} type="submit">Start playbook</button></form>}</section>
      <section className="case-section"><header><h3>Collaboration</h3><span>{detail.comments.length} comments / handoffs</span></header>{detail.comments.map((item) => <article className="case-comment" key={item.comment_id}><div><strong>{item.author_display}</strong><span>{humanize(item.comment_type)} · {formatTimestamp(item.created_at)}</span></div><p>{item.body}</p></article>)}{detail.comments.length === 0 && <p className="empty-inline">No collaboration notes.</p>}{canMutate && <form className="case-inline-form" onSubmit={(event) => { event.preventDefault(); if (!comment.trim()) return; void mutate(() => api.addCaseComment(detail.case_id, comment.trim(), detail.version), "Comment added."); setComment(""); }}><input aria-label="Case comment" required maxLength={4096} value={comment} onChange={(event) => setComment(event.target.value)} /><button className="button button--secondary" disabled={busy} type="submit">Add comment</button></form>}</section>
      <section className="case-section"><header><h3>Activity timeline</h3><span>{detail.activity.length} events</span></header><ol className="case-timeline">{detail.activity.map((item) => <li key={item.activity_id}><span>{formatTimestamp(item.occurred_at)}</span><strong>{humanize(item.activity_type)}</strong><small>{item.actor_display}</small></li>)}</ol></section>
      {detail.report_history.length > 0 && <section className="case-section"><header><h3>Report history</h3></header>{detail.report_history.map((item) => <div className="case-report-record" key={item.report_id}><span>{item.format} · {formatTimestamp(item.generated_at)}</span><code>{item.sha256.slice(0, 16)}…</code></div>)}</section>}
    </div></aside>}
  </div>;
}
