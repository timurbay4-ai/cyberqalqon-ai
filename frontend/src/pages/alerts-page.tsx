import { useEffect, useMemo, useRef, useState } from "react";

import { AlertDetail } from "../components/alert-detail";
import { AlertFilters, EMPTY_ALERT_FILTERS, type AlertFilterValues } from "../components/alert-filters";
import { AlertsTable } from "../components/alerts-table";
import { Pagination } from "../components/pagination";
import { StatePanel } from "../components/state-panel";
import type { AlertWorkflowListResponse, BackendApi } from "../types/api";
import type { AlertAssignee, AlertBulkRequest, AlertWorkflowDetail, AlertWorkflowSort, AlertWorkflowStatus } from "../types/alerts";
import type { SecurityEventSummary } from "../types/events";
import { toApiTimestamp } from "../utils/format";
import { severityLevels } from "../utils/severity";

const MAX_BULK_SELECTION = 50;

function errorMessage(reason: unknown, fallback: string): string {
  return reason instanceof Error ? reason.message : fallback;
}

export function AlertsPage({ api, openAlertId, initialRuleId, initialPageSize = 25, initialSort = "time_desc", canMutate = false, onOpenEvent = () => undefined }: { api: BackendApi; openAlertId?: string | null; initialRuleId?: string | null; initialPageSize?: 25 | 50 | 100; initialSort?: AlertWorkflowSort; canMutate?: boolean; onOpenEvent?(eventId: string): void }) {
  const [filters, setFilters] = useState<AlertFilterValues>({ ...EMPTY_ALERT_FILTERS, sort: initialSort });
  const [pageSize, setPageSize] = useState(initialPageSize);
  const [cursor, setCursor] = useState<string | undefined>();
  const [cursorStack, setCursorStack] = useState<Array<string | undefined>>([]);
  const [data, setData] = useState<AlertWorkflowListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const selectedAlertIdRef = useRef<string | null>(null);
  const [selectedWorkflow, setSelectedWorkflow] = useState<AlertWorkflowDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [relatedEvents, setRelatedEvents] = useState<SecurityEventSummary[]>([]);
  const [relatedEventsError, setRelatedEventsError] = useState<string | null>(null);
  const [assignees, setAssignees] = useState<AlertAssignee[]>([]);
  const [checkedIds, setCheckedIds] = useState<Set<string>>(new Set());
  const [bulkAction, setBulkAction] = useState<"ACKNOWLEDGE" | "IN_PROGRESS" | "RESOLVED" | "FALSE_POSITIVE" | "ASSIGN">("ACKNOWLEDGE");
  const [bulkAssignee, setBulkAssignee] = useState("");
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkFeedback, setBulkFeedback] = useState<string | null>(null);
  const [mutationBusy, setMutationBusy] = useState(false);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [mutationSuccess, setMutationSuccess] = useState<string | null>(null);

  useEffect(() => { selectedAlertIdRef.current = selectedAlertId; }, [selectedAlertId]);
  useEffect(() => {
    setPageSize((current) => current === initialPageSize ? current : initialPageSize);
    setFilters((current) => current.sort === initialSort ? current : { ...current, sort: initialSort });
  }, [initialPageSize, initialSort]);
  useEffect(() => { setSelectedAlertId(openAlertId ?? null); }, [openAlertId]);
  useEffect(() => {
    const restore = () => setSelectedAlertId(new URLSearchParams(window.location.search).get("alert"));
    window.addEventListener("popstate", restore);
    return () => window.removeEventListener("popstate", restore);
  }, []);
  useEffect(() => {
    const close = () => { const url = new URL(window.location.href); url.searchParams.delete("alert"); window.history.replaceState(window.history.state, "", url); setSelectedAlertId(null); };
    window.addEventListener("cyberqalqon:escape", close);
    return () => window.removeEventListener("cyberqalqon:escape", close);
  }, []);
  useEffect(() => {
    if (initialRuleId) {
      setFilters((current) => ({ ...current, ruleId: initialRuleId }));
      setCursor(undefined); setCursorStack([]);
    }
  }, [initialRuleId]);

  useEffect(() => {
    const controller = new AbortController();
    api.listAlertAssignees(controller.signal).then(setAssignees).catch(() => setAssignees([]));
    return () => controller.abort();
  }, [api]);

  const query = useMemo(() => ({
    ruleLevels: severityLevels(filters.severityBands),
    ruleId: filters.ruleId.trim() || undefined,
    agent: filters.agent.trim() || undefined,
    mitreMapped: filters.mitreMode === "any" ? undefined : filters.mitreMode === "mapped",
    mitreId: filters.mitreId.trim() || undefined,
    startTime: toApiTimestamp(filters.startTime),
    endTime: toApiTimestamp(filters.endTime),
    search: filters.search.trim() || undefined,
    statuses: filters.status ? [filters.status] : undefined,
    assignedTo: filters.assignedTo || undefined,
    unassigned: filters.unassigned || undefined,
    sort: filters.sort,
    limit: pageSize,
    cursor,
  }), [cursor, filters, pageSize]);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setLoading(true);
    setError(null);
    api.listAlertWorkflows(query, controller.signal)
      .then((response) => { if (active) setData(response); })
      .catch((reason: unknown) => {
        if (!active || (reason instanceof DOMException && reason.name === "AbortError")) return;
        setError(errorMessage(reason, "Alert workflow data could not be loaded."));
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [api, query, revision]);

  useEffect(() => {
    if (!selectedAlertId) {
      setSelectedWorkflow(null); setDetailError(null); setRelatedEvents([]); setRelatedEventsError(null);
      return;
    }
    const controller = new AbortController();
    let active = true;
    setSelectedWorkflow(null); setDetailError(null); setRelatedEvents([]); setRelatedEventsError(null);
    setMutationError(null); setMutationSuccess(null);
    api.getAlertWorkflow(selectedAlertId, controller.signal)
      .then((response) => { if (active) setSelectedWorkflow(response); })
      .catch((reason: unknown) => {
        if (!active || (reason instanceof DOMException && reason.name === "AbortError")) return;
        setDetailError(errorMessage(reason, "Alert workflow detail could not be loaded."));
      });
    api.listEvents({ relatedAlertId: selectedAlertId, limit: 100, sort: "newest" }, controller.signal)
      .then((response) => { if (active) setRelatedEvents(response.items); })
      .catch((reason: unknown) => {
        if (!active || (reason instanceof DOMException && reason.name === "AbortError")) return;
        setRelatedEventsError(errorMessage(reason, "Related events could not be loaded."));
      });
    return () => { active = false; controller.abort(); };
  }, [api, selectedAlertId]);

  const applyFilters = (next: AlertFilterValues) => { setFilters(next); setCursor(undefined); setCursorStack([]); setCheckedIds(new Set()); };
  const selectAlert = (alertId: string) => { const url = new URL(window.location.href); url.searchParams.set("view", "alerts"); url.searchParams.set("alert", alertId); window.history.pushState({}, "", url); setSelectedAlertId(alertId); };
  const closeAlert = () => { const url = new URL(window.location.href); url.searchParams.delete("alert"); window.history.replaceState({}, "", url); setSelectedAlertId(null); };
  const toggleChecked = (alertId: string, checked: boolean) => setCheckedIds((current) => { const next = new Set(current); if (checked && next.size < MAX_BULK_SELECTION) next.add(alertId); else if (!checked) next.delete(alertId); return next; });

  const mutate = async (operation: (workflow: AlertWorkflowDetail) => Promise<AlertWorkflowDetail>, success: string) => {
    if (!selectedWorkflow) return;
    const target = selectedWorkflow.alert.alert_id;
    setMutationBusy(true); setMutationError(null); setMutationSuccess(null);
    try {
      const updated = await operation(selectedWorkflow);
      if (selectedAlertIdRef.current !== target) return;
      setSelectedWorkflow(updated); setMutationSuccess(success); setRevision((value) => value + 1);
    } catch (reason) {
      if (selectedAlertIdRef.current === target) setMutationError(errorMessage(reason, "Alert workflow update failed."));
    } finally { setMutationBusy(false); }
  };

  const runBulk = async () => {
    if (!data || checkedIds.size === 0 || checkedIds.size > MAX_BULK_SELECTION) return;
    const items = data.items.filter((item) => checkedIds.has(item.alert.alert_id)).map((item) => ({ alert_id: item.alert.alert_id, expected_version: item.version }));
    if (items.length !== checkedIds.size) { setBulkFeedback("Selection changed. Clear it and select alerts from the current page again."); return; }
    if (!window.confirm(`Apply ${bulkAction.replaceAll("_", " ")} to ${items.length} selected alert${items.length === 1 ? "" : "s"}? The operation is all-or-nothing.`)) return;
    let payload: AlertBulkRequest;
    if (bulkAction === "ACKNOWLEDGE") payload = { action: "ACKNOWLEDGE", items };
    else if (bulkAction === "ASSIGN") payload = { action: "ASSIGN", items, assigned_to: bulkAssignee || null };
    else payload = { action: "SET_STATUS", items, status: bulkAction };
    setBulkBusy(true); setBulkFeedback(null);
    try {
      const result = await api.bulkUpdateAlerts(payload);
      setBulkFeedback(`${result.updated_count} alert${result.updated_count === 1 ? "" : "s"} updated.`);
      setCheckedIds(new Set()); setRevision((value) => value + 1);
      if (selectedAlertId) setSelectedWorkflow(await api.getAlertWorkflow(selectedAlertId));
    } catch (reason) { setBulkFeedback(errorMessage(reason, "Bulk operation was rejected; no alerts were changed.")); }
    finally { setBulkBusy(false); }
  };

  return (
    <div className="page-grid">
      <section className="page-column">
        <header className="page-header"><div><span className="eyebrow">Detection queue</span><h1>Security alerts</h1><p>Durable analyst triage over normalized Wazuh detections.</p></div><div className="workflow-metrics"><div className="page-header__metric"><strong>{data?.counts.actionable ?? "—"}</strong><span>actionable</span></div><div className="page-header__metric"><strong>{data?.counts.unassigned ?? "—"}</strong><span>unassigned</span></div></div></header>
        <AlertFilters values={filters} assignees={assignees} onApply={applyFilters} />
        {canMutate && <div className="bulk-toolbar" aria-label="Bulk alert actions"><strong>{checkedIds.size} selected</strong><span>Maximum {MAX_BULK_SELECTION}</span><label className="field"><span>Action</span><select value={bulkAction} disabled={bulkBusy} onChange={(event) => setBulkAction(event.target.value as typeof bulkAction)}><option value="ACKNOWLEDGE">Acknowledge</option><option value="IN_PROGRESS">Set in progress</option><option value="RESOLVED">Resolve</option><option value="FALSE_POSITIVE">Mark false positive</option><option value="ASSIGN">Assign</option></select></label>{bulkAction === "ASSIGN" && <label className="field"><span>Analyst</span><select value={bulkAssignee} disabled={bulkBusy} onChange={(event) => setBulkAssignee(event.target.value)}><option value="">Unassign</option>{assignees.map((item) => <option value={item.analyst_id} key={item.analyst_id}>{item.display_name} ({item.username})</option>)}</select></label>}<button className="button button--primary" type="button" disabled={bulkBusy || checkedIds.size === 0} onClick={() => { void runBulk(); }}>{bulkBusy ? "Applying…" : "Apply to selection"}</button><button className="button button--ghost" type="button" disabled={bulkBusy || checkedIds.size === 0} onClick={() => setCheckedIds(new Set())}>Clear</button>{bulkFeedback && <p role="status">{bulkFeedback}</p>}</div>}
        {loading && !data && <StatePanel kind="loading" title="Loading alerts" message="Reading durable alert workflows…" />}
        {error && <StatePanel kind="unavailable" title="Alert data unavailable" message={error} actionLabel="Retry" onAction={() => setRevision((value) => value + 1)} />}
        {!loading && !error && data?.items.length === 0 && <StatePanel kind="empty" title="No matching alerts" message="Adjust or reset the filters to broaden the query." />}
        {!error && data && data.items.length > 0 && <><AlertsTable workflows={data.items} selectedAlertId={selectedAlertId} checkedIds={checkedIds} selectionDisabled={checkedIds.size >= MAX_BULK_SELECTION} onSelect={selectAlert} onToggle={toggleChecked} /><Pagination visible={data.items.length} total={data.page.total} hasPrevious={cursorStack.length > 0} hasNext={Boolean(data.page.next_cursor)} loading={loading} pageSize={pageSize} onPageSizeChange={(next) => { setPageSize(next as 25 | 50 | 100); setCursor(undefined); setCursorStack([]); setCheckedIds(new Set()); }} onPrevious={() => { setCursor(cursorStack[cursorStack.length - 1]); setCursorStack((current) => current.slice(0, -1)); setCheckedIds(new Set()); }} onNext={() => { if (data.page.next_cursor) { setCursorStack((current) => [...current, cursor]); setCursor(data.page.next_cursor); setCheckedIds(new Set()); } }} /></>}
      </section>
      {selectedAlertId && !selectedWorkflow && !detailError && <aside className="detail-panel detail-panel--state"><StatePanel kind="loading" title="Loading alert" message="Reading workflow, notes, and history…" /></aside>}
      {detailError && <aside className="detail-panel detail-panel--state"><StatePanel kind="error" title="Alert detail unavailable" message={detailError} actionLabel="Close" onAction={closeAlert} /></aside>}
      {selectedWorkflow && <AlertDetail workflow={selectedWorkflow} api={api} assignees={assignees} canMutate={canMutate} mutationBusy={mutationBusy} mutationError={mutationError} mutationSuccess={mutationSuccess} relatedEvents={relatedEvents} relatedEventsError={relatedEventsError} onStatus={(status: AlertWorkflowStatus) => { void mutate((workflow) => api.updateAlertStatus(workflow.alert.alert_id, status, workflow.version), `Status changed to ${status.replaceAll("_", " ")}.`); }} onAssignment={(analystId) => { void mutate((workflow) => api.updateAlertAssignment(workflow.alert.alert_id, analystId, workflow.version), analystId ? "Assignment updated." : "Alert unassigned."); }} onNote={(body) => { void mutate((workflow) => api.addAlertNote(workflow.alert.alert_id, body, workflow.version), "Analyst note added."); }} onOpenEvent={onOpenEvent} onClose={closeAlert} />}
    </div>
  );
}
