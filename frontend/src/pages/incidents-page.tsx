import { useEffect, useMemo, useState } from "react";

import { ApiError } from "../api/client";
import { IncidentCreateForm } from "../components/incident-create-form";
import { IncidentDetail } from "../components/incident-detail";
import { EMPTY_INCIDENT_FILTERS, IncidentFilters, type IncidentFilterValues } from "../components/incident-filters";
import { IncidentsTable } from "../components/incidents-table";
import { Pagination } from "../components/pagination";
import { StatePanel } from "../components/state-panel";
import type { BackendApi, IncidentListResponse } from "../types/api";
import type { IncidentCreate, IncidentDetail as IncidentDetailModel, IncidentStatus } from "../types/incidents";

function errorMessage(reason: unknown): string {
  if (reason instanceof ApiError) return `${reason.message} [${reason.code}]`;
  return reason instanceof Error ? reason.message : "The incident operation failed.";
}

export function IncidentsPage({ api, canMutate = true }: { api: BackendApi; canMutate?: boolean }) {
  const [filters, setFilters] = useState<IncidentFilterValues>(EMPTY_INCIDENT_FILTERS);
  const [cursor, setCursor] = useState<string | undefined>();
  const [cursorStack, setCursorStack] = useState<Array<string | undefined>>([]);
  const [data, setData] = useState<IncidentListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const [showCreate, setShowCreate] = useState(false);
  const [createBusy, setCreateBusy] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<IncidentDetailModel | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [mutationBusy, setMutationBusy] = useState(false);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [mutationSuccess, setMutationSuccess] = useState<string | null>(null);

  const query = useMemo(() => ({
    statuses: filters.status ? [filters.status] : undefined,
    severities: filters.severity ? [filters.severity] : undefined,
    assignedTo: filters.assignedTo.trim() || undefined,
    limit: 25,
    cursor,
  }), [cursor, filters]);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setLoading(true);
    setError(null);
    api.listIncidents(query, controller.signal)
      .then((response) => { if (active) setData(response); })
      .catch((reason: unknown) => {
        if (!active || (reason instanceof DOMException && reason.name === "AbortError")) return;
        setError(errorMessage(reason));
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [api, query, revision]);

  useEffect(() => {
    if (!selectedId) { setDetail(null); setDetailError(null); return; }
    const controller = new AbortController();
    let active = true;
    setDetail(null);
    setDetailLoading(true);
    setDetailError(null);
    setMutationError(null);
    setMutationSuccess(null);
    api.getIncident(selectedId, controller.signal)
      .then((response) => { if (active) setDetail(response); })
      .catch((reason: unknown) => { if (active) setDetailError(errorMessage(reason)); })
      .finally(() => { if (active) setDetailLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [api, selectedId]);

  const applyFilters = (next: IncidentFilterValues) => {
    setFilters(next);
    setCursor(undefined);
    setCursorStack([]);
  };

  const createIncident = async (payload: IncidentCreate) => {
    setCreateBusy(true);
    setCreateError(null);
    try {
      const created = await api.createIncident(payload);
      setShowCreate(false);
      setSelectedId(created.incident_id);
      setDetail(created);
      setRevision((value) => value + 1);
    } catch (reason) {
      setCreateError(errorMessage(reason));
    } finally {
      setCreateBusy(false);
    }
  };

  const mutate = async (operation: () => Promise<IncidentDetailModel>, success: string): Promise<boolean> => {
    setMutationBusy(true);
    setMutationError(null);
    setMutationSuccess(null);
    try {
      const updated = await operation();
      setDetail(updated);
      setMutationSuccess(success);
      setRevision((value) => value + 1);
      return true;
    } catch (reason) {
      setMutationError(errorMessage(reason));
      return false;
    } finally {
      setMutationBusy(false);
    }
  };

  const requireId = () => {
    if (!selectedId) throw new Error("No incident is selected.");
    return selectedId;
  };

  return (
    <div className="page-grid">
      <section className="page-column">
        <header className="page-header"><div><span className="eyebrow">Case management</span><h1>Incidents</h1><p>Deterministic lifecycle, alert relationships, notes, and audit history.</p></div><div className="header-actions"><div className="page-header__metric"><strong>{data?.page.total ?? "—"}</strong><span>matching incidents</span></div>{canMutate && <button className="button button--primary" type="button" onClick={() => { setShowCreate(true); setCreateError(null); }}>Create incident</button>}</div></header>
        {showCreate && canMutate && <IncidentCreateForm busy={createBusy} error={createError} onCancel={() => setShowCreate(false)} onCreate={createIncident} />}
        <IncidentFilters values={filters} onApply={applyFilters} />
        {loading && !data && <StatePanel kind="loading" title="Loading incidents" message="Reading the current incident queue…" />}
        {error && <StatePanel kind="unavailable" title="Incident data unavailable" message={error} actionLabel="Retry" onAction={() => setRevision((value) => value + 1)} />}
        {!loading && !error && data?.items.length === 0 && <StatePanel kind="empty" title="No matching incidents" message="Create an incident or adjust the current filters." />}
        {!error && data && data.items.length > 0 && <><IncidentsTable incidents={data.items} selectedId={selectedId} onSelect={setSelectedId} /><Pagination visible={data.items.length} total={data.page.total} hasPrevious={cursorStack.length > 0} hasNext={Boolean(data.page.next_cursor)} loading={loading} onPrevious={() => { setCursor(cursorStack[cursorStack.length - 1]); setCursorStack((current) => current.slice(0, -1)); }} onNext={() => { if (data.page.next_cursor) { setCursorStack((current) => [...current, cursor]); setCursor(data.page.next_cursor); } }} /></>}
      </section>

      {selectedId && detailLoading && !detail && <aside className="detail-panel detail-panel--state"><StatePanel kind="loading" title="Loading incident" message="Reading lifecycle and audit history…" /></aside>}
      {selectedId && detailError && <aside className="detail-panel detail-panel--state"><StatePanel kind="error" title="Incident detail unavailable" message={detailError} actionLabel="Close" onAction={() => setSelectedId(null)} /></aside>}
      {detail && selectedId === detail.incident_id && (
        <IncidentDetail
          incident={detail}
          api={api}
          busy={mutationBusy}
          error={mutationError}
          success={mutationSuccess}
          canMutate={canMutate}
          onClose={() => setSelectedId(null)}
          onStatus={(status: IncidentStatus) => mutate(() => api.updateIncidentStatus(requireId(), { status }), `Status changed to ${status}.`)}
          onLink={(alertId) => mutate(() => api.linkIncidentAlert(requireId(), { alert_id: alertId }), "Alert linked.")}
          onNote={(body) => mutate(async () => { await api.addIncidentNote(requireId(), { body }); return api.getIncident(requireId()); }, "Note added.")}
          onAssignment={(assignedTo) => mutate(() => api.updateIncidentAssignment(requireId(), { assigned_to: assignedTo }), assignedTo ? "Assignment updated." : "Incident unassigned.")}
        />
      )}
    </div>
  );
}
