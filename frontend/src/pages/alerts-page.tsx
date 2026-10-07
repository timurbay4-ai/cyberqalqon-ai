import { useEffect, useMemo, useState } from "react";

import { AlertDetail } from "../components/alert-detail";
import { AlertFilters, EMPTY_ALERT_FILTERS, type AlertFilterValues } from "../components/alert-filters";
import { AlertsTable } from "../components/alerts-table";
import { Pagination } from "../components/pagination";
import { StatePanel } from "../components/state-panel";
import type { AlertListResponse, BackendApi } from "../types/api";
import type { NormalizedAlert } from "../types/alerts";
import { toApiTimestamp } from "../utils/format";
import { severityLevels } from "../utils/severity";

export function AlertsPage({ api }: { api: BackendApi }) {
  const [filters, setFilters] = useState<AlertFilterValues>(EMPTY_ALERT_FILTERS);
  const [cursor, setCursor] = useState<string | undefined>();
  const [cursorStack, setCursorStack] = useState<Array<string | undefined>>([]);
  const [data, setData] = useState<AlertListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<NormalizedAlert | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);

  const query = useMemo(() => ({
    ruleLevels: severityLevels(filters.severityBands),
    agent: filters.agent.trim() || undefined,
    mitreMapped: filters.mitreMode === "any" ? undefined : filters.mitreMode === "mapped",
    mitreId: filters.mitreId.trim() || undefined,
    startTime: toApiTimestamp(filters.startTime),
    endTime: toApiTimestamp(filters.endTime),
    search: filters.search.trim() || undefined,
    limit: 25,
    cursor,
  }), [cursor, filters]);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setLoading(true);
    setError(null);
    api.listAlerts(query, controller.signal)
      .then((response) => { if (active) setData(response); })
      .catch((reason: unknown) => {
        if (!active || (reason instanceof DOMException && reason.name === "AbortError")) return;
        setError(reason instanceof Error ? reason.message : "Alerts could not be loaded.");
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [api, query, revision]);

  useEffect(() => {
    if (!selectedAlertId) {
      setSelectedAlert(null);
      setDetailError(null);
      return;
    }
    const controller = new AbortController();
    let active = true;
    setSelectedAlert(null);
    setDetailError(null);
    api.getAlert(selectedAlertId, controller.signal)
      .then((response) => { if (active) setSelectedAlert(response); })
      .catch((reason: unknown) => {
        if (!active || (reason instanceof DOMException && reason.name === "AbortError")) return;
        setDetailError(reason instanceof Error ? reason.message : "Alert detail could not be loaded.");
      });
    return () => { active = false; controller.abort(); };
  }, [api, selectedAlertId]);

  const applyFilters = (next: AlertFilterValues) => {
    setFilters(next);
    setCursor(undefined);
    setCursorStack([]);
  };

  const goNext = () => {
    if (!data?.page.next_cursor) return;
    setCursorStack((current) => [...current, cursor]);
    setCursor(data.page.next_cursor);
  };

  const goPrevious = () => {
    if (!cursorStack.length) return;
    setCursor(cursorStack[cursorStack.length - 1]);
    setCursorStack((current) => current.slice(0, -1));
  };

  return (
    <div className="page-grid">
      <section className="page-column">
        <header className="page-header"><div><span className="eyebrow">Detection queue</span><h1>Security alerts</h1><p>Normalized Wazuh detections from the live backend.</p></div><div className="page-header__metric"><strong>{data?.page.total ?? "—"}</strong><span>matching alerts</span></div></header>
        <AlertFilters values={filters} onApply={applyFilters} />
        {loading && !data && <StatePanel kind="loading" title="Loading alerts" message="Reading normalized alerts…" />}
        {error && <StatePanel kind="unavailable" title="Alert data unavailable" message={error} actionLabel="Retry" onAction={() => setRevision((value) => value + 1)} />}
        {!loading && !error && data?.items.length === 0 && <StatePanel kind="empty" title="No matching alerts" message="Adjust or reset the filters to broaden the query." />}
        {!error && data && data.items.length > 0 && (
          <>
            <AlertsTable alerts={data.items} selectedAlertId={selectedAlertId} onSelect={setSelectedAlertId} />
            <Pagination visible={data.items.length} total={data.page.total} hasPrevious={cursorStack.length > 0} hasNext={Boolean(data.page.next_cursor)} loading={loading} onPrevious={goPrevious} onNext={goNext} />
          </>
        )}
      </section>
      {selectedAlertId && !selectedAlert && !detailError && <aside className="detail-panel detail-panel--state"><StatePanel kind="loading" title="Loading alert" message="Reading alert detail…" /></aside>}
      {detailError && <aside className="detail-panel detail-panel--state"><StatePanel kind="error" title="Alert detail unavailable" message={detailError} actionLabel="Close" onAction={() => setSelectedAlertId(null)} /></aside>}
      {selectedAlert && <AlertDetail alert={selectedAlert} api={api} onClose={() => setSelectedAlertId(null)} />}
    </div>
  );
}
