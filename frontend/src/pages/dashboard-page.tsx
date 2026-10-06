import { useCallback, useEffect, useState } from "react";

import { StatePanel } from "../components/state-panel";
import type { BackendApi } from "../types/api";
import { INCIDENT_STATUSES, type IncidentStatus } from "../types/incidents";
import { humanize } from "../utils/format";

interface DashboardMetrics {
  totalAlerts: number;
  criticalAlerts: number;
  mitreMappedAlerts: number;
  activeIncidents: number;
  incidentStatuses: Record<IncidentStatus, number>;
}

export function DashboardPage({ api }: { api: BackendApi }) {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const retry = useCallback(() => setRevision((value) => value + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    setMetrics(null);
    setError(null);
    Promise.all([
      api.listAlerts({ limit: 1 }, controller.signal),
      api.listAlerts({ ruleLevels: [13, 14, 15, 16], limit: 1 }, controller.signal),
      api.listAlerts({ mitreMapped: true, limit: 1 }, controller.signal),
      ...INCIDENT_STATUSES.map((status) => api.listIncidents({ statuses: [status], limit: 1 }, controller.signal)),
    ])
      .then(([allAlerts, criticalAlerts, mappedAlerts, ...incidentPages]) => {
        const incidentStatuses = Object.fromEntries(
          INCIDENT_STATUSES.map((status, index) => [status, incidentPages[index].page.total]),
        ) as Record<IncidentStatus, number>;
        setMetrics({
          totalAlerts: allAlerts.page.total,
          criticalAlerts: criticalAlerts.page.total,
          mitreMappedAlerts: mappedAlerts.page.total,
          activeIncidents: incidentStatuses.NEW + incidentStatuses.TRIAGED + incidentStatuses.INVESTIGATING,
          incidentStatuses,
        });
      })
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === "AbortError") return;
        setError(reason instanceof Error ? reason.message : "Dashboard data could not be loaded.");
      });
    return () => controller.abort();
  }, [api, revision]);

  return (
    <section className="page-column">
      <header className="page-header">
        <div><span className="eyebrow">Operational picture</span><h1>Security overview</h1><p>Live totals derived from authoritative alert and incident APIs.</p></div>
      </header>
      {!metrics && !error && <StatePanel kind="loading" title="Building overview" message="Reading current backend totals…" />}
      {error && <StatePanel kind="unavailable" title="Overview unavailable" message={error} actionLabel="Retry" onAction={retry} />}
      {metrics && (
        <>
          <div className="metric-grid">
            <article className="metric-card metric-card--critical"><span>Critical alerts</span><strong>{metrics.criticalAlerts}</strong><small>Wazuh levels 13–16</small></article>
            <article className="metric-card"><span>Total alerts</span><strong>{metrics.totalAlerts}</strong><small>All normalized records</small></article>
            <article className="metric-card"><span>MITRE mapped</span><strong>{metrics.mitreMappedAlerts}</strong><small>Upstream technique IDs</small></article>
            <article className="metric-card"><span>Active incidents</span><strong>{metrics.activeIncidents}</strong><small>New, triaged, investigating</small></article>
          </div>
          <article className="panel">
            <header className="panel__header"><div><span className="eyebrow">Workflow</span><h2>Incident status distribution</h2></div></header>
            <div className="status-distribution">
              {INCIDENT_STATUSES.map((status) => (
                <div key={status}><span>{humanize(status)}</span><strong>{metrics.incidentStatuses[status]}</strong></div>
              ))}
            </div>
          </article>
        </>
      )}
    </section>
  );
}
