/**
 * Dashboard — Security monitoring overview.
 *
 * Shows real data from the backend where available.
 * Uses a "DEMO SAMPLE DATA" notice when backend is offline and dev fixtures are shown.
 * Never labels fixture data as live monitoring statistics.
 */

import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useHealth } from '@/hooks/useHealth';
import { useIncidents } from '@/hooks/useIncidents';
import { SeverityBadge } from '@/components/SeverityBadge';
import { ReviewStatusBadge } from '@/components/ReviewStatusBadge';
import { LoadingState } from '@/components/LoadingState';
import { ErrorState } from '@/components/ErrorState';
import type { IncidentResponse, Severity } from '@/types';
import { formatRelativeTime, truncate } from '@/utils';
import { FIXTURE_INCIDENT_LIST } from '@/api/fixtures';

type SeverityCountMap = Record<Severity, number>;

function computeSeverityCounts(items: IncidentResponse[]): SeverityCountMap {
  return items.reduce<SeverityCountMap>(
    (acc, item) => {
      acc[item.severity as Severity] = (acc[item.severity as Severity] ?? 0) + 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0 },
  );
}

export function DashboardPage() {
  const { health } = useHealth();
  const { state, refetch } = useIncidents({ limit: 50 });
  const [usingDemo, setUsingDemo] = useState(false);

  // If backend is offline and we have no data, show fixture notice
  const displayData =
    state.status === 'success'
      ? state.data
      : usingDemo
      ? FIXTURE_INCIDENT_LIST
      : null;

  useEffect(() => {
    if (state.status === 'error' && state.isNetwork) {
      setUsingDemo(true);
    }
  }, [state]);

  const counts = displayData ? computeSeverityCounts(displayData.items) : null;
  const recentItems = displayData?.items.slice(0, 5) ?? [];

  return (
    <>
      <div className="page-header">
        <div className="page-header-title">
          <h1>Security Dashboard</h1>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-muted text-sm">
            {health.lastChecked
              ? `Updated ${formatRelativeTime(health.lastChecked.toISOString())}`
              : 'Connecting…'}
          </span>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={refetch}
            aria-label="Refresh dashboard data"
          >
            ↺ Refresh
          </button>
        </div>
      </div>

      {/* Demo data notice */}
      {usingDemo && state.status === 'error' && (
        <div className="demo-notice" role="alert" aria-live="polite">
          ⚠️ <strong>SAMPLE DATA SHOWN</strong> — Backend is offline.
          Data below is for UI demonstration only and does not represent live monitoring.
          Start the backend: <code>uvicorn app.main:app --port 8000</code>
        </div>
      )}

      <div className="page-body">
        {/* Backend status panel */}
        <section aria-label="Backend status" className="card mb-6">
          <div className="card-header">
            <span className="card-title">System Status</span>
          </div>
          <div className="card-body">
            <div className="flex flex-wrap gap-6">
              <div className="detail-field">
                <span className="detail-field-label">Backend</span>
                <span className="flex items-center gap-2">
                  <span
                    className={`status-dot status-dot-${health.status}`}
                    aria-hidden="true"
                  />
                  <span className="detail-field-value">
                    {health.status === 'online'
                      ? 'Online'
                      : health.status === 'degraded'
                      ? 'Degraded — database issue'
                      : health.status === 'offline'
                      ? 'Offline'
                      : 'Checking…'}
                  </span>
                </span>
              </div>
              <div className="detail-field">
                <span className="detail-field-label">AI Analysis</span>
                <span className="detail-field-value text-muted">
                  Not configured (Phase 2)
                </span>
              </div>
              <div className="detail-field">
                <span className="detail-field-label">Wazuh Integration</span>
                <span className="detail-field-value text-muted">
                  Not connected (planned Phase 3)
                </span>
              </div>
              <div className="detail-field">
                <span className="detail-field-label">Data Source</span>
                <span className="detail-field-value">
                  {usingDemo
                    ? '⚠️ Demo fixtures (backend offline)'
                    : state.status === 'success'
                    ? 'Live backend data'
                    : 'Fetching…'}
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* Stats */}
        <section aria-label="Alert severity statistics">
          {state.status === 'loading' && !displayData && (
            <LoadingState message="Loading security statistics…" />
          )}

          {state.status === 'error' && !usingDemo && (
            <ErrorState
              message={state.message}
              isNetwork={state.isNetwork}
              onRetry={refetch}
            />
          )}

          {counts && (
            <>
              <div className="stat-grid mb-6">
                <div className="stat-card" aria-label={`Total incidents: ${displayData!.total}`}>
                  <span className="stat-label">Total Incidents</span>
                  <span className="stat-value">{displayData!.total}</span>
                  <span className="stat-description">All recorded</span>
                </div>
                <div className="stat-card" aria-label={`Critical severity: ${counts.critical}`}>
                  <span className="stat-label" style={{ color: 'var(--sev-critical-text)' }}>
                    ⛔ Critical
                  </span>
                  <span className="stat-value" style={{ color: 'var(--sev-critical-text)' }}>
                    {counts.critical}
                  </span>
                  <span className="stat-description">Rule level 12–15</span>
                </div>
                <div className="stat-card" aria-label={`High severity: ${counts.high}`}>
                  <span className="stat-label" style={{ color: 'var(--sev-high-text)' }}>
                    🔴 High
                  </span>
                  <span className="stat-value" style={{ color: 'var(--sev-high-text)' }}>
                    {counts.high}
                  </span>
                  <span className="stat-description">Rule level 8–11</span>
                </div>
                <div className="stat-card" aria-label={`Medium severity: ${counts.medium}`}>
                  <span className="stat-label" style={{ color: 'var(--sev-medium-text)' }}>
                    🟡 Medium
                  </span>
                  <span className="stat-value" style={{ color: 'var(--sev-medium-text)' }}>
                    {counts.medium}
                  </span>
                  <span className="stat-description">Rule level 4–7</span>
                </div>
                <div className="stat-card" aria-label={`Low severity: ${counts.low}`}>
                  <span className="stat-label" style={{ color: 'var(--sev-low-text)' }}>
                    🔵 Low
                  </span>
                  <span className="stat-value" style={{ color: 'var(--sev-low-text)' }}>
                    {counts.low}
                  </span>
                  <span className="stat-description">Rule level 1–3</span>
                </div>
              </div>

              {/* Recent incidents */}
              <section aria-label="Recent incidents" className="card">
                <div className="card-header">
                  <span className="card-title">Recent Incidents</span>
                  <Link to="/incidents" className="btn btn-ghost btn-sm">
                    View all →
                  </Link>
                </div>
                {recentItems.length === 0 ? (
                  <div className="card-body">
                    <p className="text-muted text-sm">No incidents recorded yet.</p>
                  </div>
                ) : (
                  <div className="table-wrapper" style={{ borderRadius: 0, border: 'none' }}>
                    <table className="data-table" aria-label="Recent incidents">
                      <thead>
                        <tr>
                          <th scope="col">Severity</th>
                          <th scope="col">Agent</th>
                          <th scope="col">Rule</th>
                          <th scope="col">Status</th>
                          <th scope="col">Received</th>
                          <th scope="col"><span className="sr-only">Actions</span></th>
                        </tr>
                      </thead>
                      <tbody>
                        {recentItems.map((incident) => (
                          <tr key={incident.id} className="clickable">
                            <td><SeverityBadge severity={incident.severity} /></td>
                            <td className="table-cell-primary">
                              {incident.agent_name ?? '—'}
                            </td>
                            <td>
                              <span title={incident.rule_description ?? ''}>
                                {truncate(incident.rule_description, 48)}
                              </span>
                            </td>
                            <td><ReviewStatusBadge status={incident.review_status} /></td>
                            <td className="text-muted text-xs">
                              {formatRelativeTime(incident.created_at)}
                            </td>
                            <td>
                              <Link
                                to={`/incidents/${incident.id}`}
                                className="btn btn-ghost btn-sm"
                                aria-label={`View incident from ${incident.agent_name ?? 'unknown agent'}`}
                              >
                                View →
                              </Link>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
            </>
          )}
        </section>
      </div>
    </>
  );
}
