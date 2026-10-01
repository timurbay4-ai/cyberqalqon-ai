/**
 * Dashboard — Security monitoring overview.
 *
 * Statistics are fetched from GET /api/v1/incidents/stats (accurate DB counts).
 * Recent incidents are fetched from GET /api/v1/incidents?limit=5.
 *
 * When backend is offline:
 * - Demo fixture data is shown with a clear "SAMPLE DATA" banner.
 * - Fixture data is never labelled as live monitoring data.
 */

import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useHealth } from '@/hooks/useHealth';
import { useIncidents } from '@/hooks/useIncidents';
import { useStats } from '@/hooks/useStats';
import { SeverityBadge } from '@/components/SeverityBadge';
import { ReviewStatusBadge } from '@/components/ReviewStatusBadge';
import { LoadingState } from '@/components/LoadingState';
import { ErrorState } from '@/components/ErrorState';
import type { IncidentStatsResponse } from '@/types';
import { formatRelativeTime, formatDateTime, truncate } from '@/utils';
import { FIXTURE_INCIDENT_LIST, FIXTURE_STATS } from '@/api/fixtures';

/** Fixture stats built from the fixture incident list for demo mode */


export function DashboardPage() {
  const { health } = useHealth();
  const { state: statsState, refetch: refetchStats } = useStats();
  const { state: listState, refetch: refetchList } = useIncidents({ limit: 5 });
  const [usingDemo, setUsingDemo] = useState(false);

  const isNetworkError =
    (statsState.status === 'error' && statsState.isNetwork) ||
    (listState.status === 'error' && listState.isNetwork);

  useEffect(() => {
    if (isNetworkError) {
      setUsingDemo(true);
    }
  }, [isNetworkError]);

  const refetch = () => {
    setUsingDemo(false);
    refetchStats();
    refetchList();
  };

  // Choose data sources: live backend or clearly-labeled fixtures
  const stats: IncidentStatsResponse | null =
    statsState.status === 'success'
      ? statsState.data
      : usingDemo
      ? FIXTURE_STATS
      : null;

  const recentItems =
    listState.status === 'success'
      ? listState.data.items
      : usingDemo
      ? FIXTURE_INCIDENT_LIST.items.slice(0, 5)
      : [];

  const isLoading =
    (statsState.status === 'loading' || statsState.status === 'idle') && !usingDemo;

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

      {/* Demo data notice — prominently labeled, never ambiguous */}
      {usingDemo && (
        <div className="demo-notice" role="alert" aria-live="polite">
          ⚠️ <strong>SAMPLE DATA SHOWN</strong> — Backend is offline or unreachable.
          Statistics and incidents below are UI demonstration data only and do not
          represent live monitoring.
          Start backend: <code>cd backend &amp;&amp; uvicorn app.main:app --port 8000</code>
        </div>
      )}

      <div className="page-body">
        {/* System status panel */}
        <section aria-label="System status" className="card mb-6">
          <div className="card-header">
            <span className="card-title">System Status</span>
          </div>
          <div className="card-body">
            <div className="flex flex-wrap gap-6">
              <div className="detail-field">
                <span className="detail-field-label">Backend API</span>
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
                <span className="detail-field-label">Authentication</span>
                <span className="detail-field-value text-muted">
                  Optional token (empty = auth disabled for local dev)
                </span>
              </div>
              <div className="detail-field">
                <span className="detail-field-label">AI Analysis</span>
                <span className="detail-field-value text-muted">
                  Not configured (Phase 3)
                </span>
              </div>
              <div className="detail-field">
                <span className="detail-field-label">Data Source</span>
                <span className="detail-field-value">
                  {usingDemo
                    ? '⚠️ Demo fixtures (backend offline)'
                    : statsState.status === 'success'
                    ? 'Live backend — SQLite'
                    : 'Fetching…'}
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* Stats */}
        <section aria-label="Incident statistics">
          {isLoading && <LoadingState message="Loading security statistics…" />}

          {statsState.status === 'error' && !usingDemo && (
            <ErrorState
              message={statsState.message}
              isNetwork={statsState.isNetwork}
              onRetry={refetch}
            />
          )}

          {stats && (
            <>
              <div className="stat-grid mb-6">
                <div className="stat-card" aria-label={`Total incidents: ${stats.total}`}>
                  <span className="stat-label">Total Incidents</span>
                  <span className="stat-value">{stats.total}</span>
                  <span className="stat-description">All stored</span>
                </div>
                <div
                  className="stat-card"
                  aria-label={`Critical severity: ${stats.severity.critical}`}
                >
                  <span className="stat-label" style={{ color: 'var(--sev-critical-text)' }}>
                    ⛔ Critical
                  </span>
                  <span className="stat-value" style={{ color: 'var(--sev-critical-text)' }}>
                    {stats.severity.critical}
                  </span>
                  <span className="stat-description">Rule level 12–15</span>
                </div>
                <div
                  className="stat-card"
                  aria-label={`High severity: ${stats.severity.high}`}
                >
                  <span className="stat-label" style={{ color: 'var(--sev-high-text)' }}>
                    🔴 High
                  </span>
                  <span className="stat-value" style={{ color: 'var(--sev-high-text)' }}>
                    {stats.severity.high}
                  </span>
                  <span className="stat-description">Rule level 8–11</span>
                </div>
                <div
                  className="stat-card"
                  aria-label={`Medium severity: ${stats.severity.medium}`}
                >
                  <span className="stat-label" style={{ color: 'var(--sev-medium-text)' }}>
                    🟡 Medium
                  </span>
                  <span className="stat-value" style={{ color: 'var(--sev-medium-text)' }}>
                    {stats.severity.medium}
                  </span>
                  <span className="stat-description">Rule level 4–7</span>
                </div>
                <div
                  className="stat-card"
                  aria-label={`Low severity: ${stats.severity.low}`}
                >
                  <span className="stat-label" style={{ color: 'var(--sev-low-text)' }}>
                    🔵 Low
                  </span>
                  <span className="stat-value" style={{ color: 'var(--sev-low-text)' }}>
                    {stats.severity.low}
                  </span>
                  <span className="stat-description">Rule level 1–3</span>
                </div>
                <div
                  className="stat-card"
                  aria-label={`Needs review: ${stats.review_status.needs_review}`}
                >
                  <span className="stat-label">◉ Needs Review</span>
                  <span className="stat-value">{stats.review_status.needs_review}</span>
                  <span className="stat-description">Awaiting analyst</span>
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
                    <p className="text-muted text-sm">
                      No incidents yet. Ingest a Wazuh alert via{' '}
                      <code>POST /api/v1/ingest/wazuh</code> to populate this list.
                    </p>
                  </div>
                ) : (
                  <div
                    className="table-wrapper"
                    style={{ borderRadius: 0, border: 'none' }}
                  >
                    <table
                      className="data-table"
                      aria-label="Recent security incidents"
                    >
                      <thead>
                        <tr>
                          <th scope="col">Severity</th>
                          <th scope="col">Agent</th>
                          <th scope="col">Rule</th>
                          <th scope="col">Status</th>
                          <th scope="col">Event Time</th>
                          <th scope="col">
                            <span className="sr-only">Actions</span>
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {recentItems.map((incident) => (
                          <tr key={incident.id}>
                            <td>
                              <SeverityBadge severity={incident.severity} />
                            </td>
                            <td className="table-cell-primary">
                              {incident.agent_name ?? '—'}
                            </td>
                            <td>
                              <span title={incident.rule_description ?? ''}>
                                {truncate(incident.rule_description, 52)}
                              </span>
                              {incident.rule_id && (
                                <div className="text-muted text-xs font-mono">
                                  Rule #{incident.rule_id}
                                </div>
                              )}
                            </td>
                            <td>
                              <ReviewStatusBadge status={incident.review_status} />
                            </td>
                            <td className="text-muted text-xs">
                              {formatDateTime(
                                incident.event_timestamp ?? incident.created_at,
                              )}
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
