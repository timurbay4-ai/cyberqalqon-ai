/**
 * AlertExplorerPage — Raw alert browser for SOC analyst / debug view.
 *
 * Shows the same incident list but in a more compact, raw-data view.
 * Highlights raw_event inspection capability.
 */

import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useIncidents } from '@/hooks/useIncidents';
import { SeverityBadge } from '@/components/SeverityBadge';
import { JsonViewer } from '@/components/JsonViewer';
import { LoadingState } from '@/components/LoadingState';
import { ErrorState } from '@/components/ErrorState';
import { EmptyState } from '@/components/EmptyState';
import type { IncidentListParams, Severity } from '@/types';
import { formatDateTime } from '@/utils';

const PAGE_SIZE = 20;

export function AlertExplorerPage() {
  const [page, setPage] = useState(0);
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const params: IncidentListParams = {
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
    ...(severityFilter ? { severity: severityFilter } : {}),
  };

  const { state, refetch } = useIncidents(params);

  const totalPages =
    state.status === 'success'
      ? Math.ceil(state.data.total / PAGE_SIZE)
      : 0;

  return (
    <>
      <div className="page-header">
        <div className="page-header-title">
          <Link to="/" className="btn btn-ghost btn-sm">← Dashboard</Link>
          <h1>Alert Explorer</h1>
          <span className="text-xs text-muted">(Raw analyst view)</span>
        </div>
        <button type="button" className="btn btn-ghost btn-sm" onClick={refetch} aria-label="Refresh">
          ↺ Refresh
        </button>
      </div>

      <div className="filter-bar" role="search" aria-label="Alert filters">
        <div className="form-group">
          <label className="form-label" htmlFor="alert-severity-filter">Severity</label>
          <select
            id="alert-severity-filter"
            className="form-select"
            value={severityFilter}
            onChange={(e) => { setSeverityFilter(e.target.value as Severity | ''); setPage(0); }}
            style={{ minWidth: 160 }}
          >
            <option value="">All severities</option>
            <option value="critical">⛔ Critical</option>
            <option value="high">🔴 High</option>
            <option value="medium">🟡 Medium</option>
            <option value="low">🔵 Low</option>
          </select>
        </div>
      </div>

      <div className="page-body" style={{ padding: 0 }}>
        {state.status === 'loading' && <LoadingState message="Loading alerts…" />}

        {state.status === 'error' && (
          <ErrorState message={state.message} isNetwork={state.isNetwork} onRetry={refetch} />
        )}

        {state.status === 'success' && state.data.items.length === 0 && (
          <EmptyState
            title="No alerts found"
            description="Ingest alerts via POST /api/v1/ingest/wazuh"
            icon="🔍"
          />
        )}

        {state.status === 'success' && state.data.items.length > 0 && (
          <>
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 0,
                borderTop: '1px solid var(--border-subtle)',
              }}
            >
              {state.data.items.map((incident) => (
                <div
                  key={incident.id}
                  style={{
                    borderBottom: '1px solid var(--border-subtle)',
                  }}
                >
                  {/* Alert row */}
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 12,
                      padding: '12px 24px',
                      cursor: 'pointer',
                      background: expandedId === incident.id ? 'var(--bg-hover)' : 'transparent',
                      transition: 'background 0.1s',
                    }}
                    onClick={() =>
                      setExpandedId((prev) => (prev === incident.id ? null : incident.id))
                    }
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ')
                        setExpandedId((prev) => (prev === incident.id ? null : incident.id));
                    }}
                    role="button"
                    tabIndex={0}
                    aria-expanded={expandedId === incident.id}
                    aria-controls={`alert-detail-${incident.id}`}
                    aria-label={`Alert: ${incident.rule_description ?? incident.id}`}
                  >
                    <span style={{ fontSize: '0.75rem', opacity: 0.4, width: 12 }}>
                      {expandedId === incident.id ? '▼' : '▶'}
                    </span>
                    <SeverityBadge severity={incident.severity} />
                    <span
                      className="font-mono text-xs text-muted"
                      style={{ minWidth: 80 }}
                    >
                      L{incident.rule_level ?? '?'}
                    </span>
                    <span
                      className="text-secondary text-sm"
                      style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                    >
                      {incident.rule_description ?? incident.alert_id ?? incident.id}
                    </span>
                    <span className="text-muted text-xs" style={{ minWidth: 110 }}>
                      {incident.agent_name ?? '—'}
                    </span>
                    <span className="font-mono text-muted text-xs" style={{ minWidth: 80 }}>
                      {incident.source_ip ?? ''}
                    </span>
                    <span className="text-muted text-xs" style={{ minWidth: 155 }}>
                      {formatDateTime(incident.event_timestamp ?? incident.created_at)}
                    </span>
                    <Link
                      to={`/incidents/${incident.id}`}
                      className="btn btn-ghost btn-sm"
                      onClick={(e) => e.stopPropagation()}
                      aria-label="Full detail view"
                    >
                      Detail
                    </Link>
                  </div>

                  {/* Expandable raw event */}
                  {expandedId === incident.id && (
                    <div
                      id={`alert-detail-${incident.id}`}
                      style={{ padding: '0 24px 16px' }}
                      role="region"
                      aria-label="Raw event JSON"
                    >
                      <JsonViewer
                        data={incident.raw_event}
                        label="Raw Wazuh Event"
                        initiallyExpanded
                      />
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Pagination */}
            <div className="pagination">
              <span className="text-muted text-sm">
                {state.data.offset + 1}–{Math.min(state.data.offset + state.data.items.length, state.data.total)} of {state.data.total}
              </span>
              <div className="pagination-controls">
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  disabled={page === 0}
                  aria-label="Previous page"
                >
                  ← Prev
                </button>
                <span className="text-muted">Page {page + 1} / {Math.max(1, totalPages)}</span>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => setPage((p) => p + 1)}
                  disabled={page + 1 >= totalPages}
                  aria-label="Next page"
                >
                  Next →
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </>
  );
}
