/**
 * IncidentsPage — Alert Explorer with server-side filtering, sorting and pagination.
 *
 * Pagination uses actual backend limit/offset — never downloads all records.
 * All filter state is held in component state and sent as query params to backend.
 */

import { useState, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useIncidents } from '@/hooks/useIncidents';
import { SeverityBadge } from '@/components/SeverityBadge';
import { ReviewStatusBadge } from '@/components/ReviewStatusBadge';
import { PriorityBar } from '@/components/PriorityBar';
import { MitreTagList } from '@/components/MitreTagList';
import { LoadingState } from '@/components/LoadingState';
import { ErrorState } from '@/components/ErrorState';
import { EmptyState } from '@/components/EmptyState';
import type { IncidentListParams, Severity } from '@/types';
import { formatDateTime, truncate } from '@/utils';

const PAGE_SIZE = 25;

const SEVERITY_OPTIONS: Array<{ value: Severity | ''; label: string }> = [
  { value: '', label: 'All severities' },
  { value: 'critical', label: '⛔ Critical' },
  { value: 'high', label: '🔴 High' },
  { value: 'medium', label: '🟡 Medium' },
  { value: 'low', label: '🔵 Low' },
];

export function IncidentsPage() {
  const navigate = useNavigate();

  const [page, setPage] = useState(0);
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('');
  const [agentFilter, setAgentFilter] = useState('');
  const [mitreFilter, setMitreFilter] = useState('');

  // Committed filter state (applied on Search / Enter)
  const [committedAgent, setCommittedAgent] = useState('');
  const [committedMitre, setCommittedMitre] = useState('');

  const params: IncidentListParams = {
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
    ...(severityFilter ? { severity: severityFilter } : {}),
    ...(committedAgent ? { agent: committedAgent } : {}),
    ...(committedMitre ? { mitre_id: committedMitre } : {}),
  };

  const { state, refetch } = useIncidents(params);

  const applyFilters = useCallback(() => {
    setPage(0);
    setCommittedAgent(agentFilter);
    setCommittedMitre(mitreFilter);
  }, [agentFilter, mitreFilter]);

  const clearFilters = () => {
    setPage(0);
    setSeverityFilter('');
    setAgentFilter('');
    setMitreFilter('');
    setCommittedAgent('');
    setCommittedMitre('');
  };

  const totalPages =
    state.status === 'success'
      ? Math.ceil(state.data.total / PAGE_SIZE)
      : 0;

  const filtersActive =
    !!severityFilter || !!committedAgent || !!committedMitre;

  return (
    <>
      <div className="page-header">
        <div className="page-header-title">
          <Link to="/" className="btn btn-ghost btn-sm" aria-label="Back to dashboard">
            ← Dashboard
          </Link>
          <h1>Incident Explorer</h1>
          {state.status === 'success' && (
            <span
              className="badge badge-low"
              style={{ fontSize: 'var(--text-xs)' }}
              aria-label={`${state.data.total} total incidents`}
            >
              {state.data.total} total
            </span>
          )}
        </div>
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          onClick={refetch}
          aria-label="Refresh incident list"
        >
          ↺ Refresh
        </button>
      </div>

      {/* Filter bar */}
      <div className="filter-bar" role="search" aria-label="Incident filters">
        <div className="form-group">
          <label className="form-label" htmlFor="severity-filter">Severity</label>
          <select
            id="severity-filter"
            className="form-select"
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value as Severity | '');
              setPage(0);
            }}
            style={{ minWidth: 160 }}
          >
            {SEVERITY_OPTIONS.map(({ value, label }) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>
        </div>

        <div className="form-group" style={{ minWidth: 180 }}>
          <label className="form-label" htmlFor="agent-filter">Agent name</label>
          <input
            id="agent-filter"
            type="text"
            className="form-input"
            placeholder="e.g. WIN-PC-01"
            value={agentFilter}
            onChange={(e) => setAgentFilter(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && applyFilters()}
          />
        </div>

        <div className="form-group" style={{ minWidth: 160 }}>
          <label className="form-label" htmlFor="mitre-filter">MITRE ID</label>
          <input
            id="mitre-filter"
            type="text"
            className="form-input"
            placeholder="e.g. T1110"
            value={mitreFilter}
            onChange={(e) => setMitreFilter(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && applyFilters()}
          />
        </div>

        <div className="flex gap-2" style={{ alignSelf: 'flex-end' }}>
          <button
            type="button"
            className="btn btn-primary"
            onClick={applyFilters}
            aria-label="Apply filters"
          >
            Search
          </button>
          {filtersActive && (
            <button
              type="button"
              className="btn btn-ghost"
              onClick={clearFilters}
              aria-label="Clear all filters"
            >
              ✕ Clear
            </button>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="page-body" style={{ padding: 0 }}>
        {state.status === 'loading' && (
          <LoadingState message="Loading incidents…" />
        )}

        {state.status === 'error' && (
          <ErrorState
            message={state.message}
            isNetwork={state.isNetwork}
            onRetry={refetch}
          />
        )}

        {state.status === 'success' && state.data.items.length === 0 && (
          <EmptyState
            title="No incidents found"
            description={
              filtersActive
                ? 'No incidents match the current filters. Try adjusting your search.'
                : 'No incidents have been ingested yet. Use POST /api/v1/ingest/wazuh to submit alerts.'
            }
            icon="📭"
            action={
              filtersActive ? (
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={clearFilters}
                >
                  Clear filters
                </button>
              ) : undefined
            }
          />
        )}

        {state.status === 'success' && state.data.items.length > 0 && (
          <>
            <div className="table-wrapper" style={{ borderRadius: 0, borderLeft: 'none', borderRight: 'none', borderTop: 'none' }}>
              <table className="data-table" aria-label="Security incidents">
                <thead>
                  <tr>
                    <th scope="col">Severity</th>
                    <th scope="col">Priority</th>
                    <th scope="col">Agent</th>
                    <th scope="col">Rule</th>
                    <th scope="col">MITRE</th>
                    <th scope="col">Review</th>
                    <th scope="col">Timestamp</th>
                    <th scope="col"><span className="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  {state.data.items.map((incident) => (
                    <tr
                      key={incident.id}
                      className="clickable"
                      onClick={() => navigate(`/incidents/${incident.id}`)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          navigate(`/incidents/${incident.id}`);
                        }
                      }}
                      tabIndex={0}
                      role="row"
                      aria-label={`Incident: ${incident.rule_description ?? incident.id}. Severity: ${incident.severity}`}
                    >
                      <td><SeverityBadge severity={incident.severity} /></td>
                      <td>
                        <PriorityBar
                          score={incident.priority_score}
                          severity={incident.severity}
                        />
                      </td>
                      <td className="table-cell-primary">
                        <div>{incident.agent_name ?? '—'}</div>
                        {incident.agent_ip && (
                          <div className="text-muted text-xs font-mono">{incident.agent_ip}</div>
                        )}
                      </td>
                      <td>
                        <div className="table-cell-primary">
                          {truncate(incident.rule_description, 52)}
                        </div>
                        {incident.rule_id && (
                          <div className="text-muted text-xs font-mono">
                            Rule #{incident.rule_id} · L{incident.rule_level}
                          </div>
                        )}
                      </td>
                      <td onClick={(e) => e.stopPropagation()}>
                        <MitreTagList ids={incident.mitre_ids.slice(0, 2)} />
                        {incident.mitre_ids.length > 2 && (
                          <span className="text-muted text-xs">
                            +{incident.mitre_ids.length - 2} more
                          </span>
                        )}
                      </td>
                      <td><ReviewStatusBadge status={incident.review_status} /></td>
                      <td className="text-muted text-xs">
                        {formatDateTime(incident.event_timestamp ?? incident.created_at)}
                      </td>
                      <td onClick={(e) => e.stopPropagation()}>
                        <Link
                          to={`/incidents/${incident.id}`}
                          className="btn btn-ghost btn-sm"
                          aria-label={`View incident details for ${incident.agent_name ?? incident.id}`}
                        >
                          Detail →
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="pagination">
              <span>
                Showing {state.data.offset + 1}–{Math.min(state.data.offset + state.data.items.length, state.data.total)} of {state.data.total} incidents
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
                <span className="text-muted">
                  Page {page + 1} of {Math.max(1, totalPages)}
                </span>
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
