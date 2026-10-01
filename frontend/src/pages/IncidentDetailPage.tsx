/**
 * IncidentDetailPage — Full incident investigation view.
 *
 * Sections:
 *  1. Alert metadata & rule information
 *  2. Agent & network information
 *  3. MITRE ATT&CK identifiers (from alert data, not AI-generated)
 *  4. AI Analysis status (placeholder — AI not yet implemented)
 *  5. Original evidence: full_log, raw_event JSON
 *  6. Analyst review history & new review form
 *
 * Security: all event fields rendered as text, never as HTML.
 * JSON viewer never executes content.
 */

import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useIncident } from '@/hooks/useIncident';
import { SeverityBadge } from '@/components/SeverityBadge';
import { ReviewStatusBadge } from '@/components/ReviewStatusBadge';
import { MitreTagList } from '@/components/MitreTagList';
import { JsonViewer } from '@/components/JsonViewer';
import { PriorityBar } from '@/components/PriorityBar';
import { LoadingState } from '@/components/LoadingState';
import { ErrorState } from '@/components/ErrorState';
import { api } from '@/api/client';
import type { ReviewCreate, ReviewStatus } from '@/types';
import { formatDateTime, formatRelativeTime, aiStatusLabel } from '@/utils';

type ActiveTab = 'overview' | 'evidence' | 'mitre' | 'ai' | 'reviews';

export function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { state, refetch } = useIncident(id);
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');

  // Review form state
  const [reviewStatus, setReviewStatus] = useState<ReviewStatus>('confirmed');
  const [reviewAnalyst, setReviewAnalyst] = useState('');
  const [reviewNote, setReviewNote] = useState('');
  const [reviewSubmitting, setReviewSubmitting] = useState(false);
  const [reviewError, setReviewError] = useState<string | null>(null);
  const [reviewSuccess, setReviewSuccess] = useState(false);

  const submitReview = async () => {
    if (!id || !reviewAnalyst.trim()) return;
    setReviewSubmitting(true);
    setReviewError(null);
    setReviewSuccess(false);

    const payload: ReviewCreate = {
      status: reviewStatus,
      analyst: reviewAnalyst.trim(),
      ...(reviewNote.trim() ? { note: reviewNote.trim() } : {}),
    };

    try {
      await api.submitReview(id, payload);
      setReviewSuccess(true);
      setReviewNote('');
      refetch(); // refresh to get updated review list
    } catch (err: unknown) {
      setReviewError(err instanceof Error ? err.message : 'Failed to submit review.');
    } finally {
      setReviewSubmitting(false);
    }
  };

  if (!id) {
    return (
      <div className="page-body">
        <ErrorState message="No incident ID provided." />
      </div>
    );
  }

  if (state.status === 'loading' || state.status === 'idle') {
    return <LoadingState message="Loading incident details…" />;
  }

  if (state.status === 'error') {
    return (
      <div className="page-body">
        <ErrorState
          title={state.isNotFound ? 'Incident Not Found' : undefined}
          message={
            state.isNotFound
              ? `Incident "${id}" does not exist in the database.`
              : state.message
          }
          isNetwork={state.isNetwork}
          onRetry={state.isNotFound ? undefined : refetch}
        />
        <div className="mt-4">
          <Link to="/incidents" className="btn btn-secondary">
            ← Back to Incidents
          </Link>
        </div>
      </div>
    );
  }

  const incident = state.data;

  return (
    <>
      {/* Page header */}
      <div className="page-header">
        <div className="page-header-title">
          <div className="breadcrumb">
            <Link to="/" className="breadcrumb">Dashboard</Link>
            <span className="breadcrumb-sep" aria-hidden="true">/</span>
            <Link to="/incidents">Incidents</Link>
            <span className="breadcrumb-sep" aria-hidden="true">/</span>
            <span className="breadcrumb-current" title={incident.id}>
              {incident.id.slice(0, 8)}…
            </span>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={refetch}
            aria-label="Refresh incident data"
          >
            ↺ Refresh
          </button>
        </div>
      </div>

      {/* Summary bar */}
      <div
        style={{
          background: 'var(--bg-elevated)',
          borderBottom: '1px solid var(--border-subtle)',
          padding: 'var(--space-4) var(--space-6)',
        }}
      >
        <div className="flex flex-wrap items-center gap-4">
          <SeverityBadge severity={incident.severity} />
          <h1 style={{ fontSize: 'var(--text-lg)', fontWeight: 600, flex: 1 }}>
            {incident.rule_description ?? 'Unknown Rule'}
          </h1>
          <ReviewStatusBadge status={incident.review_status} />
          <PriorityBar score={incident.priority_score} severity={incident.severity} />
        </div>
        <div className="flex flex-wrap gap-4 mt-4" style={{ marginTop: 12 }}>
          <span className="text-muted text-xs">
            🖥 Agent: <strong className="text-secondary">{incident.agent_name ?? '—'}</strong>
          </span>
          {incident.agent_ip && (
            <span className="text-muted text-xs font-mono">{incident.agent_ip}</span>
          )}
          <span className="text-muted text-xs">
            🕐 Event: <strong className="text-secondary">
              {formatDateTime(incident.event_timestamp)}
            </strong>
          </span>
          <span className="text-muted text-xs">
            📥 Ingested: <strong className="text-secondary">
              {formatRelativeTime(incident.created_at)}
            </strong>
          </span>
          {incident.repetition_count > 1 && (
            <span className="badge badge-medium">
              🔁 {incident.repetition_count}× repeated
            </span>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="tabs" role="tablist" aria-label="Incident investigation sections">
        {(
          [
            ['overview', 'Overview'],
            ['evidence', 'Evidence'],
            ['mitre', 'MITRE ATT&CK'],
            ['ai', 'AI Analysis'],
            ['reviews', `Reviews (${incident.reviews.length})`],
          ] as Array<[ActiveTab, string]>
        ).map(([key, label]) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={activeTab === key}
            aria-controls={`tab-panel-${key}`}
            className={`tab${activeTab === key ? ' active' : ''}`}
            onClick={() => setActiveTab(key)}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Tab panels */}
      <div className="page-body">

        {/* Overview */}
        {activeTab === 'overview' && (
          <div id="tab-panel-overview" role="tabpanel" aria-label="Overview">
            <div className="flex flex-col gap-6">

              {/* Alert metadata */}
              <section className="card">
                <div className="card-header">
                  <span className="card-title">Alert Metadata</span>
                </div>
                <div className="card-body">
                  <div className="detail-grid">
                    <div className="detail-field">
                      <span className="detail-field-label">Incident ID</span>
                      <span className="detail-field-value mono">{incident.id}</span>
                    </div>
                    <div className="detail-field">
                      <span className="detail-field-label">Wazuh Alert ID</span>
                      <span className="detail-field-value mono">{incident.alert_id ?? '—'}</span>
                    </div>
                    <div className="detail-field">
                      <span className="detail-field-label">Event Timestamp</span>
                      <span className="detail-field-value">{formatDateTime(incident.event_timestamp)}</span>
                    </div>
                    <div className="detail-field">
                      <span className="detail-field-label">Ingested At</span>
                      <span className="detail-field-value">{formatDateTime(incident.created_at)}</span>
                    </div>
                    <div className="detail-field">
                      <span className="detail-field-label">Severity</span>
                      <span className="detail-field-value"><SeverityBadge severity={incident.severity} /></span>
                    </div>
                    <div className="detail-field">
                      <span className="detail-field-label">Priority Score</span>
                      <span className="detail-field-value">
                        <PriorityBar score={incident.priority_score} severity={incident.severity} />
                        <span className="text-xs text-muted" style={{ marginTop: 4, display: 'block' }}>
                          Deterministic formula: rule level + repetition + asset weight
                        </span>
                      </span>
                    </div>
                    <div className="detail-field">
                      <span className="detail-field-label">Asset Importance</span>
                      <span className="detail-field-value">{incident.asset_importance}</span>
                    </div>
                    <div className="detail-field">
                      <span className="detail-field-label">Repetition Count</span>
                      <span className="detail-field-value">{incident.repetition_count}</span>
                    </div>
                  </div>
                </div>
              </section>

              {/* Rule information */}
              <section className="card">
                <div className="card-header">
                  <span className="card-title">Rule Information</span>
                </div>
                <div className="card-body">
                  <div className="detail-grid">
                    <div className="detail-field">
                      <span className="detail-field-label">Rule ID</span>
                      <span className="detail-field-value mono">{incident.rule_id ?? '—'}</span>
                    </div>
                    <div className="detail-field">
                      <span className="detail-field-label">Rule Level (Wazuh)</span>
                      <span className="detail-field-value">{incident.rule_level ?? '—'} / 15</span>
                    </div>
                    <div className="detail-field" style={{ gridColumn: 'span 2' }}>
                      <span className="detail-field-label">Rule Description</span>
                      <span className="detail-field-value">{incident.rule_description ?? '—'}</span>
                    </div>
                  </div>
                </div>
              </section>

              {/* Agent & network */}
              <section className="card">
                <div className="card-header">
                  <span className="card-title">Agent &amp; Network Information</span>
                </div>
                <div className="card-body">
                  <div className="detail-grid">
                    <div className="detail-field">
                      <span className="detail-field-label">Agent Name</span>
                      <span className="detail-field-value">{incident.agent_name ?? '—'}</span>
                    </div>
                    <div className="detail-field">
                      <span className="detail-field-label">Agent ID</span>
                      <span className="detail-field-value mono">{incident.agent_id ?? '—'}</span>
                    </div>
                    <div className="detail-field">
                      <span className="detail-field-label">Agent IP</span>
                      <span className="detail-field-value mono">{incident.agent_ip ?? '—'}</span>
                    </div>
                    <div className="detail-field">
                      <span className="detail-field-label">Source IP</span>
                      <span className="detail-field-value mono">{incident.source_ip ?? '—'}</span>
                    </div>
                    <div className="detail-field">
                      <span className="detail-field-label">Destination IP</span>
                      <span className="detail-field-value mono">{incident.destination_ip ?? '—'}</span>
                    </div>
                    <div className="detail-field">
                      <span className="detail-field-label">User</span>
                      <span className="detail-field-value">{incident.user ?? '—'}</span>
                    </div>
                    <div className="detail-field">
                      <span className="detail-field-label">Source User</span>
                      <span className="detail-field-value">{incident.source_user ?? '—'}</span>
                    </div>
                    <div className="detail-field">
                      <span className="detail-field-label">Location</span>
                      <span className="detail-field-value mono">{incident.location ?? '—'}</span>
                    </div>
                    <div className="detail-field">
                      <span className="detail-field-label">Decoder</span>
                      <span className="detail-field-value mono">
                        {incident.decoder
                          ? (incident.decoder.name as string | undefined ?? JSON.stringify(incident.decoder))
                          : '—'}
                      </span>
                    </div>
                  </div>
                </div>
              </section>
            </div>
          </div>
        )}

        {/* Evidence */}
        {activeTab === 'evidence' && (
          <div id="tab-panel-evidence" role="tabpanel" aria-label="Evidence">
            <div className="flex flex-col gap-6">
              <section className="card">
                <div className="card-header">
                  <span className="card-title">Original Evidence</span>
                </div>
                <div className="card-body">
                  <div className="warning-message mb-4" role="note">
                    ⚠️ This is the original, unprocessed security event data from the source.
                    Treat all field values as untrusted input.
                  </div>

                  {incident.full_log && (
                    <div className="detail-section mb-6">
                      <span className="detail-section-title">Full Log Line</span>
                      <div className="json-viewer" style={{ marginTop: 8 }}>
                        <div className="json-viewer-body" style={{ maxHeight: 120 }}>
                          <pre style={{ userSelect: 'text' }}>{incident.full_log}</pre>
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="detail-section">
                    <span className="detail-section-title">Raw Wazuh Event (JSON)</span>
                    <div style={{ marginTop: 8 }}>
                      <JsonViewer
                        data={incident.raw_event}
                        label="Raw Wazuh Event"
                        initiallyExpanded
                      />
                    </div>
                  </div>

                  {Object.keys(incident.rule_metadata).length > 0 && (
                    <div className="detail-section" style={{ marginTop: 24 }}>
                      <span className="detail-section-title">Rule Metadata</span>
                      <div style={{ marginTop: 8 }}>
                        <JsonViewer
                          data={incident.rule_metadata}
                          label="Rule Metadata"
                          initiallyExpanded
                        />
                      </div>
                    </div>
                  )}
                </div>
              </section>
            </div>
          </div>
        )}

        {/* MITRE */}
        {activeTab === 'mitre' && (
          <div id="tab-panel-mitre" role="tabpanel" aria-label="MITRE ATT&CK">
            <section className="card">
              <div className="card-header">
                <span className="card-title">MITRE ATT&CK Identifiers</span>
              </div>
              <div className="card-body">
                <div className="info-message mb-4" role="note">
                  ℹ️ These technique identifiers were extracted from the Wazuh alert metadata.
                  They reflect what Wazuh rules tagged this event with.
                  Accuracy depends on the triggering rule — not verified by AI.
                </div>

                {incident.mitre_ids.length === 0 ? (
                  <p className="text-muted text-sm">No MITRE identifiers in this alert.</p>
                ) : (
                  <>
                    <div className="detail-section">
                      <span className="detail-section-title">Technique IDs</span>
                      <div style={{ marginTop: 12 }}>
                        <MitreTagList
                          ids={incident.mitre_ids}
                          techniques={incident.mitre_techniques}
                        />
                      </div>
                    </div>

                    {incident.mitre_tactics.length > 0 && (
                      <div className="detail-section" style={{ marginTop: 24 }}>
                        <span className="detail-section-title">Associated Tactics</span>
                        <div style={{ marginTop: 12 }} className="mitre-tag-list">
                          {incident.mitre_tactics.map((tactic) => (
                            <span
                              key={tactic}
                              style={{
                                padding: '4px 12px',
                                background: 'rgba(99,102,241,0.07)',
                                border: '1px solid rgba(99,102,241,0.2)',
                                borderRadius: 4,
                                fontSize: 'var(--text-xs)',
                                color: '#a5b4fc',
                              }}
                            >
                              {tactic}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {incident.mitre_techniques.length > 0 && (
                      <div className="detail-section" style={{ marginTop: 24 }}>
                        <span className="detail-section-title">Technique Names</span>
                        <div style={{ marginTop: 12 }}>
                          <ul style={{ paddingLeft: 20 }}>
                            {incident.mitre_techniques.map((tech, i) => (
                              <li key={i} className="text-secondary text-sm" style={{ marginBottom: 4 }}>
                                {tech}
                              </li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            </section>
          </div>
        )}

        {/* AI Analysis */}
        {activeTab === 'ai' && (
          <div id="tab-panel-ai" role="tabpanel" aria-label="AI Analysis">
            <section className="card">
              <div className="card-header">
                <span className="card-title">AI Analysis</span>
                <span
                  className="text-xs"
                  style={{ color: 'var(--ai-unavail-text)' }}
                  aria-label={`AI status: ${aiStatusLabel(incident.ai_status)}`}
                >
                  Status: {aiStatusLabel(incident.ai_status)}
                </span>
              </div>
              <div className="card-body">
                {incident.ai_status === 'not_configured' && (
                  <div className="info-message">
                    <span aria-hidden="true">ℹ️</span>
                    <div>
                      <strong>AI Analysis Not Configured</strong>
                      <p style={{ marginTop: 8 }}>
                        The AI engine is not yet integrated (Phase 3). When available, this section will display:
                      </p>
                      <ul style={{ marginTop: 8, paddingLeft: 20 }}>
                        <li>Security summary (Uzbek / Russian / English)</li>
                        <li>Why this event matters</li>
                        <li>Recommended investigation steps</li>
                        <li>Analysis uncertainty / limitations</li>
                      </ul>
                      <p style={{ marginTop: 8 }}>
                        This section will only show AI-generated content when a live AI provider is configured and returns a valid analysis.
                        No fabricated content will be shown.
                      </p>
                    </div>
                  </div>
                )}
                {incident.ai_status === 'unavailable' && (
                  <div className="warning-message">
                    ⚠️ AI provider is configured but currently unavailable. Analysis could not be produced.
                  </div>
                )}
                {incident.ai_status === 'failed' && (
                  <div className="error-message">
                    ⚠️ AI analysis failed for this incident. Refer to backend logs for details.
                  </div>
                )}
                {incident.ai_status === 'pending' && (
                  <div className="info-message">
                    <div className="spinner" style={{ marginRight: 8 }} aria-hidden="true" />
                    AI analysis is being generated. Refresh to check for results.
                  </div>
                )}
              </div>
            </section>
          </div>
        )}

        {/* Reviews */}
        {activeTab === 'reviews' && (
          <div id="tab-panel-reviews" role="tabpanel" aria-label="Analyst reviews">
            <div className="flex flex-col gap-6">
              {/* Existing reviews */}
              {incident.reviews.length > 0 ? (
                <section className="card">
                  <div className="card-header">
                    <span className="card-title">Review History</span>
                  </div>
                  <div className="card-body">
                    <div className="review-list">
                      {incident.reviews.map((review) => (
                        <div key={review.id} className="review-item">
                          <div className="review-item-header">
                            <span className="review-analyst">{review.analyst}</span>
                            <ReviewStatusBadge status={review.status} />
                            <span className="review-time">
                              {formatDateTime(review.created_at)}
                            </span>
                          </div>
                          {review.note && (
                            <p className="review-note">{review.note}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                </section>
              ) : (
                <div className="info-message">ℹ️ No analyst reviews yet for this incident.</div>
              )}

              {/* Submit review */}
              <section className="card">
                <div className="card-header">
                  <span className="card-title">Submit Review</span>
                </div>
                <div className="card-body">
                  <div className="flex flex-col gap-4">
                    <div className="detail-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
                      <div className="form-group">
                        <label className="form-label" htmlFor="review-analyst">Analyst Name *</label>
                        <input
                          id="review-analyst"
                          type="text"
                          className="form-input"
                          placeholder="Your name"
                          value={reviewAnalyst}
                          onChange={(e) => setReviewAnalyst(e.target.value)}
                          maxLength={128}
                          required
                          aria-required="true"
                        />
                      </div>
                      <div className="form-group">
                        <label className="form-label" htmlFor="review-status-select">Decision *</label>
                        <select
                          id="review-status-select"
                          className="form-select"
                          value={reviewStatus}
                          onChange={(e) => setReviewStatus(e.target.value as ReviewStatus)}
                          aria-required="true"
                        >
                          <option value="confirmed">✓ Confirmed — True positive</option>
                          <option value="false_positive">✕ False Positive</option>
                          <option value="needs_review">◉ Needs Further Review</option>
                        </select>
                      </div>
                    </div>

                    <div className="form-group">
                      <label className="form-label" htmlFor="review-note">Notes (optional)</label>
                      <textarea
                        id="review-note"
                        className="form-textarea"
                        placeholder="Investigation notes, findings, or justification…"
                        value={reviewNote}
                        onChange={(e) => setReviewNote(e.target.value)}
                        maxLength={4000}
                        aria-label="Review notes, optional"
                      />
                      <span className="text-xs text-muted" style={{ alignSelf: 'flex-end' }}>
                        {reviewNote.length}/4000
                      </span>
                    </div>

                    {reviewError && (
                      <div className="error-message" role="alert">
                        <span aria-hidden="true">⚠️</span> {reviewError}
                      </div>
                    )}
                    {reviewSuccess && (
                      <div className="info-message" role="status">
                        ✓ Review submitted successfully.
                      </div>
                    )}

                    <div className="flex justify-end">
                      <button
                        type="button"
                        className="btn btn-primary"
                        onClick={submitReview}
                        disabled={reviewSubmitting || !reviewAnalyst.trim()}
                        aria-disabled={reviewSubmitting || !reviewAnalyst.trim()}
                        aria-label="Submit analyst review"
                      >
                        {reviewSubmitting ? (
                          <>
                            <span className="spinner" aria-hidden="true" style={{ width: 14, height: 14 }} />
                            Submitting…
                          </>
                        ) : (
                          'Submit Review'
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              </section>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
