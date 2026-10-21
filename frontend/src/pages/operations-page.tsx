import { useEffect, useMemo, useState } from "react";

import { CopyButton } from "../components/copy-button";
import { StatePanel } from "../components/state-panel";
import { TimeValue } from "../components/time-value";
import { ApiError, BackendUnavailableError } from "../api/client";
import type { PageId } from "../layouts/app-shell";
import type { BackendApi } from "../types/api";
import type { OperationalComponent, OperationalOverview } from "../types/operations";
import { humanize } from "../utils/format";

function displayMetric(value: unknown): string {
  if (value === null || value === undefined) return "unavailable";
  if (typeof value === "boolean") return value ? "yes" : "no";
  if (typeof value === "number") return value.toLocaleString();
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

function displayBytes(value: number | null): string {
  if (value === null) return "unavailable";
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KiB`;
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MiB`;
  return `${(value / 1024 ** 3).toFixed(2)} GiB`;
}

function operationalErrorMessage(reason: unknown): string {
  if (reason instanceof ApiError) {
    if (reason.status === 401) return "Your analyst session expired. Sign in again to view Operations.";
    if (reason.status === 403) return "Your analyst role does not permit operational diagnostics.";
    if (reason.code === "OPERATIONS_QUERY_TIMEOUT") return "The bounded Operations read reached its deadline. No unbounded fallback scan was attempted.";
    if (reason.status === 503) return "Operations data is temporarily unavailable. Retry after the bounded read recovers.";
  }
  if (reason instanceof BackendUnavailableError) return reason.message;
  return reason instanceof Error ? reason.message : "Operational diagnostics are unavailable.";
}

export function OperationsPage({ api, onNavigate }: { api: BackendApi; onNavigate(page: PageId): void }) {
  const [overview, setOverview] = useState<OperationalOverview | null>(null);
  const [selected, setSelected] = useState<OperationalComponent | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setError(null);
    api.getOperationalOverview(controller.signal)
      .then(setOverview)
      .catch((reason: unknown) => {
        if (!(reason instanceof DOMException && reason.name === "AbortError"))
          setError(operationalErrorMessage(reason));
      });
    return () => controller.abort();
  }, [api, revision]);

  useEffect(() => {
    const close = () => setSelected(null);
    window.addEventListener("cyberqalqon:escape", close);
    return () => window.removeEventListener("cyberqalqon:escape", close);
  }, []);

  const degraded = useMemo(() => overview?.components.filter((item) => item.state !== "HEALTHY").length ?? 0, [overview]);
  const shipper = overview?.components.find((item) => item.component_kind === "event_shipper");
  const ingestion = overview?.ingestion_performance;
  const forward = overview?.forward_ingestion;
  const shipperMetric = (name: string): unknown => shipper?.metrics[name];
  const shipperBytes = (name: string): number | null => {
    const value = shipperMetric(name);
    return typeof value === "number" ? value : null;
  };

  return <div className="page-grid">
    <section className="page-column">
      <header className="page-header"><div><span className="eyebrow">Reliability engineering</span><h1>Operational health</h1><p>Bounded diagnostics from durable sender/shipper state, service managers, SQLite, and the read-only Wazuh API.</p></div><div className="page-header__actions"><button className="button button--ghost" type="button" onClick={() => setRevision((value) => value + 1)}>Refresh</button></div></header>
      {!overview && !error && <StatePanel kind="loading" title="Loading operational evidence" message="Reading the latest persisted collector snapshot…" />}
      {error && <StatePanel kind="unavailable" title={overview ? "Operational refresh failed" : "Operational health unavailable"} message={overview ? `${error} The last bounded snapshot remains visible below.` : error} actionLabel="Retry" onAction={() => setRevision((value) => value + 1)} />}
      {overview && <>
        <div className="inventory-explanation" role="note"><strong>Trust boundary</strong><span>Agent connectivity is authoritative only when the read-only Wazuh API succeeds. Source freshness never implies that an agent is online.</span></div>
        <div className="inventory-explanation" role="note"><strong>Bounded operational query: {overview.measurement.state}</strong><span>Measured <TimeValue value={overview.measurement.measured_at} relative /> in {overview.measurement.duration_ms.toFixed(1)} ms; cache age {overview.measurement.age_seconds.toFixed(1)} s (fresh TTL {overview.measurement.cache_ttl_seconds.toFixed(1)} s, stale limit {overview.measurement.stale_ttl_seconds.toFixed(1)} s). Reason: {humanize(overview.measurement.reason_code)}. Cache hit/miss {overview.measurement.cache_hits}/{overview.measurement.cache_misses}; in-flight/waiters {overview.measurement.inflight_queries}/{overview.measurement.pending_waiters}. SQLite reads have a {overview.measurement.query_deadline_seconds.toFixed(1)} s deadline and run outside the API event loop.</span></div>
        {(overview.measurement.state === "STALE" || overview.measurement.state === "UNKNOWN") && <div className="inventory-explanation" role="alert"><strong>Degraded Operations snapshot</strong><span>This view is not fresh. Values keep their recorded scopes; missing values remain UNKNOWN and are not inferred.</span></div>}
        <section className="metric-grid" aria-label="Operational summary">
          <button className="metric-card" type="button" onClick={() => onNavigate("hosts")}><span>Wazuh inventory</span><strong>{overview.wazuh_inventory.state}</strong><small>{overview.wazuh_inventory.agent_count ?? "Agent count unavailable"}</small></button>
          <button className="metric-card" type="button" onClick={() => document.getElementById("component-health")?.focus()}><span>Components needing attention</span><strong>{degraded}</strong><small>Open component diagnostics</small></button>
          <button className="metric-card" type="button" onClick={() => onNavigate("discover")}><span>Raw-evidence coverage</span><strong>{overview.data_quality.raw_evidence_records == null ? "UNKNOWN" : `${overview.data_quality.raw_evidence_records}/${overview.data_quality.total_events}`}</strong><small>{overview.data_quality.total_events.toLocaleString()} retained events; open normalized events</small></button>
          <button className="metric-card" type="button" onClick={() => document.getElementById("operational-events")?.focus()}><span>Operational transitions</span><strong>{overview.recent_events.length}</strong><small>Issues and recoveries</small></button>
          <button className="metric-card" type="button" onClick={() => document.getElementById("storage-retention")?.focus()}><span>Retention utilization</span><strong>{overview.storage_retention.usage_percent.toFixed(1)}%</strong><small>{overview.storage_retention.state}</small></button>
        </section>
        <article className="panel">
          <header className="panel__header"><div><span className="eyebrow">Legacy checkpoint evidence</span><h2>Legacy shipper diagnostics</h2></div><span className="tag">{String(shipperMetric("pipeline_condition") ?? "UNKNOWN")}</span></header>
          <dl className="metadata-grid">
            <div><dt>State version</dt><dd>{String(shipperMetric("shipper_state_version") ?? "unknown")}</dd></div>
            <div><dt>Active byte lag</dt><dd>{displayBytes(shipperBytes("archive_lag_bytes"))}</dd></div>
            <div><dt>Archive growth / sec</dt><dd>{displayBytes(shipperBytes("archive_growth_bytes_per_second"))}</dd></div>
            <div><dt>Cursor progress / sec</dt><dd>{displayBytes(shipperBytes("cursor_progress_bytes_per_second"))}</dd></div>
            <div><dt>Net lag / sec</dt><dd>{displayBytes(shipperBytes("net_archive_lag_bytes_per_second"))}</dd></div>
            <div><dt>Unique inserts</dt><dd>{String(shipperMetric("unique_insertions") ?? "UNKNOWN")}</dd></div>
            <div><dt>Duplicate acknowledgements</dt><dd>{String(shipperMetric("historic_duplicate_acknowledgements") ?? "UNKNOWN")}</dd></div>
            <div><dt>Retry / protocol errors</dt><dd>{String(shipperMetric("retry_attempts") ?? "UNKNOWN")} / {String(shipperMetric("protocol_errors") ?? "UNKNOWN")}</dd></div>
            <div><dt>Pending archive generations</dt><dd>{String(shipperMetric("rotated_archive_count") ?? "UNKNOWN")}</dd></div>
            <div><dt>Rate snapshot</dt><dd>{String(shipperMetric("rate_snapshot_status") ?? "UNKNOWN")}</dd></div>
          </dl>
          <p className="trust-note">This panel describes only the legacy checkpoint. Rates come from a bounded cached sample, not an archive-wide dashboard scan. Historic v2 insert and duplicate counts remain UNKNOWN.</p>
        </article>
        {forward && <article className="panel">
          <header className="panel__header"><div><span className="eyebrow">Generation isolation</span><h2>Forward ingestion boundary</h2></div><span className="tag">{forward.forward_state}</span></header>
          <dl className="metadata-grid">
            <div><dt>Legacy checkpoint</dt><dd>{forward.legacy_checkpoint_state}</dd></div>
            <div><dt>Legacy continuity</dt><dd>{forward.legacy_continuity}</dd></div>
            <div><dt>Forward service</dt><dd>{forward.service_active ? "ACTIVE" : forward.forward_state}</dd></div>
            <div><dt>Live approval</dt><dd>{forward.approval_state}</dd></div>
            <div><dt>Approval validation basis</dt><dd>{humanize(forward.approval_validation_basis)}</dd></div>
            <div><dt>Approval expiry</dt><dd>{forward.approval_expires_at ? <TimeValue value={forward.approval_expires_at} relative /> : "UNKNOWN"}</dd></div>
            <div><dt>Approval lifetime remaining</dt><dd>{forward.approval_remaining_seconds == null ? "UNKNOWN" : `${Math.floor(forward.approval_remaining_seconds / 60)} minutes`}</dd></div>
            <div><dt>Historical replay</dt><dd>{forward.historical_replay_state}</dd></div>
            <div><dt>Generation</dt><dd className="mono">{forward.generation_id ?? "not prepared"}</dd></div>
            <div><dt>Source device / inode</dt><dd>{forward.source_device ?? "unknown"} / {forward.source_inode ?? "unknown"}</dd></div>
            <div><dt>Start / cursor</dt><dd>{displayBytes(forward.start_offset_bytes)} / {displayBytes(forward.cursor_bytes)}</dd></div>
            <div><dt>Forward byte lag</dt><dd>{displayBytes(forward.lag_bytes)}</dd></div>
            <div><dt>Archive growth / sec</dt><dd>{displayBytes(forward.archive_growth_bytes_per_second)}</dd></div>
            <div><dt>Forward cursor / sec</dt><dd>{displayBytes(forward.cursor_progress_bytes_per_second)}</dd></div>
            <div><dt>Net lag / trend</dt><dd>{displayBytes(forward.net_lag_bytes_per_second)} / {forward.net_backlog_trend}</dd></div>
            <div><dt>Insert / duplicate</dt><dd>{forward.unique_insertions ?? "UNKNOWN"} / {forward.duplicate_acknowledgements ?? "UNKNOWN"}</dd></div>
            <div><dt>Filtered / malformed</dt><dd>{forward.filtered_records ?? "UNKNOWN"} / {forward.malformed_records ?? "UNKNOWN"}</dd></div>
            <div><dt>Retry / protocol / rejected</dt><dd>{forward.retry_attempts ?? "UNKNOWN"} / {forward.protocol_errors ?? "UNKNOWN"} / {forward.delivery_rejected ?? "UNKNOWN"}</dd></div>
            <div><dt>Unreconciled historical</dt><dd>{forward.unreconciled_historical_records ?? "UNKNOWN"}</dd></div>
            <div><dt>Retention pressure</dt><dd>{forward.retention_pressure}</dd></div>
            <div><dt>Last forward delivery</dt><dd>{forward.last_successful_delivery ? <TimeValue value={forward.last_successful_delivery} relative /> : "UNKNOWN"}</dd></div>
            <div><dt>Durable checkpoint updated</dt><dd>{forward.checkpoint_updated_at ? <TimeValue value={forward.checkpoint_updated_at} relative /> : "UNKNOWN"}</dd></div>
          </dl>
          <p className="trust-note">Historical gap: UNPROVEN and not replayed. Legacy progress, new forward progress, and historical replay are independent states; no combined completion percentage or drain ETA is inferred.</p>
        </article>}
        {ingestion && <article className="panel">
          <header className="panel__header"><div><span className="eyebrow">M18 bounded metrics</span><h2>Ingestion performance</h2></div><span className="tag">{ingestion.batch_endpoint_enabled ? "BATCH ENABLED" : "DISABLED BY DEFAULT"}</span></header>
          <dl className="metadata-grid">
            <div><dt>Protocol / mode</dt><dd>{ingestion.ingress_protocol_version} / {ingestion.active_request_mode ?? ingestion.configured_mode}</dd></div>
            <div><dt>Execution / samples</dt><dd>{ingestion.execution_model ?? "unavailable"} / {ingestion.request_latency_sample_size ?? "unavailable"}</dd></div>
            <div><dt>Measurement window</dt><dd>{ingestion.measurement_window_seconds?.toFixed(1) ?? "unavailable"} seconds</dd></div>
            <div><dt>Requests</dt><dd>{ingestion.requests.toLocaleString()} ({ingestion.batch_requests.toLocaleString()} batch)</dd></div>
            <div><dt>Events / request</dt><dd>{ingestion.events_per_request?.toFixed(2) ?? "unavailable"}</dd></div>
            <div><dt>Events / sec</dt><dd>{ingestion.events_per_second.toFixed(2)}</dd></div>
            <div><dt>Inserts / duplicate per sec</dt><dd>{ingestion.inserts_per_second.toFixed(2)} / {ingestion.duplicates_per_second.toFixed(2)}</dd></div>
            <div><dt>Inserted / duplicate</dt><dd>{ingestion.inserted.toLocaleString()} / {ingestion.duplicates.toLocaleString()}</dd></div>
            <div><dt>Request p50 / p95</dt><dd>{ingestion.request_latency_p50_ms?.toFixed(1) ?? "unavailable"} / {ingestion.request_latency_p95_ms?.toFixed(1) ?? "unavailable"} ms</dd></div>
            <div><dt>Transaction p50 / p95</dt><dd>{ingestion.transaction_latency_p50_ms?.toFixed(1) ?? "unavailable"} / {ingestion.transaction_latency_p95_ms?.toFixed(1) ?? "unavailable"} ms</dd></div>
            <div><dt>Retention p50 / p95</dt><dd>{ingestion.retention_latency_p50_ms?.toFixed(1) ?? "unavailable"} / {ingestion.retention_latency_p95_ms?.toFixed(1) ?? "unavailable"} ms</dd></div>
            <div><dt>Lock wait p50 / p95</dt><dd>{ingestion.lock_wait_latency_p50_ms?.toFixed(1) ?? "unavailable"} / {ingestion.lock_wait_latency_p95_ms?.toFixed(1) ?? "unavailable"} ms</dd></div>
            <div><dt>Commit p50 / p95</dt><dd>{ingestion.commit_latency_p50_ms?.toFixed(1) ?? "unavailable"} / {ingestion.commit_latency_p95_ms?.toFixed(1) ?? "unavailable"} ms</dd></div>
            <div><dt>Timeout / busy</dt><dd>{ingestion.timeout_count ?? 0} / {ingestion.sqlite_busy_errors ?? 0}</dd></div>
            <div><dt>Retryable / permanent failures</dt><dd>{ingestion.retryable_failures.toLocaleString()} / {ingestion.permanent_failures.toLocaleString()}</dd></div>
            <div><dt>Last acknowledgement</dt><dd>{ingestion.last_successful_acknowledgement ? <TimeValue value={ingestion.last_successful_acknowledgement} relative /> : "none observed"}{ingestion.last_successful_acknowledgement_age_seconds != null ? ` (${ingestion.last_successful_acknowledgement_age_seconds.toFixed(1)}s old)` : ""}</dd></div>
            <div><dt>Last failure stage</dt><dd>{ingestion.last_failure_stage ?? "none observed"}</dd></div>
          </dl>
          <p className="trust-note">These bounded in-process counters start after the current backend process starts. Pre-M18 unique and duplicate totals remain UNKNOWN and are never inferred.</p>
        </article>}
        <article className="panel"><header className="panel__header"><div><span className="eyebrow">Authoritative integration</span><h2>Wazuh inventory</h2></div><span className={`health-pill health-pill--${overview.wazuh_inventory.state.toLowerCase()}`}>{overview.wazuh_inventory.state}</span></header><p>{overview.wazuh_inventory.reason}</p><p className="cell-subtle">Authority: WAZUH_API · Manager: {overview.wazuh_inventory.manager_identity ?? "unavailable"}</p></article>
        <article className="panel" id="component-health" tabIndex={-1}><header className="panel__header"><div><span className="eyebrow">Runtime and durable state</span><h2>Component health</h2></div>{overview.snapshot_collected_at && <span className="cell-subtle">Collected <TimeValue value={overview.snapshot_collected_at} relative /></span>}</header>
          {overview.components.length === 0 ? <p className="muted-copy">No collector snapshot has been recorded. Run the documented one-shot collector.</p> : <div className="table-frame"><table className="data-table"><thead><tr><th>Component</th><th>State</th><th>Authority</th><th>Observation</th><th>Summary</th></tr></thead><tbody>{overview.components.map((item) => <tr key={item.component_key}><td><button className="row-select" type="button" onClick={() => setSelected(item)}><strong>{humanize(item.component_key)}</strong><span className="cell-subtle mono">{item.component_kind}</span></button></td><td><span className={`health-pill health-pill--${item.state.toLowerCase()}`}>{item.state}</span></td><td className="mono">{item.authority}</td><td><TimeValue value={item.observed_at} relative /></td><td>{item.summary}{item.last_error && <span className="cell-subtle">{item.last_error}</span>}</td></tr>)}</tbody></table></div>}
        </article>
        <article className="panel"><header className="panel__header"><div><span className="eyebrow">Normalization quality</span><h2>Data quality</h2></div><span className="tag">{overview.data_quality.field_completeness_measurement}</span></header><dl className="metadata-grid"><div><dt>Retained events</dt><dd>{overview.data_quality.total_events.toLocaleString()} ({overview.data_quality.total_events_measurement})</dd></div><div><dt>Raw evidence records</dt><dd>{overview.data_quality.raw_evidence_records ?? "UNKNOWN"}</dd></div><div><dt>Missing hostname</dt><dd>{overview.data_quality.missing_hostname ?? "UNKNOWN"}</dd></div><div><dt>Missing username</dt><dd>{overview.data_quality.missing_username ?? "UNKNOWN"}</dd></div><div><dt>Missing rule ID</dt><dd>{overview.data_quality.missing_rule_id ?? "UNKNOWN"}</dd></div><div><dt>Malformed / oversized</dt><dd>{overview.data_quality.malformed_events ?? "UNKNOWN"} / {overview.data_quality.oversized_events ?? "UNKNOWN"}</dd></div><div><dt>Delivery rejected</dt><dd>{overview.data_quality.delivery_rejected ?? "UNKNOWN"}</dd></div><div><dt>Duplicate attempts</dt><dd>{overview.data_quality.duplicate_events ?? "UNKNOWN"}</dd></div></dl><p className="trust-note">Retained count is exact incremental schema-17 store state ({humanize(overview.data_quality.total_events_scope)}). Field-completeness totals are {overview.data_quality.field_completeness_measurement} because they are not materialized; Operations never replaces them with an expensive live table scan. Shipper counters apply to {humanize(overview.data_quality.shipper_counters_scope)}. Historical continuity remains UNPROVEN.</p></article>
        <article className="panel" id="storage-retention" tabIndex={-1}><header className="panel__header"><div><span className="eyebrow">Capacity and evidence safety</span><h2>Storage retention</h2></div><span className="tag">{overview.storage_retention.state}</span></header><dl className="metadata-grid"><div><dt>Schema</dt><dd>{overview.storage_retention.schema_version}</dd></div><div><dt>Retained / maximum</dt><dd>{overview.storage_retention.retained_records.toLocaleString()} / {overview.storage_retention.max_records.toLocaleString()}</dd></div><div><dt>Protected evidence</dt><dd>{overview.storage_retention.protected_records.toLocaleString()} ({overview.storage_retention.protected_records_measurement ?? "NOT_MEASURED"})</dd></div><div><dt>Protected over-limit</dt><dd>{overview.storage_retention.over_limit_records.toLocaleString()}</dd></div><div><dt>Database / WAL</dt><dd>{displayBytes(overview.storage_retention.database_size_bytes)} / {displayBytes(overview.storage_retention.wal_size_bytes)}</dd></div><div><dt>Retention window</dt><dd>{overview.storage_retention.retention_days} days</dd></div><div><dt>Last cleanup</dt><dd>{overview.storage_retention.last_run_at ? <TimeValue value={overview.storage_retention.last_run_at} relative /> : "not run"}</dd></div><div><dt>Last ingestion</dt><dd>{overview.storage_retention.last_ingested_at ? <TimeValue value={overview.storage_retention.last_ingested_at} relative /> : "empty"}</dd></div><div><dt>Oldest event</dt><dd>{overview.storage_retention.oldest_event_at ? <TimeValue value={overview.storage_retention.oldest_event_at} /> : "empty"}</dd></div><div><dt>Newest event</dt><dd>{overview.storage_retention.newest_event_at ? <TimeValue value={overview.storage_retention.newest_event_at} /> : "empty"}</dd></div></dl><p className="trust-note">Protected count is the latest bounded retention-audit measurement; dashboard reads do not repeat the expensive global evidence scan. Case links, incident pins, and case evidence references are excluded from automatic deletion.</p></article>
        <article className="panel"><header className="panel__header"><div><span className="eyebrow">Archive generations</span><h2>Recovery backlog</h2></div><span className="tag">{overview.archive_backlog.state}</span></header><dl className="metadata-grid"><div><dt>Recovery readiness</dt><dd>{humanize(overview.archive_backlog.recovery_readiness)}</dd></div><div><dt>Generation tracking</dt><dd>{humanize(overview.archive_backlog.generation_state)}</dd></div><div><dt>Historical replay</dt><dd>{humanize(overview.archive_backlog.historical_replay_state)}</dd></div><div><dt>Current byte lag</dt><dd>{displayBytes(overview.archive_backlog.current_lag_bytes)}</dd></div><div><dt>Eligible / filtered</dt><dd>{overview.archive_backlog.current_eligible_records ?? "unavailable"} / {overview.archive_backlog.current_filtered_records ?? "unavailable"}</dd></div><div><dt>Malformed pending</dt><dd>{overview.archive_backlog.current_malformed_records ?? "unavailable"}</dd></div><div><dt>Rotated archives</dt><dd>{overview.archive_backlog.rotated_archive_count ?? "unavailable"}</dd></div><div><dt>Historical eligible</dt><dd>{overview.archive_backlog.historical_eligible_records ?? "not audited"}</dd></div><div><dt>Archive / cursor</dt><dd>{displayBytes(overview.archive_backlog.archive_size_bytes)} / {displayBytes(overview.archive_backlog.cursor_bytes)}</dd></div></dl><p className="trust-note">Historical counts remain “not audited” until a generation-aware, operator-approved scan records them. Current-file lag is not presented as total archive backlog.</p></article>
        <article className="panel" id="operational-events" tabIndex={-1}><header className="panel__header"><div><span className="eyebrow">Deduplicated transitions</span><h2>Issues and recoveries</h2></div></header>{overview.recent_events.length === 0 ? <p className="muted-copy">No operational state transition has been recorded.</p> : <div className="table-frame"><table className="data-table"><thead><tr><th>Time</th><th>Component</th><th>Event</th><th>Transition</th><th>Evidence</th></tr></thead><tbody>{overview.recent_events.map((event) => <tr key={event.event_id}><td><TimeValue value={event.occurred_at} relative /></td><td>{event.component_key}</td><td>{event.event_type} · {event.severity}</td><td>{event.previous_state ?? "first observation"} → {event.current_state}</td><td className="mono">{event.authority}</td></tr>)}</tbody></table></div>}</article>
      </>}
    </section>
    {selected && <aside className="detail-panel" aria-label="Component diagnostics"><header className="detail-panel__header"><div><span className="eyebrow">Operational evidence</span><h2>{humanize(selected.component_key)}</h2></div><button className="icon-button" type="button" aria-label="Close component diagnostics" onClick={() => setSelected(null)}>×</button></header><div className="detail-panel__body"><div className="detail-hero"><span className={`health-pill health-pill--${selected.state.toLowerCase()}`}>{selected.state}</span><span className="tag">{selected.authority}</span></div><p>{selected.summary}</p><dl className="metadata-grid">{Object.entries(selected.metrics).map(([key, value]) => <div key={key}><dt>{humanize(key)}</dt><dd className="mono">{displayMetric(value)}</dd></div>)}</dl><div className="copy-actions"><CopyButton value={selected.component_key} label="Copy component ID" /></div><p className="trust-note">Observed <TimeValue value={selected.observed_at} />. These values are read-only evidence; this page does not restart services or change enrollment.</p></div></aside>}
  </div>;
}
