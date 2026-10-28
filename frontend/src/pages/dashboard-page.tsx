import { useCallback, useEffect, useState } from "react";

import { StatePanel } from "../components/state-panel";
import { SourceCoverage } from "../components/source-coverage";
import type { BackendApi } from "../types/api";
import type { NamedCount, SecurityOverview, TimeSeriesPoint } from "../types/events";
import { formatTimestamp, humanize } from "../utils/format";
import type { PageId } from "../layouts/app-shell";

type Range = "24h" | "7d" | "30d";

function rangeStart(range: Range): string {
  const hours = { "24h": 24, "7d": 24 * 7, "30d": 24 * 30 }[range];
  return new Date(Date.now() - hours * 60 * 60_000).toISOString();
}

function CountList({ items, empty = "No data in this range." }: { items: NamedCount[]; empty?: string }) {
  const maximum = Math.max(1, ...items.map((item) => item.count));
  if (!items.length) return <p className="muted-copy">{empty}</p>;
  return <div className="ranked-list">{items.map((item) => <div key={item.name}><div><span>{humanize(item.name)}</span><strong>{item.count}</strong></div><span className="ranked-bar"><i style={{ width: `${Math.max(4, item.count / maximum * 100)}%` }} /></span></div>)}</div>;
}

function Series({ points, label }: { points: TimeSeriesPoint[]; label: string }) {
  const maximum = Math.max(1, ...points.map((point) => point.count));
  if (!points.length) return <p className="muted-copy">No {label.toLowerCase()} in this range.</p>;
  return <div className="timeline-bars" role="img" aria-label={`${label} over time`}>{points.map((point) => <div title={`${formatTimestamp(point.timestamp)}: ${point.count}`} key={point.timestamp}><i style={{ height: `${Math.max(5, point.count / maximum * 100)}%` }} /><span>{point.count}</span></div>)}</div>;
}

function formatBytes(value: number): string {
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / 1024 / 1024).toFixed(1)} MiB`;
}

export function DashboardPage({ api, initialRange = "24h", onOpenAlert, onNavigate = () => undefined, onOpenEvent }: { api: BackendApi; initialRange?: Range; onOpenAlert(id: string): void; onNavigate?(page: PageId): void; onOpenEvent?(id:string):void }) {
  const [overview, setOverview] = useState<SecurityOverview | null>(null);
  const [range, setRange] = useState<Range>(initialRange);
  useEffect(() => setRange(initialRange), [initialRange]);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const [loading, setLoading] = useState(true);
  const [lastRefreshedAt, setLastRefreshedAt] = useState<string | null>(null);
  const retry = useCallback(() => setRevision((value) => value + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setLoading(true); setError(null);
    api.getOverview(rangeStart(range), new Date().toISOString(), controller.signal)
      .then((response) => { if (active) { setOverview(response); setLastRefreshedAt(new Date().toISOString()); } })
      .catch((reason: unknown) => {
        if (!active || (reason instanceof DOMException && reason.name === "AbortError")) return;
        setError(reason instanceof Error ? reason.message : "Dashboard data could not be loaded.");
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [api, range, revision]);

  return (
    <section className="page-column">
      <header className="page-header">
        <div><span className="eyebrow">Operational picture</span><h1>Security overview</h1><p>Actual event, alert, incident, source, and ingestion aggregates.</p></div>
        <div className="dashboard-controls"><label className="compact-select"><span>Range</span><select value={range} onChange={(event) => setRange(event.target.value as Range)}><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option></select></label><button className="button button--secondary" type="button" disabled={loading} onClick={retry}>{loading ? "Refreshing…" : "Refresh"}</button>{lastRefreshedAt && <small>Last successful refresh {formatTimestamp(lastRefreshedAt)}</small>}</div>
      </header>
      <SourceCoverage api={api} onOpenEvent={onOpenEvent} compact/>
      {!overview && !error && <StatePanel kind="loading" title="Building overview" message="Running bounded aggregation queries…" />}
      {error && <StatePanel kind="unavailable" title="Overview unavailable" message={error} actionLabel="Retry" onAction={retry} />}
      {overview && <div aria-busy={loading}>
        {loading && <p className="refresh-status" role="status">Refreshing dashboard while keeping the last successful result visible…</p>}
        <div className="ingestion-strip" data-state={overview.ingestion.state.toLowerCase()}><strong>Ingestion {overview.ingestion.state}</strong><span>{overview.ingestion.last_ingested_at ? `Last received ${formatTimestamp(overview.ingestion.last_ingested_at)}` : "No security events received"}</span><span>{overview.ingestion.lag_seconds == null ? "Lag unavailable" : `${overview.ingestion.lag_seconds.toFixed(1)} s event-to-ingest lag`}</span></div>
        {overview.ingestion.state === "STALE" && <p className="stale-warning" role="status">Ingestion evidence is stale. Counts remain the last successfully retrieved backend values.</p>}
        <div className="metric-grid metric-grid--five">
          <button className="metric-card" type="button" onClick={() => onNavigate("discover")}><span>Security events</span><strong>{overview.total_events}</strong><small>Open Discover</small></button>
          <article className="metric-card"><span>Events / minute</span><strong>{overview.events_per_minute.toFixed(2)}</strong><small>Selected range average</small></article>
          <button className="metric-card metric-card--critical" type="button" onClick={() => onNavigate("alerts")}><span>Alerts</span><strong>{overview.total_alerts}</strong><small>Open alert queue</small></button>
          <button className="metric-card" type="button" onClick={() => onNavigate("incidents")}><span>Active incidents</span><strong>{overview.active_incidents}</strong><small>Open incident queue</small></button>
          <button className="metric-card" type="button" onClick={() => onNavigate("hosts")}><span>Reporting agents</span><strong>{overview.reporting_agents}</strong><small>Events within 15 minutes</small></button>
          <button className="metric-card" type="button" onClick={() => onNavigate("hosts")}><span>Source freshness</span><strong>{overview.active_sources} / {overview.stale_sources}</strong><small>Open source inventory</small></button>
        </div>
        <div className="pipeline-grid">
          {overview.pipeline_activity.map((component) => <article className="pipeline-card" key={component.component}><div><strong>{humanize(component.component)}</strong><span className={`health-pill health-pill--${component.state.toLowerCase()}`}>{component.state}</span></div><span>{component.delivered_records} deliveries in range</span><small>{component.last_delivery_at ? `Last ${formatTimestamp(component.last_delivery_at)}` : "No delivery observed"} · activity evidence, not process connectivity</small></article>)}
          <article className="pipeline-card"><div><strong>Retention</strong><span className={`health-pill health-pill--${overview.retention.state === "WITHIN_LIMIT" ? "active" : "stale"}`}>{overview.retention.state}</span></div><span>{overview.retention.retained_records.toLocaleString()} / {overview.retention.max_records.toLocaleString()} records</span><small>{overview.retention.retention_days} days · last run {overview.retention.last_run_at ? formatTimestamp(overview.retention.last_run_at) : "not yet recorded"} · deleted {overview.retention.last_deleted_count}</small></article>
          <article className="pipeline-card"><div><strong>SQLite database</strong><span className="health-pill health-pill--active">LOCAL</span></div><span>{formatBytes(overview.database_size_bytes)}</span><small>On-disk database size</small></article>
        </div>
        <div className="overview-grid">
          <article className="panel panel--wide"><header className="panel__header"><div><span className="eyebrow">Telemetry</span><h2>Events over time</h2></div></header><Series points={overview.events_over_time} label="Events" /></article>
          <article className="panel"><header className="panel__header"><div><span className="eyebrow">Detection</span><h2>Alerts by severity</h2></div></header><CountList items={overview.alerts_by_severity.map((item) => ({ name: item.severity, count: item.count }))} /></article>
          <article className="panel"><header className="panel__header"><div><span className="eyebrow">Telemetry</span><h2>Event sources</h2></div></header><CountList items={overview.event_sources} /></article>
          <article className="panel"><header className="panel__header"><div><span className="eyebrow">Investigations</span><h2>Incidents by status</h2></div></header><CountList items={overview.incidents_by_status} /></article>
          <article className="panel"><header className="panel__header"><div><span className="eyebrow">Network</span><h2>Top source IPs</h2></div></header><CountList items={overview.top_source_ips} /></article>
          <article className="panel"><header className="panel__header"><div><span className="eyebrow">Assets</span><h2>Top monitored hosts</h2></div></header><CountList items={overview.top_hosts} /></article>
          <article className="panel"><header className="panel__header"><div><span className="eyebrow">Network</span><h2>Top destinations</h2></div></header><CountList items={overview.top_destination_hosts} /></article>
          <article className="panel"><header className="panel__header"><div><span className="eyebrow">Detections</span><h2>Top rules</h2></div></header><CountList items={overview.top_rules} /></article>
          <article className="panel"><header className="panel__header"><div><span className="eyebrow">Detection</span><h2>Alerts over time</h2></div></header><Series points={overview.alerts_over_time} label="Alerts" /></article>
          <article className="panel"><header className="panel__header"><div><span className="eyebrow">Telemetry</span><h2>Event categories</h2></div></header><CountList items={overview.top_event_categories} /></article>
          <article className="panel panel--wide"><header className="panel__header"><div><span className="eyebrow">Investigation queue</span><h2>Latest high-priority alerts</h2></div></header>{overview.latest_high_alerts.length === 0 ? <p className="muted-copy">No level 10–16 alerts in this range.</p> : <div className="latest-alerts">{overview.latest_high_alerts.map((alert) => <button type="button" key={alert.alert_id} onClick={() => onOpenAlert(alert.alert_id)}><span className="mono">{alert.rule_id}</span><strong>{alert.description}</strong><small>{alert.agent_name} · {formatTimestamp(alert.timestamp)} · level {alert.severity}</small></button>)}</div>}</article>
        </div>
      </div>}
    </section>
  );
}
