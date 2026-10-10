import { useEffect, useMemo, useState } from "react";

import { CopyButton } from "../components/copy-button";
import { StatePanel } from "../components/state-panel";
import { TimeValue } from "../components/time-value";
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

export function OperationsPage({ api, onNavigate }: { api: BackendApi; onNavigate(page: PageId): void }) {
  const [overview, setOverview] = useState<OperationalOverview | null>(null);
  const [selected, setSelected] = useState<OperationalComponent | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setOverview(null); setError(null);
    api.getOperationalOverview(controller.signal)
      .then(setOverview)
      .catch((reason: unknown) => {
        if (!(reason instanceof DOMException && reason.name === "AbortError"))
          setError(reason instanceof Error ? reason.message : "Operational diagnostics are unavailable.");
      });
    return () => controller.abort();
  }, [api, revision]);

  useEffect(() => {
    const close = () => setSelected(null);
    window.addEventListener("cyberqalqon:escape", close);
    return () => window.removeEventListener("cyberqalqon:escape", close);
  }, []);

  const degraded = useMemo(() => overview?.components.filter((item) => item.state !== "HEALTHY").length ?? 0, [overview]);

  return <div className="page-grid">
    <section className="page-column">
      <header className="page-header"><div><span className="eyebrow">Reliability engineering</span><h1>Operational health</h1><p>Bounded diagnostics from durable sender/shipper state, service managers, SQLite, and the read-only Wazuh API.</p></div><div className="page-header__actions"><button className="button button--ghost" type="button" onClick={() => setRevision((value) => value + 1)}>Refresh</button></div></header>
      {!overview && !error && <StatePanel kind="loading" title="Loading operational evidence" message="Reading the latest persisted collector snapshot…" />}
      {error && <StatePanel kind="unavailable" title="Operational health unavailable" message={error} actionLabel="Retry" onAction={() => setRevision((value) => value + 1)} />}
      {overview && <>
        <div className="inventory-explanation" role="note"><strong>Trust boundary</strong><span>Agent connectivity is authoritative only when the read-only Wazuh API succeeds. Source freshness never implies that an agent is online.</span></div>
        <section className="metric-grid" aria-label="Operational summary">
          <button className="metric-card" type="button" onClick={() => onNavigate("hosts")}><span>Wazuh inventory</span><strong>{overview.wazuh_inventory.state}</strong><small>{overview.wazuh_inventory.agent_count ?? "Agent count unavailable"}</small></button>
          <button className="metric-card" type="button" onClick={() => document.getElementById("component-health")?.focus()}><span>Components needing attention</span><strong>{degraded}</strong><small>Open component diagnostics</small></button>
          <button className="metric-card" type="button" onClick={() => onNavigate("discover")}><span>Raw-evidence coverage</span><strong>{overview.data_quality.raw_evidence_records}/{overview.data_quality.total_events}</strong><small>Open normalized events</small></button>
          <button className="metric-card" type="button" onClick={() => document.getElementById("operational-events")?.focus()}><span>Operational transitions</span><strong>{overview.recent_events.length}</strong><small>Issues and recoveries</small></button>
        </section>
        <article className="panel"><header className="panel__header"><div><span className="eyebrow">Authoritative integration</span><h2>Wazuh inventory</h2></div><span className={`health-pill health-pill--${overview.wazuh_inventory.state.toLowerCase()}`}>{overview.wazuh_inventory.state}</span></header><p>{overview.wazuh_inventory.reason}</p><p className="cell-subtle">Authority: WAZUH_API · Manager: {overview.wazuh_inventory.manager_identity ?? "unavailable"}</p></article>
        <article className="panel" id="component-health" tabIndex={-1}><header className="panel__header"><div><span className="eyebrow">Runtime and durable state</span><h2>Component health</h2></div>{overview.snapshot_collected_at && <span className="cell-subtle">Collected <TimeValue value={overview.snapshot_collected_at} relative /></span>}</header>
          {overview.components.length === 0 ? <p className="muted-copy">No collector snapshot has been recorded. Run the documented one-shot collector.</p> : <div className="table-frame"><table className="data-table"><thead><tr><th>Component</th><th>State</th><th>Authority</th><th>Observation</th><th>Summary</th></tr></thead><tbody>{overview.components.map((item) => <tr key={item.component_key}><td><button className="row-select" type="button" onClick={() => setSelected(item)}><strong>{humanize(item.component_key)}</strong><span className="cell-subtle mono">{item.component_kind}</span></button></td><td><span className={`health-pill health-pill--${item.state.toLowerCase()}`}>{item.state}</span></td><td className="mono">{item.authority}</td><td><TimeValue value={item.observed_at} relative /></td><td>{item.summary}{item.last_error && <span className="cell-subtle">{item.last_error}</span>}</td></tr>)}</tbody></table></div>}
        </article>
        <article className="panel"><header className="panel__header"><div><span className="eyebrow">Normalization quality</span><h2>Data quality</h2></div></header><dl className="metadata-grid"><div><dt>Events / raw evidence</dt><dd>{overview.data_quality.total_events} / {overview.data_quality.raw_evidence_records}</dd></div><div><dt>Missing hostname</dt><dd>{overview.data_quality.missing_hostname}</dd></div><div><dt>Missing username</dt><dd>{overview.data_quality.missing_username}</dd></div><div><dt>Missing rule ID</dt><dd>{overview.data_quality.missing_rule_id}</dd></div><div><dt>Malformed / oversized</dt><dd>{overview.data_quality.malformed_events ?? "unavailable"} / {overview.data_quality.oversized_events ?? "unavailable"}</dd></div><div><dt>Delivery rejected</dt><dd>{overview.data_quality.delivery_rejected ?? "unavailable"}</dd></div><div><dt>Duplicate attempts</dt><dd>{overview.data_quality.duplicate_events ?? "not measured"}</dd></div></dl></article>
        <article className="panel" id="operational-events" tabIndex={-1}><header className="panel__header"><div><span className="eyebrow">Deduplicated transitions</span><h2>Issues and recoveries</h2></div></header>{overview.recent_events.length === 0 ? <p className="muted-copy">No operational state transition has been recorded.</p> : <div className="table-frame"><table className="data-table"><thead><tr><th>Time</th><th>Component</th><th>Event</th><th>Transition</th><th>Evidence</th></tr></thead><tbody>{overview.recent_events.map((event) => <tr key={event.event_id}><td><TimeValue value={event.occurred_at} relative /></td><td>{event.component_key}</td><td>{event.event_type} · {event.severity}</td><td>{event.previous_state ?? "first observation"} → {event.current_state}</td><td className="mono">{event.authority}</td></tr>)}</tbody></table></div>}</article>
      </>}
    </section>
    {selected && <aside className="detail-panel" aria-label="Component diagnostics"><header className="detail-panel__header"><div><span className="eyebrow">Operational evidence</span><h2>{humanize(selected.component_key)}</h2></div><button className="icon-button" type="button" aria-label="Close component diagnostics" onClick={() => setSelected(null)}>×</button></header><div className="detail-panel__body"><div className="detail-hero"><span className={`health-pill health-pill--${selected.state.toLowerCase()}`}>{selected.state}</span><span className="tag">{selected.authority}</span></div><p>{selected.summary}</p><dl className="metadata-grid">{Object.entries(selected.metrics).map(([key, value]) => <div key={key}><dt>{humanize(key)}</dt><dd className="mono">{displayMetric(value)}</dd></div>)}</dl><div className="copy-actions"><CopyButton value={selected.component_key} label="Copy component ID" /></div><p className="trust-note">Observed <TimeValue value={selected.observed_at} />. These values are read-only evidence; this page does not restart services or change enrollment.</p></div></aside>}
  </div>;
}
