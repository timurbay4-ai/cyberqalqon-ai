import { useEffect, useMemo, useState } from "react";

import { CopyButton } from "../components/copy-button";
import { StatePanel } from "../components/state-panel";
import { TimeValue } from "../components/time-value";
import type { BackendApi } from "../types/api";
import type { HostSummary, LogSourceSummary } from "../types/siem";
import { humanize } from "../utils/format";

export function HostsPage({ api }: { api: BackendApi }) {
  const [hosts, setHosts] = useState<HostSummary[] | null>(null);
  const [sources, setSources] = useState<LogSourceSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const [search, setSearch] = useState("");
  const [sourceType, setSourceType] = useState("");
  const [selectedHost, setSelectedHost] = useState<HostSummary | null>(null);

  useEffect(() => {
    const controller = new AbortController(); setHosts(null); setSources(null); setError(null);
    Promise.all([api.listHosts(controller.signal), api.listSources(controller.signal)])
      .then(([nextHosts, nextSources]) => { setHosts(nextHosts); setSources(nextSources); })
      .catch((reason: unknown) => { if (!(reason instanceof DOMException && reason.name === "AbortError")) setError(reason instanceof Error ? reason.message : "Inventory unavailable."); });
    return () => controller.abort();
  }, [api, revision]);

  useEffect(() => {
    const close = () => setSelectedHost(null);
    window.addEventListener("cyberqalqon:escape", close);
    return () => window.removeEventListener("cyberqalqon:escape", close);
  }, []);

  const sourceTypes = useMemo(() => [...new Set((sources ?? []).map((source) => source.source_type))].sort(), [sources]);
  const visibleHosts = useMemo(() => (hosts ?? []).filter((host) => `${host.hostname} ${host.agent_id ?? ""} ${host.agent_name ?? ""}`.toLocaleLowerCase().includes(search.trim().toLocaleLowerCase())), [hosts, search]);
  const visibleSources = useMemo(() => (sources ?? []).filter((source) => !sourceType || source.source_type === sourceType), [sourceType, sources]);

  return <div className="page-grid">
    <section className="page-column">
      <header className="page-header"><div><span className="eyebrow">Assets &amp; collection</span><h1>Hosts and log sources</h1><p>Observed source freshness is separate from Wazuh agent connectivity state.</p></div></header>
      <div className="inventory-explanation" role="note"><strong>State evidence</strong><span>ACTIVE SOURCE / STALE SOURCE comes from stored telemetry freshness. Pipeline health uses persisted delivery timestamps. Agent state remains UNKNOWN; queue depth and archive cursor lag remain unavailable because this API has no authoritative runtime feed.</span></div>
      <section className="panel inventory-filters" aria-label="Inventory filters"><label className="filter-field"><span>Host or agent</span><input type="search" value={search} onChange={(event) => setSearch(event.target.value)} /></label><label className="filter-field"><span>Source type</span><select value={sourceType} onChange={(event) => setSourceType(event.target.value)}><option value="">All sources</option>{sourceTypes.map((source) => <option value={source} key={source}>{humanize(source)}</option>)}</select></label><button className="button button--ghost" type="button" onClick={() => { setSearch(""); setSourceType(""); }}>Reset</button></section>
      {!hosts && !error && <StatePanel kind="loading" title="Loading inventory" message="Aggregating bounded event-source observations…" />}
      {error && <StatePanel kind="unavailable" title="Inventory unavailable" message={error} actionLabel="Retry" onAction={() => setRevision((value) => value + 1)} />}
      {hosts && sources && <>
        <article className="panel"><header className="panel__header"><div><span className="eyebrow">Observed assets</span><h2>Host inventory</h2></div></header>
          {visibleHosts.length === 0 ? <p className="muted-copy">{hosts.length === 0 ? "No host-attributed security events have been ingested." : "No host matches the current search."}</p> : <div className="table-frame"><table className="data-table"><thead><tr><th>Host</th><th>Platform</th><th>Agent state</th><th>Source health</th><th>Last seen</th><th>Events / alerts</th><th>Recent detections</th></tr></thead><tbody>{visibleHosts.map((host) => <tr className={selectedHost === host ? "is-selected" : undefined} key={`${host.agent_id}:${host.hostname}`}><td><button className="row-select" type="button" onClick={() => setSelectedHost(host)}><strong>{host.hostname}</strong><span className="cell-subtle">{host.agent_id ? `Agent ${host.agent_id}` : "No agent ID"}</span></button></td><td>{host.platform}</td><td><span className="health-pill health-pill--unknown">UNKNOWN</span></td><td><span className={`health-pill health-pill--${host.source_health.toLowerCase()}`}>{host.source_health} SOURCE</span></td><td><TimeValue value={host.last_seen} relative /></td><td>{host.event_count} / {host.alert_count}</td><td><span className="tag-list">{host.recent_detections.length ? host.recent_detections.map((rule) => <span className="tag" key={rule}>{rule}</span>) : "—"}</span></td></tr>)}</tbody></table></div>}
        </article>
        <article className="panel"><header className="panel__header"><div><span className="eyebrow">Collection</span><h2>Log source inventory</h2></div></header>
          {visibleSources.length === 0 ? <p className="muted-copy">{sources.length === 0 ? "No event sources have reported." : "No source matches the selected type."}</p> : <div className="table-frame"><table className="data-table"><thead><tr><th>Source</th><th>Type</th><th>Last event / ingest</th><th>Lag</th><th>Events</th><th>Source / pipeline</th><th>Runtime counters</th><th>Last error</th></tr></thead><tbody>{visibleSources.map((source) => <tr key={`${source.source_name}:${source.collection_method}`}><td><strong>{source.source_name}</strong><span className="cell-subtle">{source.hostname ?? source.agent_name ?? source.agent_id ?? "Unattributed"}</span></td><td>{humanize(source.source_type)}<span className="cell-subtle mono">{source.collection_method}</span></td><td><TimeValue value={source.last_event_at} relative /><span className="cell-subtle">Ingested <TimeValue value={source.last_ingested_at} relative /></span></td><td>{source.ingestion_lag_seconds.toFixed(1)} s</td><td>{source.event_count}</td><td><span className={`health-pill health-pill--${source.source_health.toLowerCase()}`}>{source.source_health} SOURCE</span><span className={`health-pill health-pill--${source.pipeline_health.toLowerCase()}`}>{source.pipeline_health} PIPELINE</span><span className="cell-subtle">Agent UNKNOWN</span></td><td>Queue {source.queue_depth ?? "unavailable"}<span className="cell-subtle">Cursor lag {source.archive_cursor_lag_bytes == null ? "unavailable" : `${source.archive_cursor_lag_bytes} B`}</span></td><td>{source.last_error ?? "No persisted delivery error"}</td></tr>)}</tbody></table></div>}
        </article>
      </>}
    </section>
    {selectedHost && <aside className="detail-panel" aria-label="Host detail"><header className="detail-panel__header"><div><span className="eyebrow">Observed host</span><h2>{selectedHost.hostname}</h2></div><button className="icon-button" type="button" aria-label="Close host detail" onClick={() => setSelectedHost(null)}>×</button></header><div className="detail-panel__body"><div className="detail-hero"><span className={`health-pill health-pill--${selectedHost.source_health.toLowerCase()}`}>{selectedHost.source_health} SOURCE</span><span className="health-pill health-pill--unknown">AGENT UNKNOWN</span></div><dl className="metadata-grid"><div><dt>Hostname</dt><dd>{selectedHost.hostname}</dd></div><div><dt>Platform</dt><dd>{selectedHost.platform}</dd></div><div><dt>Agent ID</dt><dd className="mono">{selectedHost.agent_id ?? "Not observed"}</dd></div><div><dt>Agent name</dt><dd>{selectedHost.agent_name ?? "Not observed"}</dd></div><div><dt>Last seen</dt><dd><TimeValue value={selectedHost.last_seen} /></dd></div><div><dt>Events / alerts</dt><dd>{selectedHost.event_count} / {selectedHost.alert_count}</dd></div></dl><div className="copy-actions"><CopyButton value={selectedHost.hostname} label="Copy hostname" />{selectedHost.agent_id && <CopyButton value={selectedHost.agent_id} label="Copy agent ID" />}</div><p className="trust-note">No IP address is shown because the current inventory contract does not provide an authoritative host IP.</p></div></aside>}
  </div>;
}
