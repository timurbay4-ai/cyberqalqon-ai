import { useEffect, useMemo, useState } from "react";

import { CopyButton } from "../components/copy-button";
import { SourceCoverage } from "../components/source-coverage";
import { StatePanel } from "../components/state-panel";
import { TimeValue } from "../components/time-value";
import type { AgentConnectionStatus, AgentDetail, AgentHealthResponse, AgentListResponse, AgentSummary, WazuhIntegrationStatus } from "../types/agents";
import type { BackendApi } from "../types/api";
import type { LogSourceSummary } from "../types/siem";
import { humanize } from "../utils/format";

const PAGE_SIZE = 25;

function statusClass(status: AgentConnectionStatus): string {
  if (status === "ONLINE") return "healthy";
  if (status === "DISCONNECTED") return "unavailable";
  if (status === "NEVER_CONNECTED") return "degraded";
  return "unknown";
}

function selectedFromUrl(): string | null {
  return new URLSearchParams(window.location.search).get("agent");
}

export function HostsPage({ api, onOpenEvent }: { api: BackendApi; onOpenEvent?(id:string):void }) {
  const [agents, setAgents] = useState<AgentListResponse | null>(null);
  const [sources, setSources] = useState<LogSourceSummary[] | null>(null);
  const [integration, setIntegration] = useState<WazuhIntegrationStatus | null>(null);
  const [detail, setDetail] = useState<AgentDetail | null>(null);
  const [history, setHistory] = useState<AgentHealthResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState<AgentConnectionStatus | "">("");
  const [platform, setPlatform] = useState("");
  const [manager, setManager] = useState("");
  const [sourceType, setSourceType] = useState("");
  const [sort, setSort] = useState<"name" | "agent_id" | "status" | "last_seen" | "version">("name");
  const [order, setOrder] = useState<"asc" | "desc">("asc");
  const [offset, setOffset] = useState(0);
  const [selectedKey, setSelectedKey] = useState<string | null>(selectedFromUrl);

  useEffect(() => {
    const controller = new AbortController();
    setAgents(null); setSources(null); setIntegration(null); setError(null);
    Promise.all([
      api.listAgents({ search: search.trim() || undefined, os: platform || undefined, connectionStatus: status || undefined, manager: manager.trim() || undefined, sourceType: sourceType || undefined, sort, order, limit: PAGE_SIZE, offset }, controller.signal),
      api.listSources(controller.signal),
      api.getWazuhIntegrationStatus(controller.signal),
    ]).then(([nextAgents, nextSources, nextIntegration]) => {
      setAgents(nextAgents); setSources(nextSources); setIntegration(nextIntegration);
    }).catch((reason: unknown) => {
      if (!(reason instanceof DOMException && reason.name === "AbortError")) setError(reason instanceof Error ? reason.message : "Agent inventory is unavailable.");
    });
    return () => controller.abort();
  }, [api, manager, offset, order, platform, revision, search, sort, sourceType, status]);

  useEffect(() => {
    if (!selectedKey) { setDetail(null); setHistory(null); setDetailError(null); return; }
    const controller = new AbortController();
    setDetail(null); setHistory(null); setDetailError(null);
    Promise.all([api.getAgent(selectedKey, controller.signal), api.getAgentHealth(selectedKey, controller.signal)])
      .then(([nextDetail, nextHistory]) => { setDetail(nextDetail); setHistory(nextHistory); })
      .catch((reason: unknown) => {
        if (!(reason instanceof DOMException && reason.name === "AbortError")) setDetailError(reason instanceof Error ? reason.message : "Agent details are unavailable.");
      });
    return () => controller.abort();
  }, [api, revision, selectedKey]);

  useEffect(() => {
    const sync = () => setSelectedKey(selectedFromUrl());
    const close = () => selectAgent(null);
    window.addEventListener("popstate", sync);
    window.addEventListener("cyberqalqon:escape", close);
    return () => { window.removeEventListener("popstate", sync); window.removeEventListener("cyberqalqon:escape", close); };
  }, []);

  const sourceTypes = useMemo(() => [...new Set((sources ?? []).map((source) => source.source_type))].sort(), [sources]);

  function selectAgent(agent: AgentSummary | null) {
    const parameters = new URLSearchParams(window.location.search);
    if (agent) parameters.set("agent", agent.agent_key); else parameters.delete("agent");
    const query = parameters.toString();
    window.history.pushState({}, "", `${window.location.pathname}${query ? `?${query}` : ""}`);
    setSelectedKey(agent?.agent_key ?? null);
  }

  function resetFilters() {
    setSearch(""); setStatus(""); setPlatform(""); setManager(""); setSourceType(""); setOffset(0);
  }

  const total = agents?.page.total ?? 0;
  return <div className="page-grid">
    <section className="page-column">
      <SourceCoverage api={api} onOpenEvent={onOpenEvent}/>
      <header className="page-header"><div><span className="eyebrow">Enterprise inventory</span><h1>Agent management</h1><p>Authoritative Wazuh connectivity, observed telemetry freshness, and pipeline state remain separate.</p></div><div className="page-header__actions"><button className="button button--ghost" type="button" onClick={() => setRevision((value) => value + 1)}>Refresh</button></div></header>
      {integration && <div className="inventory-explanation" role="note"><strong>Wazuh API: {integration.state}</strong><span>{integration.reason} Authority: WAZUH_API · TLS: {humanize(integration.tls_verification)} · observed <TimeValue value={integration.observed_at} relative />{integration.cache_stale ? " · cache stale" : ""}.</span></div>}
      <section className="panel inventory-filters" aria-label="Agent filters">
        <label className="filter-field"><span>Agent, name, IP</span><input type="search" value={search} onChange={(event) => { setSearch(event.target.value); setOffset(0); }} /></label>
        <label className="filter-field"><span>Connection</span><select value={status} onChange={(event) => { setStatus(event.target.value as AgentConnectionStatus | ""); setOffset(0); }}><option value="">All states</option><option>ONLINE</option><option>DISCONNECTED</option><option>NEVER_CONNECTED</option><option>UNKNOWN</option></select></label>
        <label className="filter-field"><span>Operating system</span><select value={platform} onChange={(event) => { setPlatform(event.target.value); setOffset(0); }}><option value="">All operating systems</option><option value="windows">Windows</option><option value="linux">Linux</option></select></label>
        <label className="filter-field"><span>Manager</span><input type="search" placeholder="All managers" value={manager} onChange={(event) => { setManager(event.target.value); setOffset(0); }} /></label>
        <label className="filter-field"><span>Source type</span><select value={sourceType} onChange={(event) => { setSourceType(event.target.value); setOffset(0); }}><option value="">All sources</option>{sourceTypes.map((value) => <option key={value}>{value}</option>)}</select></label>
        <label className="filter-field"><span>Sort</span><select value={sort} onChange={(event) => setSort(event.target.value as typeof sort)}><option value="name">Name</option><option value="agent_id">Agent ID</option><option value="status">Connection</option><option value="last_seen">Last event</option><option value="version">Version</option></select></label>
        <button className="button button--ghost" type="button" onClick={() => setOrder((value) => value === "asc" ? "desc" : "asc")}>Order {order === "asc" ? "↑" : "↓"}</button>
        <button className="button button--ghost" type="button" onClick={resetFilters}>Reset</button>
      </section>
      {!agents && !error && <StatePanel kind="loading" title="Loading agents" message="Reading the bounded provider cache and telemetry relationships…" />}
      {error && <StatePanel kind="unavailable" title="Agent inventory unavailable" message={error} actionLabel="Retry" onAction={() => setRevision((value) => value + 1)} />}
      {agents && <article className="panel"><header className="panel__header"><div><span className="eyebrow">Agents</span><h2>{total.toLocaleString()} inventory records</h2></div><span className={`health-pill health-pill--${agents.authoritative_inventory ? "healthy" : "unknown"}`}>{agents.authoritative_inventory ? "AUTHORITATIVE" : "PARTIAL"}</span></header>
        <p className="cell-subtle">{agents.message} Observation <TimeValue value={agents.observation_timestamp} relative />.</p>
        {agents.items.length === 0 ? <p className="muted-copy">No agent matches the selected filters. If the Wazuh API is unavailable, only telemetry-observed sources can be shown.</p> : <div className="table-frame"><table className="data-table"><thead><tr><th>Agent</th><th>OS / version</th><th>Manager</th><th>Connection</th><th>Keepalive / event</th><th>Data / pipeline</th><th>Authority</th></tr></thead><tbody>{agents.items.map((agent) => <tr className={selectedKey === agent.agent_key ? "is-selected" : undefined} key={agent.agent_key}><td><button className="row-select" type="button" onClick={() => selectAgent(agent)}><strong>{agent.name}</strong><span className="cell-subtle mono">{agent.agent_id}</span></button></td><td>{agent.operating_system ?? humanize(agent.os_platform ?? "unknown")}<span className="cell-subtle">{agent.agent_version ?? "Version unavailable"}</span></td><td>{agent.manager ?? "Unavailable"}</td><td><span className={`health-pill health-pill--${statusClass(agent.connection_status)}`}>{agent.connection_status}</span><span className="cell-subtle">Enrollment {agent.enrollment_status}</span></td><td>{agent.last_keepalive ? <TimeValue value={agent.last_keepalive} relative /> : "No keepalive"}<span className="cell-subtle">Event {agent.last_security_event ? <TimeValue value={agent.last_security_event} relative /> : "unavailable"}</span></td><td><span className={`health-pill health-pill--${agent.data_freshness.toLowerCase()}`}>{agent.data_freshness}</span><span className={`health-pill health-pill--${agent.pipeline_health.toLowerCase()}`}>{agent.pipeline_health}</span></td><td className="mono">{agent.status_authority}{agent.cache_stale && <span className="cell-subtle">STALE CACHE</span>}</td></tr>)}</tbody></table></div>}
        <nav className="pagination" aria-label="Agent pages"><button className="button button--ghost" type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>Previous</button><span>{total === 0 ? "0" : `${offset + 1}–${Math.min(offset + PAGE_SIZE, total)}`} of {total}</span><button className="button button--ghost" type="button" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>Next</button></nav>
      </article>}
    </section>
    {selectedKey && <aside className="detail-panel" aria-label="Agent detail"><header className="detail-panel__header"><div><span className="eyebrow">Agent diagnostics</span><h2>{detail?.name ?? "Loading agent…"}</h2></div><button className="icon-button" type="button" aria-label="Close agent detail" onClick={() => selectAgent(null)}>×</button></header><div className="detail-panel__body">
      {!detail && !detailError && <StatePanel kind="loading" title="Loading agent details" message="Joining provider state with recent evidence…" />}
      {detailError && <StatePanel kind="unavailable" title="Agent detail unavailable" message={detailError} actionLabel="Retry" onAction={() => setRevision((value) => value + 1)} />}
      {detail && <><div className="detail-hero"><span className={`health-pill health-pill--${statusClass(detail.connection_status)}`}>{detail.connection_status}</span><span className="tag">{detail.status_authority}</span></div><dl className="metadata-grid"><div><dt>Agent ID</dt><dd className="mono">{detail.agent_id}</dd></div><div><dt>Manager</dt><dd>{detail.manager ?? "Unavailable"}</dd></div><div><dt>OS</dt><dd>{detail.operating_system ?? "Unknown"}</dd></div><div><dt>Agent version</dt><dd>{detail.agent_version ?? "Unavailable"}</dd></div><div><dt>IP address</dt><dd className="mono">{detail.ip_address ?? "Unavailable"}</dd></div><div><dt>Enrollment</dt><dd>{detail.enrollment_status}</dd></div><div><dt>Last keepalive</dt><dd>{detail.last_keepalive ? <TimeValue value={detail.last_keepalive} /> : "Unavailable"}</dd></div><div><dt>Last security event</dt><dd>{detail.last_security_event ? <TimeValue value={detail.last_security_event} /> : "No data"}</dd></div></dl><div className="copy-actions"><CopyButton value={detail.agent_id} label="Copy agent ID" /><CopyButton value={detail.agent_key} label="Copy inventory ID" />{detail.ip_address && <CopyButton value={detail.ip_address} label="Copy IP address" />}</div>
        <section className="detail-section"><h3>Telemetry sources</h3>{detail.telemetry_sources.length === 0 ? <p className="muted-copy">No security event source is related to this agent.</p> : <ul className="compact-list">{detail.telemetry_sources.map((source) => <li key={`${source.source_type}:${source.ingestion_source}`}><strong>{humanize(source.source_type)}</strong> · {source.event_count} events · {source.freshness}<span className="cell-subtle">Last event <TimeValue value={source.last_event_at} relative /></span></li>)}</ul>}</section>
        <section className="detail-section"><h3>Health history</h3>{history?.items.length ? <ol className="workflow-activity">{history.items.map((item) => <li key={item.history_id}><div><strong>{item.previous_status ?? "INITIAL"} → {item.connection_status}</strong><span>WAZUH_API</span></div><TimeValue value={item.observed_at} relative /></li>)}</ol> : <p className="muted-copy">{detail.status_authority === "WAZUH_API" ? "No status transition has been recorded." : "Health history is unavailable for telemetry-only identity."}</p>}</section>
        <section className="detail-section"><h3>Relationships</h3><dl className="metadata-grid"><div><dt>Recent events</dt><dd>{detail.recent_event_ids.length}</dd></div><div><dt>Related alerts</dt><dd>{detail.related_alert_ids.length}</dd></div><div><dt>Related incidents</dt><dd>{detail.related_incident_ids.length}</dd></div><div><dt>Groups</dt><dd>{detail.groups.join(", ") || "None reported"}</dd></div></dl></section>
        <section className="detail-section"><h3>Troubleshooting</h3><ul className="compact-list">{detail.troubleshooting.map((item) => <li key={item}>{item}</li>)}</ul></section><p className="trust-note">This workspace is read-only. It cannot restart, enroll, reconfigure, or upgrade an agent.</p></>}
    </div></aside>}
  </div>;
}
