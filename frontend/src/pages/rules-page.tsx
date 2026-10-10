import { useEffect, useMemo, useState } from "react";

import { CopyButton } from "../components/copy-button";
import { SeverityBadge } from "../components/severity-badge";
import { StatePanel } from "../components/state-panel";
import { TimeValue } from "../components/time-value";
import type { BackendApi } from "../types/api";
import type { DetectionRuleSummary } from "../types/siem";
import { humanize } from "../utils/format";

function mitreUrl(id: string): string {
  return `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
}

function ruleType(rule: DetectionRuleSummary): "Correlation" | "Wazuh" {
  return rule.rule_id.startsWith("CORR-") ? "Correlation" : "Wazuh";
}

export function RulesPage({ api, onOpenAlerts = () => undefined }: { api: BackendApi; onOpenAlerts?(ruleId: string): void }) {
  const [rules, setRules] = useState<DetectionRuleSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const [search, setSearch] = useState("");
  const [sourceType, setSourceType] = useState("");
  const [severity, setSeverity] = useState("");
  const [selected, setSelected] = useState<DetectionRuleSummary | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setRules(null); setError(null);
    api.listRules(controller.signal)
      .then(setRules)
      .catch((reason: unknown) => { if (!(reason instanceof DOMException && reason.name === "AbortError")) setError(reason instanceof Error ? reason.message : "Rule catalog unavailable."); });
    return () => controller.abort();
  }, [api, revision]);

  useEffect(() => {
    const close = () => setSelected(null);
    window.addEventListener("cyberqalqon:escape", close);
    return () => window.removeEventListener("cyberqalqon:escape", close);
  }, []);

  const sourceTypes = useMemo(() => [...new Set((rules ?? []).map((rule) => rule.source_type))].sort(), [rules]);
  const filtered = useMemo(() => (rules ?? []).filter((rule) => {
    const query = search.trim().toLocaleLowerCase();
    if (query && !`${rule.rule_id} ${rule.name} ${rule.description}`.toLocaleLowerCase().includes(query)) return false;
    if (sourceType && rule.source_type !== sourceType) return false;
    if (severity === "none" && rule.severity != null) return false;
    if (severity !== "" && severity !== "none" && rule.severity !== Number(severity)) return false;
    return true;
  }), [rules, search, severity, sourceType]);

  return <div className="page-grid">
    <section className="page-column"><header className="page-header"><div><span className="eyebrow">Detection engineering</span><h1>Detection rules</h1><p>Read-only catalog of deployed Wazuh detections and deterministic M9 correlations.</p></div><span className="health-pill health-pill--unknown">Editing disabled</span></header>
      <section className="panel rule-filters" aria-label="Rule filters"><label className="filter-field"><span>Rule ID or name</span><input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="100101 or enumeration" /></label><label className="filter-field"><span>Source type</span><select value={sourceType} onChange={(event) => setSourceType(event.target.value)}><option value="">All sources</option>{sourceTypes.map((source) => <option value={source} key={source}>{humanize(source)}</option>)}</select></label><label className="filter-field"><span>Severity</span><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">All severities</option><option value="none">Not applicable</option>{Array.from({ length: 17 }, (_, level) => <option value={level} key={level}>Level {level}</option>)}</select></label><button className="button button--ghost" type="button" onClick={() => { setSearch(""); setSourceType(""); setSeverity(""); }}>Reset</button></section>
      {!rules && !error && <StatePanel kind="loading" title="Loading rule catalog" message="Reading rule activity and correlation metadata…" />}
      {error && <StatePanel kind="unavailable" title="Rule catalog unavailable" message={error} actionLabel="Retry" onAction={() => setRevision((value) => value + 1)} />}
      {rules && filtered.length === 0 && <StatePanel kind="empty" title="No matching rules" message="No read-only rule matches the current filters." />}
      {filtered.length > 0 && <div className="table-frame"><table className="data-table rules-table"><thead><tr><th>Rule</th><th>Detection</th><th>Severity</th><th>Source</th><th>MITRE</th><th>Activity</th><th>Type</th></tr></thead><tbody>{filtered.map((rule) => <tr className={selected?.rule_id === rule.rule_id ? "is-selected" : undefined} key={rule.rule_id}><td><button className="row-select mono" type="button" onClick={() => setSelected(rule)}>{rule.rule_id}</button></td><td><strong>{rule.name}</strong><span className="cell-subtle">{rule.description}</span></td><td>{rule.severity == null ? "—" : <SeverityBadge level={rule.severity} />}</td><td>{humanize(rule.source_type)}</td><td><span className="tag-list">{rule.mitre_ids.length ? rule.mitre_ids.map((id) => <a className="tag tag--mitre" href={mitreUrl(id)} target="_blank" rel="noreferrer" key={id}>{id}</a>) : "—"}</span></td><td>{rule.alert_count}<span className="cell-subtle">{rule.last_triggered ? <TimeValue value={rule.last_triggered} relative /> : "Never observed"}</span></td><td><span className="source-pill">{ruleType(rule)}</span></td></tr>)}</tbody></table></div>}
    </section>
    {selected && <aside className="detail-panel" aria-label="Rule detail"><header className="detail-panel__header"><div><span className="eyebrow">Read-only rule</span><h2>{selected.name}</h2></div><button className="icon-button" type="button" aria-label="Close rule detail" onClick={() => setSelected(null)}>×</button></header><div className="detail-panel__body"><div className="detail-hero"><span className="source-pill">{ruleType(selected)}</span>{selected.severity == null ? <span>Severity not applicable</span> : <SeverityBadge level={selected.severity} />}</div><section className="detail-section"><h3>Rule identity</h3><dl className="metadata-grid"><div><dt>Rule ID</dt><dd className="mono">{selected.rule_id}</dd></div><div><dt>Source</dt><dd>{humanize(selected.source_type)}</dd></div><div><dt>Trigger count</dt><dd>{selected.alert_count}</dd></div><div><dt>Last triggered</dt><dd>{selected.last_triggered ? <TimeValue value={selected.last_triggered} /> : "Never observed"}</dd></div></dl><CopyButton value={selected.rule_id} label="Copy rule ID" /></section><section className="detail-section"><h3>Detection explanation</h3><p>{selected.description}</p>{selected.correlation_relationship && <p className="trust-note">Correlation relationship: {selected.correlation_relationship}</p>}</section><section className="detail-section"><h3>MITRE ATT&amp;CK</h3>{selected.mitre_ids.length ? <div className="tag-list">{selected.mitre_ids.map((id) => <a className="tag tag--mitre" href={mitreUrl(id)} target="_blank" rel="noreferrer" key={id}>{id}</a>)}</div> : <p className="muted-copy">No upstream MITRE mapping.</p>}</section><button className="button button--primary" type="button" onClick={() => onOpenAlerts(selected.rule_id)}>Open related alerts</button><p className="trust-note">Rule editing remains disabled. This view performs no configuration mutation.</p></div></aside>}
  </div>;
}
