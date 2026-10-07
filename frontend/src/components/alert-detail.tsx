import type { NormalizedAlert } from "../types/alerts";
import { formatEndpoint, formatTimestamp } from "../utils/format";
import { MitreTags } from "./mitre-tags";
import { SeverityBadge } from "./severity-badge";
import { AIAnalysisPanel } from "./ai-analysis-panel";
import type { BackendApi } from "../types/api";

export function AlertDetail({ alert, api, onClose }: { alert: NormalizedAlert; api: BackendApi; onClose(): void }) {
  return (
    <aside className="detail-panel" aria-label="Alert detail">
      <header className="detail-panel__header"><div><span className="eyebrow">Normalized alert</span><h2>{alert.rule.description}</h2></div><button className="icon-button" type="button" aria-label="Close alert detail" onClick={onClose}>×</button></header>
      <div className="detail-panel__body">
        <div className="detail-hero"><SeverityBadge level={alert.rule.level} /><span>{formatTimestamp(alert.timestamp)}</span></div>
        <section className="detail-section"><h3>Detection</h3><dl className="metadata-grid"><div><dt>Alert ID</dt><dd className="mono">{alert.alert_id}</dd></div><div><dt>Rule ID</dt><dd className="mono">{alert.rule.id}</dd></div><div><dt>Decoder</dt><dd>{alert.decoder_name ?? "Not supplied"}</dd></div><div><dt>Location</dt><dd>{alert.location ?? "Not supplied"}</dd></div></dl>{(alert.rule.groups?.length ?? 0) > 0 && <div className="tag-list">{alert.rule.groups?.map((group) => <span className="tag" key={group}>{group}</span>)}</div>}</section>
        <section className="detail-section"><h3>Asset &amp; identity</h3><dl className="metadata-grid"><div><dt>Agent</dt><dd>{alert.agent.name}</dd></div><div><dt>Agent ID</dt><dd className="mono">{alert.agent.id}</dd></div><div><dt>Agent IP</dt><dd className="mono">{alert.agent.ip ?? "Not supplied"}</dd></div><div><dt>User</dt><dd>{alert.user ?? "Not supplied"}</dd></div></dl></section>
        <section className="detail-section"><h3>Network context</h3><dl className="metadata-grid"><div><dt>Source</dt><dd className="mono">{formatEndpoint(alert.source)}</dd></div><div><dt>Destination</dt><dd className="mono">{formatEndpoint(alert.destination)}</dd></div></dl></section>
        <section className="detail-section"><h3>MITRE ATT&amp;CK</h3><MitreTags mitre={alert.mitre} detailed /><p className="trust-note">Mappings are shown exactly as supplied upstream.</p></section>
        <AIAnalysisPanel api={api} targetType="alert" targetId={alert.alert_id} />
      </div>
    </aside>
  );
}
