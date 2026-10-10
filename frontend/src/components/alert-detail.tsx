import type { AlertAssignee, AlertWorkflowDetail, AlertWorkflowStatus } from "../types/alerts";
import { formatEndpoint, formatTimestamp } from "../utils/format";
import { CopyButton } from "./copy-button";
import { MitreTags } from "./mitre-tags";
import { SeverityBadge } from "./severity-badge";
import { AIAnalysisPanel } from "./ai-analysis-panel";
import type { BackendApi } from "../types/api";
import type { SecurityEventSummary } from "../types/events";
import { TimeValue } from "./time-value";
import { AlertWorkflowPanel } from "./alert-workflow-panel";

export function AlertDetail({ workflow, api, assignees = [], canMutate = false, mutationBusy = false, mutationError = null, mutationSuccess = null, relatedEvents = [], relatedEventsError = null, onStatus = () => undefined, onAssignment = () => undefined, onNote = () => undefined, onOpenEvent = () => undefined, onClose }: { workflow: AlertWorkflowDetail; api: BackendApi; assignees?: AlertAssignee[]; canMutate?: boolean; mutationBusy?: boolean; mutationError?: string | null; mutationSuccess?: string | null; relatedEvents?: SecurityEventSummary[]; relatedEventsError?: string | null; onStatus?(status: AlertWorkflowStatus): void; onAssignment?(analystId: string | null): void; onNote?(body: string): void; onOpenEvent?(eventId: string): void; onClose(): void }) {
  const alert = workflow.alert;
  return (
    <aside className="detail-panel" aria-label="Alert detail">
      <header className="detail-panel__header"><div><span className="eyebrow">Normalized alert</span><h2>{alert.rule.description}</h2></div><button className="icon-button" type="button" aria-label="Close alert detail" onClick={onClose}>×</button></header>
      <div className="detail-panel__body">
        <div className="detail-hero"><SeverityBadge level={alert.rule.level} /><TimeValue value={alert.timestamp} /></div>
        <AlertWorkflowPanel workflow={workflow} assignees={assignees} canMutate={canMutate} busy={mutationBusy} error={mutationError} success={mutationSuccess} onStatus={onStatus} onAssignment={onAssignment} onNote={onNote} />
        <section className="detail-section"><h3>Detection</h3><dl className="metadata-grid"><div><dt>Alert ID</dt><dd className="mono">{alert.alert_id}</dd></div><div><dt>Rule ID</dt><dd className="mono">{alert.rule.id}</dd></div><div><dt>Decoder</dt><dd>{alert.decoder_name ?? "Not supplied"}</dd></div><div><dt>Location</dt><dd>{alert.location ?? "Not supplied"}</dd></div></dl><div className="copy-actions"><CopyButton value={alert.alert_id} label="Copy alert ID" /><CopyButton value={alert.rule.id} label="Copy rule ID" /></div>{(alert.rule.groups?.length ?? 0) > 0 && <div className="tag-list">{alert.rule.groups?.map((group) => <span className="tag" key={group}>{group}</span>)}</div>}</section>
        <section className="detail-section"><h3>Asset &amp; identity</h3><dl className="metadata-grid"><div><dt>Agent</dt><dd>{alert.agent.name}</dd></div><div><dt>Agent ID</dt><dd className="mono">{alert.agent.id}</dd></div><div><dt>Agent IP</dt><dd className="mono">{alert.agent.ip ?? "Not supplied"}</dd></div><div><dt>User</dt><dd>{alert.user ?? "Not supplied"}</dd></div></dl><div className="copy-actions"><CopyButton value={alert.agent.name} label="Copy agent name" />{alert.agent.ip && <CopyButton value={alert.agent.ip} label="Copy agent IP" />}</div></section>
        {alert.windows && <section className="detail-section"><h3>Windows event</h3><dl className="metadata-grid"><div><dt>Event ID</dt><dd className="mono">{alert.windows.event_id}</dd></div><div><dt>Channel</dt><dd>{alert.windows.channel}</dd></div><div><dt>Provider</dt><dd>{alert.windows.provider ?? "Not supplied"}</dd></div><div><dt>Computer</dt><dd>{alert.windows.computer ?? "Not supplied"}</dd></div></dl></section>}
        <section className="detail-section"><h3>Network context</h3><dl className="metadata-grid"><div><dt>Source</dt><dd className="mono">{formatEndpoint(alert.source)}</dd></div><div><dt>Destination</dt><dd className="mono">{formatEndpoint(alert.destination)}</dd></div></dl></section>
        <section className="detail-section"><h3>MITRE ATT&amp;CK</h3><MitreTags mitre={alert.mitre} detailed /><p className="trust-note">Mappings are shown exactly as supplied upstream.</p></section>
        <section className="detail-section"><h3>Related security events</h3>
          {relatedEventsError && <p className="inline-error" role="alert">{relatedEventsError}</p>}
          {!relatedEventsError && relatedEvents.length === 0 && <p className="muted-copy">No normalized event evidence is linked to this alert.</p>}
          {relatedEvents.length > 0 && <div className="related-event-list">{relatedEvents.map((event) => <button type="button" key={event.event_id} onClick={() => onOpenEvent(event.event_id)}><div><strong>{event.message}</strong><span>{formatTimestamp(event.timestamp)}</span></div><span className="mono">{event.event_id}</span><small>{event.source_type} · rule {event.rule_id ?? "—"}</small></button>)}</div>}
        </section>
        <AIAnalysisPanel api={api} targetType="alert" targetId={alert.alert_id} />
      </div>
    </aside>
  );
}
