import type { SecurityEventDetail as EventDetailModel } from "../types/events";
import { humanize } from "../utils/format";
import { CopyButton } from "./copy-button";
import { SeverityBadge } from "./severity-badge";
import { TimeValue } from "./time-value";

interface Props {
  event: EventDetailModel;
  onClose(): void;
  onOpenAlert(alertId: string): void;
  onOpenIncident(incidentId: string): void;
}

function endpoint(ip?: string | null, port?: number | null): string {
  if (!ip) return "—";
  if (!port) return ip;
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
}

export function EventDetail({ event, onClose, onOpenAlert, onOpenIncident }: Props) {
  return (
    <aside className="detail-panel event-detail" aria-label="Security event detail">
      <header className="detail-panel__header">
        <div><span className="eyebrow">Security event</span><h2>{event.message}</h2></div>
        <button className="icon-button" type="button" aria-label="Close event detail" onClick={onClose}>×</button>
      </header>
      <div className="detail-panel__body">
        <div className="detail-hero">
          {event.severity == null ? <span className="source-pill">{humanize(event.source_type)}</span> : <SeverityBadge level={event.severity} />}
          <TimeValue value={event.timestamp} />
        </div>
        <section className="detail-section">
          <h3>Identity</h3>
          <dl className="metadata-grid">
            <div><dt>Event ID</dt><dd className="mono">{event.event_id}</dd></div>
            <div><dt>Source event ID</dt><dd className="mono">{event.source_event_id ?? "—"}</dd></div>
            <div><dt>Event code</dt><dd className="mono">{event.event_code ?? "—"}</dd></div>
            <div><dt>Source type</dt><dd>{humanize(event.source_type)}</dd></div>
            <div><dt>Ingested</dt><dd><TimeValue value={event.ingested_at} /></dd></div>
            <div><dt>Collection</dt><dd>{event.ingestion_source}</dd></div>
          </dl>
          <CopyButton value={event.event_id} label="Copy event ID" />
        </section>
        <section className="detail-section">
          <h3>Host &amp; network</h3>
          <dl className="metadata-grid">
            <div><dt>Hostname</dt><dd>{event.hostname ?? "—"}</dd></div>
            <div><dt>Agent</dt><dd>{event.agent_name ?? "—"} {event.agent_id ? `(${event.agent_id})` : ""}</dd></div>
            <div><dt>Source</dt><dd className="mono">{endpoint(event.source_ip, event.source_port)}</dd></div>
            <div><dt>Destination</dt><dd className="mono">{endpoint(event.destination_ip, event.destination_port)}</dd></div>
            <div><dt>Username</dt><dd>{event.username ?? "—"}</dd></div>
            <div><dt>Outcome</dt><dd>{event.outcome ?? "—"}</dd></div>
          </dl>
          <div className="copy-actions">
            {event.hostname && <CopyButton value={event.hostname} label="Copy hostname" />}
            {event.source_ip && <CopyButton value={event.source_ip} label="Copy source IP" />}
            {event.destination_ip && <CopyButton value={event.destination_ip} label="Copy destination IP" />}
          </div>
        </section>
        <section className="detail-section">
          <h3>Detection relationships</h3>
          <dl className="metadata-grid">
            <div><dt>Rule</dt><dd className="mono">{event.rule_id ?? "—"}</dd></div>
            <div><dt>Category</dt><dd>{event.event_category ?? "—"}</dd></div>
            <div><dt>Action</dt><dd>{event.event_action ?? "—"}</dd></div>
          </dl>
          <div className="relationship-actions">
            {event.related_alert_id && <button className="button button--secondary" type="button" onClick={() => onOpenAlert(event.related_alert_id!)}>Open alert {event.related_alert_id}</button>}
            {event.related_incident_ids.map((incidentId) => <button className="button button--secondary" type="button" key={incidentId} onClick={() => onOpenIncident(incidentId)}>Open incident {incidentId}</button>)}
            {!event.related_alert_id && event.related_incident_ids.length === 0 && <p className="muted-copy">No alert or incident relationship exists for this event.</p>}
          </div>
        </section>
        <details className="json-evidence" open>
          <summary>Structured evidence</summary>
          <div className="evidence-actions"><CopyButton value={JSON.stringify(event.structured_payload, null, 2)} label="Copy JSON" /></div>
          <pre>{JSON.stringify(event.structured_payload, null, 2)}</pre>
        </details>
        <details className="json-evidence">
          <summary>Redacted source envelope</summary>
          <pre>{JSON.stringify(event.raw_payload, null, 2)}</pre>
        </details>
        <p className="trust-note">All evidence is untrusted display data. Sensitive key/value patterns are redacted during ingestion.</p>
      </div>
    </aside>
  );
}
