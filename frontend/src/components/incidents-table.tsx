import type { IncidentSummary } from "../types/incidents";
import { formatTimestamp } from "../utils/format";
import { IncidentSeverityBadge, IncidentStatusBadge } from "./incident-badges";

export function IncidentsTable({ incidents, selectedId, onSelect }: { incidents: IncidentSummary[]; selectedId: string | null; onSelect(incidentId: string): void }) {
  return (
    <div className="table-shell">
      <table className="data-table incidents-table">
        <thead><tr><th>Updated</th><th>Incident</th><th>Severity</th><th>Status</th><th>Assignee</th><th>Alerts</th></tr></thead>
        <tbody>{incidents.map((incident) => (
          <tr className={selectedId === incident.incident_id ? "is-selected" : undefined} key={incident.incident_id}>
            <td>{formatTimestamp(incident.updated_at)}</td>
            <td><button className="row-link" type="button" onClick={() => onSelect(incident.incident_id)}>{incident.title}</button><span className="cell-subtle">{incident.incident_id}</span>{incident.auto_correlated && <span className="correlation-badge">Auto · {incident.correlation_rule}</span>}</td>
            <td><IncidentSeverityBadge severity={incident.severity} /></td>
            <td><IncidentStatusBadge status={incident.status} /></td>
            <td>{incident.assigned_to ?? "Unassigned"}</td>
            <td>{incident.alert_count}</td>
          </tr>
        ))}</tbody>
      </table>
    </div>
  );
}
