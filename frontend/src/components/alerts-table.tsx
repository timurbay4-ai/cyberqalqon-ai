import type { NormalizedAlert } from "../types/alerts";
import { formatEndpoint, formatTimestamp } from "../utils/format";
import { MitreTags } from "./mitre-tags";
import { SeverityBadge } from "./severity-badge";

export function AlertsTable({ alerts, selectedAlertId, onSelect }: { alerts: NormalizedAlert[]; selectedAlertId: string | null; onSelect(alertId: string): void }) {
  return (
    <div className="table-shell">
      <table className="data-table alerts-table">
        <thead><tr><th>Time</th><th>Severity</th><th>Detection</th><th>Asset</th><th>Source</th><th>MITRE ATT&amp;CK</th></tr></thead>
        <tbody>
          {alerts.map((alert) => (
            <tr className={selectedAlertId === alert.alert_id ? "is-selected" : undefined} aria-selected={selectedAlertId === alert.alert_id} key={alert.alert_id}>
              <td><button className="row-link" type="button" onClick={() => onSelect(alert.alert_id)}>{formatTimestamp(alert.timestamp)}</button><span className="cell-subtle">{alert.alert_id}</span></td>
              <td><SeverityBadge level={alert.rule.level} /></td>
              <td><span className="cell-primary">{alert.rule.description}</span><span className="cell-subtle">Rule {alert.rule.id}</span></td>
              <td><span className="cell-primary">{alert.agent.name}</span><span className="cell-subtle">Agent {alert.agent.id}</span></td>
              <td className="mono">{formatEndpoint(alert.source)}</td>
              <td><MitreTags mitre={alert.mitre} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
