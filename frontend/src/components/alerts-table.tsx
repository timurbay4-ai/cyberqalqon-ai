import type { AlertWorkflowSummary } from "../types/alerts";
import { formatEndpoint, formatTimestamp } from "../utils/format";
import { MitreTags } from "./mitre-tags";
import { SeverityBadge } from "./severity-badge";

export function AlertsTable({ workflows, selectedAlertId, checkedIds, selectionDisabled = false, onSelect, onToggle }: {
  workflows: AlertWorkflowSummary[];
  selectedAlertId: string | null;
  checkedIds: Set<string>;
  selectionDisabled?: boolean;
  onSelect(alertId: string): void;
  onToggle(alertId: string, checked: boolean): void;
}) {
  return (
    <div className="table-shell">
      <table className="data-table alerts-table">
        <thead><tr><th><span className="sr-only">Select</span></th><th>Time</th><th>Severity</th><th>Detection</th><th>Workflow</th><th>Assignee</th><th>Asset</th><th>Source</th><th>MITRE ATT&amp;CK</th></tr></thead>
        <tbody>
          {workflows.map((workflow) => {
            const alert = workflow.alert;
            const checked = checkedIds.has(alert.alert_id);
            return <tr className={selectedAlertId === alert.alert_id ? "is-selected" : undefined} aria-selected={selectedAlertId === alert.alert_id} key={alert.alert_id}>
              <td><input type="checkbox" aria-label={`Select alert ${alert.alert_id}`} checked={checked} disabled={!checked && selectionDisabled} onChange={(event) => onToggle(alert.alert_id, event.target.checked)} /></td>
              <td><button className="row-link" type="button" onClick={() => onSelect(alert.alert_id)}>{formatTimestamp(alert.timestamp)}</button><span className="cell-subtle">{alert.alert_id}</span></td>
              <td><SeverityBadge level={alert.rule.level} /></td>
              <td><span className="cell-primary">{alert.rule.description}</span><span className="cell-subtle">Rule {alert.rule.id}</span></td>
              <td><span className={`workflow-badge workflow-badge--${workflow.status.toLowerCase()}`}>{workflow.status.replaceAll("_", " ")}</span><span className="cell-subtle">Activity {formatTimestamp(workflow.last_activity_at)}</span></td>
              <td>{workflow.assignee?.display_name ?? "Unassigned"}<span className="cell-subtle">{workflow.note_count} note{workflow.note_count === 1 ? "" : "s"}</span></td>
              <td><span className="cell-primary">{alert.agent.name}</span><span className="cell-subtle">Agent {alert.agent.id}</span></td>
              <td className="mono">{formatEndpoint(alert.source)}</td>
              <td><MitreTags mitre={alert.mitre} /></td>
            </tr>
          })}
        </tbody>
      </table>
    </div>
  );
}
