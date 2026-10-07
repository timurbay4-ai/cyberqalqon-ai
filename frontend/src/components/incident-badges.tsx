import type { IncidentSeverity, IncidentStatus } from "../types/incidents";
import { humanize } from "../utils/format";

export function IncidentSeverityBadge({ severity }: { severity: IncidentSeverity }) {
  return <span className={`badge incident-severity incident-severity--${severity.toLowerCase()}`}>{humanize(severity)}</span>;
}

export function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  return <span className={`badge incident-status incident-status--${status.toLowerCase()}`}>{humanize(status)}</span>;
}
