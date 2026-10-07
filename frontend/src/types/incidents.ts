export const INCIDENT_STATUSES = [
  "NEW",
  "TRIAGED",
  "INVESTIGATING",
  "RESOLVED",
  "FALSE_POSITIVE",
] as const;

export const INCIDENT_SEVERITIES = [
  "INFORMATIONAL",
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
] as const;

export type IncidentStatus = (typeof INCIDENT_STATUSES)[number];
export type IncidentSeverity = (typeof INCIDENT_SEVERITIES)[number];
export type IncidentEventType =
  | "CREATED"
  | "STATUS_CHANGED"
  | "ALERT_LINKED"
  | "NOTE_ADDED"
  | "ASSIGNMENT_CHANGED";

export interface IncidentSummary {
  incident_id: string;
  title: string;
  description: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  assigned_to: string | null;
  created_at: string;
  updated_at: string;
  alert_count: number;
}

export interface IncidentNote {
  note_id: string;
  body: string;
  author: string;
  author_id: string | null;
  created_at: string;
}

export interface IncidentHistoryEvent {
  event_id: string;
  event_type: IncidentEventType;
  actor: string;
  actor_id: string | null;
  occurred_at: string;
  details: Record<string, unknown>;
}

export interface IncidentDetail extends IncidentSummary {
  alert_ids: string[];
  notes: IncidentNote[];
  history: IncidentHistoryEvent[];
}

export interface IncidentQuery {
  statuses?: IncidentStatus[];
  severities?: IncidentSeverity[];
  assignedTo?: string;
  limit?: number;
  cursor?: string;
}

export interface IncidentCreate {
  title: string;
  description?: string;
  severity: IncidentSeverity;
  assigned_to?: string | null;
  alert_ids?: string[];
}

export interface IncidentStatusUpdate {
  status: IncidentStatus;
}

export interface IncidentAlertLink {
  alert_id: string;
}

export interface IncidentNoteCreate {
  body: string;
}

export interface IncidentAssignmentUpdate {
  assigned_to: string | null;
}

export const ALLOWED_STATUS_TRANSITIONS: Record<IncidentStatus, IncidentStatus[]> = {
  NEW: ["TRIAGED", "FALSE_POSITIVE"],
  TRIAGED: ["INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"],
  INVESTIGATING: ["TRIAGED", "RESOLVED", "FALSE_POSITIVE"],
  RESOLVED: ["INVESTIGATING"],
  FALSE_POSITIVE: ["TRIAGED"],
};
