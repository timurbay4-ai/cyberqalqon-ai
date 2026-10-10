export interface AlertAgent {
  id: string;
  name: string;
  ip?: string | null;
}

export type WazuhSeverityLevel =
  | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8
  | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16;

export interface AlertRule {
  id: string;
  level: WazuhSeverityLevel;
  description: string;
  groups?: string[];
}

export interface MitreContext {
  ids: string[];
  tactics: string[];
  techniques: string[];
}

export interface NetworkEndpoint {
  ip?: string | null;
  port?: number | null;
}

export interface WindowsEventContext {
  event_id: string;
  channel: string;
  provider?: string | null;
  computer?: string | null;
}

/** Mirrors the backend NormalizedAlert schema. Every string is untrusted display data. */
export interface NormalizedAlert {
  alert_id: string;
  timestamp: string;
  agent: AlertAgent;
  rule: AlertRule;
  mitre: MitreContext;
  source?: NetworkEndpoint | null;
  destination?: NetworkEndpoint | null;
  user?: string | null;
  location?: string | null;
  decoder_name?: string | null;
  windows?: WindowsEventContext | null;
}

export type SeverityBand = "critical" | "high" | "medium" | "low" | "informational";

export interface AlertQuery {
  ruleLevels?: WazuhSeverityLevel[];
  ruleId?: string;
  agent?: string;
  mitreMapped?: boolean;
  mitreId?: string;
  startTime?: string;
  endTime?: string;
  search?: string;
  limit?: number;
  cursor?: string;
}

export const ALERT_WORKFLOW_STATUSES = [
  "NEW", "ACKNOWLEDGED", "IN_PROGRESS", "RESOLVED", "FALSE_POSITIVE",
] as const;
export type AlertWorkflowStatus = (typeof ALERT_WORKFLOW_STATUSES)[number];
export type AlertWorkflowSort = "time_desc" | "time_asc" | "severity_desc" | "severity_asc" | "activity_desc";

export interface AlertAssignee {
  analyst_id: string;
  username: string;
  display_name: string;
}

export interface AlertWorkflowNote {
  note_id: string;
  body: string;
  author_id: string | null;
  author_display: string;
  created_at: string;
}

export interface AlertWorkflowHistoryEvent {
  event_id: string;
  event_type: "STATUS_CHANGED" | "ASSIGNMENT_CHANGED" | "NOTE_ADDED";
  actor_id: string | null;
  actor_display: string;
  occurred_at: string;
  details: Record<string, unknown>;
  version: number;
}

export interface AlertWorkflowSummary {
  alert: NormalizedAlert;
  status: AlertWorkflowStatus;
  assignee: AlertAssignee | null;
  version: number;
  created_at: string;
  updated_at: string;
  last_activity_at: string;
  note_count: number;
}

export interface AlertWorkflowDetail extends AlertWorkflowSummary {
  notes: AlertWorkflowNote[];
  history: AlertWorkflowHistoryEvent[];
}

export interface AlertWorkflowCounts {
  total: number;
  actionable: number;
  unassigned: number;
  by_status: Record<AlertWorkflowStatus, number>;
}

export interface AlertWorkflowQuery extends AlertQuery {
  statuses?: AlertWorkflowStatus[];
  assignedTo?: string;
  unassigned?: boolean;
  sort?: AlertWorkflowSort;
}

export interface AlertBulkItem {
  alert_id: string;
  expected_version: number;
}

export type AlertBulkRequest =
  | { action: "ACKNOWLEDGE"; items: AlertBulkItem[] }
  | { action: "SET_STATUS"; items: AlertBulkItem[]; status: AlertWorkflowStatus }
  | { action: "ASSIGN"; items: AlertBulkItem[]; assigned_to: string | null };

export interface AlertBulkResponse {
  action: AlertBulkRequest["action"];
  selected_count: number;
  updated_count: number;
  items: AlertWorkflowSummary[];
}
