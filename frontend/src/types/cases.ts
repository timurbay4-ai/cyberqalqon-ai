export const CASE_STATUSES = ["OPEN", "TRIAGING", "INVESTIGATING", "WAITING", "RESOLVED", "CLOSED"] as const;
export const CASE_SEVERITIES = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export const CASE_PRIORITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;

export type CaseStatus = (typeof CASE_STATUSES)[number];
export type CaseSeverity = (typeof CASE_SEVERITIES)[number];
export type CasePriority = (typeof CASE_PRIORITIES)[number];
export type CaseSourceType = "MANUAL" | "ALERT" | "INCIDENT";
export type EvidenceReferenceType = "ALERT" | "EVENT" | "INCIDENT";

export interface CaseOwner { analyst_id: string; username: string; display_name: string; }
export interface CaseSla {
  policy: "LOCAL_CASE_SLA_V1";
  response_due_at: string;
  resolution_due_at: string;
  first_response_at: string | null;
  response_state: "PENDING" | "MET" | "OVERDUE" | "NOT_APPLICABLE";
  resolution_state: "PENDING" | "MET" | "OVERDUE" | "NOT_APPLICABLE";
  escalation_state: "NONE" | "RESPONSE_OVERDUE" | "RESOLUTION_OVERDUE";
}
export interface CaseSummary {
  case_id: string; title: string; description: string; severity: CaseSeverity; priority: CasePriority;
  status: CaseStatus; owner: CaseOwner | null; source_type: CaseSourceType; source_id: string | null;
  created_by_display: string; created_at: string; updated_at: string; resolved_at: string | null;
  closed_at: string | null; version: number; alert_count: number; incident_count: number;
  event_count: number; evidence_count: number; comment_count: number; sla: CaseSla;
}
export interface CaseComment {
  comment_id: string; comment_type: "COMMENT" | "HANDOFF"; body: string; author_display: string;
  from_owner_id: string | null; to_owner_id: string | null; created_at: string;
}
export interface CustodyEvent { custody_event_id: string; event_type: "ACQUIRED" | "VERIFIED" | "MISMATCH" | "UNAVAILABLE" | "ANNOTATED"; actor_display: string; occurred_at: string; details: Record<string, unknown>; }
export interface CaseEvidence {
  evidence_ref_id: string; reference_type: EvidenceReferenceType; reference_id: string; source_label: string;
  source_timestamp: string; acquisition_method: "DATABASE_REFERENCE"; digest_algorithm: "SHA-256";
  digest: string; integrity_status: "VERIFIED" | "MISMATCH" | "UNAVAILABLE"; acquired_by_display: string;
  acquired_at: string; last_verified_at: string; annotation: string; version: number; custody: CustodyEvent[];
}
export interface CaseActivity { activity_id: string; activity_type: string; actor_display: string; entity_type: string; entity_id: string; occurred_at: string; details: Record<string, unknown>; }
export interface PlaybookStep {
  step_id: string; template_step_key: string; sequence: number; title: string; description: string;
  step_type: "ACTION" | "EVIDENCE" | "APPROVAL"; status: "PENDING" | "COMPLETED";
  assigned_to: CaseOwner | null; evidence_ref_id: string | null; completion_note: string;
  completed_by_display: string | null; completed_at: string | null; version: number;
}
export interface CasePlaybook {
  playbook_id: string; template_key: string; template_version: number; name: string; status: "ACTIVE" | "COMPLETED";
  created_by_display: string; created_at: string; completed_at: string | null; version: number;
  completed_steps: number; total_steps: number; steps: PlaybookStep[];
}
export interface CaseReportRecord { report_id: string; format: "JSON" | "CSV" | "PDF"; generated_by_display: string; generated_at: string; sha256: string; size_bytes: number; redaction_profile: "CASE_REPORT_V1"; }
export interface CaseDetail extends CaseSummary {
  resolution: string; closure_reason: string; alert_ids: string[]; incident_ids: string[]; event_ids: string[];
  comments: CaseComment[]; evidence: CaseEvidence[]; activity: CaseActivity[]; playbooks: CasePlaybook[];
  report_history: CaseReportRecord[];
}
export interface CaseQuery {
  statuses?: CaseStatus[]; severities?: CaseSeverity[]; priorities?: CasePriority[]; ownerId?: string;
  search?: string; sort?: "newest" | "oldest" | "updated" | "priority"; limit?: number; cursor?: string;
}
export interface CaseCreate {
  title: string; description?: string; severity: CaseSeverity; priority: CasePriority; owner_id?: string | null;
  source_type?: CaseSourceType; source_id?: string | null;
}
export interface CaseStatusUpdate { status: CaseStatus; expected_version: number; resolution?: string; closure_reason?: string; }
export interface CaseAssignmentUpdate { owner_id: string | null; expected_version: number; handoff_note?: string; }
export interface CaseEvidenceCreate { reference_type: EvidenceReferenceType; reference_id: string; annotation?: string; expected_version: number; }
export interface PlaybookTemplateStep { key: string; title: string; description: string; step_type: "ACTION" | "EVIDENCE" | "APPROVAL"; }
export interface PlaybookTemplate { key: string; version: number; name: string; description: string; steps: PlaybookTemplateStep[]; }
export interface CaseAnalyticsCount { name: string; count: number; }
export interface CaseAnalytics {
  generated_at: string; window_days: number; open_cases: number; overdue_response: number; overdue_resolution: number;
  mtta_minutes: number | null; mttr_minutes: number | null; by_severity: CaseAnalyticsCount[]; by_owner: CaseAnalyticsCount[];
  aging_buckets: CaseAnalyticsCount[]; created_trend: CaseAnalyticsCount[]; closed_trend: CaseAnalyticsCount[]; definitions: Record<string, string>;
}
export interface SlaEvaluationResult { evaluated_cases: number; notifications_created: number; generated_at: string; }

export const CASE_TRANSITIONS: Record<CaseStatus, CaseStatus[]> = {
  OPEN: ["TRIAGING"], TRIAGING: ["INVESTIGATING", "WAITING", "RESOLVED"],
  INVESTIGATING: ["TRIAGING", "WAITING", "RESOLVED"], WAITING: ["TRIAGING", "INVESTIGATING", "RESOLVED"],
  RESOLVED: ["INVESTIGATING", "CLOSED"], CLOSED: [],
};
