import type {
  CaseActivity,
  CaseAnalytics,
  CaseAnalyticsCount,
  CaseComment,
  CaseDetail,
  CaseEvidence,
  CaseOwner,
  CasePlaybook,
  CaseReportRecord,
  CaseSla,
  CaseSummary,
  CustodyEvent,
  PlaybookStep,
  PlaybookTemplate,
} from "../types/cases";
import type { CaseListResponse } from "../types/api";

export class CaseContractError extends Error {
  constructor(path: string) { super(`Backend response did not match the expected case contract at ${path}.`); this.name = "CaseContractError"; }
}
function objectAt(value: unknown, path: string): Record<string, unknown> { if (!value || typeof value !== "object" || Array.isArray(value)) throw new CaseContractError(path); return value as Record<string, unknown>; }
function stringAt(value: unknown, path: string): string { if (typeof value !== "string") throw new CaseContractError(path); return value; }
function dateAt(value: unknown, path: string): string { const valueString = stringAt(value, path); if (Number.isNaN(Date.parse(valueString))) throw new CaseContractError(path); return valueString; }
function integerAt(value: unknown, path: string): number { if (!Number.isInteger(value) || (value as number) < 0) throw new CaseContractError(path); return value as number; }
function nullableStringAt(value: unknown, path: string): string | null { return value == null ? null : stringAt(value, path); }
function nullableDateAt(value: unknown, path: string): string | null { return value == null ? null : dateAt(value, path); }
function enumAt<const T extends readonly string[]>(value: unknown, allowed: T, path: string): T[number] { const text = stringAt(value, path); if (!(allowed as readonly string[]).includes(text)) throw new CaseContractError(path); return text as T[number]; }
function arrayAt(value: unknown, path: string): unknown[] { if (!Array.isArray(value)) throw new CaseContractError(path); return value; }
function recordAt(value: unknown, path: string): Record<string, unknown> { return objectAt(value, path); }
function ownerAt(value: unknown, path: string): CaseOwner | null { if (value == null) return null; const owner = objectAt(value, path); return { analyst_id: stringAt(owner.analyst_id, `${path}.analyst_id`), username: stringAt(owner.username, `${path}.username`), display_name: stringAt(owner.display_name, `${path}.display_name`) }; }
function slaAt(value: unknown, path: string): CaseSla { const sla = objectAt(value, path); return {
  policy: enumAt(sla.policy, ["LOCAL_CASE_SLA_V1"] as const, `${path}.policy`),
  response_due_at: dateAt(sla.response_due_at, `${path}.response_due_at`), resolution_due_at: dateAt(sla.resolution_due_at, `${path}.resolution_due_at`),
  first_response_at: nullableDateAt(sla.first_response_at, `${path}.first_response_at`),
  response_state: enumAt(sla.response_state, ["PENDING", "MET", "OVERDUE", "NOT_APPLICABLE"] as const, `${path}.response_state`),
  resolution_state: enumAt(sla.resolution_state, ["PENDING", "MET", "OVERDUE", "NOT_APPLICABLE"] as const, `${path}.resolution_state`),
  escalation_state: enumAt(sla.escalation_state, ["NONE", "RESPONSE_OVERDUE", "RESOLUTION_OVERDUE"] as const, `${path}.escalation_state`),
}; }
function summaryAt(value: unknown, path: string): CaseSummary { const item = objectAt(value, path); return {
  case_id: stringAt(item.case_id, `${path}.case_id`), title: stringAt(item.title, `${path}.title`), description: stringAt(item.description, `${path}.description`),
  severity: enumAt(item.severity, ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const, `${path}.severity`),
  priority: enumAt(item.priority, ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const, `${path}.priority`),
  status: enumAt(item.status, ["OPEN", "TRIAGING", "INVESTIGATING", "WAITING", "RESOLVED", "CLOSED"] as const, `${path}.status`),
  owner: ownerAt(item.owner, `${path}.owner`), source_type: enumAt(item.source_type, ["MANUAL", "ALERT", "INCIDENT"] as const, `${path}.source_type`),
  source_id: nullableStringAt(item.source_id, `${path}.source_id`), created_by_display: stringAt(item.created_by_display, `${path}.created_by_display`),
  created_at: dateAt(item.created_at, `${path}.created_at`), updated_at: dateAt(item.updated_at, `${path}.updated_at`),
  resolved_at: nullableDateAt(item.resolved_at, `${path}.resolved_at`), closed_at: nullableDateAt(item.closed_at, `${path}.closed_at`),
  version: integerAt(item.version, `${path}.version`), alert_count: integerAt(item.alert_count, `${path}.alert_count`),
  incident_count: integerAt(item.incident_count, `${path}.incident_count`), event_count: integerAt(item.event_count, `${path}.event_count`),
  evidence_count: integerAt(item.evidence_count, `${path}.evidence_count`), comment_count: integerAt(item.comment_count, `${path}.comment_count`), sla: slaAt(item.sla, `${path}.sla`),
}; }
function commentAt(value: unknown, path: string): CaseComment { const item = objectAt(value, path); return {
  comment_id: stringAt(item.comment_id, `${path}.comment_id`), comment_type: enumAt(item.comment_type, ["COMMENT", "HANDOFF"] as const, `${path}.comment_type`),
  body: stringAt(item.body, `${path}.body`), author_display: stringAt(item.author_display, `${path}.author_display`),
  from_owner_id: nullableStringAt(item.from_owner_id, `${path}.from_owner_id`), to_owner_id: nullableStringAt(item.to_owner_id, `${path}.to_owner_id`),
  created_at: dateAt(item.created_at, `${path}.created_at`),
}; }
function custodyAt(value: unknown, path: string): CustodyEvent { const item = objectAt(value, path); return {
  custody_event_id: stringAt(item.custody_event_id, `${path}.custody_event_id`),
  event_type: enumAt(item.event_type, ["ACQUIRED", "VERIFIED", "MISMATCH", "UNAVAILABLE", "ANNOTATED"] as const, `${path}.event_type`),
  actor_display: stringAt(item.actor_display, `${path}.actor_display`), occurred_at: dateAt(item.occurred_at, `${path}.occurred_at`), details: recordAt(item.details, `${path}.details`),
}; }
function evidenceAt(value: unknown, path: string): CaseEvidence { const item = objectAt(value, path); return {
  evidence_ref_id: stringAt(item.evidence_ref_id, `${path}.evidence_ref_id`), reference_type: enumAt(item.reference_type, ["ALERT", "EVENT", "INCIDENT"] as const, `${path}.reference_type`),
  reference_id: stringAt(item.reference_id, `${path}.reference_id`), source_label: stringAt(item.source_label, `${path}.source_label`), source_timestamp: dateAt(item.source_timestamp, `${path}.source_timestamp`),
  acquisition_method: enumAt(item.acquisition_method, ["DATABASE_REFERENCE"] as const, `${path}.acquisition_method`), digest_algorithm: enumAt(item.digest_algorithm, ["SHA-256"] as const, `${path}.digest_algorithm`),
  digest: stringAt(item.digest, `${path}.digest`), integrity_status: enumAt(item.integrity_status, ["VERIFIED", "MISMATCH", "UNAVAILABLE"] as const, `${path}.integrity_status`),
  acquired_by_display: stringAt(item.acquired_by_display, `${path}.acquired_by_display`), acquired_at: dateAt(item.acquired_at, `${path}.acquired_at`),
  last_verified_at: dateAt(item.last_verified_at, `${path}.last_verified_at`), annotation: stringAt(item.annotation, `${path}.annotation`), version: integerAt(item.version, `${path}.version`),
  custody: arrayAt(item.custody, `${path}.custody`).map((entry, index) => custodyAt(entry, `${path}.custody[${index}]`)),
}; }
function activityAt(value: unknown, path: string): CaseActivity { const item = objectAt(value, path); return {
  activity_id: stringAt(item.activity_id, `${path}.activity_id`), activity_type: stringAt(item.activity_type, `${path}.activity_type`), actor_display: stringAt(item.actor_display, `${path}.actor_display`),
  entity_type: stringAt(item.entity_type, `${path}.entity_type`), entity_id: stringAt(item.entity_id, `${path}.entity_id`), occurred_at: dateAt(item.occurred_at, `${path}.occurred_at`), details: recordAt(item.details, `${path}.details`),
}; }
function stepAt(value: unknown, path: string): PlaybookStep { const item = objectAt(value, path); return {
  step_id: stringAt(item.step_id, `${path}.step_id`), template_step_key: stringAt(item.template_step_key, `${path}.template_step_key`), sequence: integerAt(item.sequence, `${path}.sequence`),
  title: stringAt(item.title, `${path}.title`), description: stringAt(item.description, `${path}.description`), step_type: enumAt(item.step_type, ["ACTION", "EVIDENCE", "APPROVAL"] as const, `${path}.step_type`),
  status: enumAt(item.status, ["PENDING", "COMPLETED"] as const, `${path}.status`), assigned_to: ownerAt(item.assigned_to, `${path}.assigned_to`), evidence_ref_id: nullableStringAt(item.evidence_ref_id, `${path}.evidence_ref_id`),
  completion_note: stringAt(item.completion_note, `${path}.completion_note`), completed_by_display: nullableStringAt(item.completed_by_display, `${path}.completed_by_display`),
  completed_at: nullableDateAt(item.completed_at, `${path}.completed_at`), version: integerAt(item.version, `${path}.version`),
}; }
function playbookAt(value: unknown, path: string): CasePlaybook { const item = objectAt(value, path); return {
  playbook_id: stringAt(item.playbook_id, `${path}.playbook_id`), template_key: stringAt(item.template_key, `${path}.template_key`), template_version: integerAt(item.template_version, `${path}.template_version`),
  name: stringAt(item.name, `${path}.name`), status: enumAt(item.status, ["ACTIVE", "COMPLETED"] as const, `${path}.status`), created_by_display: stringAt(item.created_by_display, `${path}.created_by_display`),
  created_at: dateAt(item.created_at, `${path}.created_at`), completed_at: nullableDateAt(item.completed_at, `${path}.completed_at`), version: integerAt(item.version, `${path}.version`),
  completed_steps: integerAt(item.completed_steps, `${path}.completed_steps`), total_steps: integerAt(item.total_steps, `${path}.total_steps`), steps: arrayAt(item.steps, `${path}.steps`).map((step, index) => stepAt(step, `${path}.steps[${index}]`)),
}; }
function reportAt(value: unknown, path: string): CaseReportRecord { const item = objectAt(value, path); return {
  report_id: stringAt(item.report_id, `${path}.report_id`), format: enumAt(item.format, ["JSON", "CSV", "PDF"] as const, `${path}.format`), generated_by_display: stringAt(item.generated_by_display, `${path}.generated_by_display`),
  generated_at: dateAt(item.generated_at, `${path}.generated_at`), sha256: stringAt(item.sha256, `${path}.sha256`), size_bytes: integerAt(item.size_bytes, `${path}.size_bytes`), redaction_profile: enumAt(item.redaction_profile, ["CASE_REPORT_V1"] as const, `${path}.redaction_profile`),
}; }

export function parseCaseDetail(value: unknown): CaseDetail { const item = objectAt(value, "case"); return {
  ...summaryAt(item, "case"), resolution: stringAt(item.resolution, "case.resolution"), closure_reason: stringAt(item.closure_reason, "case.closure_reason"),
  alert_ids: arrayAt(item.alert_ids, "case.alert_ids").map((entry, index) => stringAt(entry, `case.alert_ids[${index}]`)),
  incident_ids: arrayAt(item.incident_ids, "case.incident_ids").map((entry, index) => stringAt(entry, `case.incident_ids[${index}]`)),
  event_ids: arrayAt(item.event_ids, "case.event_ids").map((entry, index) => stringAt(entry, `case.event_ids[${index}]`)),
  comments: arrayAt(item.comments, "case.comments").map((entry, index) => commentAt(entry, `case.comments[${index}]`)),
  evidence: arrayAt(item.evidence, "case.evidence").map((entry, index) => evidenceAt(entry, `case.evidence[${index}]`)),
  activity: arrayAt(item.activity, "case.activity").map((entry, index) => activityAt(entry, `case.activity[${index}]`)),
  playbooks: arrayAt(item.playbooks, "case.playbooks").map((entry, index) => playbookAt(entry, `case.playbooks[${index}]`)),
  report_history: arrayAt(item.report_history, "case.report_history").map((entry, index) => reportAt(entry, `case.report_history[${index}]`)),
}; }
export function parseCaseList(value: unknown): CaseListResponse { const page = objectAt(value, "cases"); const cursor = page.next_cursor; if (cursor !== null && typeof cursor !== "string") throw new CaseContractError("cases.next_cursor"); return {
  items: arrayAt(page.items, "cases.items").map((entry, index) => summaryAt(entry, `cases.items[${index}]`)), limit: integerAt(page.limit, "cases.limit"), total: integerAt(page.total, "cases.total"),
  next_cursor: cursor, sort: enumAt(page.sort, ["newest", "oldest", "updated", "priority"] as const, "cases.sort"),
}; }
export function parsePlaybookTemplates(value: unknown): PlaybookTemplate[] { return arrayAt(value, "playbook_templates").map((entry, index) => { const path = `playbook_templates[${index}]`; const item = objectAt(entry, path); return {
  key: stringAt(item.key, `${path}.key`), version: integerAt(item.version, `${path}.version`), name: stringAt(item.name, `${path}.name`), description: stringAt(item.description, `${path}.description`),
  steps: arrayAt(item.steps, `${path}.steps`).map((step, stepIndex) => { const stepPath = `${path}.steps[${stepIndex}]`; const stepItem = objectAt(step, stepPath); return { key: stringAt(stepItem.key, `${stepPath}.key`), title: stringAt(stepItem.title, `${stepPath}.title`), description: stringAt(stepItem.description, `${stepPath}.description`), step_type: enumAt(stepItem.step_type, ["ACTION", "EVIDENCE", "APPROVAL"] as const, `${stepPath}.step_type`) }; }),
}; }); }
function countAt(value: unknown, path: string): CaseAnalyticsCount { const item = objectAt(value, path); return { name: stringAt(item.name, `${path}.name`), count: integerAt(item.count, `${path}.count`) }; }
export function parseCaseAnalytics(value: unknown): CaseAnalytics { const item = objectAt(value, "case_analytics"); const optionalNumber = (candidate: unknown, path: string) => { if (candidate == null) return null; if (typeof candidate !== "number" || !Number.isFinite(candidate) || candidate < 0) throw new CaseContractError(path); return candidate; }; return {
  generated_at: dateAt(item.generated_at, "case_analytics.generated_at"), window_days: integerAt(item.window_days, "case_analytics.window_days"), open_cases: integerAt(item.open_cases, "case_analytics.open_cases"),
  overdue_response: integerAt(item.overdue_response, "case_analytics.overdue_response"), overdue_resolution: integerAt(item.overdue_resolution, "case_analytics.overdue_resolution"),
  mtta_minutes: optionalNumber(item.mtta_minutes, "case_analytics.mtta_minutes"), mttr_minutes: optionalNumber(item.mttr_minutes, "case_analytics.mttr_minutes"),
  by_severity: arrayAt(item.by_severity, "case_analytics.by_severity").map((entry, index) => countAt(entry, `case_analytics.by_severity[${index}]`)),
  by_owner: arrayAt(item.by_owner, "case_analytics.by_owner").map((entry, index) => countAt(entry, `case_analytics.by_owner[${index}]`)),
  aging_buckets: arrayAt(item.aging_buckets, "case_analytics.aging_buckets").map((entry, index) => countAt(entry, `case_analytics.aging_buckets[${index}]`)),
  created_trend: arrayAt(item.created_trend, "case_analytics.created_trend").map((entry, index) => countAt(entry, `case_analytics.created_trend[${index}]`)), definitions: recordAt(item.definitions, "case_analytics.definitions") as Record<string, string>,
  closed_trend: arrayAt(item.closed_trend, "case_analytics.closed_trend").map((entry, index) => countAt(entry, `case_analytics.closed_trend[${index}]`)),
}; }
