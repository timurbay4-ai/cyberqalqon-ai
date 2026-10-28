import type { AdvancedDetectionFinding, AdvancedDetectionRule } from "./detection-engineering";
import type { SecurityEventDetail, SecurityEventSummary } from "./events";

export type WorkbenchTargetType = "EVENT" | "ALERT" | "INCIDENT" | "CASE" | "CORRELATION_GROUP" | "M11_FINDING" | "SHADOW_FINDING" | "DURABLE_SHADOW_FINDING" | "ENTITY";
export type InvestigationEntityType = "IPV4" | "IPV6" | "HOSTNAME" | "USERNAME" | "AGENT_ID" | "RULE_ID" | "PROCESS_NAME" | "PROCESS_ID" | "FILE_HASH" | "DOMAIN";

export interface WorkbenchTarget {
  target_type: WorkbenchTargetType;
  target_id?: string;
  entity_type?: InvestigationEntityType;
  entity_value?: string;
  rule_id?: string;
  finding_key?: string;
  shadow_revision?: number;
  start_time?: string;
  end_time?: string;
  relative_minutes?: number | null;
  related_limit?: number;
  related_cursor?: string;
  timeline_limit?: number;
  sort?: "oldest" | "newest";
  max_execution_ms?: number;
}

export interface InvestigationEntity {
  entity_type: InvestigationEntityType;
  value: string;
  label: string;
  sensitive: boolean;
  pivot_supported: boolean;
  evidence_field: string;
}

export interface RelatedInvestigationEvent {
  event: SecurityEventSummary;
  relationship_types: string[];
}

export interface InvestigationLink {
  target_type: "ALERT" | "INCIDENT" | "CASE" | "CORRELATION_GROUP";
  target_id: string;
  title: string;
  status?: string;
  severity?: string;
}

export interface InvestigationTimelineItem {
  item_id: string;
  item_type: "SECURITY_EVENT" | "ALERT" | "DETECTION_FINDING" | "INCIDENT_ACTIVITY" | "ANALYST_NOTE" | "CASE_ACTIVITY" | "CASE_COMMENT" | "EVIDENCE_ACTION";
  timestamp: string;
  timestamp_kind: "EVENT_TIME" | "ANALYST_ACTION_TIME";
  timestamp_status: "NORMAL" | "FUTURE";
  title: string;
  source_id: string;
  severity?: number;
  actor_display?: string;
  relationship_types: string[];
  details: Record<string, unknown>;
}

export interface InvestigationIOCMatch {
  indicator_id: string;
  indicator_type: "IPV4" | "IPV6" | "DOMAIN" | "FILE_HASH";
  value: string;
  source: string;
  confidence: number;
  expires_at?: string;
  evidence_field: string;
  caveat: "IOC_MATCH_IS_NOT_PROOF_OF_COMPROMISE";
}

export interface InvestigationCorrelationGroup {
  group_id: string;
  correlation_rule: string;
  classification: string;
  confidence: string;
  grouping_keys: Record<string, string>;
  first_seen: string;
  last_seen: string;
  evidence_count: number;
  explanation: string;
  incident_id: string;
}

export interface InvestigationDetectionContext {
  rule: AdvancedDetectionRule;
  finding: AdvancedDetectionFinding;
  evaluated_event_count: number;
  execution_budget_ms: number;
  source_kind: "HISTORICAL_DRY_RUN" | "SHADOW";
  shadow_run_id?: string;
  side_effects: false;
}

export interface InvestigationWorkbench {
  target_type: WorkbenchTargetType;
  target_label: string;
  primary_event: SecurityEventDetail;
  summary: { observations: string[]; interpretations: string[]; missing_fields: string[] };
  entities: InvestigationEntity[];
  related_events: RelatedInvestigationEvent[];
  links: InvestigationLink[];
  timeline: InvestigationTimelineItem[];
  ioc_matches: InvestigationIOCMatch[];
  correlation_groups: InvestigationCorrelationGroup[];
  detection_context?: InvestigationDetectionContext;
  durable_shadow_context?: import('./shadow-history').FindingDetail;
  query: {
    start_time: string;
    end_time: string;
    related_limit: number;
    related_cursor?: string;
    related_next_cursor?: string;
    timeline_limit: number;
    sort: "oldest" | "newest";
    execution_ms: number;
    related_truncated: boolean;
    schema_version: number;
    unavailable_relationships: string[];
  };
}
