import type { MitreContext } from "./alerts";

export const EVENT_SOURCE_TYPES = [
  "authentication",
  "file_integrity",
  "network",
  "web",
  "windows_event",
  "wazuh_alert",
  "wazuh_archive",
] as const;

export type EventSourceType = typeof EVENT_SOURCE_TYPES[number];
export type EventSort = "newest" | "oldest";

export interface SecurityEventSummary {
  event_id: string;
  source_event_id?: string | null;
  event_code?: string | null;
  timestamp: string;
  ingested_at: string;
  source_type: EventSourceType;
  hostname?: string | null;
  agent_id?: string | null;
  agent_name?: string | null;
  operating_system?: string | null;
  manager_identity?: string | null;
  event_provider?: string | null;
  event_channel?: string | null;
  process_name?: string | null;
  process_path?: string | null;
  command_line?: string | null;
  process_id?: string | null;
  parent_process_name?: string | null;
  parent_process_path?: string | null;
  parent_process_id?: string | null;
  normalization_schema: string;
  source_ip?: string | null;
  destination_ip?: string | null;
  source_port?: number | null;
  destination_port?: number | null;
  username?: string | null;
  event_category?: string | null;
  event_action?: string | null;
  outcome?: string | null;
  rule_id?: string | null;
  severity?: number | null;
  mitre: MitreContext;
  message: string;
  ingestion_source: string;
  related_alert_id?: string | null;
}

export interface SecurityEventDetail extends SecurityEventSummary {
  cuse?: CUSEMetadata | null;
  structured_payload: Record<string, unknown>;
  raw_payload: Record<string, unknown>;
  related_incident_ids: string[];
  related_case_ids: string[];
  raw_evidence_ref: string;
}

export interface CUSEMetadata {
  version: "cuse-v1";
  adapter_version: "m28-v1" | "m34-network-v1";
  source_family: "WINDOWS_EVENTCHANNEL" | "SYSMON" | "LINUX_AUTH" | "SYSLOG" | "JOURNALD" | "WAZUH_GENERIC" | "ZEEK" | "SURICATA";
  normalization_status: "NORMALIZED" | "PARTIAL" | "UNSUPPORTED_SOURCE";
  provenance_status: "PARTIAL" | "UNKNOWN" | "UNPROVEN";
  historical_continuity: "UNPROVEN";
  transport_authenticated: boolean;
  endpoint_identity_verified: false;
  source_event_time: string | null;
  collector_observation_time: string;
  timestamp_basis: "SOURCE_EVENT_TIME" | "COLLECTOR_OBSERVATION_TIME";
  original_event_identity: string | null;
  source_identity_sha256: string;
  content_fingerprint: string;
  idempotency_contract: "LEGACY_RAW_ENVELOPE_SHA256" | "REGISTERED_SOURCE_RECORD_SHA256";
  delivery_identity: string | null;
  source_generation: string | null;
  warnings: string[];
  attributes: Record<string, string | number>;
}

export interface EventQuery {
  startTime?: string;
  endTime?: string;
  sourceIp?: string;
  destinationIp?: string;
  hostname?: string;
  username?: string;
  operatingSystem?: string;
  eventProvider?: string;
  eventChannel?: string;
  processName?: string;
  eventId?: string;
  ruleId?: string;
  eventCategory?: string;
  eventAction?: string;
  outcome?: string;
  severityMin?: number;
  severityMax?: number;
  sourceType?: EventSourceType;
  search?: string;
  relatedAlertId?: string;
  sort?: EventSort;
  limit?: number;
  cursor?: string;
}

export interface NamedCount { name: string; count: number }
export interface TimeSeriesPoint { timestamp: string; count: number }
export interface SeverityCount { severity: string; count: number }

export interface SecurityOverview {
  start_time: string;
  end_time: string;
  total_events: number;
  total_alerts: number;
  events_per_minute: number;
  active_incidents: number;
  reporting_agents: number;
  active_sources: number;
  stale_sources: number;
  database_size_bytes: number;
  alerts_by_severity: SeverityCount[];
  incidents_by_status: NamedCount[];
  events_over_time: TimeSeriesPoint[];
  alerts_over_time: TimeSeriesPoint[];
  top_source_ips: NamedCount[];
  top_hosts: NamedCount[];
  top_destination_hosts: NamedCount[];
  top_rules: NamedCount[];
  top_event_categories: NamedCount[];
  event_sources: NamedCount[];
  latest_high_alerts: Array<{
    alert_id: string;
    timestamp: string;
    rule_id: string;
    severity: number;
    description: string;
    agent_name: string;
  }>;
  ingestion: {
    state: "ACTIVE" | "STALE" | "EMPTY";
    last_event_at?: string | null;
    last_ingested_at?: string | null;
    lag_seconds?: number | null;
  };
  pipeline_activity: Array<{
    component: "wazuh_sender" | "event_shipper";
    state: "ACTIVE" | "STALE" | "EMPTY";
    evidence: "DELIVERY_ACTIVITY";
    last_delivery_at?: string | null;
    delivered_records: number;
  }>;
  retention: {
    state: "WITHIN_LIMIT" | "AT_LIMIT" | "OVER_LIMIT_PROTECTED";
    retention_days: number;
    max_records: number;
    retained_records: number;
    protected_records: number;
    over_limit_records: number;
    usage_percent: number;
    oldest_event_at?: string | null;
    newest_event_at?: string | null;
    last_run_at?: string | null;
    last_deleted_count: number;
  };
}

export interface SavedEventSearchQuery extends Omit<EventQuery, "cursor" | "limit" | "startTime" | "endTime" | "relatedAlertId"> {
  relativeMinutes?: 15 | 60 | 1440 | 10080 | 43200;
  startTime?: string;
  endTime?: string;
  cqql?: string;
}

export interface SavedEventSearch {
  saved_search_id: string;
  name: string;
  query: SavedEventSearchQuery;
  created_at: string;
  updated_at: string;
}

export interface SavedEventSearchCreate {
  name: string;
  query: SavedEventSearchQuery;
}

export interface CQQLSearchRequest {
  query: string;
  start_time: string;
  end_time: string;
  sort?: EventSort;
  limit?: number;
  cursor?: string;
}

export interface CQQLSearchResponse {
  items: SecurityEventSummary[];
  page: {
    limit: number;
    next_cursor: string | null;
    total: null;
    count_mode: "UNKNOWN";
    sort: EventSort;
  };
  metadata: {
    version: "cqql-v1";
    execution_ms: number;
    query_status: "COMPLETE";
    warnings: string[];
    truncated: boolean;
    data_freshness: string | null;
    clause_count: number;
    ast_depth: number;
    fts_used: boolean;
    cost_class: "LOW" | "MODERATE" | "HIGH";
    plan_class: "INDEX_FRIENDLY" | "BOOLEAN_COMPLEX" | "FTS_SELECTIVITY_UNKNOWN" | "RESOURCE_LIMITED" | "UNKNOWN_COST";
    planner_strategy: "DEFAULT" | "TIME_ORDERED_OR" | "TIME_ORDERED_BOOLEAN";
    diagnostic_reasons: Array<"INDEXED_EQUALITY" | "RANGE_COMPARISON" | "BOOLEAN_OR" | "NEGATION_SCAN" | "DERIVED_FIELD" | "UNINDEXED_FIELD" | "FTS_CANDIDATE_MATERIALIZATION" | "TIME_ORDERED_OR" | "TIME_ORDERED_BOOLEAN">;
  };
}

export type CQQLGroupField = "event.provider" | "host.name" | "source.ip" | "event.severity" | "event.code" | "event.category" | "event.source_type" | "event.outcome" | "rule.id";

export interface CQQLAnalyticsRequest {
  query: string;
  start_time: string;
  end_time: string;
  group_by: CQQLGroupField[];
  top_n?: number;
  interval?: "hour" | "day";
}

export interface CQQLAnalyticsResponse {
  version: "cqql-v1";
  query_status: "COMPLETE";
  execution_ms: number;
  completeness: "EXACT_WITHIN_BOUNDED_RANGE";
  sparse_time_series: true;
  matching_events: number;
  groups: Array<{ field: CQQLGroupField; buckets: NamedCount[]; truncated: boolean }>;
  time_series: TimeSeriesPoint[];
  clause_count: number;
  fts_used: boolean;
}

export type CQQLExportField = "timestamp" | "event_id" | "event_code" | "severity" | "source_type" | "hostname" | "source_ip" | "destination_ip" | "username" | "rule_id" | "event_category" | "outcome" | "message";

export interface CQQLExportRequest {
  query: string;
  start_time: string;
  end_time: string;
  sort?: EventSort;
  limit?: number;
  fields?: CQQLExportField[];
}

export interface CQQLFieldDescriptor {
  name: string;
  data_type: "string" | "integer" | "ip" | "mitre" | "text" | "timestamp";
  operators: string[];
  indexed: boolean;
  sensitivity: "standard" | "identity" | "network" | "evidence";
  source: string;
  derived: boolean;
  searchable: boolean;
}

export interface CQQLFieldCatalog {
  version: "cqql-v1";
  fields: CQQLFieldDescriptor[];
  limits: {
    maximum_query_length: number;
    maximum_tokens: number;
    maximum_ast_depth: number;
    maximum_boolean_clauses: number;
    maximum_page_size: number;
    maximum_time_range_days: number;
    execution_deadline_ms: number;
    maximum_concurrent_queries: number;
  };
}
