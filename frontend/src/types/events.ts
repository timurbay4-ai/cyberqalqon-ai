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
  message: string;
  ingestion_source: string;
  related_alert_id?: string | null;
}

export interface SecurityEventDetail extends SecurityEventSummary {
  structured_payload: Record<string, unknown>;
  raw_payload: Record<string, unknown>;
  related_incident_ids: string[];
}

export interface EventQuery {
  startTime?: string;
  endTime?: string;
  sourceIp?: string;
  destinationIp?: string;
  hostname?: string;
  username?: string;
  eventId?: string;
  ruleId?: string;
  eventCategory?: string;
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
    state: "WITHIN_LIMIT" | "AT_LIMIT";
    retention_days: number;
    max_records: number;
    retained_records: number;
    last_run_at?: string | null;
    last_deleted_count: number;
  };
}

export interface SavedEventSearchQuery extends Omit<EventQuery, "cursor" | "limit" | "startTime" | "endTime" | "relatedAlertId"> {
  relativeMinutes?: 15 | 60 | 1440 | 10080 | 43200;
  startTime?: string;
  endTime?: string;
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
