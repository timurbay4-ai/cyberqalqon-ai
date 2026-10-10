export type OperationalState = "HEALTHY" | "DEGRADED" | "UNAVAILABLE" | "UNKNOWN";
export type OperationalAuthority = "WAZUH_API" | "OS_SERVICE_MANAGER" | "DURABLE_SENDER_STATE" | "DURABLE_SHIPPER_STATE" | "APPLICATION_DATABASE";

export interface OperationalComponent {
  component_key: string;
  component_kind: "manager" | "wazuh_api" | "sender" | "event_shipper" | "windows_agent" | "database";
  state: OperationalState;
  authority: OperationalAuthority;
  summary: string;
  metrics: Record<string, unknown>;
  last_error: string | null;
  observed_at: string;
  first_observed_at: string;
  updated_at: string;
  version: number;
}

export interface OperationalEvent {
  event_id: string;
  component_key: string;
  event_type: "ISSUE" | "RECOVERY" | "STATUS_CHANGE";
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  previous_state: OperationalState | null;
  current_state: OperationalState;
  authority: OperationalAuthority;
  summary: string;
  details: Record<string, unknown>;
  occurred_at: string;
}

export interface OperationalOverview {
  generated_at: string;
  snapshot_collected_at: string | null;
  snapshot_age_seconds: number | null;
  components: OperationalComponent[];
  recent_events: OperationalEvent[];
  data_quality: {
    total_events: number;
    raw_evidence_records: number;
    missing_hostname: number;
    missing_username: number;
    missing_rule_id: number;
    duplicate_events: number | null;
    malformed_events: number | null;
    oversized_events: number | null;
    delivery_rejected: number | null;
    evidence: "APPLICATION_DATABASE_AND_DURABLE_SHIPPER_STATE";
  };
  wazuh_inventory: {
    state: "AVAILABLE" | "UNAVAILABLE";
    authority: "WAZUH_API";
    reason: string;
    manager_identity: string | null;
    agent_count: number | null;
  };
}
