export type AgentConnectionStatus = "ONLINE" | "DISCONNECTED" | "NEVER_CONNECTED" | "UNKNOWN";
export type AgentEnrollmentStatus = "ENROLLED" | "NEVER_ENROLLED" | "UNKNOWN";
export type AgentStatusAuthority = "WAZUH_API" | "TELEMETRY_EVIDENCE";
export type FreshnessState = "ACTIVE" | "STALE" | "NO_DATA";

export interface AgentTelemetrySource {
  source_type: string;
  ingestion_source: string;
  last_event_at: string;
  last_ingested_at: string;
  event_count: number;
  freshness: FreshnessState;
}

export interface AgentSummary {
  agent_key: string;
  agent_id: string;
  name: string;
  operating_system: string | null;
  os_platform: string | null;
  os_version: string | null;
  agent_version: string | null;
  manager: string | null;
  ip_address: string | null;
  groups: string[];
  service_status: "RUNNING" | "STOPPED" | "UNKNOWN";
  enrollment_status: AgentEnrollmentStatus;
  connection_status: AgentConnectionStatus;
  status_authority: AgentStatusAuthority;
  last_keepalive: string | null;
  disconnected_at: string | null;
  enrolled_at: string | null;
  last_security_event: string | null;
  data_freshness: FreshnessState;
  pipeline_health: "ACTIVE" | "STALE" | "EMPTY";
  observed_at: string;
  cache_expires_at: string | null;
  cache_stale: boolean;
  observed_only: boolean;
}

export interface AgentDetail extends AgentSummary {
  telemetry_sources: AgentTelemetrySource[];
  recent_event_ids: string[];
  related_alert_ids: string[];
  related_incident_ids: string[];
  troubleshooting: string[];
}

export interface AgentHealthRecord {
  history_id: string;
  connection_status: AgentConnectionStatus;
  previous_status: AgentConnectionStatus | null;
  authority: "WAZUH_API";
  observed_at: string;
  details: Record<string, unknown>;
}

export interface AgentHealthResponse {
  agent_key: string;
  status_authority: AgentStatusAuthority;
  items: AgentHealthRecord[];
}

export interface AgentQuery {
  search?: string;
  os?: string;
  connectionStatus?: AgentConnectionStatus;
  version?: string;
  manager?: string;
  sourceType?: string;
  lastSeenMinutes?: number;
  sort?: "name" | "agent_id" | "status" | "last_seen" | "version";
  order?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

export interface AgentListResponse {
  items: AgentSummary[];
  page: { limit: number; offset: number; total: number };
  authoritative_inventory: boolean;
  partial: boolean;
  observation_timestamp: string;
  cache_age_seconds: number | null;
  message: string;
}

export interface WazuhIntegrationStatus {
  state: "AVAILABLE" | "UNAVAILABLE";
  configured: boolean;
  authority: "WAZUH_API";
  reason: string;
  manager_identity: string | null;
  manager_version: string | null;
  manager_health: "HEALTHY" | "DEGRADED" | "UNKNOWN" | null;
  agent_count: number | null;
  rejected_agent_count: number;
  observed_at: string;
  cache_expires_at: string;
  cache_age_seconds: number;
  cache_stale: boolean;
  tls_verification: "SYSTEM_TRUST" | "CUSTOM_CA";
  connectivity_scope: "HTTPS_LOOPBACK";
  read_only: true;
}
