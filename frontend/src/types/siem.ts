export type HealthState = "ACTIVE" | "STALE";

export interface LogSourceSummary {
    source_name: string;
    source_type: string;
    hostname: string | null;
    agent_id: string | null;
    agent_name: string | null;
    last_event_at: string;
    last_ingested_at: string;
    ingestion_lag_seconds: number;
    event_count: number;
    source_health: HealthState;
    agent_status: "UNKNOWN";
    collection_method: string;
    pipeline_health: "ACTIVE" | "STALE" | "EMPTY";
    pipeline_evidence: "PERSISTED_DELIVERY_ACTIVITY";
    queue_depth: number | null;
    archive_cursor_lag_bytes: number | null;
    data_availability: "AVAILABLE" | "NO_DATA";
    last_error: string | null;
}

export interface HostSummary {
    hostname: string;
    agent_id: string | null;
    agent_name: string | null;
    platform: "WINDOWS" | "LINUX" | "UNKNOWN";
    agent_status: "UNKNOWN";
    source_health: HealthState;
    last_seen: string;
    alert_count: number;
    event_count: number;
    recent_detections: string[];
}

export interface DetectionRuleSummary {
    rule_id: string;
    name: string;
    description: string;
    severity: number | null;
    source_type: string;
    mitre_ids: string[];
    last_triggered: string | null;
    alert_count: number;
    correlation_relationship: string | null;
    owner: string | null;
    documentation: string | null;
    rule_version: string | null;
    version_authority: "AUTHORITATIVE" | "UNAVAILABLE";
    enabled_state: "ENABLED" | "DISABLED" | "UNKNOWN";
    enabled_evidence:
        "APPLICATION_SETTING" | "WAZUH_API_UNAVAILABLE" | "OBSERVED_ALERT_ONLY";
    tested_state: "TESTED" | "NOT_RECORDED";
    management_mode: "READ_ONLY_WAZUH" | "LOCAL_CORRELATION";
    editable: false;
}

export interface ReportCount {
    name: string;
    count: number;
}

export interface SecurityActivityReport {
    start_time: string;
    end_time: string;
    generated_at: string;
    filters: {
        severity_min: number | null;
        severity_max: number | null;
        host: string | null;
        rule_id: string | null;
    };
    total_events: number;
    total_alerts: number;
    total_incidents: number;
    event_sources: ReportCount[];
    alert_severities: ReportCount[];
    top_rules: ReportCount[];
    host_activity: ReportCount[];
    authentication_failures: number;
    file_integrity_events: number;
}

export interface ReportQuery {
    startTime?: string;
    endTime?: string;
    severityMin?: number;
    severityMax?: number;
    host?: string;
    ruleId?: string;
}
