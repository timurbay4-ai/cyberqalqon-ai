export type RuleConditionField =
    | "source_type"
    | "hostname"
    | "agent_id"
    | "agent_name"
    | "source_ip"
    | "destination_ip"
    | "username"
    | "event_category"
    | "event_action"
    | "outcome"
    | "rule_id"
    | "event_code"
    | "message";
export type RuleConditionOperator = "EQUALS" | "CONTAINS" | "STARTS_WITH";

export interface RuleCondition {
    field: RuleConditionField;
    operator: RuleConditionOperator;
    value: string;
}
export type RuleDraftStatus =
    "DRAFT" | "VALIDATED" | "TESTED" | "READY_FOR_MANUAL_DEPLOYMENT";

export interface RuleDraftDefinition {
    name: string;
    description: string;
    severity: number;
    source_type: string;
    mitre_ids: string[];
    conditions: RuleCondition[];
    documentation: string;
}

export interface RuleDraft extends RuleDraftDefinition {
    draft_id: string;
    status: RuleDraftStatus;
    version: number;
    owner_analyst_id: string | null;
    owner_display: string;
    last_tested_at: string | null;
    last_test_match_count: number | null;
    last_test_execution_ms: number | null;
    created_at: string;
    updated_at: string;
}

export interface RuleDraftCreate extends RuleDraftDefinition {
    change_summary: string;
}
export interface RuleDraftUpdate extends RuleDraftCreate {
    expected_version: number;
}

export interface RuleDraftVersion {
    version_id: string;
    draft_id: string;
    version_number: number;
    snapshot: Record<string, unknown>;
    change_summary: string;
    actor_display: string;
    created_at: string;
}

export interface RuleValidationResult {
    draft: RuleDraft;
    valid: boolean;
    errors: string[];
    warnings: string[];
}
export interface RuleDryRunRequest {
    expected_version: number;
    relative_minutes?: 15 | 60 | 1440 | 10080 | 43200;
    start_time?: string;
    end_time?: string;
    max_events: number;
}
export interface RuleDryRunResult {
    draft: RuleDraft;
    start_time: string;
    end_time: string;
    evaluated_event_count: number;
    match_count: number;
    matched_event_ids: string[];
    execution_ms: number;
    result_ids_truncated: boolean;
    side_effects: false;
}

export interface DeploymentConfirmationResult {
    draft: RuleDraft;
    live_wazuh_modified: false;
    deployment_mode: "MANUAL_REVIEW_ONLY";
    message: string;
}

export interface TechniqueCoverage {
    technique_id: string;
    rule_ids: string[];
    mapped_detection_count: number;
    enabled_detection_count: number;
    triggered_detection_count: number;
    tested_detection_count: number;
    alert_count: number;
    sources: string[];
    coverage_state: "MAPPED_ONLY" | "ENABLED_NOT_TRIGGERED" | "TRIGGERED";
}

export interface DetectionCoverage {
    techniques: TechniqueCoverage[];
    mapped_rule_count: number;
    unmapped_rule_count: number;
    validation_gap_count: number;
}

export interface FalsePositiveRuleMetric {
    rule_id: string;
    total_alerts: number;
    dispositioned_alerts: number;
    false_positive_count: number;
    false_positive_rate: number | null;
    tuning_candidate: boolean;
}

export interface NamedMetric {
    name: string;
    count: number;
}
export interface AnalyticsPoint {
    bucket: string;
    count: number;
}
export interface AnalystDispositionMetric {
    analyst: string;
    resolved_count: number;
    false_positive_count: number;
    total_count: number;
}
export interface DetectionAnalytics {
    start_time: string;
    end_time: string;
    alert_trend: AnalyticsPoint[];
    false_positive_trend: AnalyticsPoint[];
    top_rules: NamedMetric[];
    top_source_ips: NamedMetric[];
    top_hosts: NamedMetric[];
    mitre_distribution: NamedMetric[];
    ioc_matches: NamedMetric[];
    analyst_dispositions: AnalystDispositionMetric[];
    false_positive_rules: FalsePositiveRuleMetric[];
    suggested_tuning_candidates: string[];
}

export interface ThreatHuntQuery {
    relativeMinutes?: 15 | 60 | 1440 | 10080 | 43200;
    startTime?: string;
    endTime?: string;
    ip?: string;
    hostname?: string;
    username?: string;
    eventCategory?: string;
    ruleId?: string;
    mitreId?: string;
    search?: string;
    sort?: "newest" | "oldest";
    limit?: number;
    cursor?: string;
}

export interface HuntEvent {
    event_id: string;
    timestamp: string;
    source_type: string;
    hostname: string | null;
    source_ip: string | null;
    destination_ip: string | null;
    username: string | null;
    event_category: string | null;
    rule_id: string | null;
    severity: number | null;
    message: string;
    related_alert_id: string | null;
    related_incident_ids: string[];
}

export interface ThreatHuntPage {
    items: HuntEvent[];
    total: number;
    limit: number;
    next_cursor: string | null;
    start_time: string;
    end_time: string;
}

export interface SavedHunt {
    saved_hunt_id: string;
    name: string;
    query: ThreatHuntQuery;
    created_at: string;
    updated_at: string;
}

export type IndicatorType = "IPV4" | "IPV6" | "DOMAIN" | "FILE_HASH";
export interface IOCDefinition {
    indicator_type: IndicatorType;
    value: string;
    source: string;
    confidence: number;
    description: string;
    expires_at?: string | null;
}

export interface IOCIndicator extends IOCDefinition {
    indicator_id: string;
    hash_algorithm: "MD5" | "SHA1" | "SHA256" | null;
    expires_at: string | null;
    is_active: boolean;
    expired: boolean;
    version: number;
    created_at: string;
    updated_at: string;
}

export interface IOCMatch {
    indicator_id: string;
    indicator_type: IndicatorType;
    value: string;
    event_id: string;
    event_timestamp: string;
    matched_field: string;
}

export interface IOCMatchSummary {
    start_time: string;
    end_time: string;
    total_matches: number;
    matches: IOCMatch[];
    truncated: boolean;
}
