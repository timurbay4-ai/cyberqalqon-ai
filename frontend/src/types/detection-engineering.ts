export type RuleConditionField =
    | "source_type"
    | "hostname"
    | "agent_id"
    | "agent_name"
    | "operating_system"
    | "event_provider"
    | "event_channel"
    | "process_name"
    | "process_path"
    | "command_line"
    | "parent_process_name"
    | "parent_process_path"
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

export type AdvancedAvailabilityStatus =
    | "RECENTLY_OBSERVED"
    | "OBSERVED_STALE"
    | "PREREQUISITE_MISSING"
    | "NO_DATA"
    | "UNKNOWN";

export interface AdvancedDetectionPrerequisite {
    source_types: string[];
    event_codes: string[];
    event_categories: string[];
    required_fields: string[];
    parser_supported: boolean;
    configuration_status: "CONFIGURED" | "NOT_CONFIGURED" | "UNKNOWN";
    configuration_evidence: string;
}

export interface AdvancedDetectionAvailability {
    parser_supported: boolean;
    data_observed: boolean;
    recently_observed: boolean;
    configuration_status: "CONFIGURED" | "NOT_CONFIGURED" | "UNKNOWN";
    status: AdvancedAvailabilityStatus;
    observed_event_count: number;
    latest_event_at: string | null;
    missing_required_fields: string[];
    explanation: string;
}

export interface AdvancedMitreMapping {
    technique_id: string;
    technique_name: string;
    tactic: string;
    relationship: string;
}

export interface AdvancedDetectionRule {
    rule_id: string;
    name: string;
    description: string;
    enabled: false;
    activation_state: "DISABLED_BY_POLICY";
    severity: number;
    prerequisites: AdvancedDetectionPrerequisite;
    conditions: string[];
    grouping_fields: string[];
    window_seconds: number;
    threshold: number;
    deduplication: string;
    mitre_ids: string[];
    mitre_mappings: AdvancedMitreMapping[];
    false_positive_notes: string[];
    evidence_fields: string[];
    analyst_guidance: string[];
    version: string;
    validation_status: "VALIDATED_FOR_DRY_RUN";
    validation_notes: string[];
    availability: AdvancedDetectionAvailability | null;
}

export interface AdvancedRuleDryRunRequest {
    relative_minutes?: 15 | 60 | 1440 | 10080 | 43200;
    start_time?: string;
    end_time?: string;
    max_events: number;
    max_findings: number;
    max_execution_ms?: number;
}

export interface AdvancedDetectionEvidence {
    event_id: string;
    timestamp: string;
    summary: string;
}

export interface AdvancedDetectionFinding {
    finding_id: string;
    rule_id: string;
    severity: number;
    first_event_at: string;
    last_event_at: string;
    group: Record<string, string>;
    matched_event_count: number;
    threshold: number;
    event_ids: string[];
    explanation: string;
    evidence: AdvancedDetectionEvidence[];
    deduplication_key: string;
    mitre_ids: string[];
}

export interface AdvancedRuleDryRunResult {
    rule: AdvancedDetectionRule;
    availability: AdvancedDetectionAvailability;
    start_time: string;
    end_time: string;
    evaluated_event_count: number;
    finding_count: number;
    findings: AdvancedDetectionFinding[];
    execution_ms: number;
    execution_budget_ms: number;
    result_truncated: boolean;
    deterministic_ordering: true;
    side_effects: false;
}

export interface GoldenFixtureResult {
    scenario:
        | "positive"
        | "negative"
        | "boundary"
        | "duplicate"
        | "out_of_order"
        | "missing_field"
        | "cross_host"
        | "cross_account"
        | "false_positive_candidate";
    synthetic_test_data: true;
    applicable: boolean;
    ground_truth: "POSITIVE" | "NEGATIVE" | "UNLABELED";
    expected_finding_count: number;
    actual_finding_count: number;
    expected_evidence_ids: string[];
    actual_evidence_ids: string[];
    evaluator_duplicate_count: number;
    evaluation_ms: number;
    passed: boolean;
    expected_explanation: string;
    grouping_behavior: string;
    deduplication_behavior: string;
}

export interface DetectionQualityMetrics {
    labeled_fixture_count: number;
    unlabeled_fixture_count: number;
    true_positives: number;
    false_positives: number;
    true_negatives: number;
    false_negatives: number;
    precision: number | null;
    recall: number | null;
    false_positive_rate: number | null;
    duplicate_input_count: number;
    duplicate_finding_rate: number;
    missing_field_fixture_passed: boolean;
    event_order_consistent: boolean;
    repeat_evaluation_consistent: boolean;
    evidence_latency_p50_ms: number;
    evidence_latency_p95_ms: number;
    evidence_latency_max_ms: number;
    evaluation_time_p50_ms: number;
    evaluation_time_p95_ms: number;
    evaluation_time_max_ms: number;
}

export interface DetectionQualityReport {
    rule_id: string;
    dataset_version: "m15-golden-v1";
    dataset_label: "SYNTHETIC TEST DATA";
    ground_truth_scope: "LABELED_SYNTHETIC_FIXTURES_ONLY";
    live_ground_truth_available: false;
    enabled: false;
    runtime_activation_state: "DISABLED_BY_POLICY";
    deployment_eligibility: "SHADOW_ONLY";
    fixtures: GoldenFixtureResult[];
    metrics: DetectionQualityMetrics;
    all_applicable_fixtures_passed: boolean;
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
    cqql?: string;
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
