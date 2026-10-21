import type { AdvancedDetectionFinding } from "./detection-engineering";

export type DetectionLifecycleState =
    | "DRAFT"
    | "VALIDATED"
    | "TESTED"
    | "SHADOW_READY"
    | "CANARY_READY"
    | "ACTIVE"
    | "PAUSED"
    | "ROLLED_BACK"
    | "DISABLED_BY_POLICY";
export type TelemetryReadinessStatus =
    | "READY"
    | "PARTIAL"
    | "UNKNOWN"
    | "UNAVAILABLE"
    | "FAILED";

export interface DetectionRuleLifecycle {
    rule_id: string;
    configuration_state: DetectionLifecycleState;
    validation_state: "NOT_VALIDATED" | "VALID" | "INVALID";
    deployment_eligibility:
        | "BLOCKED"
        | "SHADOW_ONLY"
        | "CANARY_REVIEW_REQUIRED";
    runtime_activation_state: "DISABLED_BY_POLICY";
    telemetry_status: TelemetryReadinessStatus;
    active_configuration_version: number;
    state_version: number;
    updated_at: string;
    updated_by: string;
    inactive_reason: string;
}

export interface SafeExclusion {
    field: "hostname" | "username" | "source_ip" | "process_name";
    operator: "EQUALS" | "STARTS_WITH";
    value: string;
}
export interface DetectionEvaluationLimits {
    max_events: number;
    max_findings: number;
    max_execution_ms: number;
}
export interface DetectionConfigurationDefinition {
    threshold_count: number;
    time_window_seconds: number;
    severity: number;
    supported_event_sources: string[];
    required_normalized_fields: string[];
    entity_grouping: string[];
    safe_exclusions: SafeExclusion[];
    evaluation_limits: DetectionEvaluationLimits;
    state_expiration_seconds: number;
    state_schema_version: 1;
}
export interface DetectionConfigurationVersion
    extends DetectionConfigurationDefinition {
    config_id: string;
    rule_id: string;
    version: number;
    lifecycle_state: DetectionLifecycleState;
    author_id: string | null;
    author_display: string;
    change_reason: string;
    created_at: string;
    validation_results: string[];
}

export interface TelemetryPrerequisiteEvidence {
    rule_id: string;
    required_sources: string[];
    required_event_codes: string[];
    required_categories: string[];
    required_fields: string[];
    latest_observed_event: string | null;
    source_freshness_seconds: number | null;
    normalization_compatible: boolean;
    status: TelemetryReadinessStatus;
    missing_prerequisites: string[];
    authoritative_evidence_reference: string;
    explanation: string;
}

export interface DetectionDiagnostics {
    rule_id: string;
    evaluation_count: number;
    average_duration_ms: number;
    rule_match_count: number;
    finding_count: number;
    duplicate_event_count: number;
    skipped_event_count: number;
    missing_field_count: number;
    evaluation_timeout_count: number;
    state_recovery_count: number;
    configuration_validation_failure_count: number;
    truncation_count: number;
    last_successful_evaluation: string | null;
    last_failed_evaluation: string | null;
    evaluated_event_range_start: string | null;
    evaluated_event_range_end: string | null;
    source_freshness: string | null;
}

export interface ShadowRun {
    run_id: string;
    rule_id: string;
    configuration_version: number;
    status: "RUNNING" | "COMPLETED" | "FAILED";
    started_at: string;
    completed_at: string | null;
    start_time: string;
    end_time: string;
    operator_display: string;
    source_availability: TelemetryReadinessStatus;
    evaluated_event_count: number;
    match_count: number;
    duplicate_count: number;
    missing_field_count: number;
    execution_ms: number;
    truncated: boolean;
    outcome: string;
    error_code: string | null;
    resource_measurements: Record<string, string | number | boolean | null>;
    side_effects: false;
}
export interface ShadowFinding {
    shadow_finding_id: string;
    run_id: string;
    rule_id: string;
    finding: AdvancedDetectionFinding;
    created_at: string;
    namespace: "SHADOW";
    production_alert_id: null;
    production_incident_id: null;
    production_case_id: null;
}
export interface ShadowRunDetail {
    run: ShadowRun;
    findings: ShadowFinding[];
}

export interface TuningCandidateResult {
    candidate: { threshold_count: number; time_window_seconds: number };
    evaluated_event_count: number;
    finding_count: number;
    duplicate_count: number;
    missing_field_count: number;
    findings_by_source: Array<{ entity: string; count: number }>;
    findings_by_host: Array<{ entity: string; count: number }>;
    findings_by_user: Array<{ entity: string; count: number }>;
    repeated_finding_count: number;
    execution_ms: number;
    truncated: boolean;
}
export interface DetectionTuningComparison {
    rule_id: string;
    start_time: string;
    end_time: string;
    results: TuningCandidateResult[];
    interpretation: string;
    side_effects: false;
}

export interface CanarySafetyStatus {
    rule_id: string;
    prerequisites_validated: boolean;
    historical_evaluation_passed: boolean;
    configuration_reviewed: boolean;
    resource_budget_reviewed: boolean;
    false_positive_baseline_measured: boolean;
    version_locked: boolean;
    target_scope_selected: false;
    operator_approval_recorded: false;
    activation_path_enabled: false;
    runtime_activation_state: "DISABLED_BY_POLICY";
    blockers: string[];
}
