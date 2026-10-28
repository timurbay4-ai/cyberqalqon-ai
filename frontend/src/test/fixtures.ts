import { vi } from "vitest";
import m34Contract from './m34-api-contract.json';
import {parseSourceCoverage} from '../api/collection-contract';

import type { AlertWorkflowDetail, NormalizedAlert } from "../types/alerts";
import type { AnalystPrincipal, SessionResponse } from "../types/auth";
import type {
    AlertListResponse,
    BackendApi,
    CaseListResponse,
    IncidentListResponse,
} from "../types/api";
import type { IncidentDetail } from "../types/incidents";
import type { AIAnalysisRecord, AIStatus } from "../types/ai";
import type { SecurityEventDetail, SecurityOverview } from "../types/events";
import type {
    DetectionRuleSummary,
    HostSummary,
    LogSourceSummary,
    SecurityActivityReport,
} from "../types/siem";
import type {
    InvestigationTimelinePage,
    InvestigationWorkspace,
} from "../types/investigations";
import { DEFAULT_PREFERENCES } from "../types/preferences";
import type {
    AdvancedDetectionRule,
    DetectionAnalytics,
    DetectionCoverage,
    DetectionQualityReport,
    IOCIndicator,
    IOCMatchSummary,
    RuleDraft,
    SavedHunt,
    ThreatHuntPage,
} from "../types/detection-engineering";
import type { OperationalOverview } from "../types/operations";
import type {
    AgentDetail,
    AgentHealthResponse,
    AgentListResponse,
    WazuhIntegrationStatus,
} from "../types/agents";
import type { CaseAnalytics, CaseDetail, PlaybookTemplate } from "../types/cases";
import type { InvestigationWorkbench } from "../types/investigation-workbench";
import type {
    CanarySafetyStatus,
    DetectionConfigurationVersion,
    DetectionDiagnostics,
    DetectionRuleLifecycle,
    DetectionTuningComparison,
    ShadowRun,
    ShadowRunDetail,
    TelemetryPrerequisiteEvidence,
} from "../types/detection-readiness";

export const SAMPLE_ALERT: NormalizedAlert = {
    alert_id: "alert-001",
    timestamp: "2026-10-06T10:00:00Z",
    agent: { id: "001", name: "<img src=x onerror=attack()>", ip: null },
    rule: {
        id: "5712",
        level: 10,
        description: "<script>attack()</script>",
        groups: [],
    },
    mitre: { ids: [], tactics: [], techniques: [] },
    source: { ip: "2001:db8::10", port: 22 },
    destination: null,
    user: null,
    location: null,
    decoder_name: null,
};

export const SAMPLE_INCIDENT: IncidentDetail = {
    incident_id: "INC-001",
    title: "<script>incidentAttack()</script>",
    description: "Investigate without executing markup.",
    severity: "HIGH",
    status: "NEW",
    assigned_to: null,
    created_at: "2026-10-06T10:00:00Z",
    updated_at: "2026-10-06T10:00:00Z",
    alert_count: 1,
    auto_correlated: false,
    correlation_rule: null,
    classification: null,
    alert_ids: ["alert-001"],
    notes: [
        {
            note_id: "NOTE-1",
            body: "<img src=x onerror=attack()>",
            author: "Analyst One (analyst-1)",
            author_id: "USR-1",
            created_at: "2026-10-06T10:01:00Z",
        },
    ],
    history: [
        {
            event_id: "EVT-1",
            event_type: "CREATED",
            actor: "Analyst One (analyst-1)",
            actor_id: "USR-1",
            occurred_at: "2026-10-06T10:00:00Z",
            details: { status: "NEW" },
        },
    ],
    correlation: null,
    timeline: [
        {
            alert_id: "alert-001",
            occurred_at: "2026-10-06T10:00:00Z",
            rule_id: "5712",
            rule_level: 10,
            rule_description: "<script>attack()</script>",
            agent_id: "001",
            agent_name: "<img src=x onerror=attack()>",
            source_ip: "2001:db8::10",
            destination_ip: null,
            mitre_ids: [],
        },
    ],
};

export const SAMPLE_CASE: CaseDetail = {
    case_id: "CASE-001",
    title: "Suspicious authentication case",
    description: "Review stored authentication telemetry.",
    severity: "HIGH",
    priority: "HIGH",
    status: "OPEN",
    owner: { analyst_id: "USR-1", username: "analyst-1", display_name: "Analyst One" },
    source_type: "ALERT",
    source_id: "alert-001",
    created_by_display: "Analyst One (analyst-1)",
    created_at: "2026-10-06T10:00:00Z",
    updated_at: "2026-10-06T10:00:00Z",
    resolved_at: null,
    closed_at: null,
    version: 1,
    alert_count: 1,
    incident_count: 0,
    event_count: 0,
    evidence_count: 0,
    comment_count: 0,
    sla: {
        policy: "LOCAL_CASE_SLA_V1",
        response_due_at: "2026-10-06T10:30:00Z",
        resolution_due_at: "2026-10-06T18:00:00Z",
        first_response_at: null,
        response_state: "PENDING",
        resolution_state: "PENDING",
        escalation_state: "NONE",
    },
    resolution: "",
    closure_reason: "",
    alert_ids: ["alert-001"],
    incident_ids: [],
    event_ids: [],
    comments: [],
    evidence: [],
    activity: [{ activity_id: "CACT-1", activity_type: "CASE_CREATED", actor_display: "Analyst One (analyst-1)", entity_type: "case", entity_id: "CASE-001", occurred_at: "2026-10-06T10:00:00Z", details: { source_type: "ALERT" } }],
    playbooks: [],
    report_history: [],
};

export const CASE_PAGE: CaseListResponse = { items: [SAMPLE_CASE], limit: 25, total: 1, next_cursor: null, sort: "updated" };
export const CASE_ANALYTICS: CaseAnalytics = {
    generated_at: "2026-10-06T10:01:00Z", window_days: 30, open_cases: 1,
    overdue_response: 0, overdue_resolution: 0, mtta_minutes: null, mttr_minutes: null,
    by_severity: [{ name: "HIGH", count: 1 }], by_owner: [{ name: "Analyst One", count: 1 }],
    aging_buckets: [{ name: "<24h", count: 1 }], created_trend: [{ name: "2026-10-06", count: 1 }], closed_trend: [],
    definitions: { mtta_minutes: "Mean minutes to first response." },
};
export const CASE_PLAYBOOK_TEMPLATES: PlaybookTemplate[] = [{
    key: "login-investigation", version: 1, name: "Suspicious login investigation",
    description: "Review stored telemetry.", steps: [{ key: "review-auth", title: "Review authentication telemetry", description: "Review evidence.", step_type: "ACTION" }],
}];

export const SAMPLE_ANALYST: AnalystPrincipal = {
    analyst_id: "USR-1",
    username: "analyst-1",
    display_name: "Analyst One",
    role: "ANALYST",
    permissions: ["soc:read", "alert:write", "incident:write"],
};

export const SAMPLE_SESSION: SessionResponse = {
    analyst: SAMPLE_ANALYST,
    csrf_token: "csrf-test-token",
};

export const ALERT_PAGE: AlertListResponse = {
    items: [SAMPLE_ALERT],
    page: { limit: 25, next_cursor: null, total: 1 },
};

export const SAMPLE_INVESTIGATION: InvestigationWorkspace = {
    incident_id: "INC-001",
    checklist_items: [
        {
            checklist_item_id: "CHK-1",
            incident_id: "INC-001",
            body: "Validate the source host",
            is_completed: false,
            assigned_to: null,
            position: 0,
            version: 1,
            created_at: "2026-10-06T10:02:00Z",
            updated_at: "2026-10-06T10:02:00Z",
            completed_at: null,
            created_by_display: "Analyst One",
            updated_by_display: "Analyst One",
        },
    ],
    evidence_pins: [],
    checklist_completed: 0,
    checklist_total: 1,
};

export const SAMPLE_INVESTIGATION_TIMELINE: InvestigationTimelinePage = {
    items: [
        {
            activity_id: "ACT-1",
            activity_type: "CHECKLIST_CREATED",
            entity_type: "checklist",
            entity_id: "CHK-1",
            actor_display: "Analyst One",
            action_at: "2026-10-06T10:02:00Z",
            source_timestamp: null,
            details: { body: "Validate the source host" },
        },
    ],
    limit: 50,
    next_cursor: null,
    total: 1,
};

export const SAMPLE_ALERT_WORKFLOW: AlertWorkflowDetail = {
    alert: SAMPLE_ALERT,
    status: "NEW",
    assignee: null,
    version: 1,
    created_at: "2026-10-06T10:00:01Z",
    updated_at: "2026-10-06T10:00:01Z",
    last_activity_at: "2026-10-06T10:00:01Z",
    note_count: 0,
    notes: [],
    history: [],
};

export const ALERT_WORKFLOW_PAGE = {
    items: [SAMPLE_ALERT_WORKFLOW],
    page: {
        limit: 25,
        next_cursor: null,
        total: 1,
        sort: "time_desc" as const,
    },
    counts: {
        total: 1,
        actionable: 1,
        unassigned: 1,
        by_status: {
            NEW: 1,
            ACKNOWLEDGED: 0,
            IN_PROGRESS: 0,
            RESOLVED: 0,
            FALSE_POSITIVE: 0,
        },
    },
};

export const INCIDENT_PAGE: IncidentListResponse = {
    items: [SAMPLE_INCIDENT],
    page: { limit: 25, next_cursor: null, total: 1 },
};

export const SAMPLE_EVENT: SecurityEventDetail = {
    event_id: "EVT-0123456789ABCDEF01234567",
    source_event_id: "1791469000.1",
    event_code: null,
    timestamp: "2026-10-08T14:30:00Z",
    ingested_at: "2026-10-08T14:30:01Z",
    source_type: "web",
    hostname: "cyberqalqon-test-web",
    agent_id: "001",
    agent_name: "cyberqalqon-test-web",
    operating_system: "linux",
    manager_identity: "lab-manager",
    event_provider: null,
    event_channel: null,
    process_name: "nginx",
    process_path: "/usr/sbin/nginx",
    command_line: "nginx: worker process",
    process_id: "4242",
    parent_process_name: "nginx",
    parent_process_path: "/usr/sbin/nginx",
    parent_process_id: "1",
    normalization_schema: "wazuh-event-v2",
    source_ip: "127.0.0.1",
    destination_ip: "127.0.0.1",
    source_port: 49152,
    destination_port: 80,
    username: null,
    event_category: "web",
    event_action: null,
    outcome: null,
    rule_id: "100120",
    severity: 8,
    mitre: { ids: ["T1190"], tactics: ["Initial Access"], techniques: ["Exploit Public-Facing Application"] },
    message: "<script>untrusted event</script>",
    ingestion_source: "wazuh_archives",
    related_alert_id: "alert-001",
    structured_payload: { data: { url: "<img src=x onerror=attack()>" } },
    raw_payload: { full_log: "<script>raw attack()</script>" },
    related_incident_ids: ["INC-001"],
    related_case_ids: [],
    raw_evidence_ref: "EVT-0123456789ABCDEF01234567",
};

export const SAMPLE_WORKBENCH: InvestigationWorkbench = {
    target_type: "EVENT",
    target_label: `Event ${SAMPLE_EVENT.event_id}`,
    primary_event: SAMPLE_EVENT,
    summary: {
        observations: ["The event was stored from the web telemetry source."],
        interpretations: [
            "These facts support investigation but do not by themselves establish attacker intent or confirmed compromise.",
        ],
        missing_fields: ["username"],
    },
    entities: [],
    related_events: [],
    links: [],
    timeline: [],
    ioc_matches: [],
    correlation_groups: [],
    query: {
        start_time: "2026-10-08T13:30:00Z",
        end_time: "2026-10-08T15:30:00Z",
        related_limit: 25,
        timeline_limit: 100,
        sort: "oldest",
        execution_ms: 1.25,
        related_truncated: false,
        schema_version: 17,
        unavailable_relationships: [],
    },
};

export const SECURITY_OVERVIEW: SecurityOverview = {
    start_time: "2026-10-07T15:00:00Z",
    end_time: "2026-10-08T15:00:00Z",
    total_events: 12,
    total_alerts: 3,
    events_per_minute: 0.008,
    active_incidents: 1,
    reporting_agents: 1,
    active_sources: 1,
    stale_sources: 0,
    database_size_bytes: 1048576,
    alerts_by_severity: [{ severity: "HIGH", count: 2 }],
    incidents_by_status: [{ name: "NEW", count: 1 }],
    events_over_time: [{ timestamp: "2026-10-08T14:00:00Z", count: 12 }],
    alerts_over_time: [{ timestamp: "2026-10-08T14:00:00Z", count: 3 }],
    top_source_ips: [{ name: "127.0.0.1", count: 10 }],
    top_hosts: [{ name: "cyberqalqon-test-web", count: 12 }],
    top_destination_hosts: [{ name: "127.0.0.1", count: 12 }],
    top_rules: [{ name: "100120", count: 2 }],
    top_event_categories: [{ name: "web", count: 12 }],
    event_sources: [{ name: "web", count: 12 }],
    latest_high_alerts: [
        {
            alert_id: "alert-001",
            timestamp: "2026-10-08T14:30:00Z",
            rule_id: "100111",
            severity: 10,
            description: "Port scan",
            agent_name: "cyberqalqon-test-web",
        },
    ],
    ingestion: {
        state: "ACTIVE",
        last_event_at: "2026-10-08T14:30:00Z",
        last_ingested_at: "2026-10-08T14:30:01Z",
        lag_seconds: 1,
    },
    pipeline_activity: [
        {
            component: "event_shipper",
            state: "ACTIVE",
            evidence: "DELIVERY_ACTIVITY",
            last_delivery_at: "2026-10-08T14:30:01Z",
            delivered_records: 12,
        },
    ],
    retention: {
        state: "WITHIN_LIMIT",
        retention_days: 30,
        max_records: 100000,
        retained_records: 12,
        protected_records: 0,
        over_limit_records: 0,
        usage_percent: 0.012,
        oldest_event_at: "2026-10-08T14:00:00Z",
        newest_event_at: "2026-10-08T14:30:00Z",
        last_run_at: "2026-10-08T14:30:01Z",
        last_deleted_count: 0,
    },
};

export const SAMPLE_SOURCES: LogSourceSummary[] = [
    {
        source_name: "cyberqalqon-test-web · web",
        source_type: "web",
        hostname: "cyberqalqon-test-web",
        agent_id: "001",
        agent_name: "cyberqalqon-test-web",
        last_event_at: "2026-10-08T14:30:00Z",
        last_ingested_at: "2026-10-08T14:30:01Z",
        ingestion_lag_seconds: 1,
        event_count: 12,
        source_health: "ACTIVE",
        agent_status: "UNKNOWN",
        collection_method: "wazuh_archives",
        pipeline_health: "ACTIVE",
        pipeline_evidence: "PERSISTED_DELIVERY_ACTIVITY",
        queue_depth: null,
        archive_cursor_lag_bytes: null,
        data_availability: "AVAILABLE",
        last_error: null,
    },
];

export const SAMPLE_HOSTS: HostSummary[] = [
    {
        hostname: "cyberqalqon-test-web",
        agent_id: "001",
        agent_name: "cyberqalqon-test-web",
        platform: "LINUX",
        agent_status: "UNKNOWN",
        source_health: "ACTIVE",
        last_seen: "2026-10-08T14:30:00Z",
        alert_count: 3,
        event_count: 12,
        recent_detections: ["100111"],
    },
];

export const SAMPLE_AGENT: AgentDetail = {
    agent_key: "wazuh_0123456789abcdef0123456789abcdef0123456789abcdef",
    agent_id: "001",
    name: "cyberqalqon-test-web",
    operating_system: "Kali GNU/Linux 2026",
    os_platform: "linux",
    os_version: "2026",
    agent_version: "Wazuh v4.14.8",
    manager: "lab-manager",
    ip_address: "127.0.0.1",
    groups: ["linux", "web"],
    service_status: "UNKNOWN",
    enrollment_status: "ENROLLED",
    connection_status: "ONLINE",
    status_authority: "WAZUH_API",
    last_keepalive: "2026-10-09T16:49:55Z",
    disconnected_at: null,
    enrolled_at: "2026-10-01T12:00:00Z",
    last_security_event: "2026-10-09T16:49:50Z",
    data_freshness: "ACTIVE",
    pipeline_health: "ACTIVE",
    observed_at: "2026-10-09T16:49:55Z",
    cache_expires_at: "2026-10-09T16:50:55Z",
    cache_stale: false,
    observed_only: false,
    telemetry_sources: [{
        source_type: "web", ingestion_source: "wazuh_archives",
        last_event_at: "2026-10-09T16:49:50Z", last_ingested_at: "2026-10-09T16:49:51Z",
        event_count: 12, freshness: "ACTIVE",
    }],
    recent_event_ids: ["EVT-0123456789ABCDEF01234567"],
    related_alert_ids: ["alert-001"],
    related_incident_ids: ["INC-001"],
    troubleshooting: ["Connection state is authoritative only when status authority is WAZUH_API."],
};

export const SAMPLE_AGENT_LIST: AgentListResponse = {
    items: [SAMPLE_AGENT], page: { limit: 50, offset: 0, total: 1 },
    authoritative_inventory: true, partial: false,
    observation_timestamp: "2026-10-09T16:49:55Z", cache_age_seconds: 5,
    message: "Authoritative Wazuh inventory with telemetry relationships.",
};

export const SAMPLE_AGENT_HEALTH: AgentHealthResponse = {
    agent_key: SAMPLE_AGENT.agent_key, status_authority: "WAZUH_API",
    items: [{ history_id: "AGH-1", connection_status: "ONLINE", previous_status: "DISCONNECTED", authority: "WAZUH_API", observed_at: "2026-10-09T16:49:55Z", details: { manager: "lab-manager" } }],
};

export const WAZUH_INTEGRATION_STATUS: WazuhIntegrationStatus = {
    state: "AVAILABLE", configured: true, authority: "WAZUH_API",
    reason: "Read-only Wazuh API inventory retrieved successfully.", manager_identity: "lab-manager",
    manager_version: "v4.14.8", manager_health: "HEALTHY", agent_count: 1,
    rejected_agent_count: 0, observed_at: "2026-10-09T16:49:55Z",
    cache_expires_at: "2026-10-09T16:50:55Z", cache_age_seconds: 5,
    cache_stale: false, tls_verification: "CUSTOM_CA", connectivity_scope: "HTTPS_LOOPBACK", read_only: true,
};

export const OPERATIONAL_OVERVIEW: OperationalOverview = {
    generated_at: "2026-10-09T16:50:00Z",
    measurement: {
        state: "FRESH",
        measured_at: "2026-10-09T16:50:00Z",
        age_seconds: 0,
        duration_ms: 12.5,
        cache_ttl_seconds: 2,
        stale_ttl_seconds: 30,
        query_deadline_seconds: 2,
        reason_code: "COMPUTED",
        cache_hits: 0,
        cache_misses: 1,
        singleflight_joins: 0,
        stale_served: 0,
        inflight_queries: 1,
        pending_waiters: 0,
        execution_model: "BOUNDED_THREADPOOL",
    },
    snapshot_collected_at: "2026-10-09T16:49:55Z",
    snapshot_age_seconds: 5,
    components: [
        {
            component_key: "wazuh-manager-runtime",
            component_kind: "manager",
            state: "HEALTHY",
            authority: "OS_SERVICE_MANAGER",
            summary: "Wazuh Manager service is active.",
            metrics: { service_active: true, identity: "lab-manager" },
            last_error: null,
            observed_at: "2026-10-09T16:49:55Z",
            first_observed_at: "2026-10-09T16:49:55Z",
            updated_at: "2026-10-09T16:49:55Z",
            version: 1,
        },
        {
            component_key: "wazuh-manager-api",
            component_kind: "wazuh_api",
            state: "UNAVAILABLE",
            authority: "WAZUH_API",
            summary: "Read-only Wazuh API credentials are not configured.",
            metrics: { agent_count: null },
            last_error: "Read-only Wazuh API credentials are not configured.",
            observed_at: "2026-10-09T16:49:55Z",
            first_observed_at: "2026-10-09T16:49:55Z",
            updated_at: "2026-10-09T16:49:55Z",
            version: 1,
        },
    ],
    recent_events: [],
    data_quality: {
        total_events: 2672,
        total_events_scope: "CURRENT_RETAINED_DATABASE",
        total_events_measurement: "EXACT",
        raw_evidence_records: null,
        missing_hostname: null,
        missing_username: null,
        missing_rule_id: null,
        field_completeness_measurement: "UNKNOWN",
        field_completeness_reason: "NOT_MATERIALIZED_SCHEMA17",
        duplicate_events: null,
        duplicate_events_scope: "UNKNOWN",
        malformed_events: 0,
        oversized_events: 0,
        delivery_rejected: 0,
        shipper_counters_scope: "UNKNOWN",
        evidence: "APPLICATION_DATABASE_AND_DURABLE_SHIPPER_STATE",
    },
    storage_retention: {
        schema_version: 17,
        state: "WITHIN_LIMIT",
        retention_days: 30,
        max_records: 100000,
        retained_records: 2672,
        protected_records: 3,
        over_limit_records: 0,
        usage_percent: 2.672,
        database_size_bytes: 52428800,
        wal_size_bytes: 4194304,
        last_run_at: "2026-10-09T16:49:55Z",
        last_deleted_count: 0,
        oldest_event_at: "2026-10-08T14:00:00Z",
        newest_event_at: "2026-10-09T16:49:50Z",
        last_ingested_at: "2026-10-09T16:49:55Z",
    },
    archive_backlog: {
        state: "AVAILABLE",
        generation_state: "CURRENT_FILE_IDENTITY_ONLY",
        historical_replay_state: "NOT_CONFIGURED",
        archive_size_bytes: 500000,
        cursor_bytes: 480000,
        current_lag_bytes: 20000,
        current_eligible_records: 12,
        current_filtered_records: 4,
        current_malformed_records: 1,
        rotated_archive_count: 2,
        historical_eligible_records: null,
        recovery_readiness: "BLOCKED_RETENTION_CAP",
    },
    forward_ingestion: {
        legacy_checkpoint_state: "BLOCKED",
        legacy_continuity: "UNPROVEN",
        forward_state: "NOT_DEPLOYED",
        historical_replay_state: "NOT_STARTED",
        approval_state: "ABSENT",
        approval_validation_basis: "UNKNOWN",
        approval_expires_at: null,
        approval_remaining_seconds: null,
        generation_id: null,
        source_device: null,
        source_inode: null,
        source_size_bytes: null,
        start_offset_bytes: null,
        cursor_bytes: null,
        lag_bytes: null,
        unique_insertions: null,
        duplicate_acknowledgements: null,
        filtered_records: null,
        malformed_records: null,
        retry_attempts: null,
        protocol_errors: null,
        delivery_rejected: null,
        source_identity_matches: null,
        legacy_state_unchanged: null,
        service_active: false,
        archive_growth_bytes_per_second: null,
        cursor_progress_bytes_per_second: null,
        net_lag_bytes_per_second: null,
        net_backlog_trend: "UNKNOWN",
        rate_measurement_state: "UNKNOWN",
        unreconciled_historical_records: null,
        retention_pressure: "AT_LIMIT",
        last_successful_delivery: null,
        checkpoint_updated_at: null,
        historical_gap_warning: "UNPROVEN_HISTORY_NOT_REPLAYED",
    },
    wazuh_inventory: {
        state: "UNAVAILABLE",
        authority: "WAZUH_API",
        reason: "Read-only Wazuh API credentials are not configured; agent states remain UNKNOWN.",
        manager_identity: "lab-manager",
        agent_count: null,
    },
    ingestion_performance: {
        measurement_scope: "POST_PROCESS_START_ONLY",
        started_at: "2026-10-09T16:40:00Z",
        ingress_protocol_version: "m18-batch-v1",
        configured_mode: "batch-available-disabled-by-default",
        batch_endpoint_enabled: false,
        configured_batch_limit: 100,
        requests: 4,
        single_requests: 3,
        batch_requests: 1,
        events: 28,
        inserted: 25,
        duplicates: 3,
        retryable_failures: 0,
        permanent_failures: 0,
        requests_per_second: 0.01,
        events_per_second: 0.07,
        inserts_per_second: 0.06,
        duplicates_per_second: 0.01,
        events_per_request: 7,
        request_latency_p50_ms: 120,
        request_latency_p95_ms: 230,
        database_latency_p50_ms: 90,
        database_latency_p95_ms: 180,
        transaction_latency_p50_ms: 80,
        transaction_latency_p95_ms: 160,
        retention_latency_p50_ms: 40,
        retention_latency_p95_ms: 80,
        last_successful_acknowledgement: "2026-10-09T16:49:58Z",
        last_error: null,
        historical_unique_insertions: null,
        historical_duplicate_acknowledgements: null,
    },
};

export const SAMPLE_RULES: DetectionRuleSummary[] = [
    {
        rule_id: "100111",
        name: "TCP port scan",
        description: "Bounded local port scan detection.",
        severity: 10,
        source_type: "network",
        mitre_ids: ["T1046"],
        last_triggered: "2026-10-08T14:30:00Z",
        alert_count: 1,
        correlation_relationship: "CORR-001",
        owner: "CyberQalqon local detection engineering",
        documentation: "wazuh/rules/cyberqalqon_network_rules.xml",
        rule_version: null,
        version_authority: "UNAVAILABLE",
        enabled_state: "UNKNOWN",
        enabled_evidence: "WAZUH_API_UNAVAILABLE",
        tested_state: "NOT_RECORDED",
        management_mode: "READ_ONLY_WAZUH",
        editable: false,
    },
];

export const SAMPLE_ADVANCED_RULES: AdvancedDetectionRule[] = [
    {
        rule_id: "DET-001",
        name: "Windows brute-force candidate",
        description: "Repeated scoped Windows logon failures.",
        enabled: false,
        activation_state: "DISABLED_BY_POLICY",
        severity: 10,
        prerequisites: {
            source_types: ["windows_event"],
            event_codes: ["4625"],
            event_categories: ["windows_security"],
            required_fields: ["hostname", "username", "logon_type"],
            parser_supported: true,
            configuration_status: "UNKNOWN",
            configuration_evidence: "No authoritative collector API.",
        },
        conditions: ["Five failures in five minutes."],
        grouping_fields: ["hostname", "username", "source_ip_or_local", "logon_type"],
        window_seconds: 300,
        threshold: 5,
        deduplication: "One finding per key per cooldown.",
        mitre_ids: ["T1110.001"],
        mitre_mappings: [{
            technique_id: "T1110.001",
            technique_name: "Password Guessing",
            tactic: "Credential Access",
            relationship: "Repeated failures are password-guessing evidence.",
        }],
        false_positive_notes: ["Stale credentials can cause bursts."],
        evidence_fields: ["event_id", "hostname", "username"],
        analyst_guidance: ["Validate source and account."],
        version: "1.0.0-m11",
        validation_status: "VALIDATED_FOR_DRY_RUN",
        validation_notes: ["Four failures do not match."],
        availability: {
            parser_supported: true,
            data_observed: true,
            recently_observed: true,
            configuration_status: "UNKNOWN",
            status: "RECENTLY_OBSERVED",
            observed_event_count: 5,
            latest_event_at: "2026-10-09T08:00:00Z",
            missing_required_fields: [],
            explanation: "Eligible telemetry was recently observed; live configuration is unknown.",
        },
    },
];

const QUALITY_SCENARIOS = [
    "positive", "negative", "boundary", "duplicate", "out_of_order",
    "missing_field", "cross_host", "cross_account", "false_positive_candidate",
] as const;

export const SAMPLE_DETECTION_QUALITY: DetectionQualityReport = {
    rule_id: "DET-001",
    dataset_version: "m15-golden-v1",
    dataset_label: "SYNTHETIC TEST DATA",
    ground_truth_scope: "LABELED_SYNTHETIC_FIXTURES_ONLY",
    live_ground_truth_available: false,
    enabled: false,
    runtime_activation_state: "DISABLED_BY_POLICY",
    deployment_eligibility: "SHADOW_ONLY",
    fixtures: QUALITY_SCENARIOS.map((scenario) => ({
        scenario,
        synthetic_test_data: true,
        applicable: true,
        ground_truth: scenario === "false_positive_candidate" ? "UNLABELED" :
            ["positive", "boundary", "duplicate", "out_of_order"].includes(scenario) ? "POSITIVE" : "NEGATIVE",
        expected_finding_count: ["positive", "boundary", "duplicate", "out_of_order"].includes(scenario) ? 1 : 0,
        actual_finding_count: ["positive", "boundary", "duplicate", "out_of_order"].includes(scenario) ? 1 : 0,
        expected_evidence_ids: [],
        actual_evidence_ids: [],
        evaluator_duplicate_count: scenario === "duplicate" ? 1 : 0,
        evaluation_ms: 0.5,
        passed: true,
        expected_explanation: "",
        grouping_behavior: "host/account/source/logon type",
        deduplication_behavior: "duplicate event IDs collapse",
    })),
    metrics: {
        labeled_fixture_count: 8,
        unlabeled_fixture_count: 1,
        true_positives: 4,
        false_positives: 0,
        true_negatives: 4,
        false_negatives: 0,
        precision: 1,
        recall: 1,
        false_positive_rate: 0,
        duplicate_input_count: 1,
        duplicate_finding_rate: 0,
        missing_field_fixture_passed: true,
        event_order_consistent: true,
        repeat_evaluation_consistent: true,
        evidence_latency_p50_ms: 240000,
        evidence_latency_p95_ms: 300000,
        evidence_latency_max_ms: 300000,
        evaluation_time_p50_ms: 0.5,
        evaluation_time_p95_ms: 0.9,
        evaluation_time_max_ms: 0.9,
    },
    all_applicable_fixtures_passed: true,
    side_effects: false,
};

export const SAMPLE_DETECTION_LIFECYCLE: DetectionRuleLifecycle = {
    rule_id: "DET-001",
    configuration_state: "TESTED",
    validation_state: "VALID",
    deployment_eligibility: "SHADOW_ONLY",
    runtime_activation_state: "DISABLED_BY_POLICY",
    telemetry_status: "READY",
    active_configuration_version: 1,
    state_version: 1,
    updated_at: "2026-10-12T12:00:00Z",
    updated_by: "SYSTEM",
    inactive_reason: "Live activation is disabled by policy.",
};

export const SAMPLE_DETECTION_CONFIGURATION: DetectionConfigurationVersion = {
    config_id: "ADCFG-1",
    rule_id: "DET-001",
    version: 1,
    lifecycle_state: "TESTED",
    threshold_count: 5,
    time_window_seconds: 300,
    severity: 10,
    supported_event_sources: ["windows_event"],
    required_normalized_fields: ["hostname", "username", "logon_type"],
    entity_grouping: ["hostname", "username", "source_ip_or_local", "logon_type"],
    safe_exclusions: [],
    evaluation_limits: {
        max_events: 1000,
        max_findings: 100,
        max_execution_ms: 1000,
    },
    state_expiration_seconds: 3600,
    state_schema_version: 1,
    author_id: null,
    author_display: "SYSTEM",
    change_reason: "Imported M11 tested baseline",
    created_at: "2026-10-12T12:00:00Z",
    validation_results: ["M11 fixtures passed."],
};

export const SAMPLE_TELEMETRY_READINESS: TelemetryPrerequisiteEvidence = {
    rule_id: "DET-001",
    required_sources: ["windows_event"],
    required_event_codes: ["4625"],
    required_categories: ["windows_security"],
    required_fields: ["hostname", "username", "logon_type"],
    latest_observed_event: "2026-10-12T12:00:00Z",
    source_freshness_seconds: 30,
    normalization_compatible: true,
    status: "READY",
    missing_prerequisites: [],
    authoritative_evidence_reference: "security_events bounded evidence",
    explanation: "Eligible telemetry was observed.",
};

export const SAMPLE_DETECTION_DIAGNOSTICS: DetectionDiagnostics = {
    rule_id: "DET-001",
    evaluation_count: 1,
    average_duration_ms: 4.2,
    rule_match_count: 1,
    finding_count: 1,
    duplicate_event_count: 0,
    skipped_event_count: 0,
    missing_field_count: 0,
    evaluation_timeout_count: 0,
    state_recovery_count: 1,
    configuration_validation_failure_count: 0,
    truncation_count: 0,
    last_successful_evaluation: "2026-10-12T12:01:00Z",
    last_failed_evaluation: null,
    evaluated_event_range_start: "2026-10-11T12:00:00Z",
    evaluated_event_range_end: "2026-10-12T12:00:00Z",
    source_freshness: "READY",
};

export const SAMPLE_SHADOW_RUN: ShadowRun = {
    run_id: `SHADOW-${"A".repeat(32)}`,
    rule_id: "DET-001",
    configuration_version: 1,
    status: "COMPLETED",
    started_at: "2026-10-12T12:00:00Z",
    completed_at: "2026-10-12T12:00:01Z",
    start_time: "2026-10-11T12:00:00Z",
    end_time: "2026-10-12T12:00:00Z",
    operator_display: "Analyst One (analyst-1)",
    source_availability: "READY",
    evaluated_event_count: 5,
    match_count: 1,
    duplicate_count: 0,
    missing_field_count: 0,
    execution_ms: 4.2,
    truncated: false,
    outcome: "COMPLETED_NO_PRODUCTION_SIDE_EFFECTS",
    error_code: null,
    resource_measurements: { wall_ms: 4.2, input_events: 5 },
    side_effects: false,
};

export const SAMPLE_SHADOW_DETAIL: ShadowRunDetail = {
    run: SAMPLE_SHADOW_RUN,
    findings: [],
};

export const SAMPLE_TUNING_COMPARISON: DetectionTuningComparison = {
    rule_id: "DET-001",
    start_time: "2026-10-11T12:00:00Z",
    end_time: "2026-10-12T12:00:00Z",
    results: [
        {
            candidate: { threshold_count: 5, time_window_seconds: 300 },
            evaluated_event_count: 5,
            finding_count: 1,
            duplicate_count: 0,
            missing_field_count: 0,
            findings_by_source: [{ entity: "windows_event", count: 1 }],
            findings_by_host: [{ entity: "win-lab", count: 1 }],
            findings_by_user: [{ entity: "alice", count: 1 }],
            repeated_finding_count: 0,
            execution_ms: 2.1,
            truncated: false,
        },
        {
            candidate: { threshold_count: 10, time_window_seconds: 300 },
            evaluated_event_count: 5,
            finding_count: 0,
            duplicate_count: 0,
            missing_field_count: 0,
            findings_by_source: [],
            findings_by_host: [],
            findings_by_user: [],
            repeated_finding_count: 0,
            execution_ms: 1.9,
            truncated: false,
        },
    ],
    interpretation: "Finding differences measure sensitivity only.",
    side_effects: false,
};

export const SAMPLE_CANARY_SAFETY: CanarySafetyStatus = {
    rule_id: "DET-001",
    prerequisites_validated: true,
    historical_evaluation_passed: true,
    configuration_reviewed: true,
    resource_budget_reviewed: true,
    false_positive_baseline_measured: true,
    version_locked: false,
    target_scope_selected: false,
    operator_approval_recorded: false,
    activation_path_enabled: false,
    runtime_activation_state: "DISABLED_BY_POLICY",
    blockers: ["M14 activation path is hard-disabled."],
};

export const SAMPLE_RULE_DRAFT: RuleDraft = {
    draft_id: "DRF-1",
    name: "Local scan candidate",
    description: "Find normalized scan evidence.",
    severity: 10,
    source_type: "network",
    mitre_ids: ["T1046"],
    conditions: [
        { field: "source_ip", operator: "EQUALS", value: "127.0.0.1" },
    ],
    documentation: "Manual review required.",
    status: "VALIDATED",
    version: 2,
    owner_analyst_id: "USR-1",
    owner_display: "Analyst One (analyst-1)",
    last_tested_at: null,
    last_test_match_count: null,
    last_test_execution_ms: null,
    created_at: "2026-10-09T08:00:00Z",
    updated_at: "2026-10-09T08:01:00Z",
};

export const SAMPLE_COVERAGE: DetectionCoverage = {
    techniques: [
        {
            technique_id: "T1046",
            rule_ids: ["100111"],
            mapped_detection_count: 1,
            enabled_detection_count: 0,
            triggered_detection_count: 1,
            tested_detection_count: 0,
            alert_count: 1,
            sources: ["network"],
            coverage_state: "TRIGGERED",
        },
    ],
    mapped_rule_count: 1,
    unmapped_rule_count: 0,
    validation_gap_count: 1,
};

export const SAMPLE_ANALYTICS: DetectionAnalytics = {
    start_time: "2026-10-08T00:00:00Z",
    end_time: "2026-10-09T00:00:00Z",
    alert_trend: [{ bucket: "2026-10-08", count: 3 }],
    false_positive_trend: [],
    top_rules: [{ name: "100111", count: 1 }],
    top_source_ips: [{ name: "127.0.0.1", count: 4 }],
    top_hosts: [{ name: "cyberqalqon-test-web", count: 12 }],
    mitre_distribution: [{ name: "T1046", count: 1 }],
    ioc_matches: [],
    false_positive_rules: [
        {
            rule_id: "100111",
            total_alerts: 1,
            dispositioned_alerts: 0,
            false_positive_count: 0,
            false_positive_rate: null,
            tuning_candidate: false,
        },
    ],
    analyst_dispositions: [],
    suggested_tuning_candidates: [],
};

export const SAMPLE_HUNT_PAGE: ThreatHuntPage = {
    items: [
        {
            event_id: "EVT-0123456789ABCDEF01234567",
            timestamp: "2026-10-08T14:30:00Z",
            source_type: "network",
            hostname: "cyberqalqon-test-web",
            source_ip: "127.0.0.1",
            destination_ip: "127.0.0.1",
            username: null,
            event_category: "network",
            rule_id: "100111",
            severity: 10,
            message: "Authorized local scan evidence",
            related_alert_id: "alert-001",
            related_incident_ids: ["INC-001"],
        },
    ],
    total: 1,
    limit: 50,
    next_cursor: null,
    start_time: "2026-10-08T00:00:00Z",
    end_time: "2026-10-09T00:00:00Z",
};

export const SAMPLE_SAVED_HUNT: SavedHunt = {
    saved_hunt_id: "HNT-1",
    name: "Local scan",
    query: { relativeMinutes: 1440, ruleId: "100111", sort: "newest" },
    created_at: "2026-10-09T08:00:00Z",
    updated_at: "2026-10-09T08:00:00Z",
};

export const SAMPLE_IOC: IOCIndicator = {
    indicator_id: "IOC-1",
    indicator_type: "IPV4",
    value: "127.0.0.1",
    source: "Manual review",
    confidence: 80,
    description: "Authorized local indicator",
    expires_at: null,
    hash_algorithm: null,
    is_active: true,
    expired: false,
    version: 1,
    created_at: "2026-10-09T08:00:00Z",
    updated_at: "2026-10-09T08:00:00Z",
};

export const SAMPLE_IOC_MATCHES: IOCMatchSummary = {
    start_time: "2026-10-08T00:00:00Z",
    end_time: "2026-10-09T00:00:00Z",
    total_matches: 1,
    matches: [
        {
            indicator_id: "IOC-1",
            indicator_type: "IPV4",
            value: "127.0.0.1",
            event_id: "EVT-0123456789ABCDEF01234567",
            event_timestamp: "2026-10-08T14:30:00Z",
            matched_field: "source_ip",
        },
    ],
    truncated: false,
};

export const SAMPLE_REPORT: SecurityActivityReport = {
    start_time: "2026-10-07T15:00:00Z",
    end_time: "2026-10-08T15:00:00Z",
    generated_at: "2026-10-08T15:00:01Z",
    filters: {
        severity_min: null,
        severity_max: null,
        host: null,
        rule_id: null,
    },
    total_events: 12,
    total_alerts: 3,
    total_incidents: 1,
    event_sources: [{ name: "web", count: 12 }],
    alert_severities: [{ name: "HIGH", count: 3 }],
    top_rules: [{ name: "100111", count: 1 }],
    host_activity: [{ name: "cyberqalqon-test-web", count: 12 }],
    authentication_failures: 0,
    file_integrity_events: 2,
};

export const AI_STATUS: AIStatus = {
    state: "AVAILABLE",
    provider: "ollama",
    model: "qwen-test",
    diagnostic: null,
    checked_at: "2026-10-06T10:02:00Z",
};

export const SAMPLE_AI_ANALYSIS: AIAnalysisRecord = {
    analysis_id: "AIA-001",
    analysis_type: "ALERT_SUMMARY",
    target_type: "alert",
    target_id: "alert-001",
    requested_by: { analyst_id: "USR-1", display: "Analyst One (analyst-1)" },
    requested_at: "2026-10-06T10:02:00Z",
    completed_at: "2026-10-06T10:03:00Z",
    provider: "ollama",
    model: "qwen-test",
    model_digest: null,
    policy_version: "cyberqalqon-ai-policy-v1",
    schema_version: "ai-analysis-v1",
    context_fingerprint: "a".repeat(64),
    context: {
        context_bytes: 4096,
        truncated: false,
        alerts_included: 1,
        alerts_available: 1,
        notes_included: 0,
        notes_available: 0,
        history_included: 0,
        history_available: 0,
        raw_event_included: true,
        truncation_reasons: [],
    },
    stale: false,
    result: {
        summary: "Review <script>alert(1)</script> as inert evidence.",
        assessment: "The event may indicate repeated credential guessing.",
        key_evidence: [
            "Rule level 10",
            "Run cmd.exe /c whoami is attacker-controlled text.",
        ],
        mitre_context: [
            {
                technique_id: "T1110",
                explanation: "Stored brute force mapping.",
                basis: "observed",
            },
        ],
        timeline_summary: null,
        hypotheses: ["A password may have expired."],
        investigation_steps: ["Review adjacent authentication logs."],
        possible_false_positive_reasons: [
            "A service may hold stale credentials.",
        ],
        recommended_actions: ["Human analyst should validate the source."],
        containment_considerations: [],
        uncertainties: ["No successful login was supplied."],
    },
};

export function createMockApi(overrides: Partial<BackendApi> = {}): BackendApi {
    return {
        getShadowCatalog: vi.fn().mockResolvedValue({version:"cdrc-v2",scope:"SOURCE_TEST_RESULTS",production_active:false,simulation_enabled:false,rules:[]}),
        getDurableShadowStatus:vi.fn().mockResolvedValue({enabled:false,scope:'DISPOSABLE_DURABLE_SHADOW',production_active:false,schema_version:null,resource_state:null}),
        reconcileShadowEvidence:vi.fn().mockRejectedValue(new Error('Disposable history not configured')),
        createDurableShadowRun:vi.fn().mockRejectedValue(new Error('Disposable history not configured')),
        getDurableShadowRun:vi.fn().mockRejectedValue(new Error('Disposable history not configured')),
        resumeDurableShadowRun:vi.fn().mockRejectedValue(new Error('Disposable history not configured')),
        listDurableShadowFindings:vi.fn().mockResolvedValue({items:[],next_cursor:null,scope:'DISPOSABLE_DURABLE_SHADOW',production_active:false}),
        getDurableShadowFinding:vi.fn().mockRejectedValue(new Error('Finding unavailable')),
        transitionDurableShadowFinding:vi.fn().mockRejectedValue(new Error('Finding unavailable')),
        validateShadowRule: vi.fn().mockRejectedValue(new Error("Synthetic fixture has no configured rule")),
        simulateShadowRule: vi.fn().mockRejectedValue(new Error("Disposable simulation gate closed")),
        health: vi
            .fn()
            .mockResolvedValue({
                status: "ok",
                service: "cyberqalqon-backend",
            }),
        getSession: vi.fn().mockResolvedValue(SAMPLE_SESSION),
        login: vi.fn().mockResolvedValue(SAMPLE_SESSION),
        logout: vi.fn().mockResolvedValue(undefined),
        subscribeUnauthorized: vi.fn().mockReturnValue(() => undefined),
        listAlerts: vi.fn().mockResolvedValue(ALERT_PAGE),
        getAlert: vi.fn().mockResolvedValue(SAMPLE_ALERT),
        listAlertWorkflows: vi.fn().mockResolvedValue(ALERT_WORKFLOW_PAGE),
        getAlertWorkflow: vi.fn().mockResolvedValue(SAMPLE_ALERT_WORKFLOW),
        listAlertAssignees: vi
            .fn()
            .mockResolvedValue([
                {
                    analyst_id: "USR-1",
                    username: "analyst-1",
                    display_name: "Analyst One",
                },
            ]),
        updateAlertStatus: vi
            .fn()
            .mockResolvedValue({
                ...SAMPLE_ALERT_WORKFLOW,
                status: "ACKNOWLEDGED",
                version: 2,
            }),
        updateAlertAssignment: vi
            .fn()
            .mockResolvedValue({
                ...SAMPLE_ALERT_WORKFLOW,
                assignee: {
                    analyst_id: "USR-1",
                    username: "analyst-1",
                    display_name: "Analyst One",
                },
                version: 2,
            }),
        addAlertNote: vi
            .fn()
            .mockResolvedValue({
                ...SAMPLE_ALERT_WORKFLOW,
                note_count: 1,
                version: 2,
            }),
        bulkUpdateAlerts: vi
            .fn()
            .mockResolvedValue({
                action: "ACKNOWLEDGE",
                selected_count: 1,
                updated_count: 1,
                items: [
                    {
                        ...SAMPLE_ALERT_WORKFLOW,
                        status: "ACKNOWLEDGED",
                        version: 2,
                    },
                ],
            }),
        listNotifications: vi
            .fn()
            .mockResolvedValue({ items: [], unread_count: 0, limit: 25 }),
        markNotificationRead: vi.fn(),
        markAllNotificationsRead: vi
            .fn()
            .mockResolvedValue({ updated_count: 0, unread_count: 0 }),
        listEvents: vi
            .fn()
            .mockResolvedValue({
                items: [SAMPLE_EVENT],
                page: {
                    limit: 25,
                    next_cursor: null,
                    total: 1,
                    sort: "newest",
                },
            }),
        searchCQQL: vi.fn().mockResolvedValue({
            items: [SAMPLE_EVENT],
            page: {
                limit: 25,
                next_cursor: null,
                total: null,
                count_mode: "UNKNOWN",
                sort: "newest",
            },
            metadata: {
                version: "cqql-v1",
                execution_ms: 2.5,
                query_status: "COMPLETE",
                warnings: ["Exact result count is intentionally not computed for CQQL searches."],
                truncated: false,
                data_freshness: "2026-10-08T15:00:00Z",
                clause_count: 1,
                ast_depth: 1,
                fts_used: false,
                cost_class: "LOW",
                plan_class: "INDEX_FRIENDLY",
                planner_strategy: "DEFAULT",
                diagnostic_reasons: ["INDEXED_EQUALITY"],
            },
        }),
        getCQQLAnalytics: vi.fn().mockResolvedValue({
            version: "cqql-v1",
            query_status: "COMPLETE",
            execution_ms: 3.1,
            completeness: "EXACT_WITHIN_BOUNDED_RANGE",
            sparse_time_series: true,
            matching_events: 1,
            groups: [
                { field: "event.severity", buckets: [{ name: "8", count: 1 }], truncated: false },
                { field: "source.ip", buckets: [{ name: "127.0.0.1", count: 1 }], truncated: false },
                { field: "host.name", buckets: [{ name: "cyberqalqon-test-web", count: 1 }], truncated: false },
                { field: "event.category", buckets: [{ name: "web", count: 1 }], truncated: false },
                { field: "event.source_type", buckets: [{ name: "web", count: 1 }], truncated: false },
            ],
            time_series: [{ timestamp: "2026-10-08T15:00:00Z", count: 1 }],
            clause_count: 1,
            fts_used: false,
        }),
        downloadCQQL: vi.fn().mockResolvedValue({ blob: new Blob(["event_id\r\nEVT-1\r\n"], { type: "text/csv" }), filename: "cyberqalqon-cqql.csv" }),
        getCQQLFields: vi.fn().mockResolvedValue({
            version: "cqql-v1",
            fields: [],
            limits: {
                maximum_query_length: 2000,
                maximum_tokens: 256,
                maximum_ast_depth: 8,
                maximum_boolean_clauses: 32,
                maximum_page_size: 100,
                maximum_time_range_days: 31,
                execution_deadline_ms: 1500,
                maximum_concurrent_queries: 4,
            },
        }),
        getEvent: vi.fn().mockResolvedValue(SAMPLE_EVENT),
        getInvestigationWorkbench: vi.fn().mockResolvedValue(SAMPLE_WORKBENCH),
        listSavedEventSearches: vi.fn().mockResolvedValue([]),
        saveEventSearch: vi
            .fn()
            .mockImplementation(async (payload) => ({
                saved_search_id: "SSR-1",
                name: payload.name,
                query: payload.query,
                created_at: "2026-10-08T15:00:00Z",
                updated_at: "2026-10-08T15:00:00Z",
            })),
        updateSavedEventSearch: vi
            .fn()
            .mockImplementation(async (savedSearchId, payload) => ({
                saved_search_id: savedSearchId,
                name: payload.name,
                query: payload.query,
                created_at: "2026-10-08T15:00:00Z",
                updated_at: "2026-10-08T16:00:00Z",
            })),
        deleteSavedEventSearch: vi.fn().mockResolvedValue(undefined),
        getOverview: vi.fn().mockResolvedValue(SECURITY_OVERVIEW),
        listSources: vi.fn().mockResolvedValue(SAMPLE_SOURCES),
        listHosts: vi.fn().mockResolvedValue(SAMPLE_HOSTS),
        listAgents: vi.fn().mockResolvedValue(SAMPLE_AGENT_LIST),
        getAgent: vi.fn().mockResolvedValue(SAMPLE_AGENT),
        getAgentHealth: vi.fn().mockResolvedValue(SAMPLE_AGENT_HEALTH),
        getWazuhIntegrationStatus: vi.fn().mockResolvedValue(WAZUH_INTEGRATION_STATUS),
        getOperationalOverview: vi.fn().mockResolvedValue(OPERATIONAL_OVERVIEW),
        getSourceCoverage: vi.fn().mockResolvedValue(parseSourceCoverage(m34Contract.empty_source_coverage)),
        previewSigma: vi.fn().mockRejectedValue(new Error('No Sigma response configured in this test')),
        listRules: vi.fn().mockResolvedValue(SAMPLE_RULES),
        listAdvancedDetectionRules: vi.fn().mockResolvedValue(SAMPLE_ADVANCED_RULES),
        getDetectionQuality: vi.fn().mockResolvedValue(SAMPLE_DETECTION_QUALITY),
        dryRunAdvancedDetectionRule: vi.fn().mockImplementation(async (_ruleId, _payload) => ({
            rule: SAMPLE_ADVANCED_RULES[0],
            availability: SAMPLE_ADVANCED_RULES[0].availability!,
            start_time: "2026-09-09T08:00:00Z",
            end_time: "2026-10-09T08:00:00Z",
            evaluated_event_count: 5,
            finding_count: 1,
            findings: [{
                finding_id: "FND-1",
                rule_id: "DET-001",
                severity: 10,
                first_event_at: "2026-10-09T07:55:00Z",
                last_event_at: "2026-10-09T08:00:00Z",
                group: { hostname: "win-lab", username: "alice" },
                matched_event_count: 5,
                threshold: 5,
                event_ids: ["EVT-0123456789ABCDEF01234567"],
                explanation: "Five scoped failures met the threshold.",
                evidence: [{
                    event_id: "EVT-0123456789ABCDEF01234567",
                    timestamp: "2026-10-09T08:00:00Z",
                    summary: "4625 on win-lab; outcome=failure",
                }],
                deduplication_key: "A".repeat(64),
                mitre_ids: ["T1110.001"],
            }],
            execution_ms: 1.2,
            execution_budget_ms: 1000,
            result_truncated: false,
            deterministic_ordering: true,
            side_effects: false,
        })),
        listDetectionLifecycles: vi
            .fn()
            .mockResolvedValue([SAMPLE_DETECTION_LIFECYCLE]),
        getDetectionLifecycle: vi
            .fn()
            .mockResolvedValue(SAMPLE_DETECTION_LIFECYCLE),
        listDetectionConfigurations: vi
            .fn()
            .mockResolvedValue([SAMPLE_DETECTION_CONFIGURATION]),
        getDetectionTelemetry: vi
            .fn()
            .mockResolvedValue(SAMPLE_TELEMETRY_READINESS),
        getDetectionDiagnostics: vi
            .fn()
            .mockResolvedValue(SAMPLE_DETECTION_DIAGNOSTICS),
        listShadowRuns: vi.fn().mockResolvedValue([SAMPLE_SHADOW_RUN]),
        runShadowEvaluation: vi.fn().mockResolvedValue(SAMPLE_SHADOW_DETAIL),
        compareDetectionTuning: vi
            .fn()
            .mockResolvedValue(SAMPLE_TUNING_COMPARISON),
        getCanarySafety: vi.fn().mockResolvedValue(SAMPLE_CANARY_SAFETY),
        getDetectionCoverage: vi.fn().mockResolvedValue(SAMPLE_COVERAGE),
        getDetectionAnalytics: vi.fn().mockResolvedValue(SAMPLE_ANALYTICS),
        listRuleDrafts: vi.fn().mockResolvedValue([SAMPLE_RULE_DRAFT]),
        createRuleDraft: vi.fn().mockResolvedValue(SAMPLE_RULE_DRAFT),
        updateRuleDraft: vi
            .fn()
            .mockResolvedValue({
                ...SAMPLE_RULE_DRAFT,
                version: 3,
                status: "DRAFT",
            }),
        validateRuleDraft: vi
            .fn()
            .mockResolvedValue({
                draft: SAMPLE_RULE_DRAFT,
                valid: true,
                errors: [],
                warnings: [],
            }),
        dryRunRuleDraft: vi
            .fn()
            .mockResolvedValue({
                draft: { ...SAMPLE_RULE_DRAFT, status: "TESTED", version: 3 },
                start_time: "2026-10-08T00:00:00Z",
                end_time: "2026-10-09T00:00:00Z",
                evaluated_event_count: 12,
                match_count: 1,
                matched_event_ids: ["EVT-0123456789ABCDEF01234567"],
                execution_ms: 1.2,
                result_ids_truncated: false,
                side_effects: false,
            }),
        confirmManualDeployment: vi
            .fn()
            .mockResolvedValue({
                draft: {
                    ...SAMPLE_RULE_DRAFT,
                    status: "READY_FOR_MANUAL_DEPLOYMENT",
                    version: 4,
                },
                live_wazuh_modified: false,
                deployment_mode: "MANUAL_REVIEW_ONLY",
                message: "Manual review recorded.",
            }),
        listRuleDraftVersions: vi
            .fn()
            .mockResolvedValue([
                {
                    version_id: "DRV-1",
                    draft_id: "DRF-1",
                    version_number: 2,
                    snapshot: {},
                    change_summary: "Validated",
                    actor_display: "Analyst One",
                    created_at: "2026-10-09T08:01:00Z",
                },
            ]),
        rollbackRuleDraft: vi
            .fn()
            .mockResolvedValue({
                ...SAMPLE_RULE_DRAFT,
                version: 3,
                status: "DRAFT",
            }),
        runThreatHunt: vi.fn().mockResolvedValue(SAMPLE_HUNT_PAGE),
        listSavedHunts: vi.fn().mockResolvedValue([SAMPLE_SAVED_HUNT]),
        saveThreatHunt: vi.fn().mockResolvedValue(SAMPLE_SAVED_HUNT),
        deleteSavedHunt: vi.fn().mockResolvedValue(undefined),
        downloadThreatHunt: vi
            .fn()
            .mockResolvedValue({
                blob: new Blob(["hunt"]),
                filename: "cyberqalqon-threat-hunt.csv",
            }),
        listIOCs: vi.fn().mockResolvedValue([SAMPLE_IOC]),
        createIOC: vi.fn().mockResolvedValue(SAMPLE_IOC),
        updateIOC: vi.fn().mockResolvedValue({ ...SAMPLE_IOC, version: 2 }),
        importIOCs: vi
            .fn()
            .mockResolvedValue({
                created: 1,
                duplicates: 0,
                indicators: [SAMPLE_IOC],
            }),
        getIOCMatches: vi.fn().mockResolvedValue(SAMPLE_IOC_MATCHES),
        downloadIOCs: vi
            .fn()
            .mockResolvedValue({
                blob: new Blob(["iocs"]),
                filename: "cyberqalqon-local-iocs.json",
            }),
        getSecurityActivityReport: vi.fn().mockResolvedValue(SAMPLE_REPORT),
        downloadSecurityActivityReport: vi
            .fn()
            .mockImplementation(async (_query, format) => ({
                blob: new Blob(["report"]),
                filename: `cyberqalqon-security-activity.${format}`,
            })),
        listAnalysts: vi
            .fn()
            .mockResolvedValue([
                {
                    analyst_id: "USR-1",
                    username: "analyst-1",
                    display_name: "Analyst One",
                    role: "ADMIN",
                    is_active: true,
                    created_at: "2026-10-01T00:00:00Z",
                    updated_at: "2026-10-01T00:00:00Z",
                },
            ]),
        getSessionStatus: vi
            .fn()
            .mockResolvedValue({
                active_sessions: 1,
                current_expires_at: "2026-10-09T00:00:00Z",
            }),
        revokeOtherSessions: vi.fn().mockResolvedValue(undefined),
        changePassword: vi.fn().mockResolvedValue(undefined),
        listAuditEvents: vi.fn().mockResolvedValue({ items: [], limit: 100 }),
        listIncidents: vi.fn().mockResolvedValue(INCIDENT_PAGE),
        listCases: vi.fn().mockResolvedValue(CASE_PAGE),
        getCase: vi.fn().mockResolvedValue(SAMPLE_CASE),
        createCase: vi.fn().mockResolvedValue(SAMPLE_CASE),
        updateCaseStatus: vi.fn().mockResolvedValue({ ...SAMPLE_CASE, status: "TRIAGING", version: 2 }),
        updateCaseAssignment: vi.fn().mockResolvedValue(SAMPLE_CASE),
        addCaseComment: vi.fn().mockResolvedValue(SAMPLE_CASE),
        linkCaseReference: vi.fn().mockResolvedValue(SAMPLE_CASE),
        acquireCaseEvidence: vi.fn().mockResolvedValue(SAMPLE_CASE),
        verifyCaseEvidence: vi.fn().mockResolvedValue(SAMPLE_CASE),
        listPlaybookTemplates: vi.fn().mockResolvedValue(CASE_PLAYBOOK_TEMPLATES),
        startCasePlaybook: vi.fn().mockResolvedValue(SAMPLE_CASE),
        updateCasePlaybookStep: vi.fn().mockResolvedValue(SAMPLE_CASE),
        getCaseAnalytics: vi.fn().mockResolvedValue(CASE_ANALYTICS),
        evaluateCaseSla: vi.fn().mockResolvedValue({ evaluated_cases: 1, notifications_created: 0, generated_at: "2026-10-06T10:01:00Z" }),
        downloadCaseReport: vi.fn().mockResolvedValue({ blob: new Blob(["case report"]), filename: "cyberqalqon-CASE-001.json" }),
        getIncident: vi.fn().mockResolvedValue(SAMPLE_INCIDENT),
        createIncident: vi.fn().mockResolvedValue(SAMPLE_INCIDENT),
        updateIncidentStatus: vi
            .fn()
            .mockResolvedValue({ ...SAMPLE_INCIDENT, status: "TRIAGED" }),
        linkIncidentAlert: vi.fn().mockResolvedValue(SAMPLE_INCIDENT),
        addIncidentNote: vi.fn().mockResolvedValue(SAMPLE_INCIDENT.notes[0]),
        updateIncidentAssignment: vi
            .fn()
            .mockResolvedValue({
                ...SAMPLE_INCIDENT,
                assigned_to: "analyst-2",
            }),
        getInvestigation: vi.fn().mockResolvedValue(SAMPLE_INVESTIGATION),
        createChecklistItem: vi.fn().mockResolvedValue(SAMPLE_INVESTIGATION),
        updateChecklistItem: vi.fn().mockResolvedValue(SAMPLE_INVESTIGATION),
        reorderChecklist: vi.fn().mockResolvedValue(SAMPLE_INVESTIGATION),
        pinEvidence: vi.fn().mockResolvedValue(SAMPLE_INVESTIGATION),
        annotateEvidence: vi.fn().mockResolvedValue(SAMPLE_INVESTIGATION),
        unpinEvidence: vi.fn().mockResolvedValue(SAMPLE_INVESTIGATION),
        getInvestigationTimeline: vi
            .fn()
            .mockResolvedValue(SAMPLE_INVESTIGATION_TIMELINE),
        getPreferences: vi.fn().mockResolvedValue(DEFAULT_PREFERENCES),
        updatePreferences: vi
            .fn()
            .mockImplementation(async (payload) => ({
                ...payload,
                version: payload.expected_version + 1,
            })),
        resetPreferences: vi.fn().mockResolvedValue(DEFAULT_PREFERENCES),
        getAIStatus: vi.fn().mockResolvedValue(AI_STATUS),
        analyzeAlert: vi.fn().mockResolvedValue(SAMPLE_AI_ANALYSIS),
        analyzeIncident: vi
            .fn()
            .mockResolvedValue({
                ...SAMPLE_AI_ANALYSIS,
                analysis_type: "INCIDENT_SUMMARY",
                target_type: "incident",
                target_id: "INC-001",
            }),
        getAIAnalysis: vi.fn().mockResolvedValue(SAMPLE_AI_ANALYSIS),
        listAlertAnalyses: vi.fn().mockResolvedValue({ items: [], limit: 20 }),
        listIncidentAnalyses: vi
            .fn()
            .mockResolvedValue({ items: [], limit: 20 }),
        ...overrides,
    };
}
