import { vi } from "vitest";

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
    DetectionAnalytics,
    DetectionCoverage,
    IOCIndicator,
    IOCMatchSummary,
    RuleDraft,
    SavedHunt,
    ThreatHuntPage,
} from "../types/detection-engineering";
import type { OperationalOverview } from "../types/operations";
import type { CaseAnalytics, CaseDetail, PlaybookTemplate } from "../types/cases";

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
    message: "<script>untrusted event</script>",
    ingestion_source: "wazuh_archives",
    related_alert_id: "alert-001",
    structured_payload: { data: { url: "<img src=x onerror=attack()>" } },
    raw_payload: { full_log: "<script>raw attack()</script>" },
    related_incident_ids: ["INC-001"],
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

export const OPERATIONAL_OVERVIEW: OperationalOverview = {
    generated_at: "2026-10-09T16:50:00Z",
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
        raw_evidence_records: 2672,
        missing_hostname: 0,
        missing_username: 2500,
        missing_rule_id: 0,
        duplicate_events: null,
        malformed_events: 0,
        oversized_events: 0,
        delivery_rejected: 0,
        evidence: "APPLICATION_DATABASE_AND_DURABLE_SHIPPER_STATE",
    },
    wazuh_inventory: {
        state: "UNAVAILABLE",
        authority: "WAZUH_API",
        reason: "Read-only Wazuh API credentials are not configured; agent states remain UNKNOWN.",
        manager_identity: "lab-manager",
        agent_count: null,
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
        getEvent: vi.fn().mockResolvedValue(SAMPLE_EVENT),
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
        getOperationalOverview: vi.fn().mockResolvedValue(OPERATIONAL_OVERVIEW),
        listRules: vi.fn().mockResolvedValue(SAMPLE_RULES),
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
