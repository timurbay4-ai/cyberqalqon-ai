import {
    ALERT_WORKFLOW_STATUSES,
    type AlertAssignee,
    type AlertBulkResponse,
    type AlertWorkflowDetail,
    type AlertWorkflowHistoryEvent,
    type AlertWorkflowNote,
    type AlertWorkflowStatus,
    type AlertWorkflowSummary,
    type NormalizedAlert,
    type WazuhSeverityLevel,
} from "../types/alerts";
import {
    EVENT_SOURCE_TYPES,
    type EventSourceType,
    type SavedEventSearch,
    type SecurityEventDetail,
    type SecurityEventSummary,
    type SecurityOverview,
} from "../types/events";
import {
    AI_AVAILABILITY,
    type AIAnalysisHistory,
    type AIAnalysisRecord,
    type AIAnalysisResult,
    type AIAnalysisType,
    type AIAvailability,
    type AITargetType,
    type AIStatus,
} from "../types/ai";
import {
    ANALYST_ROLES,
    PERMISSIONS,
    type AnalystPrincipal,
    type AnalystPublic,
    type AnalystRole,
    type AnalystSessionStatus,
    type Permission,
    type SecurityAuditEvent,
    type SessionResponse,
} from "../types/auth";
import type {
    AlertListResponse,
    AlertWorkflowListResponse,
    HealthResponse,
    IncidentListResponse,
    PageMetadata,
    SecurityEventListResponse,
} from "../types/api";
import type {
    AnalystNotification,
    NotificationCategory,
    NotificationListResponse,
    NotificationReadAllResponse,
} from "../types/notifications";
import type {
    DetectionRuleSummary,
    HostSummary,
    LogSourceSummary,
    SecurityActivityReport,
} from "../types/siem";
import type {
    ChecklistItem,
    EvidencePin,
    EvidenceType,
    InvestigationActivity,
    InvestigationTimelinePage,
    InvestigationWorkspace,
} from "../types/investigations";
import type {
    AdvancedDetectionAvailability,
    AdvancedDetectionFinding,
    AdvancedDetectionRule,
    AdvancedRuleDryRunResult,
    DeploymentConfirmationResult,
    DetectionAnalytics,
    DetectionCoverage,
    DetectionQualityReport,
    HuntEvent,
    IOCIndicator,
    IOCMatchSummary,
    RuleCondition,
    RuleDraft,
    RuleDraftVersion,
    RuleDryRunResult,
    RuleValidationResult,
    SavedHunt,
    ThreatHuntPage,
    ThreatHuntQuery,
} from "../types/detection-engineering";
import type {
    CanarySafetyStatus,
    DetectionConfigurationVersion,
    DetectionDiagnostics,
    DetectionRuleLifecycle,
    DetectionTuningComparison,
    ShadowFinding,
    ShadowRun,
    ShadowRunDetail,
    TelemetryPrerequisiteEvidence,
} from "../types/detection-readiness";
import {
    DISCOVER_COLUMNS,
    type AnalystPreferences,
    type DashboardRange,
    type DiscoverColumn,
    type TableDensity,
    type TimeDisplay,
} from "../types/preferences";
import {
    INCIDENT_SEVERITIES,
    INCIDENT_STATUSES,
    type IncidentDetail,
    type IncidentCorrelation,
    type IncidentEventType,
    type IncidentHistoryEvent,
    type IncidentNote,
    type IncidentSeverity,
    type IncidentStatus,
    type IncidentSummary,
    type IncidentTimelineAlert,
} from "../types/incidents";
import type { OperationalOverview, OperationalState, OperationalAuthority } from "../types/operations";
import type {
    AgentConnectionStatus,
    AgentDetail,
    AgentHealthResponse,
    AgentListResponse,
    AgentStatusAuthority,
    AgentSummary,
    FreshnessState,
    WazuhIntegrationStatus,
} from "../types/agents";
import type {
    InvestigationEntityType,
    InvestigationTimelineItem,
    InvestigationWorkbench,
    WorkbenchTargetType,
} from "../types/investigation-workbench";

export class ContractError extends Error {
    constructor(path: string) {
        super(
            `Backend response did not match the expected contract at ${path}.`,
        );
        this.name = "ContractError";
    }
}

function objectAt(value: unknown, path: string): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new ContractError(path);
    }
    return value as Record<string, unknown>;
}

function stringAt(value: unknown, path: string): string {
    if (typeof value !== "string") throw new ContractError(path);
    return value;
}

function boundedStringAt(
    value: unknown,
    path: string,
    maximum: number,
): string {
    const text = stringAt(value, path);
    if (!text.length || text.length > maximum) throw new ContractError(path);
    return text;
}

function dateAt(value: unknown, path: string): string {
    const text = stringAt(value, path);
    if (Number.isNaN(Date.parse(text))) throw new ContractError(path);
    return text;
}

function integerAt(value: unknown, path: string, minimum = 0): number {
    if (!Number.isInteger(value) || (value as number) < minimum)
        throw new ContractError(path);
    return value as number;
}

function booleanAt(value: unknown, path: string): boolean {
    if (typeof value !== "boolean") throw new ContractError(path);
    return value;
}

function nullableStringAt(value: unknown, path: string): string | null {
    if (value === null || value === undefined) return null;
    return stringAt(value, path);
}

function stringsAt(value: unknown, path: string): string[] {
    if (!Array.isArray(value)) throw new ContractError(path);
    return value.map((item, index) => stringAt(item, `${path}[${index}]`));
}

function boundedStringsAt(
    value: unknown,
    path: string,
    maximumItems: number,
    maximumChars: number,
): string[] {
    if (!Array.isArray(value) || value.length > maximumItems)
        throw new ContractError(path);
    return value.map((item, index) =>
        boundedStringAt(item, `${path}[${index}]`, maximumChars),
    );
}

function nullableIdentifierAt(value: unknown, path: string): string | null {
    return value === undefined ? null : nullableStringAt(value, path);
}

function pageAt(value: unknown, path: string): PageMetadata {
    const page = objectAt(value, path);
    // FastAPI endpoints use `response_model_exclude_none=True`, so the final
    // page omits `next_cursor` instead of serializing it as JSON null.
    const nextCursor = page.next_cursor === undefined ? null : page.next_cursor;
    if (nextCursor !== null && typeof nextCursor !== "string") {
        throw new ContractError(`${path}.next_cursor`);
    }
    return {
        limit: integerAt(page.limit, `${path}.limit`, 1),
        next_cursor: nextCursor,
        total: integerAt(page.total, `${path}.total`),
    };
}

export function parseNormalizedAlert(
    value: unknown,
    path = "alert",
): NormalizedAlert {
    const alert = objectAt(value, path);
    const agent = objectAt(alert.agent, `${path}.agent`);
    const rule = objectAt(alert.rule, `${path}.rule`);
    const mitre = objectAt(alert.mitre, `${path}.mitre`);
    const level = integerAt(rule.level, `${path}.rule.level`);
    if (level > 16) throw new ContractError(`${path}.rule.level`);

    const endpoint = (candidate: unknown, endpointPath: string) => {
        if (candidate === null || candidate === undefined) return undefined;
        const item = objectAt(candidate, endpointPath);
        const port = item.port;
        if (port !== null && port !== undefined) {
            const parsedPort = integerAt(port, `${endpointPath}.port`, 1);
            if (parsedPort > 65535)
                throw new ContractError(`${endpointPath}.port`);
        }
        return {
            ip: nullableStringAt(item.ip, `${endpointPath}.ip`),
            port:
                port === null || port === undefined
                    ? undefined
                    : (port as number),
        };
    };
    const windows = (() => {
        if (alert.windows === null || alert.windows === undefined)
            return undefined;
        const context = objectAt(alert.windows, `${path}.windows`);
        return {
            event_id: stringAt(context.event_id, `${path}.windows.event_id`),
            channel: stringAt(context.channel, `${path}.windows.channel`),
            provider: nullableStringAt(
                context.provider,
                `${path}.windows.provider`,
            ),
            computer: nullableStringAt(
                context.computer,
                `${path}.windows.computer`,
            ),
        };
    })();

    return {
        alert_id: stringAt(alert.alert_id, `${path}.alert_id`),
        timestamp: dateAt(alert.timestamp, `${path}.timestamp`),
        agent: {
            id: stringAt(agent.id, `${path}.agent.id`),
            name: stringAt(agent.name, `${path}.agent.name`),
            ip: nullableStringAt(agent.ip, `${path}.agent.ip`),
        },
        rule: {
            id: stringAt(rule.id, `${path}.rule.id`),
            level: level as WazuhSeverityLevel,
            description: stringAt(rule.description, `${path}.rule.description`),
            groups:
                rule.groups === undefined
                    ? []
                    : stringsAt(rule.groups, `${path}.rule.groups`),
        },
        mitre: {
            ids: stringsAt(mitre.ids, `${path}.mitre.ids`),
            tactics: stringsAt(mitre.tactics, `${path}.mitre.tactics`),
            techniques: stringsAt(mitre.techniques, `${path}.mitre.techniques`),
        },
        source: endpoint(alert.source, `${path}.source`),
        destination: endpoint(alert.destination, `${path}.destination`),
        user: nullableStringAt(alert.user, `${path}.user`),
        location: nullableStringAt(alert.location, `${path}.location`),
        decoder_name: nullableStringAt(
            alert.decoder_name,
            `${path}.decoder_name`,
        ),
        windows,
    };
}

function enumAt<const T extends readonly string[]>(
    value: unknown,
    choices: T,
    path: string,
): T[number] {
    const text = stringAt(value, path);
    if (!(choices as readonly string[]).includes(text))
        throw new ContractError(path);
    return text as T[number];
}

function nonnegativeNumberAt(value: unknown, path: string): number {
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0)
        throw new ContractError(path);
    return value;
}

function finiteNumberAt(value: unknown, path: string): number {
    if (typeof value !== "number" || !Number.isFinite(value))
        throw new ContractError(path);
    return value;
}

export function parseAlertList(value: unknown): AlertListResponse {
    const response = objectAt(value, "response");
    if (!Array.isArray(response.items))
        throw new ContractError("response.items");
    return {
        items: response.items.map((item, index) =>
            parseNormalizedAlert(item, `response.items[${index}]`),
        ),
        page: pageAt(response.page, "response.page"),
    };
}

function incidentStatusAt(value: unknown, path: string): IncidentStatus {
    const status = stringAt(value, path);
    if (!(INCIDENT_STATUSES as readonly string[]).includes(status))
        throw new ContractError(path);
    return status as IncidentStatus;
}

function incidentSeverityAt(value: unknown, path: string): IncidentSeverity {
    const severity = stringAt(value, path);
    if (!(INCIDENT_SEVERITIES as readonly string[]).includes(severity))
        throw new ContractError(path);
    return severity as IncidentSeverity;
}

function incidentSummaryAt(value: unknown, path: string): IncidentSummary {
    const incident = objectAt(value, path);
    return {
        incident_id: stringAt(incident.incident_id, `${path}.incident_id`),
        title: stringAt(incident.title, `${path}.title`),
        description: stringAt(incident.description, `${path}.description`),
        severity: incidentSeverityAt(incident.severity, `${path}.severity`),
        status: incidentStatusAt(incident.status, `${path}.status`),
        assigned_to: nullableStringAt(
            incident.assigned_to,
            `${path}.assigned_to`,
        ),
        created_at: dateAt(incident.created_at, `${path}.created_at`),
        updated_at: dateAt(incident.updated_at, `${path}.updated_at`),
        alert_count: integerAt(incident.alert_count, `${path}.alert_count`),
        auto_correlated: booleanAt(
            incident.auto_correlated,
            `${path}.auto_correlated`,
        ),
        correlation_rule: nullableStringAt(
            incident.correlation_rule,
            `${path}.correlation_rule`,
        ),
        classification: nullableStringAt(
            incident.classification,
            `${path}.classification`,
        ),
    };
}

function alertWorkflowStatusAt(
    value: unknown,
    path: string,
): AlertWorkflowStatus {
    const workflowStatus = stringAt(value, path);
    if (
        !(ALERT_WORKFLOW_STATUSES as readonly string[]).includes(workflowStatus)
    )
        throw new ContractError(path);
    return workflowStatus as AlertWorkflowStatus;
}

function alertAssigneeAt(value: unknown, path: string): AlertAssignee | null {
    if (value === null || value === undefined) return null;
    const assignee = objectAt(value, path);
    return {
        analyst_id: boundedStringAt(
            assignee.analyst_id,
            `${path}.analyst_id`,
            64,
        ),
        username: boundedStringAt(assignee.username, `${path}.username`, 64),
        display_name: boundedStringAt(
            assignee.display_name,
            `${path}.display_name`,
            128,
        ),
    };
}

function alertWorkflowSummaryAt(
    value: unknown,
    path: string,
): AlertWorkflowSummary {
    const workflow = objectAt(value, path);
    return {
        alert: parseNormalizedAlert(workflow.alert, `${path}.alert`),
        status: alertWorkflowStatusAt(workflow.status, `${path}.status`),
        assignee: alertAssigneeAt(workflow.assignee, `${path}.assignee`),
        version: integerAt(workflow.version, `${path}.version`, 1),
        created_at: dateAt(workflow.created_at, `${path}.created_at`),
        updated_at: dateAt(workflow.updated_at, `${path}.updated_at`),
        last_activity_at: dateAt(
            workflow.last_activity_at,
            `${path}.last_activity_at`,
        ),
        note_count: integerAt(workflow.note_count, `${path}.note_count`),
    };
}

export function parseAlertWorkflowList(
    value: unknown,
): AlertWorkflowListResponse {
    const response = objectAt(value, "response");
    if (!Array.isArray(response.items))
        throw new ContractError("response.items");
    const page = objectAt(response.page, "response.page");
    const sort = stringAt(page.sort, "response.page.sort");
    if (
        ![
            "time_desc",
            "time_asc",
            "severity_desc",
            "severity_asc",
            "activity_desc",
        ].includes(sort)
    ) {
        throw new ContractError("response.page.sort");
    }
    const counts = objectAt(response.counts, "response.counts");
    const byStatus = objectAt(counts.by_status, "response.counts.by_status");
    return {
        items: response.items.map((item, index) =>
            alertWorkflowSummaryAt(item, `response.items[${index}]`),
        ),
        page: {
            ...pageAt(response.page, "response.page"),
            sort: sort as AlertWorkflowListResponse["page"]["sort"],
        },
        counts: {
            total: integerAt(counts.total, "response.counts.total"),
            actionable: integerAt(
                counts.actionable,
                "response.counts.actionable",
            ),
            unassigned: integerAt(
                counts.unassigned,
                "response.counts.unassigned",
            ),
            by_status: Object.fromEntries(
                ALERT_WORKFLOW_STATUSES.map((item) => [
                    item,
                    integerAt(
                        byStatus[item],
                        `response.counts.by_status.${item}`,
                    ),
                ]),
            ) as AlertWorkflowListResponse["counts"]["by_status"],
        },
    };
}

export function parseAlertWorkflow(
    value: unknown,
    path = "workflow",
): AlertWorkflowDetail {
    const workflow = objectAt(value, path);
    if (!Array.isArray(workflow.notes))
        throw new ContractError(`${path}.notes`);
    if (!Array.isArray(workflow.history))
        throw new ContractError(`${path}.history`);
    return {
        ...alertWorkflowSummaryAt(workflow, path),
        notes: workflow.notes.map((value, index): AlertWorkflowNote => {
            const note = objectAt(value, `${path}.notes[${index}]`);
            return {
                note_id: stringAt(
                    note.note_id,
                    `${path}.notes[${index}].note_id`,
                ),
                body: boundedStringAt(
                    note.body,
                    `${path}.notes[${index}].body`,
                    4096,
                ),
                author_id: nullableStringAt(
                    note.author_id,
                    `${path}.notes[${index}].author_id`,
                ),
                author_display: stringAt(
                    note.author_display,
                    `${path}.notes[${index}].author_display`,
                ),
                created_at: dateAt(
                    note.created_at,
                    `${path}.notes[${index}].created_at`,
                ),
            };
        }),
        history: workflow.history.map(
            (value, index): AlertWorkflowHistoryEvent => {
                const event = objectAt(value, `${path}.history[${index}]`);
                const eventType = stringAt(
                    event.event_type,
                    `${path}.history[${index}].event_type`,
                );
                if (
                    ![
                        "STATUS_CHANGED",
                        "ASSIGNMENT_CHANGED",
                        "NOTE_ADDED",
                    ].includes(eventType)
                )
                    throw new ContractError(
                        `${path}.history[${index}].event_type`,
                    );
                return {
                    event_id: stringAt(
                        event.event_id,
                        `${path}.history[${index}].event_id`,
                    ),
                    event_type:
                        eventType as AlertWorkflowHistoryEvent["event_type"],
                    actor_id: nullableStringAt(
                        event.actor_id,
                        `${path}.history[${index}].actor_id`,
                    ),
                    actor_display: stringAt(
                        event.actor_display,
                        `${path}.history[${index}].actor_display`,
                    ),
                    occurred_at: dateAt(
                        event.occurred_at,
                        `${path}.history[${index}].occurred_at`,
                    ),
                    details: objectAt(
                        event.details,
                        `${path}.history[${index}].details`,
                    ),
                    version: integerAt(
                        event.version,
                        `${path}.history[${index}].version`,
                        2,
                    ),
                };
            },
        ),
    };
}

export function parseAlertAssignees(value: unknown): AlertAssignee[] {
    if (!Array.isArray(value)) throw new ContractError("assignees");
    return value.map((item, index) => {
        const parsed = alertAssigneeAt(item, `assignees[${index}]`);
        if (!parsed) throw new ContractError(`assignees[${index}]`);
        return parsed;
    });
}

export function parseAlertBulkResponse(value: unknown): AlertBulkResponse {
    const response = objectAt(value, "bulk_response");
    const action = stringAt(response.action, "bulk_response.action");
    if (!["ACKNOWLEDGE", "SET_STATUS", "ASSIGN"].includes(action))
        throw new ContractError("bulk_response.action");
    if (!Array.isArray(response.items))
        throw new ContractError("bulk_response.items");
    return {
        action: action as AlertBulkResponse["action"],
        selected_count: integerAt(
            response.selected_count,
            "bulk_response.selected_count",
            1,
        ),
        updated_count: integerAt(
            response.updated_count,
            "bulk_response.updated_count",
            1,
        ),
        items: response.items.map((item, index) =>
            alertWorkflowSummaryAt(item, `bulk_response.items[${index}]`),
        ),
    };
}

const NOTIFICATION_CATEGORIES: NotificationCategory[] = [
    "CRITICAL_ALERT",
    "HIGH_ALERT",
    "ALERT_ASSIGNED",
    "INCIDENT_ASSIGNED",
    "OPERATIONAL_ISSUE",
    "OPERATIONAL_RECOVERY",
    "CASE_ASSIGNED",
    "CASE_HANDOFF",
    "CASE_SLA",
];
function notificationAt(value: unknown, path: string): AnalystNotification {
    const notification = objectAt(value, path);
    const category = stringAt(notification.category, `${path}.category`);
    const targetType = stringAt(
        notification.target_type,
        `${path}.target_type`,
    );
    if (!NOTIFICATION_CATEGORIES.includes(category as NotificationCategory))
        throw new ContractError(`${path}.category`);
    if (targetType !== "alert" && targetType !== "incident" && targetType !== "operational" && targetType !== "case")
        throw new ContractError(`${path}.target_type`);
    return {
        notification_id: stringAt(
            notification.notification_id,
            `${path}.notification_id`,
        ),
        category: category as NotificationCategory,
        title: boundedStringAt(notification.title, `${path}.title`, 160),
        preview: boundedStringAt(notification.preview, `${path}.preview`, 320),
        target_type: targetType,
        target_id: boundedStringAt(
            notification.target_id,
            `${path}.target_id`,
            255,
        ),
        created_at: dateAt(notification.created_at, `${path}.created_at`),
        read_at:
            notification.read_at === null
                ? null
                : dateAt(notification.read_at, `${path}.read_at`),
    };
}

export function parseNotificationList(
    value: unknown,
): NotificationListResponse {
    const response = objectAt(value, "notifications");
    if (!Array.isArray(response.items))
        throw new ContractError("notifications.items");
    return {
        items: response.items.map((item, index) =>
            notificationAt(item, `notifications.items[${index}]`),
        ),
        unread_count: integerAt(
            response.unread_count,
            "notifications.unread_count",
        ),
        limit: integerAt(response.limit, "notifications.limit", 1),
    };
}

export function parseNotification(value: unknown): AnalystNotification {
    return notificationAt(value, "notification");
}

export function parseNotificationReadAll(
    value: unknown,
): NotificationReadAllResponse {
    const response = objectAt(value, "notification_read_all");
    const unread = integerAt(
        response.unread_count,
        "notification_read_all.unread_count",
    );
    if (unread !== 0)
        throw new ContractError("notification_read_all.unread_count");
    return {
        updated_count: integerAt(
            response.updated_count,
            "notification_read_all.updated_count",
        ),
        unread_count: 0,
    };
}

function eventSourceAt(value: unknown, path: string): EventSourceType {
    const source = stringAt(value, path);
    if (!(EVENT_SOURCE_TYPES as readonly string[]).includes(source))
        throw new ContractError(path);
    return source as EventSourceType;
}

function nullableIntegerAt(value: unknown, path: string): number | null {
    if (value === null || value === undefined) return null;
    return integerAt(value, path);
}

function eventSummaryAt(value: unknown, path: string): SecurityEventSummary {
    const event = objectAt(value, path);
    const mitre = objectAt(event.mitre, `${path}.mitre`);
    const severity = nullableIntegerAt(event.severity, `${path}.severity`);
    if (severity !== null && severity > 16)
        throw new ContractError(`${path}.severity`);
    return {
        event_id: stringAt(event.event_id, `${path}.event_id`),
        source_event_id: nullableStringAt(
            event.source_event_id,
            `${path}.source_event_id`,
        ),
        event_code: nullableStringAt(event.event_code, `${path}.event_code`),
        timestamp: dateAt(event.timestamp, `${path}.timestamp`),
        ingested_at: dateAt(event.ingested_at, `${path}.ingested_at`),
        source_type: eventSourceAt(event.source_type, `${path}.source_type`),
        hostname: nullableStringAt(event.hostname, `${path}.hostname`),
        agent_id: nullableStringAt(event.agent_id, `${path}.agent_id`),
        agent_name: nullableStringAt(event.agent_name, `${path}.agent_name`),
        operating_system: nullableStringAt(event.operating_system, `${path}.operating_system`),
        manager_identity: nullableStringAt(event.manager_identity, `${path}.manager_identity`),
        event_provider: nullableStringAt(event.event_provider, `${path}.event_provider`),
        event_channel: nullableStringAt(event.event_channel, `${path}.event_channel`),
        process_name: nullableStringAt(event.process_name, `${path}.process_name`),
        process_path: nullableStringAt(event.process_path, `${path}.process_path`),
        command_line: nullableStringAt(event.command_line, `${path}.command_line`),
        process_id: nullableStringAt(event.process_id, `${path}.process_id`),
        parent_process_name: nullableStringAt(event.parent_process_name, `${path}.parent_process_name`),
        parent_process_path: nullableStringAt(event.parent_process_path, `${path}.parent_process_path`),
        parent_process_id: nullableStringAt(event.parent_process_id, `${path}.parent_process_id`),
        normalization_schema: stringAt(event.normalization_schema, `${path}.normalization_schema`),
        source_ip: nullableStringAt(event.source_ip, `${path}.source_ip`),
        destination_ip: nullableStringAt(
            event.destination_ip,
            `${path}.destination_ip`,
        ),
        source_port: nullableIntegerAt(
            event.source_port,
            `${path}.source_port`,
        ),
        destination_port: nullableIntegerAt(
            event.destination_port,
            `${path}.destination_port`,
        ),
        username: nullableStringAt(event.username, `${path}.username`),
        event_category: nullableStringAt(
            event.event_category,
            `${path}.event_category`,
        ),
        event_action: nullableStringAt(
            event.event_action,
            `${path}.event_action`,
        ),
        outcome: nullableStringAt(event.outcome, `${path}.outcome`),
        rule_id: nullableStringAt(event.rule_id, `${path}.rule_id`),
        severity,
        mitre: {
            ids: stringsAt(mitre.ids, `${path}.mitre.ids`),
            tactics: stringsAt(mitre.tactics, `${path}.mitre.tactics`),
            techniques: stringsAt(mitre.techniques, `${path}.mitre.techniques`),
        },
        message: stringAt(event.message, `${path}.message`),
        ingestion_source: stringAt(
            event.ingestion_source,
            `${path}.ingestion_source`,
        ),
        related_alert_id: nullableStringAt(
            event.related_alert_id,
            `${path}.related_alert_id`,
        ),
    };
}

export function parseSecurityEvent(
    value: unknown,
    path = "event",
): SecurityEventDetail {
    const event = objectAt(value, path);
    return {
        ...eventSummaryAt(event, path),
        structured_payload: objectAt(
            event.structured_payload,
            `${path}.structured_payload`,
        ),
        raw_payload: objectAt(event.raw_payload, `${path}.raw_payload`),
        related_incident_ids: stringsAt(
            event.related_incident_ids,
            `${path}.related_incident_ids`,
        ),
        related_case_ids: stringsAt(
            event.related_case_ids,
            `${path}.related_case_ids`,
        ),
        raw_evidence_ref: stringAt(event.raw_evidence_ref, `${path}.raw_evidence_ref`),
    };
}

export function parseSecurityEventList(
    value: unknown,
): SecurityEventListResponse {
    const response = objectAt(value, "response");
    if (!Array.isArray(response.items))
        throw new ContractError("response.items");
    const pageValue = objectAt(response.page, "response.page");
    const sort = stringAt(pageValue.sort, "response.page.sort");
    if (sort !== "newest" && sort !== "oldest")
        throw new ContractError("response.page.sort");
    return {
        items: response.items.map((item, index) =>
            eventSummaryAt(item, `response.items[${index}]`),
        ),
        page: { ...pageAt(response.page, "response.page"), sort },
    };
}

export function parseSavedEventSearch(
    value: unknown,
    path = "saved_search",
): SavedEventSearch {
    const row = objectAt(value, path);
    const query = objectAt(row.query, `${path}.query`);
    const sort = stringAt(query.sort, `${path}.query.sort`);
    if (sort !== "newest" && sort !== "oldest")
        throw new ContractError(`${path}.query.sort`);
    const sourceType =
        query.source_type == null
            ? undefined
            : eventSourceAt(query.source_type, `${path}.query.source_type`);
    const relativeMinutes =
        query.relative_minutes == null
            ? undefined
            : integerAt(
                  query.relative_minutes,
                  `${path}.query.relative_minutes`,
                  1,
              );
    if (
        relativeMinutes !== undefined &&
        ![15, 60, 1440, 10080, 43200].includes(relativeMinutes)
    )
        throw new ContractError(`${path}.query.relative_minutes`);
    return {
        saved_search_id: stringAt(
            row.saved_search_id,
            `${path}.saved_search_id`,
        ),
        name: stringAt(row.name, `${path}.name`),
        created_at: dateAt(row.created_at, `${path}.created_at`),
        updated_at: dateAt(row.updated_at, `${path}.updated_at`),
        query: {
            relativeMinutes:
                relativeMinutes as SavedEventSearch["query"]["relativeMinutes"],
            startTime:
                query.start_time == null
                    ? undefined
                    : dateAt(query.start_time, `${path}.query.start_time`),
            endTime:
                query.end_time == null
                    ? undefined
                    : dateAt(query.end_time, `${path}.query.end_time`),
            sourceIp:
                query.source_ip == null
                    ? undefined
                    : stringAt(query.source_ip, `${path}.query.source_ip`),
            destinationIp:
                query.destination_ip == null
                    ? undefined
                    : stringAt(
                          query.destination_ip,
                          `${path}.query.destination_ip`,
                      ),
            hostname:
                query.hostname == null
                    ? undefined
                    : stringAt(query.hostname, `${path}.query.hostname`),
            username:
                query.username == null
                    ? undefined
                    : stringAt(query.username, `${path}.query.username`),
            operatingSystem:
                query.operating_system == null
                    ? undefined
                    : stringAt(query.operating_system, `${path}.query.operating_system`),
            eventProvider:
                query.event_provider == null
                    ? undefined
                    : stringAt(query.event_provider, `${path}.query.event_provider`),
            eventChannel:
                query.event_channel == null
                    ? undefined
                    : stringAt(query.event_channel, `${path}.query.event_channel`),
            processName:
                query.process_name == null
                    ? undefined
                    : stringAt(query.process_name, `${path}.query.process_name`),
            eventId:
                query.event_id == null
                    ? undefined
                    : stringAt(query.event_id, `${path}.query.event_id`),
            ruleId:
                query.rule_id == null
                    ? undefined
                    : stringAt(query.rule_id, `${path}.query.rule_id`),
            eventCategory:
                query.event_category == null
                    ? undefined
                    : stringAt(
                          query.event_category,
                          `${path}.query.event_category`,
                      ),
            eventAction:
                query.event_action == null
                    ? undefined
                    : stringAt(query.event_action, `${path}.query.event_action`),
            outcome:
                query.outcome == null
                    ? undefined
                    : stringAt(query.outcome, `${path}.query.outcome`),
            severityMin:
                query.severity_min == null
                    ? undefined
                    : integerAt(
                          query.severity_min,
                          `${path}.query.severity_min`,
                      ),
            severityMax:
                query.severity_max == null
                    ? undefined
                    : integerAt(
                          query.severity_max,
                          `${path}.query.severity_max`,
                      ),
            sourceType,
            search:
                query.search == null
                    ? undefined
                    : stringAt(query.search, `${path}.query.search`),
            sort,
        },
    };
}

export function parseSavedEventSearches(value: unknown): SavedEventSearch[] {
    if (!Array.isArray(value)) throw new ContractError("saved_searches");
    return value.map((item, index) =>
        parseSavedEventSearch(item, `saved_searches[${index}]`),
    );
}

function namedCountsAt(
    value: unknown,
    path: string,
): Array<{ name: string; count: number }> {
    if (!Array.isArray(value)) throw new ContractError(path);
    return value.map((item, index) => {
        const entry = objectAt(item, `${path}[${index}]`);
        return {
            name: stringAt(entry.name, `${path}[${index}].name`),
            count: integerAt(entry.count, `${path}[${index}].count`),
        };
    });
}

function seriesAt(
    value: unknown,
    path: string,
): Array<{ timestamp: string; count: number }> {
    if (!Array.isArray(value)) throw new ContractError(path);
    return value.map((item, index) => {
        const entry = objectAt(item, `${path}[${index}]`);
        return {
            timestamp: dateAt(entry.timestamp, `${path}[${index}].timestamp`),
            count: integerAt(entry.count, `${path}[${index}].count`),
        };
    });
}

export function parseSecurityOverview(value: unknown): SecurityOverview {
    const overview = objectAt(value, "overview");
    const ingestion = objectAt(overview.ingestion, "overview.ingestion");
    const retention = objectAt(overview.retention, "overview.retention");
    const state = stringAt(ingestion.state, "overview.ingestion.state");
    if (!(["ACTIVE", "STALE", "EMPTY"] as const).includes(state as "ACTIVE"))
        throw new ContractError("overview.ingestion.state");
    const retentionState = stringAt(
        retention.state,
        "overview.retention.state",
    );
    if (
        retentionState !== "WITHIN_LIMIT" &&
        retentionState !== "AT_LIMIT" &&
        retentionState !== "OVER_LIMIT_PROTECTED"
    )
        throw new ContractError("overview.retention.state");
    if (
        !Array.isArray(overview.alerts_by_severity) ||
        !Array.isArray(overview.latest_high_alerts) ||
        !Array.isArray(overview.pipeline_activity)
    )
        throw new ContractError("overview");
    return {
        start_time: dateAt(overview.start_time, "overview.start_time"),
        end_time: dateAt(overview.end_time, "overview.end_time"),
        total_events: integerAt(overview.total_events, "overview.total_events"),
        total_alerts: integerAt(overview.total_alerts, "overview.total_alerts"),
        events_per_minute: nonnegativeNumberAt(
            overview.events_per_minute,
            "overview.events_per_minute",
        ),
        active_incidents: integerAt(
            overview.active_incidents,
            "overview.active_incidents",
        ),
        reporting_agents: integerAt(
            overview.reporting_agents,
            "overview.reporting_agents",
        ),
        active_sources: integerAt(
            overview.active_sources,
            "overview.active_sources",
        ),
        stale_sources: integerAt(
            overview.stale_sources,
            "overview.stale_sources",
        ),
        database_size_bytes: integerAt(
            overview.database_size_bytes,
            "overview.database_size_bytes",
        ),
        alerts_by_severity: overview.alerts_by_severity.map((item, index) => {
            const entry = objectAt(
                item,
                `overview.alerts_by_severity[${index}]`,
            );
            return {
                severity: stringAt(
                    entry.severity,
                    `overview.alerts_by_severity[${index}].severity`,
                ),
                count: integerAt(
                    entry.count,
                    `overview.alerts_by_severity[${index}].count`,
                ),
            };
        }),
        incidents_by_status: namedCountsAt(
            overview.incidents_by_status,
            "overview.incidents_by_status",
        ),
        events_over_time: seriesAt(
            overview.events_over_time,
            "overview.events_over_time",
        ),
        alerts_over_time: seriesAt(
            overview.alerts_over_time,
            "overview.alerts_over_time",
        ),
        top_source_ips: namedCountsAt(
            overview.top_source_ips,
            "overview.top_source_ips",
        ),
        top_hosts: namedCountsAt(overview.top_hosts, "overview.top_hosts"),
        top_destination_hosts: namedCountsAt(
            overview.top_destination_hosts,
            "overview.top_destination_hosts",
        ),
        top_rules: namedCountsAt(overview.top_rules, "overview.top_rules"),
        top_event_categories: namedCountsAt(
            overview.top_event_categories,
            "overview.top_event_categories",
        ),
        event_sources: namedCountsAt(
            overview.event_sources,
            "overview.event_sources",
        ),
        latest_high_alerts: overview.latest_high_alerts.map((item, index) => {
            const entry = objectAt(
                item,
                `overview.latest_high_alerts[${index}]`,
            );
            return {
                alert_id: stringAt(
                    entry.alert_id,
                    `overview.latest_high_alerts[${index}].alert_id`,
                ),
                timestamp: dateAt(
                    entry.timestamp,
                    `overview.latest_high_alerts[${index}].timestamp`,
                ),
                rule_id: stringAt(
                    entry.rule_id,
                    `overview.latest_high_alerts[${index}].rule_id`,
                ),
                severity: integerAt(
                    entry.severity,
                    `overview.latest_high_alerts[${index}].severity`,
                ),
                description: stringAt(
                    entry.description,
                    `overview.latest_high_alerts[${index}].description`,
                ),
                agent_name: stringAt(
                    entry.agent_name,
                    `overview.latest_high_alerts[${index}].agent_name`,
                ),
            };
        }),
        ingestion: {
            state: state as "ACTIVE" | "STALE" | "EMPTY",
            last_event_at:
                ingestion.last_event_at == null
                    ? null
                    : dateAt(
                          ingestion.last_event_at,
                          "overview.ingestion.last_event_at",
                      ),
            last_ingested_at:
                ingestion.last_ingested_at == null
                    ? null
                    : dateAt(
                          ingestion.last_ingested_at,
                          "overview.ingestion.last_ingested_at",
                      ),
            lag_seconds:
                ingestion.lag_seconds == null
                    ? null
                    : nonnegativeNumberAt(
                          ingestion.lag_seconds,
                          "overview.ingestion.lag_seconds",
                      ),
        },
        pipeline_activity: overview.pipeline_activity.map((item, index) => {
            const path = `overview.pipeline_activity[${index}]`;
            const row = objectAt(item, path);
            const component = stringAt(row.component, `${path}.component`);
            const activityState = stringAt(row.state, `${path}.state`);
            if (component !== "wazuh_sender" && component !== "event_shipper")
                throw new ContractError(`${path}.component`);
            if (
                !(["ACTIVE", "STALE", "EMPTY"] as const).includes(
                    activityState as "ACTIVE",
                )
            )
                throw new ContractError(`${path}.state`);
            if (row.evidence !== "DELIVERY_ACTIVITY")
                throw new ContractError(`${path}.evidence`);
            return {
                component,
                state: activityState as "ACTIVE" | "STALE" | "EMPTY",
                evidence: "DELIVERY_ACTIVITY" as const,
                last_delivery_at:
                    row.last_delivery_at == null
                        ? null
                        : dateAt(
                              row.last_delivery_at,
                              `${path}.last_delivery_at`,
                          ),
                delivered_records: integerAt(
                    row.delivered_records,
                    `${path}.delivered_records`,
                ),
            };
        }),
        retention: {
            state: retentionState,
            retention_days: integerAt(
                retention.retention_days,
                "overview.retention.retention_days",
                1,
            ),
            max_records: integerAt(
                retention.max_records,
                "overview.retention.max_records",
                100,
            ),
            retained_records: integerAt(
                retention.retained_records,
                "overview.retention.retained_records",
            ),
            protected_records: integerAt(
                retention.protected_records,
                "overview.retention.protected_records",
            ),
            over_limit_records: integerAt(
                retention.over_limit_records,
                "overview.retention.over_limit_records",
            ),
            usage_percent: nonnegativeNumberAt(
                retention.usage_percent,
                "overview.retention.usage_percent",
            ),
            oldest_event_at:
                retention.oldest_event_at == null
                    ? null
                    : dateAt(retention.oldest_event_at, "overview.retention.oldest_event_at"),
            newest_event_at:
                retention.newest_event_at == null
                    ? null
                    : dateAt(retention.newest_event_at, "overview.retention.newest_event_at"),
            last_run_at:
                retention.last_run_at == null
                    ? null
                    : dateAt(
                          retention.last_run_at,
                          "overview.retention.last_run_at",
                      ),
            last_deleted_count: integerAt(
                retention.last_deleted_count,
                "overview.retention.last_deleted_count",
            ),
        },
    };
}

function countRowsAt(
    value: unknown,
    path: string,
): Array<{ name: string; count: number }> {
    if (!Array.isArray(value)) throw new ContractError(path);
    return value.map((item, index) => {
        const row = objectAt(item, `${path}[${index}]`);
        return {
            name: stringAt(row.name, `${path}[${index}].name`),
            count: integerAt(row.count, `${path}[${index}].count`),
        };
    });
}

export function parseLogSources(value: unknown): LogSourceSummary[] {
    if (!Array.isArray(value)) throw new ContractError("sources");
    return value.map((item, index) => {
        const path = `sources[${index}]`;
        const row = objectAt(item, path);
        const health = stringAt(row.source_health, `${path}.source_health`);
        const pipelineHealth = stringAt(
            row.pipeline_health,
            `${path}.pipeline_health`,
        );
        if (health !== "ACTIVE" && health !== "STALE")
            throw new ContractError(`${path}.source_health`);
        if (!["ACTIVE", "STALE", "EMPTY"].includes(pipelineHealth))
            throw new ContractError(`${path}.pipeline_health`);
        if (stringAt(row.agent_status, `${path}.agent_status`) !== "UNKNOWN")
            throw new ContractError(`${path}.agent_status`);
        if (
            stringAt(row.pipeline_evidence, `${path}.pipeline_evidence`) !==
            "PERSISTED_DELIVERY_ACTIVITY"
        )
            throw new ContractError(`${path}.pipeline_evidence`);
        const queueDepth = nullableIntegerAt(
            row.queue_depth,
            `${path}.queue_depth`,
        );
        const cursorLag = nullableIntegerAt(
            row.archive_cursor_lag_bytes,
            `${path}.archive_cursor_lag_bytes`,
        );
        const availability = stringAt(
            row.data_availability,
            `${path}.data_availability`,
        );
        if (availability !== "AVAILABLE" && availability !== "NO_DATA")
            throw new ContractError(`${path}.data_availability`);
        return {
            source_name: stringAt(row.source_name, `${path}.source_name`),
            source_type: stringAt(row.source_type, `${path}.source_type`),
            hostname: nullableStringAt(row.hostname, `${path}.hostname`),
            agent_id: nullableStringAt(row.agent_id, `${path}.agent_id`),
            agent_name: nullableStringAt(row.agent_name, `${path}.agent_name`),
            last_event_at: dateAt(row.last_event_at, `${path}.last_event_at`),
            last_ingested_at: dateAt(
                row.last_ingested_at,
                `${path}.last_ingested_at`,
            ),
            ingestion_lag_seconds: nonnegativeNumberAt(
                row.ingestion_lag_seconds,
                `${path}.ingestion_lag_seconds`,
            ),
            event_count: integerAt(row.event_count, `${path}.event_count`),
            source_health: health,
            agent_status: "UNKNOWN",
            collection_method: stringAt(
                row.collection_method,
                `${path}.collection_method`,
            ),
            pipeline_health:
                pipelineHealth as LogSourceSummary["pipeline_health"],
            pipeline_evidence: "PERSISTED_DELIVERY_ACTIVITY",
            queue_depth: queueDepth,
            archive_cursor_lag_bytes: cursorLag,
            data_availability:
                availability as LogSourceSummary["data_availability"],
            last_error: nullableStringAt(row.last_error, `${path}.last_error`),
        };
    });
}

export function parseHosts(value: unknown): HostSummary[] {
    if (!Array.isArray(value)) throw new ContractError("hosts");
    return value.map((item, index) => {
        const path = `hosts[${index}]`;
        const row = objectAt(item, path);
        const platform = stringAt(row.platform, `${path}.platform`);
        const health = stringAt(row.source_health, `${path}.source_health`);
        if (!["WINDOWS", "LINUX", "UNKNOWN"].includes(platform))
            throw new ContractError(`${path}.platform`);
        if (health !== "ACTIVE" && health !== "STALE")
            throw new ContractError(`${path}.source_health`);
        if (stringAt(row.agent_status, `${path}.agent_status`) !== "UNKNOWN")
            throw new ContractError(`${path}.agent_status`);
        return {
            hostname: stringAt(row.hostname, `${path}.hostname`),
            agent_id: nullableStringAt(row.agent_id, `${path}.agent_id`),
            agent_name: nullableStringAt(row.agent_name, `${path}.agent_name`),
            platform: platform as HostSummary["platform"],
            agent_status: "UNKNOWN",
            source_health: health,
            last_seen: dateAt(row.last_seen, `${path}.last_seen`),
            alert_count: integerAt(row.alert_count, `${path}.alert_count`),
            event_count: integerAt(row.event_count, `${path}.event_count`),
            recent_detections: stringsAt(
                row.recent_detections,
                `${path}.recent_detections`,
            ),
        };
    });
}

const OPERATIONAL_STATES: OperationalState[] = ["HEALTHY", "DEGRADED", "UNAVAILABLE", "UNKNOWN"];
const OPERATIONAL_AUTHORITIES: OperationalAuthority[] = ["WAZUH_API", "OS_SERVICE_MANAGER", "DURABLE_SENDER_STATE", "DURABLE_SHIPPER_STATE", "APPLICATION_DATABASE"];

function operationalStateAt(value: unknown, path: string): OperationalState {
    const state = stringAt(value, path) as OperationalState;
    if (!OPERATIONAL_STATES.includes(state)) throw new ContractError(path);
    return state;
}

function operationalAuthorityAt(value: unknown, path: string): OperationalAuthority {
    const authority = stringAt(value, path) as OperationalAuthority;
    if (!OPERATIONAL_AUTHORITIES.includes(authority)) throw new ContractError(path);
    return authority;
}

export function parseOperationalOverview(value: unknown): OperationalOverview {
    const row = objectAt(value, "operations");
    if (!Array.isArray(row.components)) throw new ContractError("operations.components");
    if (!Array.isArray(row.recent_events)) throw new ContractError("operations.recent_events");
    const quality = objectAt(row.data_quality, "operations.data_quality");
    const measurement = objectAt(row.measurement, "operations.measurement");
    const storage = objectAt(row.storage_retention, "operations.storage_retention");
    const backlog = objectAt(row.archive_backlog, "operations.archive_backlog");
    const forward = objectAt(row.forward_ingestion, "operations.forward_ingestion");
    const inventory = objectAt(row.wazuh_inventory, "operations.wazuh_inventory");
    const performance = row.ingestion_performance == null
        ? null
        : objectAt(row.ingestion_performance, "operations.ingestion_performance");
    const inventoryState = stringAt(inventory.state, "operations.wazuh_inventory.state");
    const measurementState = enumAt(measurement.state, ["FRESH", "CACHED", "STALE", "UNKNOWN"] as const, "operations.measurement.state");
    const measurementReason = measurement.reason_code == null
        ? measurementState === "FRESH" ? "COMPUTED" : measurementState === "CACHED" ? "CACHE_HIT" : "REFRESH_FAILED"
        : enumAt(measurement.reason_code, ["COMPUTED", "CACHE_HIT", "REFRESH_IN_PROGRESS", "REFRESH_FAILED"] as const, "operations.measurement.reason_code");
    const legacyFieldCompleteness = quality.field_completeness_measurement == null;
    if (stringAt(measurement.execution_model, "operations.measurement.execution_model") !== "BOUNDED_THREADPOOL")
        throw new ContractError("operations.measurement.execution_model");
    if (inventoryState !== "AVAILABLE" && inventoryState !== "UNAVAILABLE")
        throw new ContractError("operations.wazuh_inventory.state");
    if (stringAt(inventory.authority, "operations.wazuh_inventory.authority") !== "WAZUH_API")
        throw new ContractError("operations.wazuh_inventory.authority");
    const retentionState = stringAt(storage.state, "operations.storage_retention.state");
    if (!["WITHIN_LIMIT", "AT_LIMIT", "OVER_LIMIT_PROTECTED"].includes(retentionState))
        throw new ContractError("operations.storage_retention.state");
    const backlogState = stringAt(backlog.state, "operations.archive_backlog.state");
    if (!["AVAILABLE", "UNAVAILABLE"].includes(backlogState))
        throw new ContractError("operations.archive_backlog.state");
    const generationState = stringAt(backlog.generation_state, "operations.archive_backlog.generation_state");
    if (!["TRACKED", "CURRENT_FILE_IDENTITY_ONLY", "UNAVAILABLE"].includes(generationState))
        throw new ContractError("operations.archive_backlog.generation_state");
    const replayState = stringAt(backlog.historical_replay_state, "operations.archive_backlog.historical_replay_state");
    if (!["NOT_CONFIGURED", "PAUSED", "RUNNING", "COMPLETE", "BLOCKED"].includes(replayState))
        throw new ContractError("operations.archive_backlog.historical_replay_state");
    const recoveryReadiness = stringAt(backlog.recovery_readiness, "operations.archive_backlog.recovery_readiness");
    if (!["BLOCKED_RETENTION_CAP", "READY_FOR_APPROVAL", "NOT_AUDITED"].includes(recoveryReadiness))
        throw new ContractError("operations.archive_backlog.recovery_readiness");
    const legacyCheckpointState = enumAt(forward.legacy_checkpoint_state, ["ACTIVE", "PAUSED", "BLOCKED", "UNKNOWN"] as const, "operations.forward_ingestion.legacy_checkpoint_state");
    const legacyContinuity = enumAt(forward.legacy_continuity, ["UNPROVEN", "PROVEN", "UNKNOWN"] as const, "operations.forward_ingestion.legacy_continuity");
    const forwardState = enumAt(forward.forward_state, ["NOT_DEPLOYED", "READY", "ACTIVE", "BLOCKED", "UNKNOWN"] as const, "operations.forward_ingestion.forward_state");
    const forwardReplayState = enumAt(forward.historical_replay_state, ["NOT_STARTED", "PAUSED", "RUNNING", "COMPLETE", "BLOCKED", "UNKNOWN"] as const, "operations.forward_ingestion.historical_replay_state");
    const approvalState = enumAt(forward.approval_state, ["ABSENT", "PRESENT_UNVERIFIED", "VALID", "EXPIRED", "MISMATCH", "INVALID", "UNKNOWN"] as const, "operations.forward_ingestion.approval_state");
    const approvalValidationBasis = enumAt(forward.approval_validation_basis, ["BOUNDED_SCOPE_TIME_IDENTITY", "PRESENCE_ONLY", "UNKNOWN"] as const, "operations.forward_ingestion.approval_validation_basis");
    const forwardBacklogTrend = enumAt(forward.net_backlog_trend, ["DRAINING", "GROWING", "STABLE", "UNKNOWN"] as const, "operations.forward_ingestion.net_backlog_trend");
    const forwardRateState = enumAt(forward.rate_measurement_state, ["FRESH", "STALE", "UNKNOWN"] as const, "operations.forward_ingestion.rate_measurement_state");
    const forwardRetentionPressure = enumAt(forward.retention_pressure, ["WITHIN_LIMIT", "AT_LIMIT", "OVER_LIMIT_PROTECTED"] as const, "operations.forward_ingestion.retention_pressure");
    if (stringAt(forward.historical_gap_warning, "operations.forward_ingestion.historical_gap_warning") !== "UNPROVEN_HISTORY_NOT_REPLAYED")
        throw new ContractError("operations.forward_ingestion.historical_gap_warning");
    const performanceMode = performance == null
        ? null
        : stringAt(performance.configured_mode, "operations.ingestion_performance.configured_mode");
    if (performanceMode != null && !["batch-available-disabled-by-default", "batch-enabled"].includes(performanceMode))
        throw new ContractError("operations.ingestion_performance.configured_mode");
    if (performance != null && stringAt(performance.measurement_scope, "operations.ingestion_performance.measurement_scope") !== "POST_PROCESS_START_ONLY")
        throw new ContractError("operations.ingestion_performance.measurement_scope");
    if (performance != null && stringAt(performance.ingress_protocol_version, "operations.ingestion_performance.ingress_protocol_version") !== "m18-batch-v1")
        throw new ContractError("operations.ingestion_performance.ingress_protocol_version");
    return {
        generated_at: dateAt(row.generated_at, "operations.generated_at"),
        measurement: {
            state: measurementState,
            measured_at: dateAt(measurement.measured_at, "operations.measurement.measured_at"),
            age_seconds: nonnegativeNumberAt(measurement.age_seconds, "operations.measurement.age_seconds"),
            duration_ms: nonnegativeNumberAt(measurement.duration_ms, "operations.measurement.duration_ms"),
            cache_ttl_seconds: nonnegativeNumberAt(measurement.cache_ttl_seconds, "operations.measurement.cache_ttl_seconds"),
            stale_ttl_seconds: measurement.stale_ttl_seconds == null ? nonnegativeNumberAt(measurement.cache_ttl_seconds, "operations.measurement.cache_ttl_seconds") : nonnegativeNumberAt(measurement.stale_ttl_seconds, "operations.measurement.stale_ttl_seconds"),
            query_deadline_seconds: measurement.query_deadline_seconds == null ? 2 : nonnegativeNumberAt(measurement.query_deadline_seconds, "operations.measurement.query_deadline_seconds"),
            reason_code: measurementReason,
            cache_hits: measurement.cache_hits == null ? 0 : integerAt(measurement.cache_hits, "operations.measurement.cache_hits"),
            cache_misses: measurement.cache_misses == null ? 0 : integerAt(measurement.cache_misses, "operations.measurement.cache_misses"),
            singleflight_joins: measurement.singleflight_joins == null ? 0 : integerAt(measurement.singleflight_joins, "operations.measurement.singleflight_joins"),
            stale_served: measurement.stale_served == null ? 0 : integerAt(measurement.stale_served, "operations.measurement.stale_served"),
            inflight_queries: measurement.inflight_queries == null ? 0 : integerAt(measurement.inflight_queries, "operations.measurement.inflight_queries"),
            pending_waiters: measurement.pending_waiters == null ? 0 : integerAt(measurement.pending_waiters, "operations.measurement.pending_waiters"),
            execution_model: "BOUNDED_THREADPOOL",
        },
        snapshot_collected_at: row.snapshot_collected_at == null ? null : dateAt(row.snapshot_collected_at, "operations.snapshot_collected_at"),
        snapshot_age_seconds: row.snapshot_age_seconds == null ? null : nonnegativeNumberAt(row.snapshot_age_seconds, "operations.snapshot_age_seconds"),
        components: row.components.map((value, index) => {
            const path = `operations.components[${index}]`;
            const item = objectAt(value, path);
            const kind = stringAt(item.component_kind, `${path}.component_kind`);
            if (!["manager", "wazuh_api", "sender", "event_shipper", "windows_agent", "database", "telemetry_source"].includes(kind))
                throw new ContractError(`${path}.component_kind`);
            return {
                component_key: boundedStringAt(item.component_key, `${path}.component_key`, 128),
                component_kind: kind as OperationalOverview["components"][number]["component_kind"],
                state: operationalStateAt(item.state, `${path}.state`),
                authority: operationalAuthorityAt(item.authority, `${path}.authority`),
                summary: boundedStringAt(item.summary, `${path}.summary`, 320),
                metrics: objectAt(item.metrics, `${path}.metrics`),
                last_error: nullableStringAt(item.last_error, `${path}.last_error`),
                observed_at: dateAt(item.observed_at, `${path}.observed_at`),
                first_observed_at: dateAt(item.first_observed_at, `${path}.first_observed_at`),
                updated_at: dateAt(item.updated_at, `${path}.updated_at`),
                version: integerAt(item.version, `${path}.version`, 1),
            };
        }),
        recent_events: row.recent_events.map((value, index) => {
            const path = `operations.recent_events[${index}]`;
            const item = objectAt(value, path);
            const eventType = stringAt(item.event_type, `${path}.event_type`);
            const severity = stringAt(item.severity, `${path}.severity`);
            if (!["ISSUE", "RECOVERY", "STATUS_CHANGE"].includes(eventType)) throw new ContractError(`${path}.event_type`);
            if (!["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(severity)) throw new ContractError(`${path}.severity`);
            return {
                event_id: stringAt(item.event_id, `${path}.event_id`),
                component_key: stringAt(item.component_key, `${path}.component_key`),
                event_type: eventType as OperationalOverview["recent_events"][number]["event_type"],
                severity: severity as OperationalOverview["recent_events"][number]["severity"],
                previous_state: item.previous_state == null ? null : operationalStateAt(item.previous_state, `${path}.previous_state`),
                current_state: operationalStateAt(item.current_state, `${path}.current_state`),
                authority: operationalAuthorityAt(item.authority, `${path}.authority`),
                summary: stringAt(item.summary, `${path}.summary`),
                details: objectAt(item.details, `${path}.details`),
                occurred_at: dateAt(item.occurred_at, `${path}.occurred_at`),
            };
        }),
        data_quality: {
            total_events: integerAt(quality.total_events, "operations.data_quality.total_events"),
            total_events_scope: quality.total_events_scope == null ? "CURRENT_RETAINED_DATABASE" : enumAt(quality.total_events_scope, ["CURRENT_RETAINED_DATABASE"] as const, "operations.data_quality.total_events_scope"),
            total_events_measurement: quality.total_events_measurement == null ? "EXACT" : enumAt(quality.total_events_measurement, ["EXACT"] as const, "operations.data_quality.total_events_measurement"),
            raw_evidence_records: nullableIntegerAt(quality.raw_evidence_records, "operations.data_quality.raw_evidence_records"),
            missing_hostname: nullableIntegerAt(quality.missing_hostname, "operations.data_quality.missing_hostname"),
            missing_username: nullableIntegerAt(quality.missing_username, "operations.data_quality.missing_username"),
            missing_rule_id: nullableIntegerAt(quality.missing_rule_id, "operations.data_quality.missing_rule_id"),
            field_completeness_measurement: legacyFieldCompleteness ? "EXACT" : enumAt(quality.field_completeness_measurement, ["UNKNOWN", "EXACT"] as const, "operations.data_quality.field_completeness_measurement"),
            field_completeness_reason: quality.field_completeness_reason == null ? "LEGACY_LIVE_FULL_SCAN" : enumAt(quality.field_completeness_reason, ["NOT_MATERIALIZED_SCHEMA17", "LEGACY_LIVE_FULL_SCAN"] as const, "operations.data_quality.field_completeness_reason"),
            duplicate_events: nullableIntegerAt(quality.duplicate_events, "operations.data_quality.duplicate_events"),
            duplicate_events_scope: quality.duplicate_events_scope == null ? "UNKNOWN" : enumAt(quality.duplicate_events_scope, ["CURRENT_SENDER_STATE", "UNKNOWN"] as const, "operations.data_quality.duplicate_events_scope"),
            malformed_events: nullableIntegerAt(quality.malformed_events, "operations.data_quality.malformed_events"),
            oversized_events: nullableIntegerAt(quality.oversized_events, "operations.data_quality.oversized_events"),
            delivery_rejected: nullableIntegerAt(quality.delivery_rejected, "operations.data_quality.delivery_rejected"),
            shipper_counters_scope: quality.shipper_counters_scope == null ? "UNKNOWN" : enumAt(quality.shipper_counters_scope, ["CURRENT_FORWARD_GENERATION", "UNKNOWN"] as const, "operations.data_quality.shipper_counters_scope"),
            evidence: stringAt(quality.evidence, "operations.data_quality.evidence") as OperationalOverview["data_quality"]["evidence"],
        },
        storage_retention: {
            schema_version: integerAt(storage.schema_version, "operations.storage_retention.schema_version"),
            state: retentionState as OperationalOverview["storage_retention"]["state"],
            retention_days: integerAt(storage.retention_days, "operations.storage_retention.retention_days", 1),
            max_records: integerAt(storage.max_records, "operations.storage_retention.max_records", 1),
            retained_records: integerAt(storage.retained_records, "operations.storage_retention.retained_records"),
            protected_records: integerAt(storage.protected_records, "operations.storage_retention.protected_records"),
            over_limit_records: integerAt(storage.over_limit_records, "operations.storage_retention.over_limit_records"),
            usage_percent: nonnegativeNumberAt(storage.usage_percent, "operations.storage_retention.usage_percent"),
            database_size_bytes: integerAt(storage.database_size_bytes, "operations.storage_retention.database_size_bytes"),
            wal_size_bytes: integerAt(storage.wal_size_bytes, "operations.storage_retention.wal_size_bytes"),
            last_run_at: storage.last_run_at == null ? null : dateAt(storage.last_run_at, "operations.storage_retention.last_run_at"),
            last_deleted_count: integerAt(storage.last_deleted_count, "operations.storage_retention.last_deleted_count"),
            oldest_event_at: storage.oldest_event_at == null ? null : dateAt(storage.oldest_event_at, "operations.storage_retention.oldest_event_at"),
            newest_event_at: storage.newest_event_at == null ? null : dateAt(storage.newest_event_at, "operations.storage_retention.newest_event_at"),
            last_ingested_at: storage.last_ingested_at == null ? null : dateAt(storage.last_ingested_at, "operations.storage_retention.last_ingested_at"),
        },
        archive_backlog: {
            state: backlogState as OperationalOverview["archive_backlog"]["state"],
            generation_state: generationState as OperationalOverview["archive_backlog"]["generation_state"],
            historical_replay_state: replayState as OperationalOverview["archive_backlog"]["historical_replay_state"],
            archive_size_bytes: nullableIntegerAt(backlog.archive_size_bytes, "operations.archive_backlog.archive_size_bytes"),
            cursor_bytes: nullableIntegerAt(backlog.cursor_bytes, "operations.archive_backlog.cursor_bytes"),
            current_lag_bytes: nullableIntegerAt(backlog.current_lag_bytes, "operations.archive_backlog.current_lag_bytes"),
            current_eligible_records: nullableIntegerAt(backlog.current_eligible_records, "operations.archive_backlog.current_eligible_records"),
            current_filtered_records: nullableIntegerAt(backlog.current_filtered_records, "operations.archive_backlog.current_filtered_records"),
            current_malformed_records: nullableIntegerAt(backlog.current_malformed_records, "operations.archive_backlog.current_malformed_records"),
            rotated_archive_count: nullableIntegerAt(backlog.rotated_archive_count, "operations.archive_backlog.rotated_archive_count"),
            historical_eligible_records: nullableIntegerAt(backlog.historical_eligible_records, "operations.archive_backlog.historical_eligible_records"),
            recovery_readiness: recoveryReadiness as OperationalOverview["archive_backlog"]["recovery_readiness"],
        },
        forward_ingestion: {
            legacy_checkpoint_state: legacyCheckpointState,
            legacy_continuity: legacyContinuity,
            forward_state: forwardState,
            historical_replay_state: forwardReplayState,
            approval_state: approvalState,
            approval_validation_basis: approvalValidationBasis,
            approval_expires_at: forward.approval_expires_at == null ? null : dateAt(forward.approval_expires_at, "operations.forward_ingestion.approval_expires_at"),
            approval_remaining_seconds: forward.approval_remaining_seconds == null ? null : nonnegativeNumberAt(forward.approval_remaining_seconds, "operations.forward_ingestion.approval_remaining_seconds"),
            generation_id: nullableStringAt(forward.generation_id, "operations.forward_ingestion.generation_id"),
            source_device: nullableIntegerAt(forward.source_device, "operations.forward_ingestion.source_device"),
            source_inode: nullableIntegerAt(forward.source_inode, "operations.forward_ingestion.source_inode"),
            source_size_bytes: nullableIntegerAt(forward.source_size_bytes, "operations.forward_ingestion.source_size_bytes"),
            start_offset_bytes: nullableIntegerAt(forward.start_offset_bytes, "operations.forward_ingestion.start_offset_bytes"),
            cursor_bytes: nullableIntegerAt(forward.cursor_bytes, "operations.forward_ingestion.cursor_bytes"),
            lag_bytes: nullableIntegerAt(forward.lag_bytes, "operations.forward_ingestion.lag_bytes"),
            unique_insertions: nullableIntegerAt(forward.unique_insertions, "operations.forward_ingestion.unique_insertions"),
            duplicate_acknowledgements: nullableIntegerAt(forward.duplicate_acknowledgements, "operations.forward_ingestion.duplicate_acknowledgements"),
            filtered_records: nullableIntegerAt(forward.filtered_records, "operations.forward_ingestion.filtered_records"),
            malformed_records: nullableIntegerAt(forward.malformed_records, "operations.forward_ingestion.malformed_records"),
            retry_attempts: nullableIntegerAt(forward.retry_attempts, "operations.forward_ingestion.retry_attempts"),
            protocol_errors: nullableIntegerAt(forward.protocol_errors, "operations.forward_ingestion.protocol_errors"),
            delivery_rejected: nullableIntegerAt(forward.delivery_rejected, "operations.forward_ingestion.delivery_rejected"),
            source_identity_matches: forward.source_identity_matches == null ? null : booleanAt(forward.source_identity_matches, "operations.forward_ingestion.source_identity_matches"),
            legacy_state_unchanged: forward.legacy_state_unchanged == null ? null : booleanAt(forward.legacy_state_unchanged, "operations.forward_ingestion.legacy_state_unchanged"),
            service_active: booleanAt(forward.service_active, "operations.forward_ingestion.service_active"),
            archive_growth_bytes_per_second: forward.archive_growth_bytes_per_second == null ? null : nonnegativeNumberAt(forward.archive_growth_bytes_per_second, "operations.forward_ingestion.archive_growth_bytes_per_second"),
            cursor_progress_bytes_per_second: forward.cursor_progress_bytes_per_second == null ? null : nonnegativeNumberAt(forward.cursor_progress_bytes_per_second, "operations.forward_ingestion.cursor_progress_bytes_per_second"),
            net_lag_bytes_per_second: forward.net_lag_bytes_per_second == null ? null : finiteNumberAt(forward.net_lag_bytes_per_second, "operations.forward_ingestion.net_lag_bytes_per_second"),
            net_backlog_trend: forwardBacklogTrend,
            rate_measurement_state: forwardRateState,
            unreconciled_historical_records: nullableIntegerAt(forward.unreconciled_historical_records, "operations.forward_ingestion.unreconciled_historical_records"),
            retention_pressure: forwardRetentionPressure,
            last_successful_delivery: forward.last_successful_delivery == null ? null : dateAt(forward.last_successful_delivery, "operations.forward_ingestion.last_successful_delivery"),
            checkpoint_updated_at: forward.checkpoint_updated_at == null ? null : dateAt(forward.checkpoint_updated_at, "operations.forward_ingestion.checkpoint_updated_at"),
            historical_gap_warning: "UNPROVEN_HISTORY_NOT_REPLAYED",
        },
        wazuh_inventory: {
            state: inventoryState,
            authority: "WAZUH_API",
            reason: boundedStringAt(inventory.reason, "operations.wazuh_inventory.reason", 320),
            manager_identity: nullableStringAt(inventory.manager_identity, "operations.wazuh_inventory.manager_identity"),
            agent_count: nullableIntegerAt(inventory.agent_count, "operations.wazuh_inventory.agent_count"),
        },
        ...(performance == null ? {} : {
            ingestion_performance: {
                measurement_scope: stringAt(performance.measurement_scope, "operations.ingestion_performance.measurement_scope") as "POST_PROCESS_START_ONLY",
                started_at: dateAt(performance.started_at, "operations.ingestion_performance.started_at"),
                ...(performance.captured_at == null ? {} : { captured_at: dateAt(performance.captured_at, "operations.ingestion_performance.captured_at") }),
                ...(performance.measurement_window_seconds == null ? {} : { measurement_window_seconds: nonnegativeNumberAt(performance.measurement_window_seconds, "operations.ingestion_performance.measurement_window_seconds") }),
                ...(performance.request_latency_sample_size == null ? {} : { request_latency_sample_size: integerAt(performance.request_latency_sample_size, "operations.ingestion_performance.request_latency_sample_size") }),
                ...(performance.active_request_mode == null ? {} : { active_request_mode: enumAt(performance.active_request_mode, ["single-event", "batch"] as const, "operations.ingestion_performance.active_request_mode") }),
                ...(performance.execution_model == null ? {} : { execution_model: enumAt(performance.execution_model, ["bounded-threadpool"] as const, "operations.ingestion_performance.execution_model") }),
                ingress_protocol_version: stringAt(performance.ingress_protocol_version, "operations.ingestion_performance.ingress_protocol_version") as "m18-batch-v1",
                configured_mode: performanceMode as "batch-available-disabled-by-default" | "batch-enabled",
                batch_endpoint_enabled: booleanAt(performance.batch_endpoint_enabled, "operations.ingestion_performance.batch_endpoint_enabled"),
                configured_batch_limit: integerAt(performance.configured_batch_limit, "operations.ingestion_performance.configured_batch_limit", 1),
                requests: integerAt(performance.requests, "operations.ingestion_performance.requests"),
                single_requests: integerAt(performance.single_requests, "operations.ingestion_performance.single_requests"),
                batch_requests: integerAt(performance.batch_requests, "operations.ingestion_performance.batch_requests"),
                events: integerAt(performance.events, "operations.ingestion_performance.events"),
                inserted: integerAt(performance.inserted, "operations.ingestion_performance.inserted"),
                duplicates: integerAt(performance.duplicates, "operations.ingestion_performance.duplicates"),
                retryable_failures: integerAt(performance.retryable_failures, "operations.ingestion_performance.retryable_failures"),
                permanent_failures: integerAt(performance.permanent_failures, "operations.ingestion_performance.permanent_failures"),
                requests_per_second: nonnegativeNumberAt(performance.requests_per_second, "operations.ingestion_performance.requests_per_second"),
                events_per_second: nonnegativeNumberAt(performance.events_per_second, "operations.ingestion_performance.events_per_second"),
                inserts_per_second: nonnegativeNumberAt(performance.inserts_per_second, "operations.ingestion_performance.inserts_per_second"),
                duplicates_per_second: nonnegativeNumberAt(performance.duplicates_per_second, "operations.ingestion_performance.duplicates_per_second"),
                events_per_request: performance.events_per_request == null ? null : nonnegativeNumberAt(performance.events_per_request, "operations.ingestion_performance.events_per_request"),
                request_latency_p50_ms: performance.request_latency_p50_ms == null ? null : nonnegativeNumberAt(performance.request_latency_p50_ms, "operations.ingestion_performance.request_latency_p50_ms"),
                request_latency_p95_ms: performance.request_latency_p95_ms == null ? null : nonnegativeNumberAt(performance.request_latency_p95_ms, "operations.ingestion_performance.request_latency_p95_ms"),
                database_latency_p50_ms: performance.database_latency_p50_ms == null ? null : nonnegativeNumberAt(performance.database_latency_p50_ms, "operations.ingestion_performance.database_latency_p50_ms"),
                database_latency_p95_ms: performance.database_latency_p95_ms == null ? null : nonnegativeNumberAt(performance.database_latency_p95_ms, "operations.ingestion_performance.database_latency_p95_ms"),
                transaction_latency_p50_ms: performance.transaction_latency_p50_ms == null ? null : nonnegativeNumberAt(performance.transaction_latency_p50_ms, "operations.ingestion_performance.transaction_latency_p50_ms"),
                transaction_latency_p95_ms: performance.transaction_latency_p95_ms == null ? null : nonnegativeNumberAt(performance.transaction_latency_p95_ms, "operations.ingestion_performance.transaction_latency_p95_ms"),
                retention_latency_p50_ms: performance.retention_latency_p50_ms == null ? null : nonnegativeNumberAt(performance.retention_latency_p50_ms, "operations.ingestion_performance.retention_latency_p50_ms"),
                retention_latency_p95_ms: performance.retention_latency_p95_ms == null ? null : nonnegativeNumberAt(performance.retention_latency_p95_ms, "operations.ingestion_performance.retention_latency_p95_ms"),
                lock_wait_latency_p50_ms: performance.lock_wait_latency_p50_ms == null ? null : nonnegativeNumberAt(performance.lock_wait_latency_p50_ms, "operations.ingestion_performance.lock_wait_latency_p50_ms"),
                lock_wait_latency_p95_ms: performance.lock_wait_latency_p95_ms == null ? null : nonnegativeNumberAt(performance.lock_wait_latency_p95_ms, "operations.ingestion_performance.lock_wait_latency_p95_ms"),
                commit_latency_p50_ms: performance.commit_latency_p50_ms == null ? null : nonnegativeNumberAt(performance.commit_latency_p50_ms, "operations.ingestion_performance.commit_latency_p50_ms"),
                commit_latency_p95_ms: performance.commit_latency_p95_ms == null ? null : nonnegativeNumberAt(performance.commit_latency_p95_ms, "operations.ingestion_performance.commit_latency_p95_ms"),
                retention_candidate_latency_p95_ms: performance.retention_candidate_latency_p95_ms == null ? null : nonnegativeNumberAt(performance.retention_candidate_latency_p95_ms, "operations.ingestion_performance.retention_candidate_latency_p95_ms"),
                protected_check_latency_p95_ms: performance.protected_check_latency_p95_ms == null ? null : nonnegativeNumberAt(performance.protected_check_latency_p95_ms, "operations.ingestion_performance.protected_check_latency_p95_ms"),
                timeout_count: performance.timeout_count == null ? 0 : integerAt(performance.timeout_count, "operations.ingestion_performance.timeout_count"),
                pre_commit_deadline_violations: performance.pre_commit_deadline_violations == null ? 0 : integerAt(performance.pre_commit_deadline_violations, "operations.ingestion_performance.pre_commit_deadline_violations"),
                sqlite_busy_errors: performance.sqlite_busy_errors == null ? 0 : integerAt(performance.sqlite_busy_errors, "operations.ingestion_performance.sqlite_busy_errors"),
                last_failure_stage: nullableStringAt(performance.last_failure_stage, "operations.ingestion_performance.last_failure_stage"),
                last_successful_acknowledgement: performance.last_successful_acknowledgement == null ? null : dateAt(performance.last_successful_acknowledgement, "operations.ingestion_performance.last_successful_acknowledgement"),
                last_successful_acknowledgement_age_seconds: performance.last_successful_acknowledgement_age_seconds == null ? null : nonnegativeNumberAt(performance.last_successful_acknowledgement_age_seconds, "operations.ingestion_performance.last_successful_acknowledgement_age_seconds"),
                last_error: nullableStringAt(performance.last_error, "operations.ingestion_performance.last_error"),
                historical_unique_insertions: nullableIntegerAt(performance.historical_unique_insertions, "operations.ingestion_performance.historical_unique_insertions"),
                historical_duplicate_acknowledgements: nullableIntegerAt(performance.historical_duplicate_acknowledgements, "operations.ingestion_performance.historical_duplicate_acknowledgements"),
            },
        }),
    };
}

const AGENT_CONNECTION_STATUSES = ["ONLINE", "DISCONNECTED", "NEVER_CONNECTED", "UNKNOWN"] as const;
const AGENT_AUTHORITIES = ["WAZUH_API", "TELEMETRY_EVIDENCE"] as const;
const FRESHNESS_STATES = ["ACTIVE", "STALE", "NO_DATA"] as const;

function nullableDate(value: unknown, path: string): string | null {
    return value == null ? null : dateAt(value, path);
}

function agentSummaryAt(value: unknown, path: string): AgentSummary {
    const row = objectAt(value, path);
    const serviceStatus = enumAt(row.service_status, ["RUNNING", "STOPPED", "UNKNOWN"] as const, `${path}.service_status`);
    const enrollmentStatus = enumAt(row.enrollment_status, ["ENROLLED", "NEVER_ENROLLED", "UNKNOWN"] as const, `${path}.enrollment_status`);
    const pipelineHealth = enumAt(row.pipeline_health, ["ACTIVE", "STALE", "EMPTY"] as const, `${path}.pipeline_health`);
    return {
        agent_key: stringAt(row.agent_key, `${path}.agent_key`),
        agent_id: stringAt(row.agent_id, `${path}.agent_id`),
        name: stringAt(row.name, `${path}.name`),
        operating_system: nullableStringAt(row.operating_system, `${path}.operating_system`),
        os_platform: nullableStringAt(row.os_platform, `${path}.os_platform`),
        os_version: nullableStringAt(row.os_version, `${path}.os_version`),
        agent_version: nullableStringAt(row.agent_version, `${path}.agent_version`),
        manager: nullableStringAt(row.manager, `${path}.manager`),
        ip_address: nullableStringAt(row.ip_address, `${path}.ip_address`),
        groups: stringsAt(row.groups, `${path}.groups`),
        service_status: serviceStatus,
        enrollment_status: enrollmentStatus,
        connection_status: enumAt(row.connection_status, AGENT_CONNECTION_STATUSES, `${path}.connection_status`) as AgentConnectionStatus,
        status_authority: enumAt(row.status_authority, AGENT_AUTHORITIES, `${path}.status_authority`) as AgentStatusAuthority,
        last_keepalive: nullableDate(row.last_keepalive, `${path}.last_keepalive`),
        disconnected_at: nullableDate(row.disconnected_at, `${path}.disconnected_at`),
        enrolled_at: nullableDate(row.enrolled_at, `${path}.enrolled_at`),
        last_security_event: nullableDate(row.last_security_event, `${path}.last_security_event`),
        data_freshness: enumAt(row.data_freshness, FRESHNESS_STATES, `${path}.data_freshness`) as FreshnessState,
        pipeline_health: pipelineHealth,
        observed_at: dateAt(row.observed_at, `${path}.observed_at`),
        cache_expires_at: nullableDate(row.cache_expires_at, `${path}.cache_expires_at`),
        cache_stale: booleanAt(row.cache_stale, `${path}.cache_stale`),
        observed_only: booleanAt(row.observed_only, `${path}.observed_only`),
    };
}

export function parseAgentList(value: unknown): AgentListResponse {
    const row = objectAt(value, "agents");
    if (!Array.isArray(row.items)) throw new ContractError("agents.items");
    const page = objectAt(row.page, "agents.page");
    const age = row.cache_age_seconds == null ? null : nonnegativeNumberAt(row.cache_age_seconds, "agents.cache_age_seconds");
    return {
        items: row.items.map((item, index) => agentSummaryAt(item, `agents.items[${index}]`)),
        page: {
            limit: integerAt(page.limit, "agents.page.limit"),
            offset: integerAt(page.offset, "agents.page.offset"),
            total: integerAt(page.total, "agents.page.total"),
        },
        authoritative_inventory: booleanAt(row.authoritative_inventory, "agents.authoritative_inventory"),
        partial: booleanAt(row.partial, "agents.partial"),
        observation_timestamp: dateAt(row.observation_timestamp, "agents.observation_timestamp"),
        cache_age_seconds: age,
        message: stringAt(row.message, "agents.message"),
    };
}

export function parseAgentDetail(value: unknown): AgentDetail {
    const row = objectAt(value, "agent");
    if (!Array.isArray(row.telemetry_sources)) throw new ContractError("agent.telemetry_sources");
    return {
        ...agentSummaryAt(row, "agent"),
        telemetry_sources: row.telemetry_sources.map((value, index) => {
            const source = objectAt(value, `agent.telemetry_sources[${index}]`);
            return {
                source_type: stringAt(source.source_type, `agent.telemetry_sources[${index}].source_type`),
                ingestion_source: stringAt(source.ingestion_source, `agent.telemetry_sources[${index}].ingestion_source`),
                last_event_at: dateAt(source.last_event_at, `agent.telemetry_sources[${index}].last_event_at`),
                last_ingested_at: dateAt(source.last_ingested_at, `agent.telemetry_sources[${index}].last_ingested_at`),
                event_count: integerAt(source.event_count, `agent.telemetry_sources[${index}].event_count`),
                freshness: enumAt(source.freshness, FRESHNESS_STATES, `agent.telemetry_sources[${index}].freshness`) as FreshnessState,
            };
        }),
        recent_event_ids: stringsAt(row.recent_event_ids, "agent.recent_event_ids"),
        related_alert_ids: stringsAt(row.related_alert_ids, "agent.related_alert_ids"),
        related_incident_ids: stringsAt(row.related_incident_ids, "agent.related_incident_ids"),
        troubleshooting: stringsAt(row.troubleshooting, "agent.troubleshooting"),
    };
}

export function parseAgentHealth(value: unknown): AgentHealthResponse {
    const row = objectAt(value, "agent_health");
    if (!Array.isArray(row.items)) throw new ContractError("agent_health.items");
    return {
        agent_key: stringAt(row.agent_key, "agent_health.agent_key"),
        status_authority: enumAt(row.status_authority, AGENT_AUTHORITIES, "agent_health.status_authority") as AgentStatusAuthority,
        items: row.items.map((value, index) => {
            const item = objectAt(value, `agent_health.items[${index}]`);
            const previous = item.previous_status == null ? null : enumAt(item.previous_status, AGENT_CONNECTION_STATUSES, `agent_health.items[${index}].previous_status`);
            if (item.authority !== "WAZUH_API") throw new ContractError(`agent_health.items[${index}].authority`);
            return {
                history_id: stringAt(item.history_id, `agent_health.items[${index}].history_id`),
                connection_status: enumAt(item.connection_status, AGENT_CONNECTION_STATUSES, `agent_health.items[${index}].connection_status`) as AgentConnectionStatus,
                previous_status: previous,
                authority: "WAZUH_API" as const,
                observed_at: dateAt(item.observed_at, `agent_health.items[${index}].observed_at`),
                details: objectAt(item.details, `agent_health.items[${index}].details`),
            };
        }),
    };
}

export function parseWazuhIntegrationStatus(value: unknown): WazuhIntegrationStatus {
    const row = objectAt(value, "wazuh_integration");
    const state = enumAt(row.state, ["AVAILABLE", "UNAVAILABLE"] as const, "wazuh_integration.state");
    const health = row.manager_health == null ? null : enumAt(row.manager_health, ["HEALTHY", "DEGRADED", "UNKNOWN"] as const, "wazuh_integration.manager_health");
    const tls = enumAt(row.tls_verification, ["SYSTEM_TRUST", "CUSTOM_CA"] as const, "wazuh_integration.tls_verification");
    if (row.authority !== "WAZUH_API" || row.connectivity_scope !== "HTTPS_LOOPBACK" || row.read_only !== true) throw new ContractError("wazuh_integration.security");
    return {
        state,
        configured: booleanAt(row.configured, "wazuh_integration.configured"),
        authority: "WAZUH_API",
        reason: stringAt(row.reason, "wazuh_integration.reason"),
        manager_identity: nullableStringAt(row.manager_identity, "wazuh_integration.manager_identity"),
        manager_version: nullableStringAt(row.manager_version, "wazuh_integration.manager_version"),
        manager_health: health,
        agent_count: nullableIntegerAt(row.agent_count, "wazuh_integration.agent_count"),
        rejected_agent_count: integerAt(row.rejected_agent_count, "wazuh_integration.rejected_agent_count"),
        observed_at: dateAt(row.observed_at, "wazuh_integration.observed_at"),
        cache_expires_at: dateAt(row.cache_expires_at, "wazuh_integration.cache_expires_at"),
        cache_age_seconds: nonnegativeNumberAt(row.cache_age_seconds, "wazuh_integration.cache_age_seconds"),
        cache_stale: booleanAt(row.cache_stale, "wazuh_integration.cache_stale"),
        tls_verification: tls,
        connectivity_scope: "HTTPS_LOOPBACK",
        read_only: true,
    };
}

export function parseDetectionRules(value: unknown): DetectionRuleSummary[] {
    if (!Array.isArray(value)) throw new ContractError("rules");
    return value.map((item, index) => {
        const path = `rules[${index}]`;
        const row = objectAt(item, path);
        if (row.editable !== false) throw new ContractError(`${path}.editable`);
        const severity = nullableIntegerAt(row.severity, `${path}.severity`);
        if (severity !== null && severity > 16)
            throw new ContractError(`${path}.severity`);
        return {
            rule_id: stringAt(row.rule_id, `${path}.rule_id`),
            name: stringAt(row.name, `${path}.name`),
            description: stringAt(row.description, `${path}.description`),
            severity,
            source_type: stringAt(row.source_type, `${path}.source_type`),
            mitre_ids: stringsAt(row.mitre_ids, `${path}.mitre_ids`),
            last_triggered:
                row.last_triggered == null
                    ? null
                    : dateAt(row.last_triggered, `${path}.last_triggered`),
            alert_count: integerAt(row.alert_count, `${path}.alert_count`),
            correlation_relationship: nullableStringAt(
                row.correlation_relationship,
                `${path}.correlation_relationship`,
            ),
            owner: nullableStringAt(row.owner, `${path}.owner`),
            documentation: nullableStringAt(
                row.documentation,
                `${path}.documentation`,
            ),
            rule_version: nullableStringAt(
                row.rule_version,
                `${path}.rule_version`,
            ),
            version_authority: enumAt(
                row.version_authority,
                ["AUTHORITATIVE", "UNAVAILABLE"] as const,
                `${path}.version_authority`,
            ),
            enabled_state: enumAt(
                row.enabled_state,
                ["ENABLED", "DISABLED", "UNKNOWN"] as const,
                `${path}.enabled_state`,
            ),
            enabled_evidence: enumAt(
                row.enabled_evidence,
                [
                    "APPLICATION_SETTING",
                    "WAZUH_API_UNAVAILABLE",
                    "OBSERVED_ALERT_ONLY",
                ] as const,
                `${path}.enabled_evidence`,
            ),
            tested_state: enumAt(
                row.tested_state,
                ["TESTED", "NOT_RECORDED"] as const,
                `${path}.tested_state`,
            ),
            management_mode: enumAt(
                row.management_mode,
                ["READ_ONLY_WAZUH", "LOCAL_CORRELATION"] as const,
                `${path}.management_mode`,
            ),
            editable: false,
        };
    });
}

export function parseSecurityActivityReport(
    value: unknown,
): SecurityActivityReport {
    const row = objectAt(value, "report");
    const filters = objectAt(row.filters, "report.filters");
    return {
        start_time: dateAt(row.start_time, "report.start_time"),
        end_time: dateAt(row.end_time, "report.end_time"),
        generated_at: dateAt(row.generated_at, "report.generated_at"),
        filters: {
            severity_min: nullableIntegerAt(
                filters.severity_min,
                "report.filters.severity_min",
            ),
            severity_max: nullableIntegerAt(
                filters.severity_max,
                "report.filters.severity_max",
            ),
            host: nullableStringAt(filters.host, "report.filters.host"),
            rule_id: nullableStringAt(
                filters.rule_id,
                "report.filters.rule_id",
            ),
        },
        total_events: integerAt(row.total_events, "report.total_events"),
        total_alerts: integerAt(row.total_alerts, "report.total_alerts"),
        total_incidents: integerAt(
            row.total_incidents,
            "report.total_incidents",
        ),
        event_sources: countRowsAt(row.event_sources, "report.event_sources"),
        alert_severities: countRowsAt(
            row.alert_severities,
            "report.alert_severities",
        ),
        top_rules: countRowsAt(row.top_rules, "report.top_rules"),
        host_activity: countRowsAt(row.host_activity, "report.host_activity"),
        authentication_failures: integerAt(
            row.authentication_failures,
            "report.authentication_failures",
        ),
        file_integrity_events: integerAt(
            row.file_integrity_events,
            "report.file_integrity_events",
        ),
    };
}

export function parseIncidentList(value: unknown): IncidentListResponse {
    const response = objectAt(value, "response");
    if (!Array.isArray(response.items))
        throw new ContractError("response.items");
    return {
        items: response.items.map((item, index) =>
            incidentSummaryAt(item, `response.items[${index}]`),
        ),
        page: pageAt(response.page, "response.page"),
    };
}

export function parseIncidentNote(value: unknown, path = "note"): IncidentNote {
    const note = objectAt(value, path);
    return {
        note_id: stringAt(note.note_id, `${path}.note_id`),
        body: stringAt(note.body, `${path}.body`),
        author: stringAt(note.author, `${path}.author`),
        author_id: nullableIdentifierAt(note.author_id, `${path}.author_id`),
        created_at: dateAt(note.created_at, `${path}.created_at`),
    };
}

function historyAt(value: unknown, path: string): IncidentHistoryEvent {
    const event = objectAt(value, path);
    const eventType = stringAt(event.event_type, `${path}.event_type`);
    const eventTypes: IncidentEventType[] = [
        "CREATED",
        "STATUS_CHANGED",
        "ALERT_LINKED",
        "NOTE_ADDED",
        "ASSIGNMENT_CHANGED",
    ];
    if (!eventTypes.includes(eventType as IncidentEventType)) {
        throw new ContractError(`${path}.event_type`);
    }
    return {
        event_id: stringAt(event.event_id, `${path}.event_id`),
        event_type: eventType as IncidentEventType,
        actor: stringAt(event.actor, `${path}.actor`),
        actor_id: nullableIdentifierAt(event.actor_id, `${path}.actor_id`),
        occurred_at: dateAt(event.occurred_at, `${path}.occurred_at`),
        details: objectAt(event.details, `${path}.details`),
    };
}

function nullableNumberAt(value: unknown, path: string): number | null {
    if (value === null || value === undefined) return null;
    return nonnegativeNumberAt(value, path);
}

function ruleConditionAt(value: unknown, path: string): RuleCondition {
    const row = objectAt(value, path);
    return {
        field: enumAt(
            row.field,
            [
                "source_type",
                "hostname",
                "agent_id",
                "agent_name",
                "operating_system",
                "event_provider",
                "event_channel",
                "process_name",
                "process_path",
                "command_line",
                "parent_process_name",
                "parent_process_path",
                "source_ip",
                "destination_ip",
                "username",
                "event_category",
                "event_action",
                "outcome",
                "rule_id",
                "event_code",
                "message",
            ] as const,
            `${path}.field`,
        ),
        operator: enumAt(
            row.operator,
            ["EQUALS", "CONTAINS", "STARTS_WITH"] as const,
            `${path}.operator`,
        ),
        value: stringAt(row.value, `${path}.value`),
    };
}

export function parseRuleDraft(value: unknown, path = "rule_draft"): RuleDraft {
    const row = objectAt(value, path);
    if (!Array.isArray(row.conditions))
        throw new ContractError(`${path}.conditions`);
    const severity = integerAt(row.severity, `${path}.severity`);
    if (severity > 16) throw new ContractError(`${path}.severity`);
    return {
        draft_id: stringAt(row.draft_id, `${path}.draft_id`),
        name: stringAt(row.name, `${path}.name`),
        description: stringAt(row.description, `${path}.description`),
        severity,
        source_type: stringAt(row.source_type, `${path}.source_type`),
        mitre_ids: stringsAt(row.mitre_ids, `${path}.mitre_ids`),
        conditions: row.conditions.map((item, index) =>
            ruleConditionAt(item, `${path}.conditions[${index}]`),
        ),
        documentation: stringAt(row.documentation, `${path}.documentation`),
        status: enumAt(
            row.status,
            [
                "DRAFT",
                "VALIDATED",
                "TESTED",
                "READY_FOR_MANUAL_DEPLOYMENT",
            ] as const,
            `${path}.status`,
        ),
        version: integerAt(row.version, `${path}.version`, 1),
        owner_analyst_id: nullableStringAt(
            row.owner_analyst_id,
            `${path}.owner_analyst_id`,
        ),
        owner_display: stringAt(row.owner_display, `${path}.owner_display`),
        last_tested_at:
            row.last_tested_at == null
                ? null
                : dateAt(row.last_tested_at, `${path}.last_tested_at`),
        last_test_match_count: nullableIntegerAt(
            row.last_test_match_count,
            `${path}.last_test_match_count`,
        ),
        last_test_execution_ms: nullableNumberAt(
            row.last_test_execution_ms,
            `${path}.last_test_execution_ms`,
        ),
        created_at: dateAt(row.created_at, `${path}.created_at`),
        updated_at: dateAt(row.updated_at, `${path}.updated_at`),
    };
}

export function parseRuleDrafts(value: unknown): RuleDraft[] {
    if (!Array.isArray(value)) throw new ContractError("rule_drafts");
    return value.map((item, index) =>
        parseRuleDraft(item, `rule_drafts[${index}]`),
    );
}

export function parseRuleDraftVersions(value: unknown): RuleDraftVersion[] {
    if (!Array.isArray(value)) throw new ContractError("rule_versions");
    return value.map((item, index) => {
        const path = `rule_versions[${index}]`;
        const row = objectAt(item, path);
        return {
            version_id: stringAt(row.version_id, `${path}.version_id`),
            draft_id: stringAt(row.draft_id, `${path}.draft_id`),
            version_number: integerAt(
                row.version_number,
                `${path}.version_number`,
                1,
            ),
            snapshot: objectAt(row.snapshot, `${path}.snapshot`),
            change_summary: stringAt(
                row.change_summary,
                `${path}.change_summary`,
            ),
            actor_display: stringAt(row.actor_display, `${path}.actor_display`),
            created_at: dateAt(row.created_at, `${path}.created_at`),
        };
    });
}

export function parseRuleValidation(value: unknown): RuleValidationResult {
    const row = objectAt(value, "rule_validation");
    return {
        draft: parseRuleDraft(row.draft, "rule_validation.draft"),
        valid: booleanAt(row.valid, "rule_validation.valid"),
        errors: stringsAt(row.errors, "rule_validation.errors"),
        warnings: stringsAt(row.warnings, "rule_validation.warnings"),
    };
}

function parseAdvancedAvailability(
    value: unknown,
    path: string,
): AdvancedDetectionAvailability {
    const row = objectAt(value, path);
    const latest = row.latest_event_at;
    return {
        parser_supported: booleanAt(
            row.parser_supported,
            `${path}.parser_supported`,
        ),
        data_observed: booleanAt(row.data_observed, `${path}.data_observed`),
        recently_observed: booleanAt(
            row.recently_observed,
            `${path}.recently_observed`,
        ),
        configuration_status: enumAt(
            row.configuration_status,
            ["CONFIGURED", "NOT_CONFIGURED", "UNKNOWN"] as const,
            `${path}.configuration_status`,
        ),
        status: enumAt(
            row.status,
            [
                "RECENTLY_OBSERVED",
                "OBSERVED_STALE",
                "PREREQUISITE_MISSING",
                "NO_DATA",
                "UNKNOWN",
            ] as const,
            `${path}.status`,
        ),
        observed_event_count: integerAt(
            row.observed_event_count,
            `${path}.observed_event_count`,
        ),
        latest_event_at:
            latest === null ? null : dateAt(latest, `${path}.latest_event_at`),
        missing_required_fields: stringsAt(
            row.missing_required_fields,
            `${path}.missing_required_fields`,
        ),
        explanation: stringAt(row.explanation, `${path}.explanation`),
    };
}

export function parseAdvancedDetectionRule(
    value: unknown,
    path = "advanced_detection_rule",
): AdvancedDetectionRule {
    const row = objectAt(value, path);
    if (row.enabled !== false || row.activation_state !== "DISABLED_BY_POLICY")
        throw new ContractError(`${path}.activation_state`);
    const prerequisite = objectAt(
        row.prerequisites,
        `${path}.prerequisites`,
    );
    const severity = integerAt(row.severity, `${path}.severity`);
    if (severity > 16) throw new ContractError(`${path}.severity`);
    if (!Array.isArray(row.mitre_mappings))
        throw new ContractError(`${path}.mitre_mappings`);
    const availability = row.availability;
    return {
        rule_id: stringAt(row.rule_id, `${path}.rule_id`),
        name: stringAt(row.name, `${path}.name`),
        description: stringAt(row.description, `${path}.description`),
        enabled: false,
        activation_state: "DISABLED_BY_POLICY",
        severity,
        prerequisites: {
            source_types: stringsAt(
                prerequisite.source_types,
                `${path}.prerequisites.source_types`,
            ),
            event_codes: stringsAt(
                prerequisite.event_codes,
                `${path}.prerequisites.event_codes`,
            ),
            event_categories: stringsAt(
                prerequisite.event_categories,
                `${path}.prerequisites.event_categories`,
            ),
            required_fields: stringsAt(
                prerequisite.required_fields,
                `${path}.prerequisites.required_fields`,
            ),
            parser_supported: booleanAt(
                prerequisite.parser_supported,
                `${path}.prerequisites.parser_supported`,
            ),
            configuration_status: enumAt(
                prerequisite.configuration_status,
                ["CONFIGURED", "NOT_CONFIGURED", "UNKNOWN"] as const,
                `${path}.prerequisites.configuration_status`,
            ),
            configuration_evidence: stringAt(
                prerequisite.configuration_evidence,
                `${path}.prerequisites.configuration_evidence`,
            ),
        },
        conditions: stringsAt(row.conditions, `${path}.conditions`),
        grouping_fields: stringsAt(
            row.grouping_fields,
            `${path}.grouping_fields`,
        ),
        window_seconds: integerAt(
            row.window_seconds,
            `${path}.window_seconds`,
            1,
        ),
        threshold: integerAt(row.threshold, `${path}.threshold`, 1),
        deduplication: stringAt(row.deduplication, `${path}.deduplication`),
        mitre_ids: stringsAt(row.mitre_ids, `${path}.mitre_ids`),
        mitre_mappings: row.mitre_mappings.map((item, index) => {
            const mappingPath = `${path}.mitre_mappings[${index}]`;
            const mapping = objectAt(item, mappingPath);
            return {
                technique_id: stringAt(
                    mapping.technique_id,
                    `${mappingPath}.technique_id`,
                ),
                technique_name: stringAt(
                    mapping.technique_name,
                    `${mappingPath}.technique_name`,
                ),
                tactic: stringAt(mapping.tactic, `${mappingPath}.tactic`),
                relationship: stringAt(
                    mapping.relationship,
                    `${mappingPath}.relationship`,
                ),
            };
        }),
        false_positive_notes: stringsAt(
            row.false_positive_notes,
            `${path}.false_positive_notes`,
        ),
        evidence_fields: stringsAt(
            row.evidence_fields,
            `${path}.evidence_fields`,
        ),
        analyst_guidance: stringsAt(
            row.analyst_guidance,
            `${path}.analyst_guidance`,
        ),
        version: stringAt(row.version, `${path}.version`),
        validation_status: enumAt(
            row.validation_status,
            ["VALIDATED_FOR_DRY_RUN"] as const,
            `${path}.validation_status`,
        ),
        validation_notes: stringsAt(
            row.validation_notes,
            `${path}.validation_notes`,
        ),
        availability:
            availability === null
                ? null
                : parseAdvancedAvailability(
                      availability,
                      `${path}.availability`,
                  ),
    };
}

export function parseAdvancedDetectionRules(
    value: unknown,
): AdvancedDetectionRule[] {
    if (!Array.isArray(value))
        throw new ContractError("advanced_detection_rules");
    return value.map((item, index) =>
        parseAdvancedDetectionRule(
            item,
            `advanced_detection_rules[${index}]`,
        ),
    );
}

function parseAdvancedFinding(
    value: unknown,
    path: string,
): AdvancedDetectionFinding {
    const row = objectAt(value, path);
    const rawGroup = objectAt(row.group, `${path}.group`);
    const group = Object.fromEntries(
        Object.entries(rawGroup).map(([key, item]) => [
            key,
            stringAt(item, `${path}.group.${key}`),
        ]),
    );
    if (!Array.isArray(row.evidence))
        throw new ContractError(`${path}.evidence`);
    const severity = integerAt(row.severity, `${path}.severity`);
    if (severity > 16) throw new ContractError(`${path}.severity`);
    return {
        finding_id: stringAt(row.finding_id, `${path}.finding_id`),
        rule_id: stringAt(row.rule_id, `${path}.rule_id`),
        severity,
        first_event_at: dateAt(
            row.first_event_at,
            `${path}.first_event_at`,
        ),
        last_event_at: dateAt(row.last_event_at, `${path}.last_event_at`),
        group,
        matched_event_count: integerAt(
            row.matched_event_count,
            `${path}.matched_event_count`,
            1,
        ),
        threshold: integerAt(row.threshold, `${path}.threshold`, 1),
        event_ids: stringsAt(row.event_ids, `${path}.event_ids`),
        explanation: stringAt(row.explanation, `${path}.explanation`),
        evidence: row.evidence.map((item, index) => {
            const evidencePath = `${path}.evidence[${index}]`;
            const evidence = objectAt(item, evidencePath);
            return {
                event_id: stringAt(
                    evidence.event_id,
                    `${evidencePath}.event_id`,
                ),
                timestamp: dateAt(
                    evidence.timestamp,
                    `${evidencePath}.timestamp`,
                ),
                summary: stringAt(
                    evidence.summary,
                    `${evidencePath}.summary`,
                ),
            };
        }),
        deduplication_key: stringAt(
            row.deduplication_key,
            `${path}.deduplication_key`,
        ),
        mitre_ids: stringsAt(row.mitre_ids, `${path}.mitre_ids`),
    };
}

export function parseAdvancedRuleDryRun(
    value: unknown,
): AdvancedRuleDryRunResult {
    const row = objectAt(value, "advanced_dry_run");
    if (row.side_effects !== false || row.deterministic_ordering !== true)
        throw new ContractError("advanced_dry_run.safety");
    if (!Array.isArray(row.findings))
        throw new ContractError("advanced_dry_run.findings");
    return {
        rule: parseAdvancedDetectionRule(
            row.rule,
            "advanced_dry_run.rule",
        ),
        availability: parseAdvancedAvailability(
            row.availability,
            "advanced_dry_run.availability",
        ),
        start_time: dateAt(row.start_time, "advanced_dry_run.start_time"),
        end_time: dateAt(row.end_time, "advanced_dry_run.end_time"),
        evaluated_event_count: integerAt(
            row.evaluated_event_count,
            "advanced_dry_run.evaluated_event_count",
        ),
        finding_count: integerAt(
            row.finding_count,
            "advanced_dry_run.finding_count",
        ),
        findings: row.findings.map((item, index) =>
            parseAdvancedFinding(
                item,
                `advanced_dry_run.findings[${index}]`,
            ),
        ),
        execution_ms: nonnegativeNumberAt(
            row.execution_ms,
            "advanced_dry_run.execution_ms",
        ),
        execution_budget_ms: integerAt(
            row.execution_budget_ms,
            "advanced_dry_run.execution_budget_ms",
            50,
        ),
        result_truncated: booleanAt(
            row.result_truncated,
            "advanced_dry_run.result_truncated",
        ),
        deterministic_ordering: true,
        side_effects: false,
    };
}

export function parseDetectionQuality(
    value: unknown,
    path = "detection_quality",
): DetectionQualityReport {
    const row = objectAt(value, path);
    if (
        row.dataset_version !== "m15-golden-v1" ||
        row.dataset_label !== "SYNTHETIC TEST DATA" ||
        row.ground_truth_scope !== "LABELED_SYNTHETIC_FIXTURES_ONLY" ||
        row.live_ground_truth_available !== false ||
        row.enabled !== false ||
        row.runtime_activation_state !== "DISABLED_BY_POLICY" ||
        row.deployment_eligibility !== "SHADOW_ONLY" ||
        row.side_effects !== false
    ) throw new ContractError(`${path}.safety`);
    if (!Array.isArray(row.fixtures) || row.fixtures.length !== 9)
        throw new ContractError(`${path}.fixtures`);
    const fixtures = row.fixtures.map((item, index) => {
        const fixturePath = `${path}.fixtures[${index}]`;
        const fixture = objectAt(item, fixturePath);
        if (fixture.synthetic_test_data !== true)
            throw new ContractError(`${fixturePath}.synthetic_test_data`);
        return {
            scenario: enumAt(fixture.scenario, [
                "positive", "negative", "boundary", "duplicate", "out_of_order",
                "missing_field", "cross_host", "cross_account", "false_positive_candidate",
            ] as const, `${fixturePath}.scenario`),
            synthetic_test_data: true as const,
            applicable: booleanAt(fixture.applicable, `${fixturePath}.applicable`),
            ground_truth: enumAt(
                fixture.ground_truth,
                ["POSITIVE", "NEGATIVE", "UNLABELED"] as const,
                `${fixturePath}.ground_truth`,
            ),
            expected_finding_count: integerAt(
                fixture.expected_finding_count, `${fixturePath}.expected_finding_count`,
            ),
            actual_finding_count: integerAt(
                fixture.actual_finding_count, `${fixturePath}.actual_finding_count`,
            ),
            expected_evidence_ids: stringsAt(
                fixture.expected_evidence_ids, `${fixturePath}.expected_evidence_ids`,
            ),
            actual_evidence_ids: stringsAt(
                fixture.actual_evidence_ids, `${fixturePath}.actual_evidence_ids`,
            ),
            evaluator_duplicate_count: integerAt(
                fixture.evaluator_duplicate_count, `${fixturePath}.evaluator_duplicate_count`,
            ),
            evaluation_ms: nonnegativeNumberAt(
                fixture.evaluation_ms, `${fixturePath}.evaluation_ms`,
            ),
            passed: booleanAt(fixture.passed, `${fixturePath}.passed`),
            expected_explanation: stringAt(
                fixture.expected_explanation, `${fixturePath}.expected_explanation`,
            ),
            grouping_behavior: stringAt(
                fixture.grouping_behavior, `${fixturePath}.grouping_behavior`,
            ),
            deduplication_behavior: stringAt(
                fixture.deduplication_behavior, `${fixturePath}.deduplication_behavior`,
            ),
        };
    });
    if (new Set(fixtures.map((item) => item.scenario)).size !== 9)
        throw new ContractError(`${path}.fixtures.scenario`);
    const rawMetrics = objectAt(row.metrics, `${path}.metrics`);
    const nullableRate = (candidate: unknown, ratePath: string) => {
        const parsed = nullableNumberAt(candidate, ratePath);
        if (parsed !== null && (parsed < 0 || parsed > 1))
            throw new ContractError(ratePath);
        return parsed;
    };
    const rate = (candidate: unknown, ratePath: string) => {
        const parsed = nonnegativeNumberAt(candidate, ratePath);
        if (parsed > 1) throw new ContractError(ratePath);
        return parsed;
    };
    return {
        rule_id: stringAt(row.rule_id, `${path}.rule_id`),
        dataset_version: "m15-golden-v1",
        dataset_label: "SYNTHETIC TEST DATA",
        ground_truth_scope: "LABELED_SYNTHETIC_FIXTURES_ONLY",
        live_ground_truth_available: false,
        enabled: false,
        runtime_activation_state: "DISABLED_BY_POLICY",
        deployment_eligibility: "SHADOW_ONLY",
        fixtures,
        metrics: {
            labeled_fixture_count: integerAt(rawMetrics.labeled_fixture_count, `${path}.metrics.labeled_fixture_count`),
            unlabeled_fixture_count: integerAt(rawMetrics.unlabeled_fixture_count, `${path}.metrics.unlabeled_fixture_count`),
            true_positives: integerAt(rawMetrics.true_positives, `${path}.metrics.true_positives`),
            false_positives: integerAt(rawMetrics.false_positives, `${path}.metrics.false_positives`),
            true_negatives: integerAt(rawMetrics.true_negatives, `${path}.metrics.true_negatives`),
            false_negatives: integerAt(rawMetrics.false_negatives, `${path}.metrics.false_negatives`),
            precision: nullableRate(rawMetrics.precision, `${path}.metrics.precision`),
            recall: nullableRate(rawMetrics.recall, `${path}.metrics.recall`),
            false_positive_rate: nullableRate(rawMetrics.false_positive_rate, `${path}.metrics.false_positive_rate`),
            duplicate_input_count: integerAt(rawMetrics.duplicate_input_count, `${path}.metrics.duplicate_input_count`),
            duplicate_finding_rate: rate(rawMetrics.duplicate_finding_rate, `${path}.metrics.duplicate_finding_rate`),
            missing_field_fixture_passed: booleanAt(rawMetrics.missing_field_fixture_passed, `${path}.metrics.missing_field_fixture_passed`),
            event_order_consistent: booleanAt(rawMetrics.event_order_consistent, `${path}.metrics.event_order_consistent`),
            repeat_evaluation_consistent: booleanAt(rawMetrics.repeat_evaluation_consistent, `${path}.metrics.repeat_evaluation_consistent`),
            evidence_latency_p50_ms: nonnegativeNumberAt(rawMetrics.evidence_latency_p50_ms, `${path}.metrics.evidence_latency_p50_ms`),
            evidence_latency_p95_ms: nonnegativeNumberAt(rawMetrics.evidence_latency_p95_ms, `${path}.metrics.evidence_latency_p95_ms`),
            evidence_latency_max_ms: nonnegativeNumberAt(rawMetrics.evidence_latency_max_ms, `${path}.metrics.evidence_latency_max_ms`),
            evaluation_time_p50_ms: nonnegativeNumberAt(rawMetrics.evaluation_time_p50_ms, `${path}.metrics.evaluation_time_p50_ms`),
            evaluation_time_p95_ms: nonnegativeNumberAt(rawMetrics.evaluation_time_p95_ms, `${path}.metrics.evaluation_time_p95_ms`),
            evaluation_time_max_ms: nonnegativeNumberAt(rawMetrics.evaluation_time_max_ms, `${path}.metrics.evaluation_time_max_ms`),
        },
        all_applicable_fixtures_passed: booleanAt(
            row.all_applicable_fixtures_passed,
            `${path}.all_applicable_fixtures_passed`,
        ),
        side_effects: false,
    };
}

const M14_LIFECYCLE_STATES = [
    "DRAFT", "VALIDATED", "TESTED", "SHADOW_READY", "CANARY_READY",
    "ACTIVE", "PAUSED", "ROLLED_BACK", "DISABLED_BY_POLICY",
] as const;
const M14_TELEMETRY_STATES = [
    "READY", "PARTIAL", "UNKNOWN", "UNAVAILABLE", "FAILED",
] as const;

export function parseDetectionRuleLifecycle(
    value: unknown,
    path = "detection_lifecycle",
): DetectionRuleLifecycle {
    const row = objectAt(value, path);
    if (row.runtime_activation_state !== "DISABLED_BY_POLICY")
        throw new ContractError(`${path}.runtime_activation_state`);
    return {
        rule_id: stringAt(row.rule_id, `${path}.rule_id`),
        configuration_state: enumAt(
            row.configuration_state, M14_LIFECYCLE_STATES, `${path}.configuration_state`,
        ),
        validation_state: enumAt(
            row.validation_state,
            ["NOT_VALIDATED", "VALID", "INVALID"] as const,
            `${path}.validation_state`,
        ),
        deployment_eligibility: enumAt(
            row.deployment_eligibility,
            ["BLOCKED", "SHADOW_ONLY", "CANARY_REVIEW_REQUIRED"] as const,
            `${path}.deployment_eligibility`,
        ),
        runtime_activation_state: "DISABLED_BY_POLICY",
        telemetry_status: enumAt(
            row.telemetry_status, M14_TELEMETRY_STATES, `${path}.telemetry_status`,
        ),
        active_configuration_version: integerAt(
            row.active_configuration_version, `${path}.active_configuration_version`, 1,
        ),
        state_version: integerAt(row.state_version, `${path}.state_version`, 1),
        updated_at: dateAt(row.updated_at, `${path}.updated_at`),
        updated_by: stringAt(row.updated_by, `${path}.updated_by`),
        inactive_reason: stringAt(row.inactive_reason, `${path}.inactive_reason`),
    };
}

export function parseDetectionRuleLifecycles(
    value: unknown,
): DetectionRuleLifecycle[] {
    if (!Array.isArray(value)) throw new ContractError("detection_lifecycles");
    return value.map((item, index) =>
        parseDetectionRuleLifecycle(item, `detection_lifecycles[${index}]`),
    );
}

function parseConfiguration(
    value: unknown,
    path: string,
): DetectionConfigurationVersion {
    const row = objectAt(value, path);
    const limits = objectAt(row.evaluation_limits, `${path}.evaluation_limits`);
    if (!Array.isArray(row.safe_exclusions))
        throw new ContractError(`${path}.safe_exclusions`);
    return {
        config_id: stringAt(row.config_id, `${path}.config_id`),
        rule_id: stringAt(row.rule_id, `${path}.rule_id`),
        version: integerAt(row.version, `${path}.version`, 1),
        lifecycle_state: enumAt(
            row.lifecycle_state, M14_LIFECYCLE_STATES, `${path}.lifecycle_state`,
        ),
        threshold_count: integerAt(row.threshold_count, `${path}.threshold_count`, 1),
        time_window_seconds: integerAt(
            row.time_window_seconds, `${path}.time_window_seconds`, 30,
        ),
        severity: integerAt(row.severity, `${path}.severity`),
        supported_event_sources: stringsAt(
            row.supported_event_sources, `${path}.supported_event_sources`,
        ),
        required_normalized_fields: stringsAt(
            row.required_normalized_fields, `${path}.required_normalized_fields`,
        ),
        entity_grouping: stringsAt(row.entity_grouping, `${path}.entity_grouping`),
        safe_exclusions: row.safe_exclusions.map((item, index) => {
            const exclusionPath = `${path}.safe_exclusions[${index}]`;
            const exclusion = objectAt(item, exclusionPath);
            return {
                field: enumAt(
                    exclusion.field,
                    ["hostname", "username", "source_ip", "process_name"] as const,
                    `${exclusionPath}.field`,
                ),
                operator: enumAt(
                    exclusion.operator, ["EQUALS", "STARTS_WITH"] as const,
                    `${exclusionPath}.operator`,
                ),
                value: stringAt(exclusion.value, `${exclusionPath}.value`),
            };
        }),
        evaluation_limits: {
            max_events: integerAt(limits.max_events, `${path}.evaluation_limits.max_events`, 1),
            max_findings: integerAt(limits.max_findings, `${path}.evaluation_limits.max_findings`, 1),
            max_execution_ms: integerAt(
                limits.max_execution_ms, `${path}.evaluation_limits.max_execution_ms`, 50,
            ),
        },
        state_expiration_seconds: integerAt(
            row.state_expiration_seconds, `${path}.state_expiration_seconds`, 60,
        ),
        state_schema_version: (() => {
            const version = integerAt(
                row.state_schema_version, `${path}.state_schema_version`, 1,
            );
            if (version !== 1) throw new ContractError(`${path}.state_schema_version`);
            return 1 as const;
        })(),
        author_id:
            row.author_id === null ? null : stringAt(row.author_id, `${path}.author_id`),
        author_display: stringAt(row.author_display, `${path}.author_display`),
        change_reason: stringAt(row.change_reason, `${path}.change_reason`),
        created_at: dateAt(row.created_at, `${path}.created_at`),
        validation_results: stringsAt(
            row.validation_results, `${path}.validation_results`,
        ),
    };
}

export function parseDetectionConfigurations(
    value: unknown,
): DetectionConfigurationVersion[] {
    if (!Array.isArray(value)) throw new ContractError("detection_configurations");
    return value.map((item, index) =>
        parseConfiguration(item, `detection_configurations[${index}]`),
    );
}

export function parseTelemetryPrerequisite(
    value: unknown,
    path = "telemetry_prerequisite",
): TelemetryPrerequisiteEvidence {
    const row = objectAt(value, path);
    return {
        rule_id: stringAt(row.rule_id, `${path}.rule_id`),
        required_sources: stringsAt(row.required_sources, `${path}.required_sources`),
        required_event_codes: stringsAt(
            row.required_event_codes, `${path}.required_event_codes`,
        ),
        required_categories: stringsAt(
            row.required_categories, `${path}.required_categories`,
        ),
        required_fields: stringsAt(row.required_fields, `${path}.required_fields`),
        latest_observed_event:
            row.latest_observed_event === null
                ? null
                : dateAt(row.latest_observed_event, `${path}.latest_observed_event`),
        source_freshness_seconds:
            row.source_freshness_seconds === null
                ? null
                : integerAt(row.source_freshness_seconds, `${path}.source_freshness_seconds`),
        normalization_compatible: booleanAt(
            row.normalization_compatible, `${path}.normalization_compatible`,
        ),
        status: enumAt(row.status, M14_TELEMETRY_STATES, `${path}.status`),
        missing_prerequisites: stringsAt(
            row.missing_prerequisites, `${path}.missing_prerequisites`,
        ),
        authoritative_evidence_reference: stringAt(
            row.authoritative_evidence_reference,
            `${path}.authoritative_evidence_reference`,
        ),
        explanation: stringAt(row.explanation, `${path}.explanation`),
    };
}

export function parseDetectionDiagnostics(value: unknown): DetectionDiagnostics {
    const path = "detection_diagnostics";
    const row = objectAt(value, path);
    const nullableDate = (item: unknown, field: string) =>
        item === null ? null : dateAt(item, `${path}.${field}`);
    return {
        rule_id: stringAt(row.rule_id, `${path}.rule_id`),
        evaluation_count: integerAt(row.evaluation_count, `${path}.evaluation_count`),
        average_duration_ms: nonnegativeNumberAt(
            row.average_duration_ms, `${path}.average_duration_ms`,
        ),
        rule_match_count: integerAt(row.rule_match_count, `${path}.rule_match_count`),
        finding_count: integerAt(row.finding_count, `${path}.finding_count`),
        duplicate_event_count: integerAt(
            row.duplicate_event_count, `${path}.duplicate_event_count`,
        ),
        skipped_event_count: integerAt(
            row.skipped_event_count, `${path}.skipped_event_count`,
        ),
        missing_field_count: integerAt(
            row.missing_field_count, `${path}.missing_field_count`,
        ),
        evaluation_timeout_count: integerAt(
            row.evaluation_timeout_count, `${path}.evaluation_timeout_count`,
        ),
        state_recovery_count: integerAt(
            row.state_recovery_count, `${path}.state_recovery_count`,
        ),
        configuration_validation_failure_count: integerAt(
            row.configuration_validation_failure_count,
            `${path}.configuration_validation_failure_count`,
        ),
        truncation_count: integerAt(row.truncation_count, `${path}.truncation_count`),
        last_successful_evaluation: nullableDate(
            row.last_successful_evaluation, "last_successful_evaluation",
        ),
        last_failed_evaluation: nullableDate(
            row.last_failed_evaluation, "last_failed_evaluation",
        ),
        evaluated_event_range_start: nullableDate(
            row.evaluated_event_range_start, "evaluated_event_range_start",
        ),
        evaluated_event_range_end: nullableDate(
            row.evaluated_event_range_end, "evaluated_event_range_end",
        ),
        source_freshness:
            row.source_freshness === null
                ? null
                : stringAt(row.source_freshness, `${path}.source_freshness`),
    };
}

function parseShadowRun(value: unknown, path: string): ShadowRun {
    const row = objectAt(value, path);
    if (row.side_effects !== false)
        throw new ContractError(`${path}.side_effects`);
    const resources = objectAt(row.resource_measurements, `${path}.resource_measurements`);
    for (const [key, item] of Object.entries(resources)) {
        if (item !== null && !["string", "number", "boolean"].includes(typeof item))
            throw new ContractError(`${path}.resource_measurements.${key}`);
    }
    return {
        run_id: stringAt(row.run_id, `${path}.run_id`),
        rule_id: stringAt(row.rule_id, `${path}.rule_id`),
        configuration_version: integerAt(
            row.configuration_version, `${path}.configuration_version`, 1,
        ),
        status: enumAt(row.status, ["RUNNING", "COMPLETED", "FAILED"] as const, `${path}.status`),
        started_at: dateAt(row.started_at, `${path}.started_at`),
        completed_at:
            row.completed_at === null ? null : dateAt(row.completed_at, `${path}.completed_at`),
        start_time: dateAt(row.start_time, `${path}.start_time`),
        end_time: dateAt(row.end_time, `${path}.end_time`),
        operator_display: stringAt(row.operator_display, `${path}.operator_display`),
        source_availability: enumAt(
            row.source_availability, M14_TELEMETRY_STATES, `${path}.source_availability`,
        ),
        evaluated_event_count: integerAt(
            row.evaluated_event_count, `${path}.evaluated_event_count`,
        ),
        match_count: integerAt(row.match_count, `${path}.match_count`),
        duplicate_count: integerAt(row.duplicate_count, `${path}.duplicate_count`),
        missing_field_count: integerAt(
            row.missing_field_count, `${path}.missing_field_count`,
        ),
        execution_ms: nonnegativeNumberAt(row.execution_ms, `${path}.execution_ms`),
        truncated: booleanAt(row.truncated, `${path}.truncated`),
        outcome: stringAt(row.outcome, `${path}.outcome`),
        error_code:
            row.error_code === null ? null : stringAt(row.error_code, `${path}.error_code`),
        resource_measurements: resources as Record<
            string,
            string | number | boolean | null
        >,
        side_effects: false,
    };
}

export function parseShadowRuns(value: unknown): ShadowRun[] {
    if (!Array.isArray(value)) throw new ContractError("shadow_runs");
    return value.map((item, index) => parseShadowRun(item, `shadow_runs[${index}]`));
}

export function parseShadowRunDetail(value: unknown): ShadowRunDetail {
    const row = objectAt(value, "shadow_run_detail");
    if (!Array.isArray(row.findings))
        throw new ContractError("shadow_run_detail.findings");
    const findings: ShadowFinding[] = row.findings.map((item, index) => {
        const path = `shadow_run_detail.findings[${index}]`;
        const finding = objectAt(item, path);
        if (
            finding.namespace !== "SHADOW" ||
            finding.production_alert_id !== null ||
            finding.production_incident_id !== null ||
            finding.production_case_id !== null
        ) throw new ContractError(`${path}.isolation`);
        return {
            shadow_finding_id: stringAt(
                finding.shadow_finding_id, `${path}.shadow_finding_id`,
            ),
            run_id: stringAt(finding.run_id, `${path}.run_id`),
            rule_id: stringAt(finding.rule_id, `${path}.rule_id`),
            finding: parseAdvancedFinding(finding.finding, `${path}.finding`),
            created_at: dateAt(finding.created_at, `${path}.created_at`),
            namespace: "SHADOW",
            production_alert_id: null,
            production_incident_id: null,
            production_case_id: null,
        };
    });
    return {
        run: parseShadowRun(row.run, "shadow_run_detail.run"),
        findings,
    };
}

export function parseTuningComparison(value: unknown): DetectionTuningComparison {
    const path = "tuning_comparison";
    const row = objectAt(value, path);
    if (row.side_effects !== false || !Array.isArray(row.results))
        throw new ContractError(`${path}.safety`);
    const parseCounts = (value: unknown, field: string) => {
        if (!Array.isArray(value)) throw new ContractError(`${path}.${field}`);
        return value.map((item, index) => {
            const count = objectAt(item, `${path}.${field}[${index}]`);
            return {
                entity: stringAt(count.entity, `${path}.${field}[${index}].entity`),
                count: integerAt(count.count, `${path}.${field}[${index}].count`),
            };
        });
    };
    return {
        rule_id: stringAt(row.rule_id, `${path}.rule_id`),
        start_time: dateAt(row.start_time, `${path}.start_time`),
        end_time: dateAt(row.end_time, `${path}.end_time`),
        results: row.results.map((item, index) => {
            const resultPath = `${path}.results[${index}]`;
            const result = objectAt(item, resultPath);
            const candidate = objectAt(result.candidate, `${resultPath}.candidate`);
            return {
                candidate: {
                    threshold_count: integerAt(
                        candidate.threshold_count, `${resultPath}.candidate.threshold_count`, 1,
                    ),
                    time_window_seconds: integerAt(
                        candidate.time_window_seconds,
                        `${resultPath}.candidate.time_window_seconds`, 30,
                    ),
                },
                evaluated_event_count: integerAt(
                    result.evaluated_event_count, `${resultPath}.evaluated_event_count`,
                ),
                finding_count: integerAt(result.finding_count, `${resultPath}.finding_count`),
                duplicate_count: integerAt(
                    result.duplicate_count, `${resultPath}.duplicate_count`,
                ),
                missing_field_count: integerAt(
                    result.missing_field_count, `${resultPath}.missing_field_count`,
                ),
                findings_by_source: parseCounts(
                    result.findings_by_source, `results[${index}].findings_by_source`,
                ),
                findings_by_host: parseCounts(
                    result.findings_by_host, `results[${index}].findings_by_host`,
                ),
                findings_by_user: parseCounts(
                    result.findings_by_user, `results[${index}].findings_by_user`,
                ),
                repeated_finding_count: integerAt(
                    result.repeated_finding_count, `${resultPath}.repeated_finding_count`,
                ),
                execution_ms: nonnegativeNumberAt(
                    result.execution_ms, `${resultPath}.execution_ms`,
                ),
                truncated: booleanAt(result.truncated, `${resultPath}.truncated`),
            };
        }),
        interpretation: stringAt(row.interpretation, `${path}.interpretation`),
        side_effects: false,
    };
}

export function parseCanarySafety(value: unknown): CanarySafetyStatus {
    const path = "canary_safety";
    const row = objectAt(value, path);
    if (
        row.target_scope_selected !== false ||
        row.operator_approval_recorded !== false ||
        row.activation_path_enabled !== false ||
        row.runtime_activation_state !== "DISABLED_BY_POLICY"
    ) throw new ContractError(`${path}.activation_boundary`);
    return {
        rule_id: stringAt(row.rule_id, `${path}.rule_id`),
        prerequisites_validated: booleanAt(
            row.prerequisites_validated, `${path}.prerequisites_validated`,
        ),
        historical_evaluation_passed: booleanAt(
            row.historical_evaluation_passed, `${path}.historical_evaluation_passed`,
        ),
        configuration_reviewed: booleanAt(
            row.configuration_reviewed, `${path}.configuration_reviewed`,
        ),
        resource_budget_reviewed: booleanAt(
            row.resource_budget_reviewed, `${path}.resource_budget_reviewed`,
        ),
        false_positive_baseline_measured: booleanAt(
            row.false_positive_baseline_measured,
            `${path}.false_positive_baseline_measured`,
        ),
        version_locked: booleanAt(row.version_locked, `${path}.version_locked`),
        target_scope_selected: false,
        operator_approval_recorded: false,
        activation_path_enabled: false,
        runtime_activation_state: "DISABLED_BY_POLICY",
        blockers: stringsAt(row.blockers, `${path}.blockers`),
    };
}

export function parseRuleDryRun(value: unknown): RuleDryRunResult {
    const row = objectAt(value, "dry_run");
    if (row.side_effects !== false)
        throw new ContractError("dry_run.side_effects");
    return {
        draft: parseRuleDraft(row.draft, "dry_run.draft"),
        start_time: dateAt(row.start_time, "dry_run.start_time"),
        end_time: dateAt(row.end_time, "dry_run.end_time"),
        evaluated_event_count: integerAt(
            row.evaluated_event_count,
            "dry_run.evaluated_event_count",
        ),
        match_count: integerAt(row.match_count, "dry_run.match_count"),
        matched_event_ids: stringsAt(
            row.matched_event_ids,
            "dry_run.matched_event_ids",
        ),
        execution_ms: nonnegativeNumberAt(
            row.execution_ms,
            "dry_run.execution_ms",
        ),
        result_ids_truncated: booleanAt(
            row.result_ids_truncated,
            "dry_run.result_ids_truncated",
        ),
        side_effects: false,
    };
}

export function parseDeploymentConfirmation(
    value: unknown,
): DeploymentConfirmationResult {
    const row = objectAt(value, "deployment_confirmation");
    if (
        row.live_wazuh_modified !== false ||
        row.deployment_mode !== "MANUAL_REVIEW_ONLY"
    )
        throw new ContractError("deployment_confirmation.mode");
    return {
        draft: parseRuleDraft(row.draft, "deployment_confirmation.draft"),
        live_wazuh_modified: false,
        deployment_mode: "MANUAL_REVIEW_ONLY",
        message: stringAt(row.message, "deployment_confirmation.message"),
    };
}

export function parseDetectionCoverage(value: unknown): DetectionCoverage {
    const row = objectAt(value, "coverage");
    if (!Array.isArray(row.techniques))
        throw new ContractError("coverage.techniques");
    return {
        techniques: row.techniques.map((item, index) => {
            const path = `coverage.techniques[${index}]`;
            const entry = objectAt(item, path);
            return {
                technique_id: stringAt(
                    entry.technique_id,
                    `${path}.technique_id`,
                ),
                rule_ids: stringsAt(entry.rule_ids, `${path}.rule_ids`),
                mapped_detection_count: integerAt(
                    entry.mapped_detection_count,
                    `${path}.mapped_detection_count`,
                ),
                enabled_detection_count: integerAt(
                    entry.enabled_detection_count,
                    `${path}.enabled_detection_count`,
                ),
                triggered_detection_count: integerAt(
                    entry.triggered_detection_count,
                    `${path}.triggered_detection_count`,
                ),
                tested_detection_count: integerAt(
                    entry.tested_detection_count,
                    `${path}.tested_detection_count`,
                ),
                alert_count: integerAt(
                    entry.alert_count,
                    `${path}.alert_count`,
                ),
                sources: stringsAt(entry.sources, `${path}.sources`),
                coverage_state: enumAt(
                    entry.coverage_state,
                    [
                        "MAPPED_ONLY",
                        "ENABLED_NOT_TRIGGERED",
                        "TRIGGERED",
                    ] as const,
                    `${path}.coverage_state`,
                ),
            };
        }),
        mapped_rule_count: integerAt(
            row.mapped_rule_count,
            "coverage.mapped_rule_count",
        ),
        unmapped_rule_count: integerAt(
            row.unmapped_rule_count,
            "coverage.unmapped_rule_count",
        ),
        validation_gap_count: integerAt(
            row.validation_gap_count,
            "coverage.validation_gap_count",
        ),
    };
}

function namedMetricsAt(
    value: unknown,
    path: string,
): Array<{ name: string; count: number }> {
    if (!Array.isArray(value)) throw new ContractError(path);
    return value.map((item, index) => {
        const row = objectAt(item, `${path}[${index}]`);
        return {
            name: stringAt(row.name, `${path}[${index}].name`),
            count: integerAt(row.count, `${path}[${index}].count`),
        };
    });
}

function analyticsPointsAt(
    value: unknown,
    path: string,
): Array<{ bucket: string; count: number }> {
    if (!Array.isArray(value)) throw new ContractError(path);
    return value.map((item, index) => {
        const row = objectAt(item, `${path}[${index}]`);
        return {
            bucket: stringAt(row.bucket, `${path}[${index}].bucket`),
            count: integerAt(row.count, `${path}[${index}].count`),
        };
    });
}

export function parseDetectionAnalytics(value: unknown): DetectionAnalytics {
    const row = objectAt(value, "analytics");
    if (!Array.isArray(row.false_positive_rules))
        throw new ContractError("analytics.false_positive_rules");
    return {
        start_time: dateAt(row.start_time, "analytics.start_time"),
        end_time: dateAt(row.end_time, "analytics.end_time"),
        alert_trend: analyticsPointsAt(
            row.alert_trend,
            "analytics.alert_trend",
        ),
        false_positive_trend: analyticsPointsAt(
            row.false_positive_trend,
            "analytics.false_positive_trend",
        ),
        top_rules: namedMetricsAt(row.top_rules, "analytics.top_rules"),
        top_source_ips: namedMetricsAt(
            row.top_source_ips,
            "analytics.top_source_ips",
        ),
        top_hosts: namedMetricsAt(row.top_hosts, "analytics.top_hosts"),
        mitre_distribution: namedMetricsAt(
            row.mitre_distribution,
            "analytics.mitre_distribution",
        ),
        ioc_matches: namedMetricsAt(row.ioc_matches, "analytics.ioc_matches"),
        analyst_dispositions: (() => {
            if (!Array.isArray(row.analyst_dispositions))
                throw new ContractError("analytics.analyst_dispositions");
            return row.analyst_dispositions.map((item, index) => {
                const path = `analytics.analyst_dispositions[${index}]`;
                const entry = objectAt(item, path);
                return {
                    analyst: stringAt(entry.analyst, `${path}.analyst`),
                    resolved_count: integerAt(
                        entry.resolved_count,
                        `${path}.resolved_count`,
                    ),
                    false_positive_count: integerAt(
                        entry.false_positive_count,
                        `${path}.false_positive_count`,
                    ),
                    total_count: integerAt(
                        entry.total_count,
                        `${path}.total_count`,
                    ),
                };
            });
        })(),
        false_positive_rules: row.false_positive_rules.map((item, index) => {
            const path = `analytics.false_positive_rules[${index}]`;
            const entry = objectAt(item, path);
            const rate =
                entry.false_positive_rate == null
                    ? null
                    : nonnegativeNumberAt(
                          entry.false_positive_rate,
                          `${path}.false_positive_rate`,
                      );
            if (rate !== null && rate > 1)
                throw new ContractError(`${path}.false_positive_rate`);
            return {
                rule_id: stringAt(entry.rule_id, `${path}.rule_id`),
                total_alerts: integerAt(
                    entry.total_alerts,
                    `${path}.total_alerts`,
                ),
                dispositioned_alerts: integerAt(
                    entry.dispositioned_alerts,
                    `${path}.dispositioned_alerts`,
                ),
                false_positive_count: integerAt(
                    entry.false_positive_count,
                    `${path}.false_positive_count`,
                ),
                false_positive_rate: rate,
                tuning_candidate: booleanAt(
                    entry.tuning_candidate,
                    `${path}.tuning_candidate`,
                ),
            };
        }),
        suggested_tuning_candidates: stringsAt(
            row.suggested_tuning_candidates,
            "analytics.suggested_tuning_candidates",
        ),
    };
}

function huntQueryAt(value: unknown, path: string): ThreatHuntQuery {
    const row = objectAt(value, path);
    const relative =
        row.relative_minutes == null
            ? undefined
            : (integerAt(
                  row.relative_minutes,
                  `${path}.relative_minutes`,
                  1,
              ) as ThreatHuntQuery["relativeMinutes"]);
    return {
        relativeMinutes: relative,
        startTime:
            row.start_time == null
                ? undefined
                : dateAt(row.start_time, `${path}.start_time`),
        endTime:
            row.end_time == null
                ? undefined
                : dateAt(row.end_time, `${path}.end_time`),
        ip: nullableStringAt(row.ip, `${path}.ip`) ?? undefined,
        hostname:
            nullableStringAt(row.hostname, `${path}.hostname`) ?? undefined,
        username:
            nullableStringAt(row.username, `${path}.username`) ?? undefined,
        eventCategory:
            nullableStringAt(row.event_category, `${path}.event_category`) ??
            undefined,
        ruleId: nullableStringAt(row.rule_id, `${path}.rule_id`) ?? undefined,
        mitreId:
            nullableStringAt(row.mitre_id, `${path}.mitre_id`) ?? undefined,
        search: nullableStringAt(row.search, `${path}.search`) ?? undefined,
        sort: enumAt(row.sort, ["newest", "oldest"] as const, `${path}.sort`),
    };
}

function huntEventAt(value: unknown, path: string): HuntEvent {
    const row = objectAt(value, path);
    return {
        event_id: stringAt(row.event_id, `${path}.event_id`),
        timestamp: dateAt(row.timestamp, `${path}.timestamp`),
        source_type: stringAt(row.source_type, `${path}.source_type`),
        hostname: nullableStringAt(row.hostname, `${path}.hostname`),
        source_ip: nullableStringAt(row.source_ip, `${path}.source_ip`),
        destination_ip: nullableStringAt(
            row.destination_ip,
            `${path}.destination_ip`,
        ),
        username: nullableStringAt(row.username, `${path}.username`),
        event_category: nullableStringAt(
            row.event_category,
            `${path}.event_category`,
        ),
        rule_id: nullableStringAt(row.rule_id, `${path}.rule_id`),
        severity: nullableIntegerAt(row.severity, `${path}.severity`),
        message: stringAt(row.message, `${path}.message`),
        related_alert_id: nullableStringAt(
            row.related_alert_id,
            `${path}.related_alert_id`,
        ),
        related_incident_ids: stringsAt(
            row.related_incident_ids,
            `${path}.related_incident_ids`,
        ),
    };
}

export function parseThreatHuntPage(value: unknown): ThreatHuntPage {
    const row = objectAt(value, "hunt");
    if (!Array.isArray(row.items)) throw new ContractError("hunt.items");
    const cursor = row.next_cursor;
    if (cursor !== null && typeof cursor !== "string")
        throw new ContractError("hunt.next_cursor");
    return {
        items: row.items.map((item, index) =>
            huntEventAt(item, `hunt.items[${index}]`),
        ),
        total: integerAt(row.total, "hunt.total"),
        limit: integerAt(row.limit, "hunt.limit", 1),
        next_cursor: cursor,
        start_time: dateAt(row.start_time, "hunt.start_time"),
        end_time: dateAt(row.end_time, "hunt.end_time"),
    };
}

export function parseSavedHunts(value: unknown): SavedHunt[] {
    if (!Array.isArray(value)) throw new ContractError("saved_hunts");
    return value.map((item, index) => {
        const path = `saved_hunts[${index}]`;
        const row = objectAt(item, path);
        return {
            saved_hunt_id: stringAt(row.saved_hunt_id, `${path}.saved_hunt_id`),
            name: stringAt(row.name, `${path}.name`),
            query: huntQueryAt(row.query, `${path}.query`),
            created_at: dateAt(row.created_at, `${path}.created_at`),
            updated_at: dateAt(row.updated_at, `${path}.updated_at`),
        };
    });
}

export function parseSavedHunt(value: unknown): SavedHunt {
    return parseSavedHunts([value])[0];
}

function iocAt(value: unknown, path: string): IOCIndicator {
    const row = objectAt(value, path);
    const algorithm = nullableStringAt(
        row.hash_algorithm,
        `${path}.hash_algorithm`,
    );
    if (algorithm !== null && !["MD5", "SHA1", "SHA256"].includes(algorithm))
        throw new ContractError(`${path}.hash_algorithm`);
    return {
        indicator_id: stringAt(row.indicator_id, `${path}.indicator_id`),
        indicator_type: enumAt(
            row.indicator_type,
            ["IPV4", "IPV6", "DOMAIN", "FILE_HASH"] as const,
            `${path}.indicator_type`,
        ),
        value: stringAt(row.value, `${path}.value`),
        hash_algorithm: algorithm as IOCIndicator["hash_algorithm"],
        source: stringAt(row.source, `${path}.source`),
        confidence: integerAt(row.confidence, `${path}.confidence`),
        description: stringAt(row.description, `${path}.description`),
        expires_at:
            row.expires_at == null
                ? null
                : dateAt(row.expires_at, `${path}.expires_at`),
        is_active: booleanAt(row.is_active, `${path}.is_active`),
        expired: booleanAt(row.expired, `${path}.expired`),
        version: integerAt(row.version, `${path}.version`, 1),
        created_at: dateAt(row.created_at, `${path}.created_at`),
        updated_at: dateAt(row.updated_at, `${path}.updated_at`),
    };
}

export function parseIOCs(value: unknown): IOCIndicator[] {
    if (!Array.isArray(value)) throw new ContractError("iocs");
    return value.map((item, index) => iocAt(item, `iocs[${index}]`));
}

export function parseIOC(value: unknown): IOCIndicator {
    return iocAt(value, "ioc");
}

export function parseIOCImport(value: unknown): {
    created: number;
    duplicates: number;
    indicators: IOCIndicator[];
} {
    const row = objectAt(value, "ioc_import");
    if (!Array.isArray(row.indicators))
        throw new ContractError("ioc_import.indicators");
    return {
        created: integerAt(row.created, "ioc_import.created"),
        duplicates: integerAt(row.duplicates, "ioc_import.duplicates"),
        indicators: row.indicators.map((item, index) =>
            iocAt(item, `ioc_import.indicators[${index}]`),
        ),
    };
}

export function parseIOCMatches(value: unknown): IOCMatchSummary {
    const row = objectAt(value, "ioc_matches");
    if (!Array.isArray(row.matches))
        throw new ContractError("ioc_matches.matches");
    return {
        start_time: dateAt(row.start_time, "ioc_matches.start_time"),
        end_time: dateAt(row.end_time, "ioc_matches.end_time"),
        total_matches: integerAt(
            row.total_matches,
            "ioc_matches.total_matches",
        ),
        truncated: booleanAt(row.truncated, "ioc_matches.truncated"),
        matches: row.matches.map((item, index) => {
            const path = `ioc_matches.matches[${index}]`;
            const match = objectAt(item, path);
            return {
                indicator_id: stringAt(
                    match.indicator_id,
                    `${path}.indicator_id`,
                ),
                indicator_type: enumAt(
                    match.indicator_type,
                    ["IPV4", "IPV6", "DOMAIN", "FILE_HASH"] as const,
                    `${path}.indicator_type`,
                ),
                value: stringAt(match.value, `${path}.value`),
                event_id: stringAt(match.event_id, `${path}.event_id`),
                event_timestamp: dateAt(
                    match.event_timestamp,
                    `${path}.event_timestamp`,
                ),
                matched_field: stringAt(
                    match.matched_field,
                    `${path}.matched_field`,
                ),
            };
        }),
    };
}

function correlationAt(
    value: unknown,
    path: string,
): IncidentCorrelation | null {
    if (value === null) return null;
    const correlation = objectAt(value, path);
    const confidence = stringAt(correlation.confidence, `${path}.confidence`);
    if (confidence !== "EXACT_MATCH" && confidence !== "STRONG_MATCH") {
        throw new ContractError(`${path}.confidence`);
    }
    return {
        correlation_rule: stringAt(
            correlation.correlation_rule,
            `${path}.correlation_rule`,
        ),
        classification: stringAt(
            correlation.classification,
            `${path}.classification`,
        ),
        confidence,
        source_identity: stringAt(
            correlation.source_identity,
            `${path}.source_identity`,
        ),
        target_identity: stringAt(
            correlation.target_identity,
            `${path}.target_identity`,
        ),
        explanation: stringAt(correlation.explanation, `${path}.explanation`),
        first_seen: dateAt(correlation.first_seen, `${path}.first_seen`),
        last_seen: dateAt(correlation.last_seen, `${path}.last_seen`),
        related_alert_count: integerAt(
            correlation.related_alert_count,
            `${path}.related_alert_count`,
            2,
        ),
    };
}

function timelineAlertAt(value: unknown, path: string): IncidentTimelineAlert {
    const alert = objectAt(value, path);
    const level = integerAt(alert.rule_level, `${path}.rule_level`);
    if (level > 16) throw new ContractError(`${path}.rule_level`);
    return {
        alert_id: stringAt(alert.alert_id, `${path}.alert_id`),
        occurred_at: dateAt(alert.occurred_at, `${path}.occurred_at`),
        rule_id: stringAt(alert.rule_id, `${path}.rule_id`),
        rule_level: level,
        rule_description: stringAt(
            alert.rule_description,
            `${path}.rule_description`,
        ),
        agent_id: stringAt(alert.agent_id, `${path}.agent_id`),
        agent_name: stringAt(alert.agent_name, `${path}.agent_name`),
        source_ip: nullableStringAt(alert.source_ip, `${path}.source_ip`),
        destination_ip: nullableStringAt(
            alert.destination_ip,
            `${path}.destination_ip`,
        ),
        mitre_ids: stringsAt(alert.mitre_ids, `${path}.mitre_ids`),
    };
}

export function parseIncidentDetail(value: unknown): IncidentDetail {
    const incident = objectAt(value, "incident");
    const summary = incidentSummaryAt(incident, "incident");
    if (!Array.isArray(incident.notes))
        throw new ContractError("incident.notes");
    if (!Array.isArray(incident.history))
        throw new ContractError("incident.history");
    if (!Array.isArray(incident.timeline))
        throw new ContractError("incident.timeline");
    return {
        ...summary,
        alert_ids: stringsAt(incident.alert_ids, "incident.alert_ids"),
        notes: incident.notes.map((note, index) =>
            parseIncidentNote(note, `incident.notes[${index}]`),
        ),
        history: incident.history.map((event, index) =>
            historyAt(event, `incident.history[${index}]`),
        ),
        correlation: correlationAt(
            incident.correlation,
            "incident.correlation",
        ),
        timeline: incident.timeline.map((alert, index) =>
            timelineAlertAt(alert, `incident.timeline[${index}]`),
        ),
    };
}

function checklistItemAt(value: unknown, path: string): ChecklistItem {
    const item = objectAt(value, path);
    return {
        checklist_item_id: boundedStringAt(
            item.checklist_item_id,
            `${path}.checklist_item_id`,
            64,
        ),
        incident_id: boundedStringAt(
            item.incident_id,
            `${path}.incident_id`,
            64,
        ),
        body: boundedStringAt(item.body, `${path}.body`, 1024),
        is_completed: booleanAt(item.is_completed, `${path}.is_completed`),
        assigned_to: alertAssigneeAt(item.assigned_to, `${path}.assigned_to`),
        position: integerAt(item.position, `${path}.position`),
        version: integerAt(item.version, `${path}.version`, 1),
        created_at: dateAt(item.created_at, `${path}.created_at`),
        updated_at: dateAt(item.updated_at, `${path}.updated_at`),
        completed_at:
            item.completed_at === null
                ? null
                : dateAt(item.completed_at, `${path}.completed_at`),
        created_by_display: stringAt(
            item.created_by_display,
            `${path}.created_by_display`,
        ),
        updated_by_display: stringAt(
            item.updated_by_display,
            `${path}.updated_by_display`,
        ),
    };
}

function evidencePinAt(value: unknown, path: string): EvidencePin {
    const pin = objectAt(value, path);
    const evidenceType = stringAt(pin.evidence_type, `${path}.evidence_type`);
    if (!["EVENT", "ALERT", "INCIDENT_EVIDENCE"].includes(evidenceType))
        throw new ContractError(`${path}.evidence_type`);
    return {
        evidence_pin_id: boundedStringAt(
            pin.evidence_pin_id,
            `${path}.evidence_pin_id`,
            64,
        ),
        incident_id: boundedStringAt(
            pin.incident_id,
            `${path}.incident_id`,
            64,
        ),
        evidence_type: evidenceType as EvidenceType,
        evidence_id: boundedStringAt(
            pin.evidence_id,
            `${path}.evidence_id`,
            255,
        ),
        annotation: stringAt(pin.annotation, `${path}.annotation`),
        source_timestamp: dateAt(
            pin.source_timestamp,
            `${path}.source_timestamp`,
        ),
        pinned_by_display: stringAt(
            pin.pinned_by_display,
            `${path}.pinned_by_display`,
        ),
        pinned_at: dateAt(pin.pinned_at, `${path}.pinned_at`),
        updated_at: dateAt(pin.updated_at, `${path}.updated_at`),
        version: integerAt(pin.version, `${path}.version`, 1),
    };
}

export function parseInvestigationWorkspace(
    value: unknown,
): InvestigationWorkspace {
    const workspace = objectAt(value, "investigation");
    if (!Array.isArray(workspace.checklist_items))
        throw new ContractError("investigation.checklist_items");
    if (!Array.isArray(workspace.evidence_pins))
        throw new ContractError("investigation.evidence_pins");
    return {
        incident_id: boundedStringAt(
            workspace.incident_id,
            "investigation.incident_id",
            64,
        ),
        checklist_items: workspace.checklist_items.map((item, index) =>
            checklistItemAt(item, `investigation.checklist_items[${index}]`),
        ),
        evidence_pins: workspace.evidence_pins.map((item, index) =>
            evidencePinAt(item, `investigation.evidence_pins[${index}]`),
        ),
        checklist_completed: integerAt(
            workspace.checklist_completed,
            "investigation.checklist_completed",
        ),
        checklist_total: integerAt(
            workspace.checklist_total,
            "investigation.checklist_total",
        ),
    };
}

export function parseInvestigationTimeline(
    value: unknown,
): InvestigationTimelinePage {
    const page = objectAt(value, "investigation_timeline");
    if (!Array.isArray(page.items))
        throw new ContractError("investigation_timeline.items");
    const next = page.next_cursor;
    if (next !== null && typeof next !== "string")
        throw new ContractError("investigation_timeline.next_cursor");
    return {
        items: page.items.map((value, index): InvestigationActivity => {
            const path = `investigation_timeline.items[${index}]`;
            const item = objectAt(value, path);
            return {
                activity_id: stringAt(item.activity_id, `${path}.activity_id`),
                activity_type: stringAt(
                    item.activity_type,
                    `${path}.activity_type`,
                ),
                entity_type: stringAt(item.entity_type, `${path}.entity_type`),
                entity_id: stringAt(item.entity_id, `${path}.entity_id`),
                actor_display: stringAt(
                    item.actor_display,
                    `${path}.actor_display`,
                ),
                action_at: dateAt(item.action_at, `${path}.action_at`),
                source_timestamp:
                    item.source_timestamp === null
                        ? null
                        : dateAt(
                              item.source_timestamp,
                              `${path}.source_timestamp`,
                          ),
                details: objectAt(item.details, `${path}.details`),
            };
        }),
        limit: integerAt(page.limit, "investigation_timeline.limit", 1),
        next_cursor: next,
        total: integerAt(page.total, "investigation_timeline.total"),
    };
}

export function parsePreferences(value: unknown): AnalystPreferences {
    const preferences = objectAt(value, "preferences");
    const dashboardRange = stringAt(
        preferences.dashboard_range,
        "preferences.dashboard_range",
    );
    const density = stringAt(
        preferences.table_density,
        "preferences.table_density",
    );
    const timeDisplay = stringAt(
        preferences.time_display,
        "preferences.time_display",
    );
    const sort = stringAt(
        preferences.alert_default_sort,
        "preferences.alert_default_sort",
    );
    if (!["24h", "7d", "30d"].includes(dashboardRange))
        throw new ContractError("preferences.dashboard_range");
    if (!["COMFORTABLE", "COMPACT"].includes(density))
        throw new ContractError("preferences.table_density");
    if (!["LOCAL", "UTC", "RELATIVE"].includes(timeDisplay))
        throw new ContractError("preferences.time_display");
    if (
        ![
            "time_desc",
            "time_asc",
            "severity_desc",
            "severity_asc",
            "activity_desc",
        ].includes(sort)
    )
        throw new ContractError("preferences.alert_default_sort");
    const columns = stringsAt(
        preferences.discover_columns,
        "preferences.discover_columns",
    );
    if (
        columns.some(
            (column) =>
                !(DISCOVER_COLUMNS as readonly string[]).includes(column),
        )
    )
        throw new ContractError("preferences.discover_columns");
    return {
        dashboard_range: dashboardRange as DashboardRange,
        discover_page_size: integerAt(
            preferences.discover_page_size,
            "preferences.discover_page_size",
            1,
        ) as AnalystPreferences["discover_page_size"],
        alert_page_size: integerAt(
            preferences.alert_page_size,
            "preferences.alert_page_size",
            1,
        ) as AnalystPreferences["alert_page_size"],
        incident_page_size: integerAt(
            preferences.incident_page_size,
            "preferences.incident_page_size",
            1,
        ) as AnalystPreferences["incident_page_size"],
        table_density: density as TableDensity,
        time_display: timeDisplay as TimeDisplay,
        alert_default_sort: sort as AnalystPreferences["alert_default_sort"],
        discover_columns: columns as DiscoverColumn[],
        version: integerAt(preferences.version, "preferences.version", 1),
    };
}

export function parseHealth(value: unknown): HealthResponse {
    const health = objectAt(value, "health");
    return {
        status: stringAt(health.status, "health.status"),
        service: stringAt(health.service, "health.service"),
    };
}

function principalAt(value: unknown, path: string): AnalystPrincipal {
    const principal = objectAt(value, path);
    const role = stringAt(principal.role, `${path}.role`);
    if (!(ANALYST_ROLES as readonly string[]).includes(role))
        throw new ContractError(`${path}.role`);
    const permissions = stringsAt(principal.permissions, `${path}.permissions`);
    if (
        permissions.some(
            (permission) =>
                !(PERMISSIONS as readonly string[]).includes(permission),
        )
    ) {
        throw new ContractError(`${path}.permissions`);
    }
    return {
        analyst_id: stringAt(principal.analyst_id, `${path}.analyst_id`),
        username: stringAt(principal.username, `${path}.username`),
        display_name: stringAt(principal.display_name, `${path}.display_name`),
        role: role as AnalystRole,
        permissions: permissions as Permission[],
    };
}

export function parseSession(value: unknown): SessionResponse {
    const session = objectAt(value, "session");
    return {
        analyst: principalAt(session.analyst, "session.analyst"),
        csrf_token: stringAt(session.csrf_token, "session.csrf_token"),
    };
}

export function parseAnalysts(value: unknown): AnalystPublic[] {
    if (!Array.isArray(value)) throw new ContractError("analysts");
    return value.map((item, index) => {
        const path = `analysts[${index}]`;
        const row = objectAt(item, path);
        const role = stringAt(row.role, `${path}.role`);
        if (!(ANALYST_ROLES as readonly string[]).includes(role))
            throw new ContractError(`${path}.role`);
        return {
            analyst_id: stringAt(row.analyst_id, `${path}.analyst_id`),
            username: stringAt(row.username, `${path}.username`),
            display_name: stringAt(row.display_name, `${path}.display_name`),
            role: role as AnalystRole,
            is_active: booleanAt(row.is_active, `${path}.is_active`),
            created_at: dateAt(row.created_at, `${path}.created_at`),
            updated_at: dateAt(row.updated_at, `${path}.updated_at`),
        };
    });
}

export function parseAnalystSessionStatus(
    value: unknown,
): AnalystSessionStatus {
    const row = objectAt(value, "session_status");
    return {
        active_sessions: integerAt(
            row.active_sessions,
            "session_status.active_sessions",
            1,
        ),
        current_expires_at: dateAt(
            row.current_expires_at,
            "session_status.current_expires_at",
        ),
    };
}

export function parseSecurityAuditPage(value: unknown): {
    items: SecurityAuditEvent[];
    limit: number;
} {
    const page = objectAt(value, "audit_page");
    if (!Array.isArray(page.items)) throw new ContractError("audit_page.items");
    return {
        limit: integerAt(page.limit, "audit_page.limit", 1),
        items: page.items.map((item, index) => {
            const path = `audit_page.items[${index}]`;
            const row = objectAt(item, path);
            const outcome = stringAt(row.outcome, `${path}.outcome`);
            if (
                !(["SUCCESS", "DENIED", "FAILURE"] as const).includes(
                    outcome as "SUCCESS",
                )
            )
                throw new ContractError(`${path}.outcome`);
            return {
                audit_id: stringAt(row.audit_id, `${path}.audit_id`),
                action: stringAt(row.action, `${path}.action`),
                actor_id: nullableStringAt(row.actor_id, `${path}.actor_id`),
                actor_display: stringAt(
                    row.actor_display,
                    `${path}.actor_display`,
                ),
                target_type: stringAt(row.target_type, `${path}.target_type`),
                target_id: nullableStringAt(row.target_id, `${path}.target_id`),
                outcome: outcome as SecurityAuditEvent["outcome"],
                occurred_at: dateAt(row.occurred_at, `${path}.occurred_at`),
                details: objectAt(row.details, `${path}.details`),
            };
        }),
    };
}

function analysisResultAt(value: unknown, path: string): AIAnalysisResult {
    const result = objectAt(value, path);
    const mitre = result.mitre_context;
    if (!Array.isArray(mitre) || mitre.length > 12)
        throw new ContractError(`${path}.mitre_context`);
    return {
        summary: boundedStringAt(result.summary, `${path}.summary`, 2000),
        assessment: boundedStringAt(
            result.assessment,
            `${path}.assessment`,
            4000,
        ),
        key_evidence: boundedStringsAt(
            result.key_evidence,
            `${path}.key_evidence`,
            12,
            1200,
        ),
        mitre_context: mitre.map((item, index) => {
            const entry = objectAt(item, `${path}.mitre_context[${index}]`);
            const basis = stringAt(
                entry.basis,
                `${path}.mitre_context[${index}].basis`,
            );
            if (basis !== "observed" && basis !== "inferred")
                throw new ContractError(
                    `${path}.mitre_context[${index}].basis`,
                );
            return {
                technique_id: boundedStringAt(
                    entry.technique_id,
                    `${path}.mitre_context[${index}].technique_id`,
                    32,
                ),
                explanation: boundedStringAt(
                    entry.explanation,
                    `${path}.mitre_context[${index}].explanation`,
                    1200,
                ),
                basis,
            };
        }),
        timeline_summary:
            result.timeline_summary === null
                ? null
                : boundedStringAt(
                      result.timeline_summary,
                      `${path}.timeline_summary`,
                      2400,
                  ),
        hypotheses: boundedStringsAt(
            result.hypotheses,
            `${path}.hypotheses`,
            10,
            1200,
        ),
        investigation_steps: boundedStringsAt(
            result.investigation_steps,
            `${path}.investigation_steps`,
            12,
            1200,
        ),
        possible_false_positive_reasons: boundedStringsAt(
            result.possible_false_positive_reasons,
            `${path}.possible_false_positive_reasons`,
            10,
            1200,
        ),
        recommended_actions: boundedStringsAt(
            result.recommended_actions,
            `${path}.recommended_actions`,
            12,
            1200,
        ),
        containment_considerations: boundedStringsAt(
            result.containment_considerations,
            `${path}.containment_considerations`,
            10,
            1200,
        ),
        uncertainties: boundedStringsAt(
            result.uncertainties,
            `${path}.uncertainties`,
            10,
            1200,
        ),
    };
}

export function parseAIStatus(value: unknown): AIStatus {
    const status = objectAt(value, "ai_status");
    const state = stringAt(status.state, "ai_status.state");
    if (!(AI_AVAILABILITY as readonly string[]).includes(state))
        throw new ContractError("ai_status.state");
    if (status.provider !== "ollama")
        throw new ContractError("ai_status.provider");
    return {
        state: state as AIAvailability,
        provider: "ollama",
        model: nullableStringAt(status.model, "ai_status.model"),
        diagnostic: nullableStringAt(status.diagnostic, "ai_status.diagnostic"),
        checked_at: dateAt(status.checked_at, "ai_status.checked_at"),
    };
}

export function parseAIAnalysis(
    value: unknown,
    path = "analysis",
): AIAnalysisRecord {
    const analysis = objectAt(value, path);
    const types: AIAnalysisType[] = [
        "ALERT_SUMMARY",
        "INCIDENT_SUMMARY",
        "ANALYST_QUESTION",
    ];
    const analysisType = stringAt(
        analysis.analysis_type,
        `${path}.analysis_type`,
    );
    if (!types.includes(analysisType as AIAnalysisType))
        throw new ContractError(`${path}.analysis_type`);
    const targetType = stringAt(analysis.target_type, `${path}.target_type`);
    if (targetType !== "alert" && targetType !== "incident")
        throw new ContractError(`${path}.target_type`);
    const requester = objectAt(analysis.requested_by, `${path}.requested_by`);
    const context = objectAt(analysis.context, `${path}.context`);
    if (analysis.provider !== "ollama")
        throw new ContractError(`${path}.provider`);
    if (analysis.policy_version !== "cyberqalqon-ai-policy-v1")
        throw new ContractError(`${path}.policy_version`);
    if (analysis.schema_version !== "ai-analysis-v1")
        throw new ContractError(`${path}.schema_version`);
    const fingerprint = stringAt(
        analysis.context_fingerprint,
        `${path}.context_fingerprint`,
    );
    if (!/^[0-9a-f]{64}$/.test(fingerprint))
        throw new ContractError(`${path}.context_fingerprint`);
    return {
        analysis_id: stringAt(analysis.analysis_id, `${path}.analysis_id`),
        analysis_type: analysisType as AIAnalysisType,
        target_type: targetType as AITargetType,
        target_id: stringAt(analysis.target_id, `${path}.target_id`),
        requested_by: {
            analyst_id: stringAt(
                requester.analyst_id,
                `${path}.requested_by.analyst_id`,
            ),
            display: stringAt(
                requester.display,
                `${path}.requested_by.display`,
            ),
        },
        requested_at: dateAt(analysis.requested_at, `${path}.requested_at`),
        completed_at: dateAt(analysis.completed_at, `${path}.completed_at`),
        provider: "ollama",
        model: boundedStringAt(analysis.model, `${path}.model`, 256),
        model_digest: nullableStringAt(
            analysis.model_digest,
            `${path}.model_digest`,
        ),
        policy_version: "cyberqalqon-ai-policy-v1",
        schema_version: "ai-analysis-v1",
        context_fingerprint: fingerprint,
        context: {
            context_bytes: integerAt(
                context.context_bytes,
                `${path}.context.context_bytes`,
            ),
            truncated: booleanAt(
                context.truncated,
                `${path}.context.truncated`,
            ),
            alerts_included: integerAt(
                context.alerts_included,
                `${path}.context.alerts_included`,
            ),
            alerts_available: integerAt(
                context.alerts_available,
                `${path}.context.alerts_available`,
            ),
            notes_included: integerAt(
                context.notes_included,
                `${path}.context.notes_included`,
            ),
            notes_available: integerAt(
                context.notes_available,
                `${path}.context.notes_available`,
            ),
            history_included: integerAt(
                context.history_included,
                `${path}.context.history_included`,
            ),
            history_available: integerAt(
                context.history_available,
                `${path}.context.history_available`,
            ),
            raw_event_included: booleanAt(
                context.raw_event_included,
                `${path}.context.raw_event_included`,
            ),
            truncation_reasons: boundedStringsAt(
                context.truncation_reasons,
                `${path}.context.truncation_reasons`,
                20,
                256,
            ),
        },
        stale: booleanAt(analysis.stale, `${path}.stale`),
        result: analysisResultAt(analysis.result, `${path}.result`),
    };
}

export function parseAIAnalysisHistory(value: unknown): AIAnalysisHistory {
    const history = objectAt(value, "analysis_history");
    if (!Array.isArray(history.items) || history.items.length > 50)
        throw new ContractError("analysis_history.items");
    return {
        items: history.items.map((item, index) =>
            parseAIAnalysis(item, `analysis_history.items[${index}]`),
        ),
        limit: integerAt(history.limit, "analysis_history.limit", 1),
    };
}

const WORKBENCH_TARGETS = ["EVENT", "ALERT", "INCIDENT", "CASE", "CORRELATION_GROUP", "M11_FINDING", "SHADOW_FINDING", "ENTITY"] as const;
const WORKBENCH_ENTITIES = ["IPV4", "IPV6", "HOSTNAME", "USERNAME", "AGENT_ID", "RULE_ID", "PROCESS_NAME", "PROCESS_ID", "FILE_HASH", "DOMAIN"] as const;
const TIMELINE_TYPES = ["SECURITY_EVENT", "ALERT", "DETECTION_FINDING", "INCIDENT_ACTIVITY", "ANALYST_NOTE", "CASE_ACTIVITY", "CASE_COMMENT", "EVIDENCE_ACTION"] as const;

export function parseInvestigationWorkbench(value: unknown): InvestigationWorkbench {
    const item = objectAt(value, "workbench");
    const summary = objectAt(item.summary, "workbench.summary");
    const query = objectAt(item.query, "workbench.query");
    const entities = item.entities;
    const related = item.related_events;
    const links = item.links;
    const timeline = item.timeline;
    const iocs = item.ioc_matches;
    const correlations = item.correlation_groups;
    if (!Array.isArray(entities) || entities.length > 50) throw new ContractError("workbench.entities");
    if (!Array.isArray(related) || related.length > 100) throw new ContractError("workbench.related_events");
    if (!Array.isArray(links) || links.length > 100) throw new ContractError("workbench.links");
    if (!Array.isArray(timeline) || timeline.length > 200) throw new ContractError("workbench.timeline");
    if (!Array.isArray(iocs) || iocs.length > 50) throw new ContractError("workbench.ioc_matches");
    if (!Array.isArray(correlations) || correlations.length > 20) throw new ContractError("workbench.correlation_groups");
    const parsedTimeline: InvestigationTimelineItem[] = timeline.map((valueAtIndex, index) => {
        const entry = objectAt(valueAtIndex, `workbench.timeline[${index}]`);
        const severity = entry.severity == null ? undefined : integerAt(entry.severity, `workbench.timeline[${index}].severity`);
        if (severity !== undefined && severity > 16) throw new ContractError(`workbench.timeline[${index}].severity`);
        return {
            item_id: boundedStringAt(entry.item_id, `workbench.timeline[${index}].item_id`, 255),
            item_type: enumAt(entry.item_type, TIMELINE_TYPES, `workbench.timeline[${index}].item_type`),
            timestamp: dateAt(entry.timestamp, `workbench.timeline[${index}].timestamp`),
            timestamp_kind: enumAt(entry.timestamp_kind, ["EVENT_TIME", "ANALYST_ACTION_TIME"] as const, `workbench.timeline[${index}].timestamp_kind`),
            timestamp_status: enumAt(entry.timestamp_status, ["NORMAL", "FUTURE"] as const, `workbench.timeline[${index}].timestamp_status`),
            title: boundedStringAt(entry.title, `workbench.timeline[${index}].title`, 512),
            source_id: boundedStringAt(entry.source_id, `workbench.timeline[${index}].source_id`, 255),
            severity,
            actor_display: entry.actor_display == null ? undefined : boundedStringAt(entry.actor_display, `workbench.timeline[${index}].actor_display`, 256),
            relationship_types: boundedStringsAt(entry.relationship_types, `workbench.timeline[${index}].relationship_types`, 12, 64),
            details: objectAt(entry.details, `workbench.timeline[${index}].details`),
        };
    });
    const detection = item.detection_context == null ? undefined : (() => {
        const context = objectAt(item.detection_context, "workbench.detection_context");
        const sideEffects = booleanAt(context.side_effects, "workbench.detection_context.side_effects");
        if (sideEffects) throw new ContractError("workbench.detection_context.side_effects");
        return {
            rule: parseAdvancedDetectionRule(context.rule, "workbench.detection_context.rule"),
            finding: parseAdvancedFinding(context.finding, "workbench.detection_context.finding"),
            evaluated_event_count: integerAt(context.evaluated_event_count, "workbench.detection_context.evaluated_event_count"),
            execution_budget_ms: integerAt(context.execution_budget_ms, "workbench.detection_context.execution_budget_ms", 50),
            source_kind: enumAt(
                context.source_kind ?? "HISTORICAL_DRY_RUN",
                ["HISTORICAL_DRY_RUN", "SHADOW"] as const,
                "workbench.detection_context.source_kind",
            ),
            shadow_run_id:
                context.shadow_run_id == null
                    ? undefined
                    : stringAt(context.shadow_run_id, "workbench.detection_context.shadow_run_id"),
            side_effects: false as const,
        };
    })();
    return {
        target_type: enumAt(item.target_type, WORKBENCH_TARGETS, "workbench.target_type") as WorkbenchTargetType,
        target_label: boundedStringAt(item.target_label, "workbench.target_label", 320),
        primary_event: parseSecurityEvent(item.primary_event, "workbench.primary_event"),
        summary: {
            observations: boundedStringsAt(summary.observations, "workbench.summary.observations", 20, 1024),
            interpretations: boundedStringsAt(summary.interpretations, "workbench.summary.interpretations", 10, 1024),
            missing_fields: boundedStringsAt(summary.missing_fields, "workbench.summary.missing_fields", 30, 128),
        },
        entities: entities.map((valueAtIndex, index) => {
            const entity = objectAt(valueAtIndex, `workbench.entities[${index}]`);
            return {
                entity_type: enumAt(entity.entity_type, WORKBENCH_ENTITIES, `workbench.entities[${index}].entity_type`) as InvestigationEntityType,
                value: boundedStringAt(entity.value, `workbench.entities[${index}].value`, 2048),
                label: boundedStringAt(entity.label, `workbench.entities[${index}].label`, 80),
                sensitive: booleanAt(entity.sensitive, `workbench.entities[${index}].sensitive`),
                pivot_supported: booleanAt(entity.pivot_supported, `workbench.entities[${index}].pivot_supported`),
                evidence_field: boundedStringAt(entity.evidence_field, `workbench.entities[${index}].evidence_field`, 128),
            };
        }),
        related_events: related.map((valueAtIndex, index) => {
            const entry = objectAt(valueAtIndex, `workbench.related_events[${index}]`);
            return {
                event: eventSummaryAt(entry.event, `workbench.related_events[${index}].event`),
                relationship_types: boundedStringsAt(entry.relationship_types, `workbench.related_events[${index}].relationship_types`, 12, 64),
            };
        }),
        links: links.map((valueAtIndex, index) => {
            const link = objectAt(valueAtIndex, `workbench.links[${index}]`);
            return {
                target_type: enumAt(link.target_type, ["ALERT", "INCIDENT", "CASE", "CORRELATION_GROUP"] as const, `workbench.links[${index}].target_type`),
                target_id: boundedStringAt(link.target_id, `workbench.links[${index}].target_id`, 255),
                title: boundedStringAt(link.title, `workbench.links[${index}].title`, 320),
                status: link.status == null ? undefined : boundedStringAt(link.status, `workbench.links[${index}].status`, 64),
                severity: link.severity == null ? undefined : boundedStringAt(link.severity, `workbench.links[${index}].severity`, 32),
            };
        }),
        timeline: parsedTimeline,
        ioc_matches: iocs.map((valueAtIndex, index) => {
            const match = objectAt(valueAtIndex, `workbench.ioc_matches[${index}]`);
            const caveat = enumAt(match.caveat, ["IOC_MATCH_IS_NOT_PROOF_OF_COMPROMISE"] as const, `workbench.ioc_matches[${index}].caveat`);
            return {
                indicator_id: stringAt(match.indicator_id, `workbench.ioc_matches[${index}].indicator_id`),
                indicator_type: enumAt(match.indicator_type, ["IPV4", "IPV6", "DOMAIN", "FILE_HASH"] as const, `workbench.ioc_matches[${index}].indicator_type`),
                value: stringAt(match.value, `workbench.ioc_matches[${index}].value`),
                source: stringAt(match.source, `workbench.ioc_matches[${index}].source`),
                confidence: integerAt(match.confidence, `workbench.ioc_matches[${index}].confidence`),
                expires_at: match.expires_at == null ? undefined : dateAt(match.expires_at, `workbench.ioc_matches[${index}].expires_at`),
                evidence_field: stringAt(match.evidence_field, `workbench.ioc_matches[${index}].evidence_field`), caveat,
            };
        }),
        correlation_groups: correlations.map((valueAtIndex, index) => {
            const group = objectAt(valueAtIndex, `workbench.correlation_groups[${index}]`);
            return {
                group_id: stringAt(group.group_id, `workbench.correlation_groups[${index}].group_id`),
                correlation_rule: stringAt(group.correlation_rule, `workbench.correlation_groups[${index}].correlation_rule`),
                classification: stringAt(group.classification, `workbench.correlation_groups[${index}].classification`),
                confidence: stringAt(group.confidence, `workbench.correlation_groups[${index}].confidence`),
                grouping_keys: objectAt(group.grouping_keys, `workbench.correlation_groups[${index}].grouping_keys`) as Record<string, string>,
                first_seen: dateAt(group.first_seen, `workbench.correlation_groups[${index}].first_seen`),
                last_seen: dateAt(group.last_seen, `workbench.correlation_groups[${index}].last_seen`),
                evidence_count: integerAt(group.evidence_count, `workbench.correlation_groups[${index}].evidence_count`, 2),
                explanation: stringAt(group.explanation, `workbench.correlation_groups[${index}].explanation`),
                incident_id: stringAt(group.incident_id, `workbench.correlation_groups[${index}].incident_id`),
            };
        }),
        detection_context: detection,
        query: {
            start_time: dateAt(query.start_time, "workbench.query.start_time"),
            end_time: dateAt(query.end_time, "workbench.query.end_time"),
            related_limit: integerAt(query.related_limit, "workbench.query.related_limit", 1),
            related_cursor: query.related_cursor == null ? undefined : boundedStringAt(query.related_cursor, "workbench.query.related_cursor", 2048),
            related_next_cursor: query.related_next_cursor == null ? undefined : boundedStringAt(query.related_next_cursor, "workbench.query.related_next_cursor", 2048),
            timeline_limit: integerAt(query.timeline_limit, "workbench.query.timeline_limit", 1),
            sort: enumAt(query.sort, ["oldest", "newest"] as const, "workbench.query.sort"),
            execution_ms: nonnegativeNumberAt(query.execution_ms, "workbench.query.execution_ms"),
            related_truncated: booleanAt(query.related_truncated, "workbench.query.related_truncated"),
            schema_version: integerAt(query.schema_version, "workbench.query.schema_version"),
            unavailable_relationships: boundedStringsAt(query.unavailable_relationships, "workbench.query.unavailable_relationships", 20, 64),
        },
    };
}
