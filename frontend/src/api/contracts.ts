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
    DeploymentConfirmationResult,
    DetectionAnalytics,
    DetectionCoverage,
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
    if (retentionState !== "WITHIN_LIMIT" && retentionState !== "AT_LIMIT")
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
    const inventory = objectAt(row.wazuh_inventory, "operations.wazuh_inventory");
    const inventoryState = stringAt(inventory.state, "operations.wazuh_inventory.state");
    if (inventoryState !== "AVAILABLE" && inventoryState !== "UNAVAILABLE")
        throw new ContractError("operations.wazuh_inventory.state");
    if (stringAt(inventory.authority, "operations.wazuh_inventory.authority") !== "WAZUH_API")
        throw new ContractError("operations.wazuh_inventory.authority");
    return {
        generated_at: dateAt(row.generated_at, "operations.generated_at"),
        snapshot_collected_at: row.snapshot_collected_at == null ? null : dateAt(row.snapshot_collected_at, "operations.snapshot_collected_at"),
        snapshot_age_seconds: row.snapshot_age_seconds == null ? null : nonnegativeNumberAt(row.snapshot_age_seconds, "operations.snapshot_age_seconds"),
        components: row.components.map((value, index) => {
            const path = `operations.components[${index}]`;
            const item = objectAt(value, path);
            const kind = stringAt(item.component_kind, `${path}.component_kind`);
            if (!["manager", "wazuh_api", "sender", "event_shipper", "windows_agent", "database"].includes(kind))
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
            raw_evidence_records: integerAt(quality.raw_evidence_records, "operations.data_quality.raw_evidence_records"),
            missing_hostname: integerAt(quality.missing_hostname, "operations.data_quality.missing_hostname"),
            missing_username: integerAt(quality.missing_username, "operations.data_quality.missing_username"),
            missing_rule_id: integerAt(quality.missing_rule_id, "operations.data_quality.missing_rule_id"),
            duplicate_events: nullableIntegerAt(quality.duplicate_events, "operations.data_quality.duplicate_events"),
            malformed_events: nullableIntegerAt(quality.malformed_events, "operations.data_quality.malformed_events"),
            oversized_events: nullableIntegerAt(quality.oversized_events, "operations.data_quality.oversized_events"),
            delivery_rejected: nullableIntegerAt(quality.delivery_rejected, "operations.data_quality.delivery_rejected"),
            evidence: stringAt(quality.evidence, "operations.data_quality.evidence") as OperationalOverview["data_quality"]["evidence"],
        },
        wazuh_inventory: {
            state: inventoryState,
            authority: "WAZUH_API",
            reason: boundedStringAt(inventory.reason, "operations.wazuh_inventory.reason", 320),
            manager_identity: nullableStringAt(inventory.manager_identity, "operations.wazuh_inventory.manager_identity"),
            agent_count: nullableIntegerAt(inventory.agent_count, "operations.wazuh_inventory.agent_count"),
        },
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
