import {parseShadowCatalog,parseShadowValidation,parseShadowResult} from "./shadow-contracts";
import {parseDurableStatus,parseDurableRun,parseFindingPage,parseFindingDetail} from './shadow-history-contracts';
import {parseReconciliationPage} from './evidence-consistency-contract';
import {parseSourceCoverage} from './collection-contract';
import {parseSigmaPreview} from './sigma-contract';
import type {DurableRequest,FindingTransition} from '../types/shadow-history';
import type {ShadowRule,ShadowSimulationRequest} from "../types/shadow-detection";
import {
    parseAlertList,
    parseAdvancedDetectionRules,
    parseAdvancedRuleDryRun,
    parseDetectionQuality,
    parseAlertAssignees,
    parseAlertBulkResponse,
    parseAlertWorkflow,
    parseAlertWorkflowList,
    parseAIAnalysis,
    parseAIAnalysisHistory,
    parseAIStatus,
    parseHealth,
    parseIncidentDetail,
    parseIncidentList,
    parseIncidentNote,
    parseInvestigationWorkbench,
    parseNormalizedAlert,
    parseSecurityEvent,
    parseSecurityEventList,
    parseCQQLFieldCatalog,
    parseCQQLAnalyticsResponse,
    parseCQQLSearchResponse,
    parseSavedEventSearch,
    parseSavedEventSearches,
    parseSecurityOverview,
    parseLogSources,
    parseHosts,
    parseOperationalOverview,
    parseAgentList,
    parseAgentDetail,
    parseAgentHealth,
    parseWazuhIntegrationStatus,
    parseDetectionRules,
    parseSecurityActivityReport,
    parseAnalysts,
    parseAnalystSessionStatus,
    parseSecurityAuditPage,
    parseSession,
    parseNotification,
    parseNotificationList,
    parseNotificationReadAll,
    parseInvestigationWorkspace,
    parseInvestigationTimeline,
    parsePreferences,
    parseDeploymentConfirmation,
    parseDetectionAnalytics,
    parseDetectionCoverage,
    parseIOC,
    parseIOCImport,
    parseIOCMatches,
    parseIOCs,
    parseRuleDraft,
    parseRuleDrafts,
    parseRuleDraftVersions,
    parseRuleDryRun,
    parseRuleValidation,
    parseSavedHunts,
    parseSavedHunt,
    parseThreatHuntPage,
    parseCanarySafety,
    parseDetectionConfigurations,
    parseDetectionDiagnostics,
    parseDetectionRuleLifecycle,
    parseDetectionRuleLifecycles,
    parseShadowRunDetail,
    parseShadowRuns,
    parseTelemetryPrerequisite,
    parseTuningComparison,
} from "./contracts";
import {
    parseCaseAnalytics,
    parseCaseDetail,
    parseCaseList,
    parsePlaybookTemplates,
} from "./case-contracts";
import type {
    AlertBulkRequest,
    AlertQuery,
    AlertWorkflowQuery,
    AlertWorkflowStatus,
} from "../types/alerts";
import type { CQQLAnalyticsRequest, CQQLExportRequest, CQQLSearchRequest, EventQuery, SavedEventSearchCreate } from "../types/events";
import type { LoginCredentials, PasswordChange } from "../types/auth";
import type { AIAnalysisRequest } from "../types/ai";
import type { BackendApi } from "../types/api";
import type {
    IncidentAlertLink,
    IncidentAssignmentUpdate,
    IncidentCreate,
    IncidentNoteCreate,
    IncidentQuery,
    IncidentStatusUpdate,
} from "../types/incidents";
import type { ReportQuery } from "../types/siem";
import type { AgentQuery } from "../types/agents";
import type {
    ChecklistCreate,
    ChecklistReorder,
    ChecklistUpdate,
    EvidencePinCreate,
} from "../types/investigations";
import type { AnalystPreferencesUpdate } from "../types/preferences";
import type {
    CaseAssignmentUpdate,
    CaseCreate,
    CaseEvidenceCreate,
    CaseQuery,
    CaseStatusUpdate,
} from "../types/cases";
import type {
    AdvancedRuleDryRunRequest,
    IOCDefinition,
    RuleDraftCreate,
    RuleDraftUpdate,
    RuleDryRunRequest,
    ThreatHuntQuery,
} from "../types/detection-engineering";
import type { WorkbenchTarget } from "../types/investigation-workbench";
import type { DetectionConfigurationDefinition } from "../types/detection-readiness";

type Parser<T> = (value: unknown) => T;
type Fetcher = (
    input: RequestInfo | URL,
    init?: RequestInit,
) => Promise<Response>;
const DEFAULT_API_BASE_URL = "";

export function resolveApiBaseUrl(
    configured = import.meta.env.VITE_API_BASE_URL,
): string {
    return configured?.trim() ?? DEFAULT_API_BASE_URL;
}

export class ApiError extends Error {
    constructor(
        message: string,
        readonly status: number,
        readonly code: string,
        readonly field?: string,
        readonly runId?: string,
        readonly requestId?: string,
        readonly retryable?: boolean,
    ) {
        super(message);
        this.name = "ApiError";
    }
}

export class BackendUnavailableError extends Error {
    constructor() {
        super(
            "The CyberQalqon backend is unavailable. Check the service and retry.",
        );
        this.name = "BackendUnavailableError";
    }
}

function queryString(
    entries: Array<[string, string | number | boolean | undefined]>,
): string {
    const parameters = new URLSearchParams();
    entries.forEach(([key, value]) => {
        if (value !== undefined && value !== "")
            parameters.append(key, String(value));
    });
    const query = parameters.toString();
    return query ? `?${query}` : "";
}

function savedSearchBody(payload: SavedEventSearchCreate): string {
    const query = payload.query;
    return JSON.stringify({
        name: payload.name,
        query: {
            relative_minutes: query.relativeMinutes,
            start_time: query.startTime,
            end_time: query.endTime,
            source_ip: query.sourceIp,
            destination_ip: query.destinationIp,
            hostname: query.hostname,
            username: query.username,
            operating_system: query.operatingSystem,
            event_provider: query.eventProvider,
            event_channel: query.eventChannel,
            process_name: query.processName,
            event_id: query.eventId,
            rule_id: query.ruleId,
            event_category: query.eventCategory,
            event_action: query.eventAction,
            outcome: query.outcome,
            severity_min: query.severityMin,
            severity_max: query.severityMax,
            source_type: query.sourceType,
            search: query.search,
            cqql: query.cqql,
            sort: query.sort ?? "newest",
        },
    });
}

function huntEntries(
    query: ThreatHuntQuery = {},
): Array<[string, string | number | boolean | undefined]> {
    return [
        ["relative_minutes", query.relativeMinutes],
        ["start_time", query.startTime],
        ["end_time", query.endTime],
        ["ip", query.ip],
        ["hostname", query.hostname],
        ["username", query.username],
        ["event_category", query.eventCategory],
        ["rule_id", query.ruleId],
        ["mitre_id", query.mitreId],
        ["search", query.search],
        ["cqql", query.cqql],
        ["sort", query.sort],
        ["limit", query.limit],
        ["cursor", query.cursor],
    ];
}

function savedHuntQuery(query: ThreatHuntQuery): Record<string, unknown> {
    return {
        relative_minutes: query.relativeMinutes,
        start_time: query.startTime,
        end_time: query.endTime,
        ip: query.ip,
        hostname: query.hostname,
        username: query.username,
        event_category: query.eventCategory,
        rule_id: query.ruleId,
        mitre_id: query.mitreId,
        search: query.search,
        cqql: query.cqql,
        sort: query.sort ?? "newest",
    };
}

function errorFrom(value: unknown, status: number): ApiError {
    if (typeof value === "object" && value !== null && "detail" in value) {
        const detail = (value as { detail?: unknown }).detail;
        if (typeof detail === "object" && detail !== null) {
            const body = detail as Record<string, unknown>;
            if (
                typeof body.code === "string" &&
                typeof body.message === "string"
            ) {
                return new ApiError(
                    body.message,
                    status,
                    body.code,
                    typeof body.field === "string" ? body.field : undefined,
                    typeof body.run_id==='string'&&/^RUN-[a-f0-9]{32}$/.test(body.run_id)?body.run_id:undefined,
                    typeof body.request_id==='string'&&/^[a-f0-9]{32}$/.test(body.request_id)?body.request_id:undefined,
                    typeof body.retryable==='boolean'?body.retryable:undefined,
                );
            }
        }
    }
    return new ApiError(
        `Backend request failed with status ${status}.`,
        status,
        "http_error",
    );
}

export class HttpBackendApi implements BackendApi {
    private readonly baseUrl: string;
    private csrfToken: string | null = null;
    private readonly unauthorizedHandlers = new Set<() => void>();

    constructor(
        baseUrl = resolveApiBaseUrl(),
        // Keep the browser-native fetch receiver intact. Storing `fetch`
        // directly and later invoking `this.fetcher(...)` rebinds `this` to the
        // API client, which real Chromium rejects as an illegal invocation.
        private readonly fetcher: Fetcher = (input, init) => fetch(input, init),
    ) {
        this.baseUrl = baseUrl.trim().replace(/\/$/, "");
    }

    private async request<T>(
        path: string,
        parser: Parser<T>,
        init: RequestInit = {},
        signal?: AbortSignal,
        notifyUnauthorized = true,
    ): Promise<T> {
        let response: Response;
        const headers = new Headers(init.headers);
        headers.set("Accept", "application/json");
        if (init.body) headers.set("Content-Type", "application/json");
        try {
            response = await this.fetcher(`${this.baseUrl}${path}`, {
                ...init,
                credentials: "include",
                headers,
                signal,
            });
        } catch (error) {
            if (error instanceof DOMException && error.name === "AbortError")
                throw error;
            throw new BackendUnavailableError();
        }

        let payload: unknown;
        try {
            payload = await response.json();
        } catch {
            if (!response.ok)
                throw new ApiError(
                    "Backend returned an unreadable error.",
                    response.status,
                    "invalid_error",
                );
            throw new ApiError(
                "Backend returned malformed JSON.",
                502,
                "invalid_response",
            );
        }

        if (!response.ok) {
            if (response.status === 401 && notifyUnauthorized) {
                this.csrfToken = null;
                this.unauthorizedHandlers.forEach((handler) => handler());
            }
            throw errorFrom(payload, response.status);
        }
        return parser(payload);
    }

    private mutation(init: RequestInit): RequestInit {
        const headers = new Headers(init.headers);
        if (this.csrfToken) headers.set("X-CSRF-Token", this.csrfToken);
        return {
            ...init,
            headers,
        };
    }

    private async requestVoid(
        path: string,
        init: RequestInit,
        signal?: AbortSignal,
    ): Promise<void> {
        let response: Response;
        const mutation = this.mutation(init);
        const headers = new Headers(mutation.headers);
        headers.set("Accept", "application/json");
        try {
            response = await this.fetcher(`${this.baseUrl}${path}`, {
                ...mutation,
                credentials: "include",
                headers,
                signal,
            });
        } catch (error) {
            if (error instanceof DOMException && error.name === "AbortError")
                throw error;
            throw new BackendUnavailableError();
        }
        if (!response.ok) {
            let payload: unknown = null;
            try {
                payload = await response.json();
            } catch {
                /* preserve a safe generic error */
            }
            if (response.status === 401)
                this.unauthorizedHandlers.forEach((handler) => handler());
            throw errorFrom(payload, response.status);
        }
    }

    private async download(
        path: string,
        fallback: string,
        accept: string,
        signal?: AbortSignal,
        init: RequestInit = {},
    ) {
        let response: Response;
        const configured = init.method && init.method !== "GET" ? this.mutation(init) : init;
        const headers = new Headers(configured.headers);
        headers.set("Accept", accept);
        try {
            response = await this.fetcher(`${this.baseUrl}${path}`, {
                ...configured,
                credentials: "include",
                headers,
                signal,
            });
        } catch (error) {
            if (error instanceof DOMException && error.name === "AbortError")
                throw error;
            throw new BackendUnavailableError();
        }
        if (!response.ok) {
            let payload: unknown = null;
            try {
                payload = await response.json();
            } catch {
                /* safe generic error */
            }
            if (response.status === 401)
                this.unauthorizedHandlers.forEach((handler) => handler());
            throw errorFrom(payload, response.status);
        }
        const disposition = response.headers.get("content-disposition") ?? "";
        const serverName = /filename=([^;]+)/i
            .exec(disposition)?.[1]
            ?.replace(/^"|"$/g, "");
        const filename =
            serverName && /^[a-zA-Z0-9._-]+$/.test(serverName)
                ? serverName
                : fallback;
        return { blob: await response.blob(), filename };
    }

    subscribeUnauthorized(handler: () => void) {
        this.unauthorizedHandlers.add(handler);
        return () => this.unauthorizedHandlers.delete(handler);
    }

    health(signal?: AbortSignal) {
        return this.request("/health", parseHealth, {}, signal);
    }

    async getSession(signal?: AbortSignal) {
        const session = await this.request(
            "/api/v1/auth/session",
            parseSession,
            {},
            signal,
            false,
        );
        this.csrfToken = session.csrf_token;
        return session;
    }

    async login(credentials: LoginCredentials, signal?: AbortSignal) {
        const session = await this.request(
            "/api/v1/auth/login",
            parseSession,
            { method: "POST", body: JSON.stringify(credentials) },
            signal,
            false,
        );
        this.csrfToken = session.csrf_token;
        return session;
    }

    async logout(signal?: AbortSignal) {
        try {
            await this.requestVoid(
                "/api/v1/auth/logout",
                { method: "POST" },
                signal,
            );
        } finally {
            this.csrfToken = null;
        }
    }

    listAlerts(query: AlertQuery = {}, signal?: AbortSignal) {
        const entries: Array<[string, string | number | boolean | undefined]> =
            [];
        query.ruleLevels?.forEach((level) =>
            entries.push(["rule_level", level]),
        );
        entries.push(
            ["rule_id", query.ruleId],
            ["agent", query.agent],
            ["mitre_mapped", query.mitreMapped],
            ["mitre_id", query.mitreId],
            ["start_time", query.startTime],
            ["end_time", query.endTime],
            ["search", query.search],
            ["limit", query.limit],
            ["cursor", query.cursor],
        );
        return this.request(
            `/api/v1/alerts${queryString(entries)}`,
            parseAlertList,
            {},
            signal,
        );
    }

    getAlert(alertId: string, signal?: AbortSignal) {
        return this.request(
            `/api/v1/alerts/${encodeURIComponent(alertId)}`,
            parseNormalizedAlert,
            {},
            signal,
        );
    }

    listAlertWorkflows(query: AlertWorkflowQuery = {}, signal?: AbortSignal) {
        const entries: Array<[string, string | number | boolean | undefined]> =
            [];
        query.statuses?.forEach((value) => entries.push(["status", value]));
        query.ruleLevels?.forEach((level) =>
            entries.push(["rule_level", level]),
        );
        entries.push(
            ["assigned_to", query.assignedTo],
            ["unassigned", query.unassigned],
            ["sort", query.sort],
            ["rule_id", query.ruleId],
            ["agent", query.agent],
            ["mitre_mapped", query.mitreMapped],
            ["mitre_id", query.mitreId],
            ["start_time", query.startTime],
            ["end_time", query.endTime],
            ["search", query.search],
            ["limit", query.limit],
            ["cursor", query.cursor],
        );
        return this.request(
            `/api/v1/alert-workflows${queryString(entries)}`,
            parseAlertWorkflowList,
            {},
            signal,
        );
    }

    getAlertWorkflow(alertId: string, signal?: AbortSignal) {
        return this.request(
            `/api/v1/alert-workflows/${encodeURIComponent(alertId)}`,
            parseAlertWorkflow,
            {},
            signal,
        );
    }

    listAlertAssignees(signal?: AbortSignal) {
        return this.request(
            "/api/v1/alert-workflows/assignees",
            parseAlertAssignees,
            {},
            signal,
        );
    }

    updateAlertStatus(
        alertId: string,
        workflowStatus: AlertWorkflowStatus,
        expectedVersion: number,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/alert-workflows/${encodeURIComponent(alertId)}/status`,
            parseAlertWorkflow,
            this.mutation({
                method: "PATCH",
                body: JSON.stringify({
                    status: workflowStatus,
                    expected_version: expectedVersion,
                }),
            }),
            signal,
        );
    }

    updateAlertAssignment(
        alertId: string,
        assignedTo: string | null,
        expectedVersion: number,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/alert-workflows/${encodeURIComponent(alertId)}/assignment`,
            parseAlertWorkflow,
            this.mutation({
                method: "PATCH",
                body: JSON.stringify({
                    assigned_to: assignedTo,
                    expected_version: expectedVersion,
                }),
            }),
            signal,
        );
    }

    addAlertNote(
        alertId: string,
        body: string,
        expectedVersion: number,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/alert-workflows/${encodeURIComponent(alertId)}/notes`,
            parseAlertWorkflow,
            this.mutation({
                method: "POST",
                body: JSON.stringify({
                    body,
                    expected_version: expectedVersion,
                }),
            }),
            signal,
        );
    }

    bulkUpdateAlerts(payload: AlertBulkRequest, signal?: AbortSignal) {
        return this.request(
            "/api/v1/alert-workflows/bulk",
            parseAlertBulkResponse,
            this.mutation({ method: "POST", body: JSON.stringify(payload) }),
            signal,
        );
    }

    listNotifications(limit = 25, unreadOnly = false, signal?: AbortSignal) {
        return this.request(
            `/api/v1/notifications${queryString([
                ["limit", limit],
                ["unread_only", unreadOnly],
            ])}`,
            parseNotificationList,
            {},
            signal,
        );
    }

    markNotificationRead(notificationId: string, signal?: AbortSignal) {
        return this.request(
            `/api/v1/notifications/${encodeURIComponent(notificationId)}/read`,
            parseNotification,
            this.mutation({ method: "PATCH" }),
            signal,
        );
    }

    markAllNotificationsRead(signal?: AbortSignal) {
        return this.request(
            "/api/v1/notifications/read-all",
            parseNotificationReadAll,
            this.mutation({ method: "POST" }),
            signal,
        );
    }

    listEvents(query: EventQuery = {}, signal?: AbortSignal) {
        return this.request(
            `/api/v1/events${queryString([
                ["start_time", query.startTime],
                ["end_time", query.endTime],
                ["source_ip", query.sourceIp],
                ["destination_ip", query.destinationIp],
                ["hostname", query.hostname],
                ["username", query.username],
                ["operating_system", query.operatingSystem],
                ["event_provider", query.eventProvider],
                ["event_channel", query.eventChannel],
                ["process_name", query.processName],
                ["event_id", query.eventId],
                ["rule_id", query.ruleId],
                ["event_category", query.eventCategory],
                ["event_action", query.eventAction],
                ["outcome", query.outcome],
                ["severity_min", query.severityMin],
                ["severity_max", query.severityMax],
                ["source_type", query.sourceType],
                ["search", query.search],
                ["related_alert_id", query.relatedAlertId],
                ["sort", query.sort],
                ["limit", query.limit],
                ["cursor", query.cursor],
            ])}`,
            parseSecurityEventList,
            {},
            signal,
        );
    }

    searchCQQL(query: CQQLSearchRequest, signal?: AbortSignal) {
        return this.request(
            "/api/v1/siem/search",
            parseCQQLSearchResponse,
            { method: "POST", body: JSON.stringify(query) },
            signal,
        );
    }

    getCQQLAnalytics(query: CQQLAnalyticsRequest, signal?: AbortSignal) {
        return this.request(
            "/api/v1/siem/search/analytics",
            parseCQQLAnalyticsResponse,
            { method: "POST", body: JSON.stringify(query) },
            signal,
        );
    }

    downloadCQQL(query: CQQLExportRequest, signal?: AbortSignal) {
        return this.download(
            "/api/v1/siem/search/export.csv",
            "cyberqalqon-cqql.csv",
            "text/csv",
            signal,
            { method: "POST", body: JSON.stringify(query) },
        );
    }

    getCQQLFields(signal?: AbortSignal) {
        return this.request(
            "/api/v1/siem/search/fields",
            parseCQQLFieldCatalog,
            {},
            signal,
        );
    }

    getEvent(eventId: string, signal?: AbortSignal) {
        return this.request(
            `/api/v1/events/${encodeURIComponent(eventId)}`,
            parseSecurityEvent,
            {},
            signal,
        );
    }

    getInvestigationWorkbench(target: WorkbenchTarget, signal?: AbortSignal) {
        return this.request(
            "/api/v1/investigations/workbench",
            parseInvestigationWorkbench,
            this.mutation({ method: "POST", body: JSON.stringify(target) }),
            signal,
        );
    }

    listSavedEventSearches(signal?: AbortSignal) {
        return this.request(
            "/api/v1/events/saved-searches",
            parseSavedEventSearches,
            {},
            signal,
        );
    }

    saveEventSearch(payload: SavedEventSearchCreate, signal?: AbortSignal) {
        return this.request(
            "/api/v1/events/saved-searches",
            parseSavedEventSearch,
            this.mutation({ method: "POST", body: savedSearchBody(payload) }),
            signal,
        );
    }

    updateSavedEventSearch(
        savedSearchId: string,
        payload: SavedEventSearchCreate,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/events/saved-searches/${encodeURIComponent(savedSearchId)}`,
            parseSavedEventSearch,
            this.mutation({ method: "PUT", body: savedSearchBody(payload) }),
            signal,
        );
    }

    deleteSavedEventSearch(savedSearchId: string, signal?: AbortSignal) {
        return this.requestVoid(
            `/api/v1/events/saved-searches/${encodeURIComponent(savedSearchId)}`,
            { method: "DELETE" },
            signal,
        );
    }

    getOverview(startTime?: string, endTime?: string, signal?: AbortSignal) {
        return this.request(
            `/api/v1/overview${queryString([
                ["start_time", startTime],
                ["end_time", endTime],
            ])}`,
            parseSecurityOverview,
            {},
            signal,
        );
    }

    listSources(signal?: AbortSignal) {
        return this.request("/api/v1/sources", parseLogSources, {}, signal);
    }

    listHosts(signal?: AbortSignal) {
        return this.request("/api/v1/hosts", parseHosts, {}, signal);
    }

    listAgents(query: AgentQuery = {}, signal?: AbortSignal) {
        return this.request(
            `/api/v1/agents${queryString([
                ["search", query.search],
                ["os", query.os],
                ["connection_status", query.connectionStatus],
                ["version", query.version],
                ["manager", query.manager],
                ["source_type", query.sourceType],
                ["last_seen_minutes", query.lastSeenMinutes],
                ["sort", query.sort],
                ["order", query.order],
                ["limit", query.limit],
                ["offset", query.offset],
            ])}`,
            parseAgentList,
            {},
            signal,
        );
    }

    getAgent(agentKey: string, signal?: AbortSignal) {
        return this.request(
            `/api/v1/agents/${encodeURIComponent(agentKey)}`,
            parseAgentDetail,
            {},
            signal,
        );
    }

    getAgentHealth(agentKey: string, signal?: AbortSignal) {
        return this.request(
            `/api/v1/agents/${encodeURIComponent(agentKey)}/health`,
            parseAgentHealth,
            {},
            signal,
        );
    }

    getWazuhIntegrationStatus(signal?: AbortSignal) {
        return this.request(
            "/api/v1/integrations/wazuh/status",
            parseWazuhIntegrationStatus,
            {},
            signal,
        );
    }

    previewSigma(source:string,signal?:AbortSignal) {
        return this.request('/api/v1/detection-engineering/sigma/preview',parseSigmaPreview,
            {method:'POST',body:JSON.stringify({yaml:source,profile:'CQ_ENDPOINT_SHADOW_V1'})},signal);
    }

    getSourceCoverage(signal?: AbortSignal) {
        return this.request('/api/v1/collection/sources',parseSourceCoverage,{},signal);
    }

    getOperationalOverview(signal?: AbortSignal) {
        return this.request(
            "/api/v1/operations/overview",
            parseOperationalOverview,
            {},
            signal,
        );
    }

    listRules(signal?: AbortSignal) {
        return this.request("/api/v1/rules", parseDetectionRules, {}, signal);
    }

    getDetectionCoverage(signal?: AbortSignal) {
        return this.request(
            "/api/v1/detection-engineering/coverage",
            parseDetectionCoverage,
            {},
            signal,
        );
    }

    listAdvancedDetectionRules(days = 30, signal?: AbortSignal) {
        return this.request(
            `/api/v1/detection-engineering/advanced-rules${queryString([["days", days]])}`,
            parseAdvancedDetectionRules,
            {},
            signal,
        );
    }

    getShadowCatalog(signal?:AbortSignal) {
        return this.request('/api/v1/detection-engineering/shadow-v2/catalog',parseShadowCatalog,{},signal);
    }
    getDurableShadowStatus(signal?:AbortSignal){return this.request('/api/v1/detection-engineering/shadow-v2/history-status',parseDurableStatus,{},signal);}
    reconcileShadowEvidence(cursor?:string|null,signal?:AbortSignal){return this.request('/api/v1/detection-engineering/shadow-v2/reconciliation'+(cursor?'?cursor='+encodeURIComponent(cursor):''),parseReconciliationPage,{},signal);}
    createDurableShadowRun(payload:DurableRequest,signal?:AbortSignal){return this.request('/api/v1/detection-engineering/shadow-v2/runs',parseDurableRun,this.mutation({method:'POST',body:JSON.stringify(payload)}),signal);}
    getDurableShadowRun(id:string,signal?:AbortSignal){return this.request('/api/v1/detection-engineering/shadow-v2/runs/'+encodeURIComponent(id),parseDurableRun,{},signal);}
    resumeDurableShadowRun(id:string,signal?:AbortSignal){return this.request('/api/v1/detection-engineering/shadow-v2/runs/'+encodeURIComponent(id)+'/resume',parseDurableRun,this.mutation({method:'POST'}),signal);}
    listDurableShadowFindings(cursor?:string|null,signal?:AbortSignal){return this.request('/api/v1/detection-engineering/shadow-v2/findings'+(cursor?'?cursor='+encodeURIComponent(cursor):''),parseFindingPage,{},signal);}
    getDurableShadowFinding(id:string,revision?:number,signal?:AbortSignal){return this.request('/api/v1/detection-engineering/shadow-v2/findings/'+encodeURIComponent(id)+(revision?'?revision='+revision:''),parseFindingDetail,{},signal);}
    transitionDurableShadowFinding(id:string,change:FindingTransition,signal?:AbortSignal){return this.request('/api/v1/detection-engineering/shadow-v2/findings/'+encodeURIComponent(id)+'/transitions',parseFindingDetail,this.mutation({method:'POST',body:JSON.stringify(change)}),signal);}
    validateShadowRule(rule:ShadowRule,signal?:AbortSignal) {
        return this.request('/api/v1/detection-engineering/shadow-v2/validate',parseShadowValidation,
            this.mutation({method:'POST',body:JSON.stringify(rule)}),signal);
    }
    simulateShadowRule(payload:ShadowSimulationRequest,signal?:AbortSignal) {
        return this.request('/api/v1/detection-engineering/shadow-v2/simulate',parseShadowResult,
            this.mutation({method:'POST',body:JSON.stringify(payload)}),signal);
    }

    dryRunAdvancedDetectionRule(
        ruleId: string,
        payload: AdvancedRuleDryRunRequest,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/detection-engineering/advanced-rules/${encodeURIComponent(ruleId)}/dry-run`,
            parseAdvancedRuleDryRun,
            this.mutation({ method: "POST", body: JSON.stringify(payload) }),
            signal,
        );
    }

    getDetectionQuality(ruleId: string, signal?: AbortSignal) {
        return this.request(
            `/api/v1/detection-engineering/advanced-quality/${encodeURIComponent(ruleId)}`,
            parseDetectionQuality,
            {},
            signal,
        );
    }

    listDetectionLifecycles(signal?: AbortSignal) {
        return this.request(
            "/api/v1/detection-readiness/rules",
            parseDetectionRuleLifecycles,
            {},
            signal,
        );
    }

    getDetectionLifecycle(ruleId: string, signal?: AbortSignal) {
        return this.request(
            `/api/v1/detection-readiness/rules/${encodeURIComponent(ruleId)}/lifecycle`,
            parseDetectionRuleLifecycle,
            {},
            signal,
        );
    }

    listDetectionConfigurations(ruleId: string, signal?: AbortSignal) {
        return this.request(
            `/api/v1/detection-readiness/rules/${encodeURIComponent(ruleId)}/configurations`,
            parseDetectionConfigurations,
            {},
            signal,
        );
    }

    getDetectionTelemetry(ruleId: string, signal?: AbortSignal) {
        return this.request(
            `/api/v1/detection-readiness/rules/${encodeURIComponent(ruleId)}/telemetry`,
            parseTelemetryPrerequisite,
            {},
            signal,
        );
    }

    getDetectionDiagnostics(ruleId: string, signal?: AbortSignal) {
        return this.request(
            `/api/v1/detection-readiness/rules/${encodeURIComponent(ruleId)}/diagnostics`,
            parseDetectionDiagnostics,
            {},
            signal,
        );
    }

    listShadowRuns(ruleId: string, signal?: AbortSignal) {
        return this.request(
            `/api/v1/detection-readiness/rules/${encodeURIComponent(ruleId)}/shadow-runs`,
            parseShadowRuns,
            {},
            signal,
        );
    }

    runShadowEvaluation(ruleId: string, signal?: AbortSignal) {
        return this.request(
            `/api/v1/detection-readiness/rules/${encodeURIComponent(ruleId)}/shadow-runs`,
            parseShadowRunDetail,
            this.mutation({
                method: "POST",
                body: JSON.stringify({
                    relative_minutes: 1440,
                    max_events: 1000,
                    max_findings: 100,
                    max_execution_ms: 2000,
                }),
            }),
            signal,
        );
    }

    compareDetectionTuning(
        ruleId: string,
        baseline: DetectionConfigurationDefinition,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/detection-readiness/rules/${encodeURIComponent(ruleId)}/tuning`,
            parseTuningComparison,
            this.mutation({
                method: "POST",
                body: JSON.stringify({
                    relative_minutes: 1440,
                    candidates: [
                        {
                            threshold_count: baseline.threshold_count,
                            time_window_seconds: baseline.time_window_seconds,
                        },
                        {
                            threshold_count: Math.min(100, baseline.threshold_count + 5),
                            time_window_seconds: baseline.time_window_seconds,
                        },
                    ],
                    max_events: 2000,
                    max_findings: 200,
                    max_execution_ms: 3000,
                }),
            }),
            signal,
        );
    }

    getCanarySafety(ruleId: string, signal?: AbortSignal) {
        return this.request(
            `/api/v1/detection-readiness/rules/${encodeURIComponent(ruleId)}/canary-safety`,
            parseCanarySafety,
            {},
            signal,
        );
    }

    getDetectionAnalytics(days = 30, signal?: AbortSignal) {
        return this.request(
            `/api/v1/detection-engineering/analytics${queryString([["days", days]])}`,
            parseDetectionAnalytics,
            {},
            signal,
        );
    }

    listRuleDrafts(signal?: AbortSignal) {
        return this.request(
            "/api/v1/detection-engineering/drafts",
            parseRuleDrafts,
            {},
            signal,
        );
    }

    createRuleDraft(payload: RuleDraftCreate, signal?: AbortSignal) {
        return this.request(
            "/api/v1/detection-engineering/drafts",
            parseRuleDraft,
            this.mutation({ method: "POST", body: JSON.stringify(payload) }),
            signal,
        );
    }

    updateRuleDraft(
        draftId: string,
        payload: RuleDraftUpdate,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/detection-engineering/drafts/${encodeURIComponent(draftId)}`,
            parseRuleDraft,
            this.mutation({ method: "PUT", body: JSON.stringify(payload) }),
            signal,
        );
    }

    validateRuleDraft(
        draftId: string,
        expectedVersion: number,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/detection-engineering/drafts/${encodeURIComponent(draftId)}/validate`,
            parseRuleValidation,
            this.mutation({
                method: "POST",
                body: JSON.stringify({ expected_version: expectedVersion }),
            }),
            signal,
        );
    }

    dryRunRuleDraft(
        draftId: string,
        payload: RuleDryRunRequest,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/detection-engineering/drafts/${encodeURIComponent(draftId)}/dry-run`,
            parseRuleDryRun,
            this.mutation({ method: "POST", body: JSON.stringify(payload) }),
            signal,
        );
    }

    confirmManualDeployment(
        draftId: string,
        expectedVersion: number,
        reason: string,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/detection-engineering/drafts/${encodeURIComponent(draftId)}/confirm-manual-deployment`,
            parseDeploymentConfirmation,
            this.mutation({
                method: "POST",
                body: JSON.stringify({
                    expected_version: expectedVersion,
                    confirmation: "I_UNDERSTAND_MANUAL_DEPLOYMENT_REQUIRED",
                    reason,
                }),
            }),
            signal,
        );
    }

    listRuleDraftVersions(draftId: string, signal?: AbortSignal) {
        return this.request(
            `/api/v1/detection-engineering/drafts/${encodeURIComponent(draftId)}/versions`,
            parseRuleDraftVersions,
            {},
            signal,
        );
    }

    rollbackRuleDraft(
        draftId: string,
        sourceVersion: number,
        expectedVersion: number,
        changeSummary: string,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/detection-engineering/drafts/${encodeURIComponent(draftId)}/rollback`,
            parseRuleDraft,
            this.mutation({
                method: "POST",
                body: JSON.stringify({
                    source_version: sourceVersion,
                    expected_version: expectedVersion,
                    change_summary: changeSummary,
                }),
            }),
            signal,
        );
    }

    runThreatHunt(query: ThreatHuntQuery = {}, signal?: AbortSignal) {
        return this.request(
            `/api/v1/threat-hunts${queryString(huntEntries(query))}`,
            parseThreatHuntPage,
            {},
            signal,
        );
    }

    listSavedHunts(signal?: AbortSignal) {
        return this.request(
            "/api/v1/threat-hunts/saved",
            parseSavedHunts,
            {},
            signal,
        );
    }

    saveThreatHunt(name: string, query: ThreatHuntQuery, signal?: AbortSignal) {
        return this.request(
            "/api/v1/threat-hunts/saved",
            parseSavedHunt,
            this.mutation({
                method: "POST",
                body: JSON.stringify({ name, query: savedHuntQuery(query) }),
            }),
            signal,
        );
    }

    deleteSavedHunt(savedHuntId: string, signal?: AbortSignal) {
        return this.requestVoid(
            `/api/v1/threat-hunts/saved/${encodeURIComponent(savedHuntId)}`,
            { method: "DELETE" },
            signal,
        );
    }

    downloadThreatHunt(query: ThreatHuntQuery = {}, signal?: AbortSignal) {
        return this.download(
            `/api/v1/threat-hunts/export.csv${queryString(huntEntries({ ...query, limit: undefined, cursor: undefined }))}`,
            "cyberqalqon-threat-hunt.csv",
            "text/csv",
            signal,
        );
    }

    listIOCs(
        filters: {
            indicatorType?: string;
            activeOnly?: boolean;
            search?: string;
            limit?: number;
        } = {},
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/iocs${queryString([
                ["indicator_type", filters.indicatorType],
                ["active_only", filters.activeOnly],
                ["search", filters.search],
                ["limit", filters.limit],
            ])}`,
            parseIOCs,
            {},
            signal,
        );
    }

    createIOC(payload: IOCDefinition, signal?: AbortSignal) {
        return this.request(
            "/api/v1/iocs",
            parseIOC,
            this.mutation({ method: "POST", body: JSON.stringify(payload) }),
            signal,
        );
    }

    updateIOC(
        indicatorId: string,
        payload: IOCDefinition & {
            expected_version: number;
            is_active: boolean;
        },
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/iocs/${encodeURIComponent(indicatorId)}`,
            parseIOC,
            this.mutation({ method: "PUT", body: JSON.stringify(payload) }),
            signal,
        );
    }

    importIOCs(indicators: IOCDefinition[], signal?: AbortSignal) {
        return this.request(
            "/api/v1/iocs/import",
            parseIOCImport,
            this.mutation({
                method: "POST",
                body: JSON.stringify({ indicators }),
            }),
            signal,
        );
    }

    getIOCMatches(days = 7, limit = 500, signal?: AbortSignal) {
        return this.request(
            `/api/v1/iocs/matches${queryString([
                ["days", days],
                ["limit", limit],
            ])}`,
            parseIOCMatches,
            {},
            signal,
        );
    }

    downloadIOCs(signal?: AbortSignal) {
        return this.download(
            "/api/v1/iocs/export.json",
            "cyberqalqon-local-iocs.json",
            "application/json",
            signal,
        );
    }

    getSecurityActivityReport(query: ReportQuery = {}, signal?: AbortSignal) {
        return this.request(
            `/api/v1/reports/security-activity${queryString([
                ["start_time", query.startTime],
                ["end_time", query.endTime],
                ["severity_min", query.severityMin],
                ["severity_max", query.severityMax],
                ["host", query.host],
                ["rule_id", query.ruleId],
            ])}`,
            parseSecurityActivityReport,
            {},
            signal,
        );
    }

    async downloadSecurityActivityReport(
        query: ReportQuery,
        format: "csv" | "json",
        signal?: AbortSignal,
    ) {
        const path = `/api/v1/reports/security-activity.${format}${queryString([
            ["start_time", query.startTime],
            ["end_time", query.endTime],
            ["severity_min", query.severityMin],
            ["severity_max", query.severityMax],
            ["host", query.host],
            ["rule_id", query.ruleId],
        ])}`;
        let response: Response;
        try {
            response = await this.fetcher(`${this.baseUrl}${path}`, {
                credentials: "include",
                headers: {
                    Accept: format === "csv" ? "text/csv" : "application/json",
                },
                signal,
            });
        } catch (error) {
            if (error instanceof DOMException && error.name === "AbortError")
                throw error;
            throw new BackendUnavailableError();
        }
        if (!response.ok) {
            let payload: unknown = null;
            try {
                payload = await response.json();
            } catch {
                /* safe generic error below */
            }
            if (response.status === 401)
                this.unauthorizedHandlers.forEach((handler) => handler());
            throw errorFrom(payload, response.status);
        }
        const disposition = response.headers.get("content-disposition") ?? "";
        const serverName = /filename=([^;]+)/i
            .exec(disposition)?.[1]
            ?.replace(/^"|"$/g, "");
        const fallback = `cyberqalqon-security-activity.${format}`;
        const filename =
            serverName && /^[a-zA-Z0-9._-]+$/.test(serverName)
                ? serverName
                : fallback;
        return { blob: await response.blob(), filename };
    }

    listAnalysts(signal?: AbortSignal) {
        return this.request("/api/v1/auth/analysts", parseAnalysts, {}, signal);
    }

    getSessionStatus(signal?: AbortSignal) {
        return this.request(
            "/api/v1/auth/sessions",
            parseAnalystSessionStatus,
            {},
            signal,
        );
    }

    revokeOtherSessions(signal?: AbortSignal) {
        return this.requestVoid(
            "/api/v1/auth/sessions/revoke-others",
            { method: "POST" },
            signal,
        );
    }

    changePassword(payload: PasswordChange, signal?: AbortSignal) {
        return this.requestVoid(
            "/api/v1/auth/password",
            { method: "PATCH", body: JSON.stringify(payload) },
            signal,
        );
    }

    listAuditEvents(
        limit = 100,
        signal?: AbortSignal,
        filters: {
            action?: string;
            actorId?: string;
            targetType?: string;
            outcome?: "SUCCESS" | "DENIED" | "FAILURE";
            search?: string;
        } = {},
    ) {
        return this.request(
            `/api/v1/audit-events${queryString([
                ["limit", limit],
                ["action", filters.action],
                ["actor_id", filters.actorId],
                ["target_type", filters.targetType],
                ["outcome", filters.outcome],
                ["search", filters.search],
            ])}`,
            parseSecurityAuditPage,
            {},
            signal,
        );
    }

    listIncidents(query: IncidentQuery = {}, signal?: AbortSignal) {
        const entries: Array<[string, string | number | boolean | undefined]> =
            [];
        query.statuses?.forEach((status) => entries.push(["status", status]));
        query.severities?.forEach((severity) =>
            entries.push(["severity", severity]),
        );
        entries.push(
            ["assigned_to", query.assignedTo],
            ["limit", query.limit],
            ["cursor", query.cursor],
        );
        return this.request(
            `/api/v1/incidents${queryString(entries)}`,
            parseIncidentList,
            {},
            signal,
        );
    }

    listCases(query: CaseQuery = {}, signal?: AbortSignal) {
        const entries: Array<[string, string | number | boolean | undefined]> = [];
        query.statuses?.forEach((value) => entries.push(["status", value]));
        query.severities?.forEach((value) => entries.push(["severity", value]));
        query.priorities?.forEach((value) => entries.push(["priority", value]));
        entries.push(
            ["owner_id", query.ownerId], ["search", query.search], ["sort", query.sort],
            ["limit", query.limit], ["cursor", query.cursor],
        );
        return this.request(`/api/v1/cases${queryString(entries)}`, parseCaseList, {}, signal);
    }

    getCase(caseId: string, signal?: AbortSignal) {
        return this.request(`/api/v1/cases/${encodeURIComponent(caseId)}`, parseCaseDetail, {}, signal);
    }

    createCase(payload: CaseCreate, signal?: AbortSignal) {
        return this.request("/api/v1/cases", parseCaseDetail, this.mutation({ method: "POST", body: JSON.stringify(payload) }), signal);
    }

    updateCaseStatus(caseId: string, payload: CaseStatusUpdate, signal?: AbortSignal) {
        return this.request(`/api/v1/cases/${encodeURIComponent(caseId)}/status`, parseCaseDetail, this.mutation({ method: "POST", body: JSON.stringify(payload) }), signal);
    }

    updateCaseAssignment(caseId: string, payload: CaseAssignmentUpdate, signal?: AbortSignal) {
        return this.request(`/api/v1/cases/${encodeURIComponent(caseId)}/assignment`, parseCaseDetail, this.mutation({ method: "POST", body: JSON.stringify(payload) }), signal);
    }

    addCaseComment(caseId: string, body: string, expectedVersion: number, signal?: AbortSignal) {
        return this.request(`/api/v1/cases/${encodeURIComponent(caseId)}/comments`, parseCaseDetail, this.mutation({ method: "POST", body: JSON.stringify({ body, expected_version: expectedVersion }) }), signal);
    }

    linkCaseReference(caseId: string, kind: "alert" | "incident" | "event", referenceId: string, expectedVersion: number, signal?: AbortSignal) {
        return this.request(`/api/v1/cases/${encodeURIComponent(caseId)}/related/${kind}`, parseCaseDetail, this.mutation({ method: "POST", body: JSON.stringify({ reference_id: referenceId, expected_version: expectedVersion }) }), signal);
    }

    acquireCaseEvidence(caseId: string, payload: CaseEvidenceCreate, signal?: AbortSignal) {
        return this.request(`/api/v1/cases/${encodeURIComponent(caseId)}/evidence`, parseCaseDetail, this.mutation({ method: "POST", body: JSON.stringify(payload) }), signal);
    }

    verifyCaseEvidence(caseId: string, evidenceId: string, expectedVersion: number, signal?: AbortSignal) {
        return this.request(`/api/v1/cases/${encodeURIComponent(caseId)}/evidence/${encodeURIComponent(evidenceId)}/verify`, parseCaseDetail, this.mutation({ method: "POST", body: JSON.stringify({ expected_version: expectedVersion }) }), signal);
    }

    listPlaybookTemplates(signal?: AbortSignal) {
        return this.request("/api/v1/cases/playbooks/templates", parsePlaybookTemplates, {}, signal);
    }

    startCasePlaybook(caseId: string, templateKey: string, expectedVersion: number, signal?: AbortSignal) {
        return this.request(`/api/v1/cases/${encodeURIComponent(caseId)}/playbooks`, parseCaseDetail, this.mutation({ method: "POST", body: JSON.stringify({ template_key: templateKey, expected_version: expectedVersion }) }), signal);
    }

    updateCasePlaybookStep(
        caseId: string,
        playbookId: string,
        stepId: string,
        payload: { expected_version: number; status: "PENDING" | "COMPLETED"; assigned_to?: string | null; evidence_ref_id?: string | null; completion_note?: string },
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/cases/${encodeURIComponent(caseId)}/playbooks/${encodeURIComponent(playbookId)}/steps/${encodeURIComponent(stepId)}`,
            parseCaseDetail,
            this.mutation({ method: "PATCH", body: JSON.stringify(payload) }),
            signal,
        );
    }

    getCaseAnalytics(days = 30, signal?: AbortSignal) {
        return this.request(`/api/v1/cases/analytics${queryString([["days", days]])}`, parseCaseAnalytics, {}, signal);
    }

    evaluateCaseSla(signal?: AbortSignal) {
        return this.request(
            "/api/v1/cases/sla/evaluate",
            (value) => {
                if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid SLA evaluation response");
                const item = value as Record<string, unknown>;
                if (!Number.isInteger(item.evaluated_cases) || !Number.isInteger(item.notifications_created) || typeof item.generated_at !== "string") throw new Error("Invalid SLA evaluation response");
                return { evaluated_cases: item.evaluated_cases as number, notifications_created: item.notifications_created as number, generated_at: item.generated_at };
            },
            this.mutation({ method: "POST" }),
            signal,
        );
    }

    async downloadCaseReport(caseId: string, format: "json" | "csv" | "pdf", signal?: AbortSignal) {
        const path = `/api/v1/cases/${encodeURIComponent(caseId)}/reports/${format}`;
        let response: Response;
        try {
            const init = this.mutation({ method: "POST", headers: { Accept: format === "pdf" ? "application/pdf" : format === "csv" ? "text/csv" : "application/json" } });
            response = await this.fetcher(`${this.baseUrl}${path}`, { ...init, credentials: "include", signal });
        } catch (error) {
            if (error instanceof DOMException && error.name === "AbortError") throw error;
            throw new BackendUnavailableError();
        }
        if (!response.ok) {
            let payload: unknown = null;
            try { payload = await response.json(); } catch { /* safe generic error */ }
            if (response.status === 401) this.unauthorizedHandlers.forEach((handler) => handler());
            throw errorFrom(payload, response.status);
        }
        const disposition = response.headers.get("content-disposition") ?? "";
        const candidate = /filename=([^;]+)/i.exec(disposition)?.[1]?.replace(/^"|"$/g, "");
        const filename = candidate && /^[a-zA-Z0-9._-]+$/.test(candidate) ? candidate : `cyberqalqon-case.${format}`;
        return { blob: await response.blob(), filename };
    }

    getIncident(incidentId: string, signal?: AbortSignal) {
        return this.request(
            `/api/v1/incidents/${encodeURIComponent(incidentId)}`,
            parseIncidentDetail,
            {},
            signal,
        );
    }

    createIncident(payload: IncidentCreate, signal?: AbortSignal) {
        return this.request(
            "/api/v1/incidents",
            parseIncidentDetail,
            this.mutation({ method: "POST", body: JSON.stringify(payload) }),
            signal,
        );
    }

    updateIncidentStatus(
        incidentId: string,
        payload: IncidentStatusUpdate,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/incidents/${encodeURIComponent(incidentId)}/status`,
            parseIncidentDetail,
            this.mutation({ method: "PATCH", body: JSON.stringify(payload) }),
            signal,
        );
    }

    linkIncidentAlert(
        incidentId: string,
        payload: IncidentAlertLink,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/incidents/${encodeURIComponent(incidentId)}/alerts`,
            parseIncidentDetail,
            this.mutation({ method: "POST", body: JSON.stringify(payload) }),
            signal,
        );
    }

    addIncidentNote(
        incidentId: string,
        payload: IncidentNoteCreate,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/incidents/${encodeURIComponent(incidentId)}/notes`,
            parseIncidentNote,
            this.mutation({ method: "POST", body: JSON.stringify(payload) }),
            signal,
        );
    }

    updateIncidentAssignment(
        incidentId: string,
        payload: IncidentAssignmentUpdate,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/incidents/${encodeURIComponent(incidentId)}/assignment`,
            parseIncidentDetail,
            this.mutation({ method: "PATCH", body: JSON.stringify(payload) }),
            signal,
        );
    }

    getInvestigation(incidentId: string, signal?: AbortSignal) {
        return this.request(
            `/api/v1/incidents/${encodeURIComponent(incidentId)}/investigation`,
            parseInvestigationWorkspace,
            {},
            signal,
        );
    }

    createChecklistItem(
        incidentId: string,
        payload: ChecklistCreate,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/incidents/${encodeURIComponent(incidentId)}/investigation/checklist`,
            parseInvestigationWorkspace,
            this.mutation({ method: "POST", body: JSON.stringify(payload) }),
            signal,
        );
    }

    updateChecklistItem(
        incidentId: string,
        itemId: string,
        payload: ChecklistUpdate,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/incidents/${encodeURIComponent(incidentId)}/investigation/checklist/${encodeURIComponent(itemId)}`,
            parseInvestigationWorkspace,
            this.mutation({ method: "PATCH", body: JSON.stringify(payload) }),
            signal,
        );
    }

    reorderChecklist(
        incidentId: string,
        payload: ChecklistReorder,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/incidents/${encodeURIComponent(incidentId)}/investigation/checklist/reorder`,
            parseInvestigationWorkspace,
            this.mutation({ method: "POST", body: JSON.stringify(payload) }),
            signal,
        );
    }

    pinEvidence(
        incidentId: string,
        payload: EvidencePinCreate,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/incidents/${encodeURIComponent(incidentId)}/investigation/evidence`,
            parseInvestigationWorkspace,
            this.mutation({ method: "POST", body: JSON.stringify(payload) }),
            signal,
        );
    }

    annotateEvidence(
        incidentId: string,
        pinId: string,
        annotation: string,
        expectedVersion: number,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/incidents/${encodeURIComponent(incidentId)}/investigation/evidence/${encodeURIComponent(pinId)}`,
            parseInvestigationWorkspace,
            this.mutation({
                method: "PATCH",
                body: JSON.stringify({
                    annotation,
                    expected_version: expectedVersion,
                }),
            }),
            signal,
        );
    }

    unpinEvidence(
        incidentId: string,
        pinId: string,
        expectedVersion: number,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/incidents/${encodeURIComponent(incidentId)}/investigation/evidence/${encodeURIComponent(pinId)}/unpin`,
            parseInvestigationWorkspace,
            this.mutation({
                method: "POST",
                body: JSON.stringify({ expected_version: expectedVersion }),
            }),
            signal,
        );
    }

    getInvestigationTimeline(
        incidentId: string,
        limit = 50,
        cursor?: string,
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/incidents/${encodeURIComponent(incidentId)}/investigation/timeline${queryString(
                [
                    ["limit", limit],
                    ["cursor", cursor],
                ],
            )}`,
            parseInvestigationTimeline,
            {},
            signal,
        );
    }

    getPreferences(signal?: AbortSignal) {
        return this.request(
            "/api/v1/preferences",
            parsePreferences,
            {},
            signal,
        );
    }

    updatePreferences(payload: AnalystPreferencesUpdate, signal?: AbortSignal) {
        return this.request(
            "/api/v1/preferences",
            parsePreferences,
            this.mutation({ method: "PUT", body: JSON.stringify(payload) }),
            signal,
        );
    }

    resetPreferences(expectedVersion: number, signal?: AbortSignal) {
        return this.request(
            "/api/v1/preferences/reset",
            parsePreferences,
            this.mutation({
                method: "POST",
                body: JSON.stringify({ expected_version: expectedVersion }),
            }),
            signal,
        );
    }

    getAIStatus(signal?: AbortSignal) {
        return this.request("/api/v1/ai/status", parseAIStatus, {}, signal);
    }

    analyzeAlert(
        alertId: string,
        payload: AIAnalysisRequest = {},
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/ai/alerts/${encodeURIComponent(alertId)}/analyze`,
            parseAIAnalysis,
            this.mutation({ method: "POST", body: JSON.stringify(payload) }),
            signal,
        );
    }

    analyzeIncident(
        incidentId: string,
        payload: AIAnalysisRequest = {},
        signal?: AbortSignal,
    ) {
        return this.request(
            `/api/v1/ai/incidents/${encodeURIComponent(incidentId)}/analyze`,
            parseAIAnalysis,
            this.mutation({ method: "POST", body: JSON.stringify(payload) }),
            signal,
        );
    }

    getAIAnalysis(analysisId: string, signal?: AbortSignal) {
        return this.request(
            `/api/v1/ai/analyses/${encodeURIComponent(analysisId)}`,
            parseAIAnalysis,
            {},
            signal,
        );
    }

    listAlertAnalyses(alertId: string, signal?: AbortSignal) {
        return this.request(
            `/api/v1/ai/alerts/${encodeURIComponent(alertId)}/analyses`,
            parseAIAnalysisHistory,
            {},
            signal,
        );
    }

    listIncidentAnalyses(incidentId: string, signal?: AbortSignal) {
        return this.request(
            `/api/v1/ai/incidents/${encodeURIComponent(incidentId)}/analyses`,
            parseAIAnalysisHistory,
            {},
            signal,
        );
    }
}

export const backendApi: BackendApi = new HttpBackendApi();
