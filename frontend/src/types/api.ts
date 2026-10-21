import type {
    AlertAssignee,
    AlertBulkRequest,
    AlertBulkResponse,
    AlertQuery,
    AlertWorkflowDetail,
    AlertWorkflowQuery,
    AlertWorkflowSummary,
    AlertWorkflowCounts,
    AlertWorkflowSort,
    AlertWorkflowStatus,
    NormalizedAlert,
} from "./alerts";
import type {
    AnalystPublic,
    AnalystSessionStatus,
    LoginCredentials,
    PasswordChange,
    SecurityAuditEvent,
    SessionResponse,
} from "./auth";
import type {
    EventQuery,
    SavedEventSearch,
    SavedEventSearchCreate,
    SecurityEventDetail,
    SecurityEventSummary,
    SecurityOverview,
} from "./events";
import type {
    AIAnalysisHistory,
    AIAnalysisRecord,
    AIAnalysisRequest,
    AIStatus,
} from "./ai";
import type {
    IncidentAlertLink,
    IncidentAssignmentUpdate,
    IncidentCreate,
    IncidentDetail,
    IncidentNote,
    IncidentNoteCreate,
    IncidentQuery,
    IncidentStatusUpdate,
    IncidentSummary,
} from "./incidents";
import type {
    DetectionRuleSummary,
    HostSummary,
    LogSourceSummary,
    ReportQuery,
    SecurityActivityReport,
} from "./siem";
import type {
    AnalystNotification,
    NotificationListResponse,
    NotificationReadAllResponse,
} from "./notifications";
import type {
    AnalystPreferences,
    AnalystPreferencesUpdate,
} from "./preferences";
import type {
    ChecklistCreate,
    ChecklistReorder,
    ChecklistUpdate,
    EvidencePinCreate,
    InvestigationTimelinePage,
    InvestigationWorkspace,
} from "./investigations";
import type {
    AdvancedDetectionRule,
    AdvancedRuleDryRunRequest,
    AdvancedRuleDryRunResult,
    DeploymentConfirmationResult,
    DetectionAnalytics,
    DetectionCoverage,
    DetectionQualityReport,
    IOCDefinition,
    IOCIndicator,
    IOCMatchSummary,
    RuleDraft,
    RuleDraftCreate,
    RuleDraftUpdate,
    RuleDraftVersion,
    RuleDryRunRequest,
    RuleDryRunResult,
    RuleValidationResult,
    SavedHunt,
    ThreatHuntPage,
    ThreatHuntQuery,
} from "./detection-engineering";
import type { OperationalOverview } from "./operations";
import type {
    AgentDetail,
    AgentHealthResponse,
    AgentListResponse,
    AgentQuery,
    WazuhIntegrationStatus,
} from "./agents";
import type {
    CaseAnalytics,
    CaseAssignmentUpdate,
    CaseCreate,
    CaseDetail,
    CaseEvidenceCreate,
    CaseQuery,
    CaseStatusUpdate,
    CaseSummary,
    PlaybookTemplate,
    SlaEvaluationResult,
} from "./cases";
import type { InvestigationWorkbench, WorkbenchTarget } from "./investigation-workbench";
import type {
    CanarySafetyStatus,
    DetectionConfigurationDefinition,
    DetectionConfigurationVersion,
    DetectionDiagnostics,
    DetectionRuleLifecycle,
    DetectionTuningComparison,
    ShadowRun,
    ShadowRunDetail,
    TelemetryPrerequisiteEvidence,
} from "./detection-readiness";

export interface PageMetadata {
    limit: number;
    next_cursor: string | null;
    total: number;
}

export interface AlertListResponse {
    items: NormalizedAlert[];
    page: PageMetadata;
}

export interface IncidentListResponse {
    items: IncidentSummary[];
    page: PageMetadata;
}

export interface CaseListResponse {
    items: CaseSummary[];
    limit: number;
    total: number;
    next_cursor: string | null;
    sort: "newest" | "oldest" | "updated" | "priority";
}

export interface AlertWorkflowListResponse {
    items: AlertWorkflowSummary[];
    page: PageMetadata & { sort: AlertWorkflowSort };
    counts: AlertWorkflowCounts;
}

export interface SecurityEventListResponse {
    items: SecurityEventSummary[];
    page: PageMetadata & { sort: "newest" | "oldest" };
}

export interface HealthResponse {
    status: string;
    service: string;
}

export interface BackendApi {
    health(signal?: AbortSignal): Promise<HealthResponse>;
    getSession(signal?: AbortSignal): Promise<SessionResponse>;
    login(
        credentials: LoginCredentials,
        signal?: AbortSignal,
    ): Promise<SessionResponse>;
    logout(signal?: AbortSignal): Promise<void>;
    subscribeUnauthorized(handler: () => void): () => void;
    listAlerts(
        query?: AlertQuery,
        signal?: AbortSignal,
    ): Promise<AlertListResponse>;
    getAlert(alertId: string, signal?: AbortSignal): Promise<NormalizedAlert>;
    listAlertWorkflows(
        query?: AlertWorkflowQuery,
        signal?: AbortSignal,
    ): Promise<AlertWorkflowListResponse>;
    getAlertWorkflow(
        alertId: string,
        signal?: AbortSignal,
    ): Promise<AlertWorkflowDetail>;
    listAlertAssignees(signal?: AbortSignal): Promise<AlertAssignee[]>;
    updateAlertStatus(
        alertId: string,
        status: AlertWorkflowStatus,
        expectedVersion: number,
        signal?: AbortSignal,
    ): Promise<AlertWorkflowDetail>;
    updateAlertAssignment(
        alertId: string,
        assignedTo: string | null,
        expectedVersion: number,
        signal?: AbortSignal,
    ): Promise<AlertWorkflowDetail>;
    addAlertNote(
        alertId: string,
        body: string,
        expectedVersion: number,
        signal?: AbortSignal,
    ): Promise<AlertWorkflowDetail>;
    bulkUpdateAlerts(
        payload: AlertBulkRequest,
        signal?: AbortSignal,
    ): Promise<AlertBulkResponse>;
    listNotifications(
        limit?: number,
        unreadOnly?: boolean,
        signal?: AbortSignal,
    ): Promise<NotificationListResponse>;
    markNotificationRead(
        notificationId: string,
        signal?: AbortSignal,
    ): Promise<AnalystNotification>;
    markAllNotificationsRead(
        signal?: AbortSignal,
    ): Promise<NotificationReadAllResponse>;
    listEvents(
        query?: EventQuery,
        signal?: AbortSignal,
    ): Promise<SecurityEventListResponse>;
    getEvent(
        eventId: string,
        signal?: AbortSignal,
    ): Promise<SecurityEventDetail>;
    getInvestigationWorkbench(
        target: WorkbenchTarget,
        signal?: AbortSignal,
    ): Promise<InvestigationWorkbench>;
    listSavedEventSearches(signal?: AbortSignal): Promise<SavedEventSearch[]>;
    saveEventSearch(
        payload: SavedEventSearchCreate,
        signal?: AbortSignal,
    ): Promise<SavedEventSearch>;
    updateSavedEventSearch(
        savedSearchId: string,
        payload: SavedEventSearchCreate,
        signal?: AbortSignal,
    ): Promise<SavedEventSearch>;
    deleteSavedEventSearch(
        savedSearchId: string,
        signal?: AbortSignal,
    ): Promise<void>;
    getOverview(
        startTime?: string,
        endTime?: string,
        signal?: AbortSignal,
    ): Promise<SecurityOverview>;
    listSources(signal?: AbortSignal): Promise<LogSourceSummary[]>;
    listHosts(signal?: AbortSignal): Promise<HostSummary[]>;
    listAgents(query?: AgentQuery, signal?: AbortSignal): Promise<AgentListResponse>;
    getAgent(agentKey: string, signal?: AbortSignal): Promise<AgentDetail>;
    getAgentHealth(agentKey: string, signal?: AbortSignal): Promise<AgentHealthResponse>;
    getWazuhIntegrationStatus(signal?: AbortSignal): Promise<WazuhIntegrationStatus>;
    getOperationalOverview(signal?: AbortSignal): Promise<OperationalOverview>;
    listRules(signal?: AbortSignal): Promise<DetectionRuleSummary[]>;
    getDetectionCoverage(signal?: AbortSignal): Promise<DetectionCoverage>;
    listAdvancedDetectionRules(
        days?: number,
        signal?: AbortSignal,
    ): Promise<AdvancedDetectionRule[]>;
    dryRunAdvancedDetectionRule(
        ruleId: string,
        payload: AdvancedRuleDryRunRequest,
        signal?: AbortSignal,
    ): Promise<AdvancedRuleDryRunResult>;
    getDetectionQuality(
        ruleId: string,
        signal?: AbortSignal,
    ): Promise<DetectionQualityReport>;
    listDetectionLifecycles(signal?: AbortSignal): Promise<DetectionRuleLifecycle[]>;
    getDetectionLifecycle(
        ruleId: string,
        signal?: AbortSignal,
    ): Promise<DetectionRuleLifecycle>;
    listDetectionConfigurations(
        ruleId: string,
        signal?: AbortSignal,
    ): Promise<DetectionConfigurationVersion[]>;
    getDetectionTelemetry(
        ruleId: string,
        signal?: AbortSignal,
    ): Promise<TelemetryPrerequisiteEvidence>;
    getDetectionDiagnostics(
        ruleId: string,
        signal?: AbortSignal,
    ): Promise<DetectionDiagnostics>;
    listShadowRuns(ruleId: string, signal?: AbortSignal): Promise<ShadowRun[]>;
    runShadowEvaluation(
        ruleId: string,
        signal?: AbortSignal,
    ): Promise<ShadowRunDetail>;
    compareDetectionTuning(
        ruleId: string,
        baseline: DetectionConfigurationDefinition,
        signal?: AbortSignal,
    ): Promise<DetectionTuningComparison>;
    getCanarySafety(
        ruleId: string,
        signal?: AbortSignal,
    ): Promise<CanarySafetyStatus>;
    getDetectionAnalytics(
        days?: number,
        signal?: AbortSignal,
    ): Promise<DetectionAnalytics>;
    listRuleDrafts(signal?: AbortSignal): Promise<RuleDraft[]>;
    createRuleDraft(
        payload: RuleDraftCreate,
        signal?: AbortSignal,
    ): Promise<RuleDraft>;
    updateRuleDraft(
        draftId: string,
        payload: RuleDraftUpdate,
        signal?: AbortSignal,
    ): Promise<RuleDraft>;
    validateRuleDraft(
        draftId: string,
        expectedVersion: number,
        signal?: AbortSignal,
    ): Promise<RuleValidationResult>;
    dryRunRuleDraft(
        draftId: string,
        payload: RuleDryRunRequest,
        signal?: AbortSignal,
    ): Promise<RuleDryRunResult>;
    confirmManualDeployment(
        draftId: string,
        expectedVersion: number,
        reason: string,
        signal?: AbortSignal,
    ): Promise<DeploymentConfirmationResult>;
    listRuleDraftVersions(
        draftId: string,
        signal?: AbortSignal,
    ): Promise<RuleDraftVersion[]>;
    rollbackRuleDraft(
        draftId: string,
        sourceVersion: number,
        expectedVersion: number,
        changeSummary: string,
        signal?: AbortSignal,
    ): Promise<RuleDraft>;
    runThreatHunt(
        query?: ThreatHuntQuery,
        signal?: AbortSignal,
    ): Promise<ThreatHuntPage>;
    listSavedHunts(signal?: AbortSignal): Promise<SavedHunt[]>;
    saveThreatHunt(
        name: string,
        query: ThreatHuntQuery,
        signal?: AbortSignal,
    ): Promise<SavedHunt>;
    deleteSavedHunt(savedHuntId: string, signal?: AbortSignal): Promise<void>;
    downloadThreatHunt(
        query?: ThreatHuntQuery,
        signal?: AbortSignal,
    ): Promise<{ blob: Blob; filename: string }>;
    listIOCs(
        filters?: {
            indicatorType?: string;
            activeOnly?: boolean;
            search?: string;
            limit?: number;
        },
        signal?: AbortSignal,
    ): Promise<IOCIndicator[]>;
    createIOC(
        payload: IOCDefinition,
        signal?: AbortSignal,
    ): Promise<IOCIndicator>;
    updateIOC(
        indicatorId: string,
        payload: IOCDefinition & {
            expected_version: number;
            is_active: boolean;
        },
        signal?: AbortSignal,
    ): Promise<IOCIndicator>;
    importIOCs(
        indicators: IOCDefinition[],
        signal?: AbortSignal,
    ): Promise<{
        created: number;
        duplicates: number;
        indicators: IOCIndicator[];
    }>;
    getIOCMatches(
        days?: number,
        limit?: number,
        signal?: AbortSignal,
    ): Promise<IOCMatchSummary>;
    downloadIOCs(
        signal?: AbortSignal,
    ): Promise<{ blob: Blob; filename: string }>;
    getSecurityActivityReport(
        query?: ReportQuery,
        signal?: AbortSignal,
    ): Promise<SecurityActivityReport>;
    downloadSecurityActivityReport(
        query: ReportQuery,
        format: "csv" | "json",
        signal?: AbortSignal,
    ): Promise<{ blob: Blob; filename: string }>;
    listAnalysts(signal?: AbortSignal): Promise<AnalystPublic[]>;
    getSessionStatus(signal?: AbortSignal): Promise<AnalystSessionStatus>;
    revokeOtherSessions(signal?: AbortSignal): Promise<void>;
    changePassword(
        payload: PasswordChange,
        signal?: AbortSignal,
    ): Promise<void>;
    listAuditEvents(
        limit?: number,
        signal?: AbortSignal,
        filters?: {
            action?: string;
            actorId?: string;
            targetType?: string;
            outcome?: "SUCCESS" | "DENIED" | "FAILURE";
            search?: string;
        },
    ): Promise<{ items: SecurityAuditEvent[]; limit: number }>;
    listIncidents(
        query?: IncidentQuery,
        signal?: AbortSignal,
    ): Promise<IncidentListResponse>;
    listCases(query?: CaseQuery, signal?: AbortSignal): Promise<CaseListResponse>;
    getCase(caseId: string, signal?: AbortSignal): Promise<CaseDetail>;
    createCase(payload: CaseCreate, signal?: AbortSignal): Promise<CaseDetail>;
    updateCaseStatus(caseId: string, payload: CaseStatusUpdate, signal?: AbortSignal): Promise<CaseDetail>;
    updateCaseAssignment(caseId: string, payload: CaseAssignmentUpdate, signal?: AbortSignal): Promise<CaseDetail>;
    addCaseComment(caseId: string, body: string, expectedVersion: number, signal?: AbortSignal): Promise<CaseDetail>;
    linkCaseReference(caseId: string, kind: "alert" | "incident" | "event", referenceId: string, expectedVersion: number, signal?: AbortSignal): Promise<CaseDetail>;
    acquireCaseEvidence(caseId: string, payload: CaseEvidenceCreate, signal?: AbortSignal): Promise<CaseDetail>;
    verifyCaseEvidence(caseId: string, evidenceId: string, expectedVersion: number, signal?: AbortSignal): Promise<CaseDetail>;
    listPlaybookTemplates(signal?: AbortSignal): Promise<PlaybookTemplate[]>;
    startCasePlaybook(caseId: string, templateKey: string, expectedVersion: number, signal?: AbortSignal): Promise<CaseDetail>;
    updateCasePlaybookStep(caseId: string, playbookId: string, stepId: string, payload: { expected_version: number; status: "PENDING" | "COMPLETED"; assigned_to?: string | null; evidence_ref_id?: string | null; completion_note?: string }, signal?: AbortSignal): Promise<CaseDetail>;
    getCaseAnalytics(days?: number, signal?: AbortSignal): Promise<CaseAnalytics>;
    evaluateCaseSla(signal?: AbortSignal): Promise<SlaEvaluationResult>;
    downloadCaseReport(caseId: string, format: "json" | "csv" | "pdf", signal?: AbortSignal): Promise<{ blob: Blob; filename: string }>;
    getIncident(
        incidentId: string,
        signal?: AbortSignal,
    ): Promise<IncidentDetail>;
    createIncident(
        payload: IncidentCreate,
        signal?: AbortSignal,
    ): Promise<IncidentDetail>;
    updateIncidentStatus(
        incidentId: string,
        payload: IncidentStatusUpdate,
        signal?: AbortSignal,
    ): Promise<IncidentDetail>;
    linkIncidentAlert(
        incidentId: string,
        payload: IncidentAlertLink,
        signal?: AbortSignal,
    ): Promise<IncidentDetail>;
    addIncidentNote(
        incidentId: string,
        payload: IncidentNoteCreate,
        signal?: AbortSignal,
    ): Promise<IncidentNote>;
    updateIncidentAssignment(
        incidentId: string,
        payload: IncidentAssignmentUpdate,
        signal?: AbortSignal,
    ): Promise<IncidentDetail>;
    getInvestigation(
        incidentId: string,
        signal?: AbortSignal,
    ): Promise<InvestigationWorkspace>;
    createChecklistItem(
        incidentId: string,
        payload: ChecklistCreate,
        signal?: AbortSignal,
    ): Promise<InvestigationWorkspace>;
    updateChecklistItem(
        incidentId: string,
        itemId: string,
        payload: ChecklistUpdate,
        signal?: AbortSignal,
    ): Promise<InvestigationWorkspace>;
    reorderChecklist(
        incidentId: string,
        payload: ChecklistReorder,
        signal?: AbortSignal,
    ): Promise<InvestigationWorkspace>;
    pinEvidence(
        incidentId: string,
        payload: EvidencePinCreate,
        signal?: AbortSignal,
    ): Promise<InvestigationWorkspace>;
    annotateEvidence(
        incidentId: string,
        pinId: string,
        annotation: string,
        expectedVersion: number,
        signal?: AbortSignal,
    ): Promise<InvestigationWorkspace>;
    unpinEvidence(
        incidentId: string,
        pinId: string,
        expectedVersion: number,
        signal?: AbortSignal,
    ): Promise<InvestigationWorkspace>;
    getInvestigationTimeline(
        incidentId: string,
        limit?: number,
        cursor?: string,
        signal?: AbortSignal,
    ): Promise<InvestigationTimelinePage>;
    getPreferences(signal?: AbortSignal): Promise<AnalystPreferences>;
    updatePreferences(
        payload: AnalystPreferencesUpdate,
        signal?: AbortSignal,
    ): Promise<AnalystPreferences>;
    resetPreferences(
        expectedVersion: number,
        signal?: AbortSignal,
    ): Promise<AnalystPreferences>;
    getAIStatus(signal?: AbortSignal): Promise<AIStatus>;
    analyzeAlert(
        alertId: string,
        payload?: AIAnalysisRequest,
        signal?: AbortSignal,
    ): Promise<AIAnalysisRecord>;
    analyzeIncident(
        incidentId: string,
        payload?: AIAnalysisRequest,
        signal?: AbortSignal,
    ): Promise<AIAnalysisRecord>;
    getAIAnalysis(
        analysisId: string,
        signal?: AbortSignal,
    ): Promise<AIAnalysisRecord>;
    listAlertAnalyses(
        alertId: string,
        signal?: AbortSignal,
    ): Promise<AIAnalysisHistory>;
    listIncidentAnalyses(
        incidentId: string,
        signal?: AbortSignal,
    ): Promise<AIAnalysisHistory>;
}
