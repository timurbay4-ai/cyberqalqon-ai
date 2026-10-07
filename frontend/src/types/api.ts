import type { AlertQuery, NormalizedAlert } from "./alerts";
import type { LoginCredentials, SessionResponse } from "./auth";
import type { AIAnalysisHistory, AIAnalysisRecord, AIAnalysisRequest, AIStatus } from "./ai";
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

export interface HealthResponse {
  status: string;
  service: string;
}

export interface BackendApi {
  health(signal?: AbortSignal): Promise<HealthResponse>;
  getSession(signal?: AbortSignal): Promise<SessionResponse>;
  login(credentials: LoginCredentials, signal?: AbortSignal): Promise<SessionResponse>;
  logout(signal?: AbortSignal): Promise<void>;
  subscribeUnauthorized(handler: () => void): () => void;
  listAlerts(query?: AlertQuery, signal?: AbortSignal): Promise<AlertListResponse>;
  getAlert(alertId: string, signal?: AbortSignal): Promise<NormalizedAlert>;
  listIncidents(query?: IncidentQuery, signal?: AbortSignal): Promise<IncidentListResponse>;
  getIncident(incidentId: string, signal?: AbortSignal): Promise<IncidentDetail>;
  createIncident(payload: IncidentCreate, signal?: AbortSignal): Promise<IncidentDetail>;
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
  getAIStatus(signal?: AbortSignal): Promise<AIStatus>;
  analyzeAlert(alertId: string, payload?: AIAnalysisRequest, signal?: AbortSignal): Promise<AIAnalysisRecord>;
  analyzeIncident(incidentId: string, payload?: AIAnalysisRequest, signal?: AbortSignal): Promise<AIAnalysisRecord>;
  getAIAnalysis(analysisId: string, signal?: AbortSignal): Promise<AIAnalysisRecord>;
  listAlertAnalyses(alertId: string, signal?: AbortSignal): Promise<AIAnalysisHistory>;
  listIncidentAnalyses(incidentId: string, signal?: AbortSignal): Promise<AIAnalysisHistory>;
}
