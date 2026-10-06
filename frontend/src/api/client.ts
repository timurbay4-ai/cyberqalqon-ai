import {
  parseAlertList,
  parseHealth,
  parseIncidentDetail,
  parseIncidentList,
  parseIncidentNote,
  parseNormalizedAlert,
  parseSession,
} from "./contracts";
import type { AlertQuery } from "../types/alerts";
import type { LoginCredentials } from "../types/auth";
import type { BackendApi } from "../types/api";
import type {
  IncidentAlertLink,
  IncidentAssignmentUpdate,
  IncidentCreate,
  IncidentNoteCreate,
  IncidentQuery,
  IncidentStatusUpdate,
} from "../types/incidents";

type Parser<T> = (value: unknown) => T;
type Fetcher = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
    readonly field?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export class BackendUnavailableError extends Error {
  constructor() {
    super("The CyberQalqon backend is unavailable. Check the service and retry.");
    this.name = "BackendUnavailableError";
  }
}

function queryString(entries: Array<[string, string | number | boolean | undefined]>): string {
  const parameters = new URLSearchParams();
  entries.forEach(([key, value]) => {
    if (value !== undefined && value !== "") parameters.append(key, String(value));
  });
  const query = parameters.toString();
  return query ? `?${query}` : "";
}

function errorFrom(value: unknown, status: number): ApiError {
  if (typeof value === "object" && value !== null && "detail" in value) {
    const detail = (value as { detail?: unknown }).detail;
    if (typeof detail === "object" && detail !== null) {
      const body = detail as Record<string, unknown>;
      if (typeof body.code === "string" && typeof body.message === "string") {
        return new ApiError(
          body.message,
          status,
          body.code,
          typeof body.field === "string" ? body.field : undefined,
        );
      }
    }
  }
  return new ApiError(`Backend request failed with status ${status}.`, status, "http_error");
}

export class HttpBackendApi implements BackendApi {
  private readonly baseUrl: string;
  private csrfToken: string | null = null;
  private readonly unauthorizedHandlers = new Set<() => void>();

  constructor(
    baseUrl = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000",
    private readonly fetcher: Fetcher = fetch,
  ) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
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
      if (error instanceof DOMException && error.name === "AbortError") throw error;
      throw new BackendUnavailableError();
    }

    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      if (!response.ok) throw new ApiError("Backend returned an unreadable error.", response.status, "invalid_error");
      throw new ApiError("Backend returned malformed JSON.", 502, "invalid_response");
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

  private async requestVoid(path: string, init: RequestInit, signal?: AbortSignal): Promise<void> {
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
      if (error instanceof DOMException && error.name === "AbortError") throw error;
      throw new BackendUnavailableError();
    }
    if (!response.ok) {
      let payload: unknown = null;
      try { payload = await response.json(); } catch { /* preserve a safe generic error */ }
      if (response.status === 401) this.unauthorizedHandlers.forEach((handler) => handler());
      throw errorFrom(payload, response.status);
    }
  }

  subscribeUnauthorized(handler: () => void) {
    this.unauthorizedHandlers.add(handler);
    return () => this.unauthorizedHandlers.delete(handler);
  }

  health(signal?: AbortSignal) {
    return this.request("/health", parseHealth, {}, signal);
  }

  async getSession(signal?: AbortSignal) {
    const session = await this.request("/api/v1/auth/session", parseSession, {}, signal, false);
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
      await this.requestVoid("/api/v1/auth/logout", { method: "POST" }, signal);
    } finally {
      this.csrfToken = null;
    }
  }

  listAlerts(query: AlertQuery = {}, signal?: AbortSignal) {
    const entries: Array<[string, string | number | boolean | undefined]> = [];
    query.ruleLevels?.forEach((level) => entries.push(["rule_level", level]));
    entries.push(
      ["agent", query.agent],
      ["mitre_mapped", query.mitreMapped],
      ["mitre_id", query.mitreId],
      ["start_time", query.startTime],
      ["end_time", query.endTime],
      ["search", query.search],
      ["limit", query.limit],
      ["cursor", query.cursor],
    );
    return this.request(`/api/v1/alerts${queryString(entries)}`, parseAlertList, {}, signal);
  }

  getAlert(alertId: string, signal?: AbortSignal) {
    return this.request(
      `/api/v1/alerts/${encodeURIComponent(alertId)}`,
      parseNormalizedAlert,
      {},
      signal,
    );
  }

  listIncidents(query: IncidentQuery = {}, signal?: AbortSignal) {
    const entries: Array<[string, string | number | boolean | undefined]> = [];
    query.statuses?.forEach((status) => entries.push(["status", status]));
    query.severities?.forEach((severity) => entries.push(["severity", severity]));
    entries.push(
      ["assigned_to", query.assignedTo],
      ["limit", query.limit],
      ["cursor", query.cursor],
    );
    return this.request(`/api/v1/incidents${queryString(entries)}`, parseIncidentList, {}, signal);
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

  updateIncidentStatus(incidentId: string, payload: IncidentStatusUpdate, signal?: AbortSignal) {
    return this.request(
      `/api/v1/incidents/${encodeURIComponent(incidentId)}/status`,
      parseIncidentDetail,
      this.mutation({ method: "PATCH", body: JSON.stringify(payload) }),
      signal,
    );
  }

  linkIncidentAlert(incidentId: string, payload: IncidentAlertLink, signal?: AbortSignal) {
    return this.request(
      `/api/v1/incidents/${encodeURIComponent(incidentId)}/alerts`,
      parseIncidentDetail,
      this.mutation({ method: "POST", body: JSON.stringify(payload) }),
      signal,
    );
  }

  addIncidentNote(incidentId: string, payload: IncidentNoteCreate, signal?: AbortSignal) {
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
}

export const backendApi: BackendApi = new HttpBackendApi();
