/**
 * CyberQalqon AI — Centralized API Client
 *
 * All backend communication goes through this module.
 * Base URL is read from VITE_API_BASE_URL env var (never hardcoded).
 *
 * Handles:
 *  - Network errors
 *  - Non-2xx responses (parses backend error envelope)
 *  - Timeouts (10s default)
 *  - No credentials/secrets stored here
 */

import type {
  HealthResponse,
  IncidentListParams,
  IncidentListResponse,
  IncidentResponse,
  IncidentStatsResponse,
  ReviewCreate,
} from '@/types';

// ---------------------------------------------------------------------------
// Configuration — URL only, no secrets
// ---------------------------------------------------------------------------

const API_BASE_URL =
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ??
  'http://127.0.0.1:8000';

const DEFAULT_TIMEOUT_MS = 10_000;

// ---------------------------------------------------------------------------
// Custom error type
// ---------------------------------------------------------------------------

export class ApiRequestError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ApiRequestError';
  }
}

export class NetworkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NetworkError';
  }
}

// ---------------------------------------------------------------------------
// Internal fetch wrapper
// ---------------------------------------------------------------------------

async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const controller = new AbortController();
  const timeoutId = setTimeout(
    () => controller.abort(),
    DEFAULT_TIMEOUT_MS,
  );

  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...options.headers,
      },
    });
  } catch (err) {
    clearTimeout(timeoutId);
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new NetworkError(
        'Request timed out. The backend may be unavailable.',
      );
    }
    throw new NetworkError(
      'Cannot reach the CyberQalqon backend. Is it running?',
    );
  } finally {
    clearTimeout(timeoutId);
  }

  if (!response.ok) {
    let code = `HTTP_${response.status}`;
    let message = `Request failed with status ${response.status}`;
    try {
      const body = await response.json();
      if (body?.error?.code) code = body.error.code as string;
      if (body?.error?.message) message = body.error.message as string;
    } catch {
      /* response body may not be JSON */
    }
    throw new ApiRequestError(response.status, code, message);
  }

  return response.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// API surface
// ---------------------------------------------------------------------------

export const api = {
  /**
   * GET /health — basic liveness probe
   */
  health(): Promise<HealthResponse> {
    return apiFetch<HealthResponse>('/health');
  },

  /**
   * GET /ready — readiness probe (checks DB connectivity)
   */
  ready(): Promise<HealthResponse> {
    return apiFetch<HealthResponse>('/ready');
  },

  /**
   * GET /api/v1/incidents — paginated, filterable incident list
   */
  listIncidents(params: IncidentListParams = {}): Promise<IncidentListResponse> {
    const query = new URLSearchParams();
    if (params.limit != null) query.set('limit', String(params.limit));
    if (params.offset != null) query.set('offset', String(params.offset));
    if (params.severity) query.set('severity', params.severity);
    if (params.agent) query.set('agent', params.agent);
    if (params.mitre_id) query.set('mitre_id', params.mitre_id);
    const qs = query.toString();
    return apiFetch<IncidentListResponse>(
      `/api/v1/incidents${qs ? `?${qs}` : ''}`,
    );
  },

  /**
   * GET /api/v1/incidents/:id — single incident detail
   */
  getIncident(id: string): Promise<IncidentResponse> {
    return apiFetch<IncidentResponse>(`/api/v1/incidents/${encodeURIComponent(id)}`);
  },

  /**
   * POST /api/v1/incidents/:id/review — submit analyst review
   */
  submitReview(incidentId: string, review: ReviewCreate): Promise<IncidentResponse> {
    return apiFetch<IncidentResponse>(
      `/api/v1/incidents/${encodeURIComponent(incidentId)}/review`,
      {
        method: 'POST',
        body: JSON.stringify(review),
      },
    );
  },

  /**
   * GET /api/v1/incidents/stats — pre-computed severity/review counts
   *
   * NOTE: This path must be proxied before the /:id route in the backend router.
   * The backend places /stats before /{incident_id} so "stats" is not treated as an ID.
   */
  getStats(): Promise<IncidentStatsResponse> {
    return apiFetch<IncidentStatsResponse>('/api/v1/incidents/stats');
  },
};
