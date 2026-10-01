/**
 * CyberQalqon AI — Frontend TypeScript Types
 *
 * These types mirror the backend Pydantic schemas exactly.
 * Source: backend/app/schemas/incident.py, review.py
 * API doc: docs/api/BACKEND_API.md (dev-backend branch)
 */

// ---------------------------------------------------------------------------
// Backend health / readiness
// ---------------------------------------------------------------------------

export interface HealthResponse {
  status: 'ok' | string;
  service: string;
}

// ---------------------------------------------------------------------------
// Reviews
// ---------------------------------------------------------------------------

export type ReviewStatus = 'confirmed' | 'false_positive' | 'needs_review';

export interface ReviewResponse {
  id: string;
  status: ReviewStatus;
  analyst: string;
  note: string | null;
  created_at: string; // ISO 8601
}

export interface ReviewCreate {
  status: ReviewStatus;
  analyst: string;
  note?: string;
}

// ---------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type AIStatus =
  | 'not_configured'
  | 'pending'
  | 'success'
  | 'partial'
  | 'failed'
  | 'unavailable';

export interface IncidentResponse {
  id: string;
  alert_id: string | null;
  event_timestamp: string | null; // ISO 8601
  created_at: string;             // ISO 8601
  updated_at: string;             // ISO 8601
  agent_id: string | null;
  agent_name: string | null;
  agent_ip: string | null;
  rule_id: string | null;
  rule_level: number | null;
  rule_description: string | null;
  rule_metadata: Record<string, unknown>;
  mitre_ids: string[];
  mitre_tactics: string[];
  mitre_techniques: string[];
  source_ip: string | null;
  destination_ip: string | null;
  user: string | null;
  source_user: string | null;
  destination_user: string | null;
  location: string | null;
  decoder: Record<string, unknown> | null;
  full_log: string | null;
  raw_event: Record<string, unknown>;
  severity: Severity;
  priority_score: number;
  repetition_count: number;
  asset_importance: string;
  ai_status: AIStatus;
  review_status: ReviewStatus;
  reviews: ReviewResponse[];
}

export interface IncidentListResponse {
  total: number;
  limit: number;
  offset: number;
  items: IncidentResponse[];
}

// ---------------------------------------------------------------------------
// Statistics — GET /api/v1/incidents/stats
// ---------------------------------------------------------------------------

export interface IncidentStatsResponse {
  total: number;
  severity: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  review_status: {
    needs_review: number;
    confirmed: number;
    false_positive: number;
  };
}

// ---------------------------------------------------------------------------
// Query params for GET /api/v1/incidents
// ---------------------------------------------------------------------------

export interface IncidentListParams {
  limit?: number;
  offset?: number;
  severity?: Severity;
  agent?: string;
  mitre_id?: string;
}

// ---------------------------------------------------------------------------
// Error envelope returned by backend on failures
// ---------------------------------------------------------------------------

export interface ApiError {
  error: {
    code: string;
    message: string;
  };
}

// ---------------------------------------------------------------------------
// MITRE technique reference (static lookup, not from backend)
// ---------------------------------------------------------------------------

export interface MitreTechnique {
  id: string;
  name: string;
  url: string;
  tactic?: string;
}
