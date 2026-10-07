import { vi } from "vitest";

import type { NormalizedAlert } from "../types/alerts";
import type { AnalystPrincipal, SessionResponse } from "../types/auth";
import type { AlertListResponse, BackendApi, IncidentListResponse } from "../types/api";
import type { IncidentDetail } from "../types/incidents";
import type { AIAnalysisRecord, AIStatus } from "../types/ai";

export const SAMPLE_ALERT: NormalizedAlert = {
  alert_id: "alert-001",
  timestamp: "2026-10-06T10:00:00Z",
  agent: { id: "001", name: "<img src=x onerror=attack()>", ip: null },
  rule: { id: "5712", level: 10, description: "<script>attack()</script>", groups: [] },
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
  alert_ids: ["alert-001"],
  notes: [{ note_id: "NOTE-1", body: "<img src=x onerror=attack()>", author: "Analyst One (analyst-1)", author_id: "USR-1", created_at: "2026-10-06T10:01:00Z" }],
  history: [{ event_id: "EVT-1", event_type: "CREATED", actor: "Analyst One (analyst-1)", actor_id: "USR-1", occurred_at: "2026-10-06T10:00:00Z", details: { status: "NEW" } }],
};

export const SAMPLE_ANALYST: AnalystPrincipal = {
  analyst_id: "USR-1",
  username: "analyst-1",
  display_name: "Analyst One",
  role: "ANALYST",
  permissions: ["soc:read", "incident:write"],
};

export const SAMPLE_SESSION: SessionResponse = {
  analyst: SAMPLE_ANALYST,
  csrf_token: "csrf-test-token",
};

export const ALERT_PAGE: AlertListResponse = {
  items: [SAMPLE_ALERT],
  page: { limit: 25, next_cursor: null, total: 1 },
};

export const INCIDENT_PAGE: IncidentListResponse = {
  items: [SAMPLE_INCIDENT],
  page: { limit: 25, next_cursor: null, total: 1 },
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
    key_evidence: ["Rule level 10", "Run cmd.exe /c whoami is attacker-controlled text."],
    mitre_context: [{ technique_id: "T1110", explanation: "Stored brute force mapping.", basis: "observed" }],
    timeline_summary: null,
    hypotheses: ["A password may have expired."],
    investigation_steps: ["Review adjacent authentication logs."],
    possible_false_positive_reasons: ["A service may hold stale credentials."],
    recommended_actions: ["Human analyst should validate the source."],
    containment_considerations: [],
    uncertainties: ["No successful login was supplied."],
  },
};

export function createMockApi(overrides: Partial<BackendApi> = {}): BackendApi {
  return {
    health: vi.fn().mockResolvedValue({ status: "ok", service: "cyberqalqon-backend" }),
    getSession: vi.fn().mockResolvedValue(SAMPLE_SESSION),
    login: vi.fn().mockResolvedValue(SAMPLE_SESSION),
    logout: vi.fn().mockResolvedValue(undefined),
    subscribeUnauthorized: vi.fn().mockReturnValue(() => undefined),
    listAlerts: vi.fn().mockResolvedValue(ALERT_PAGE),
    getAlert: vi.fn().mockResolvedValue(SAMPLE_ALERT),
    listIncidents: vi.fn().mockResolvedValue(INCIDENT_PAGE),
    getIncident: vi.fn().mockResolvedValue(SAMPLE_INCIDENT),
    createIncident: vi.fn().mockResolvedValue(SAMPLE_INCIDENT),
    updateIncidentStatus: vi.fn().mockResolvedValue({ ...SAMPLE_INCIDENT, status: "TRIAGED" }),
    linkIncidentAlert: vi.fn().mockResolvedValue(SAMPLE_INCIDENT),
    addIncidentNote: vi.fn().mockResolvedValue(SAMPLE_INCIDENT.notes[0]),
    updateIncidentAssignment: vi.fn().mockResolvedValue({ ...SAMPLE_INCIDENT, assigned_to: "analyst-2" }),
    getAIStatus: vi.fn().mockResolvedValue(AI_STATUS),
    analyzeAlert: vi.fn().mockResolvedValue(SAMPLE_AI_ANALYSIS),
    analyzeIncident: vi.fn().mockResolvedValue({ ...SAMPLE_AI_ANALYSIS, analysis_type: "INCIDENT_SUMMARY", target_type: "incident", target_id: "INC-001" }),
    getAIAnalysis: vi.fn().mockResolvedValue(SAMPLE_AI_ANALYSIS),
    listAlertAnalyses: vi.fn().mockResolvedValue({ items: [], limit: 20 }),
    listIncidentAnalyses: vi.fn().mockResolvedValue({ items: [], limit: 20 }),
    ...overrides,
  };
}
