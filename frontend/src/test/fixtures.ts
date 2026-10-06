import { vi } from "vitest";

import type { NormalizedAlert } from "../types/alerts";
import type { AnalystPrincipal, SessionResponse } from "../types/auth";
import type { AlertListResponse, BackendApi, IncidentListResponse } from "../types/api";
import type { IncidentDetail } from "../types/incidents";

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
    ...overrides,
  };
}
