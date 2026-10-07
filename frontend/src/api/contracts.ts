import type { NormalizedAlert, WazuhSeverityLevel } from "../types/alerts";
import { AI_AVAILABILITY, type AIAnalysisHistory, type AIAnalysisRecord, type AIAnalysisResult, type AIAnalysisType, type AIAvailability, type AITargetType, type AIStatus } from "../types/ai";
import { ANALYST_ROLES, PERMISSIONS, type AnalystPrincipal, type AnalystRole, type Permission, type SessionResponse } from "../types/auth";
import type { AlertListResponse, HealthResponse, IncidentListResponse, PageMetadata } from "../types/api";
import {
  INCIDENT_SEVERITIES,
  INCIDENT_STATUSES,
  type IncidentDetail,
  type IncidentEventType,
  type IncidentHistoryEvent,
  type IncidentNote,
  type IncidentSeverity,
  type IncidentStatus,
  type IncidentSummary,
} from "../types/incidents";

export class ContractError extends Error {
  constructor(path: string) {
    super(`Backend response did not match the expected contract at ${path}.`);
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

function boundedStringAt(value: unknown, path: string, maximum: number): string {
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
  if (!Number.isInteger(value) || (value as number) < minimum) throw new ContractError(path);
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

function boundedStringsAt(value: unknown, path: string, maximumItems: number, maximumChars: number): string[] {
  if (!Array.isArray(value) || value.length > maximumItems) throw new ContractError(path);
  return value.map((item, index) => boundedStringAt(item, `${path}[${index}]`, maximumChars));
}

function nullableIdentifierAt(value: unknown, path: string): string | null {
  return value === undefined ? null : nullableStringAt(value, path);
}

function pageAt(value: unknown, path: string): PageMetadata {
  const page = objectAt(value, path);
  const nextCursor = page.next_cursor;
  if (nextCursor !== null && typeof nextCursor !== "string") {
    throw new ContractError(`${path}.next_cursor`);
  }
  return {
    limit: integerAt(page.limit, `${path}.limit`, 1),
    next_cursor: nextCursor,
    total: integerAt(page.total, `${path}.total`),
  };
}

export function parseNormalizedAlert(value: unknown, path = "alert"): NormalizedAlert {
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
      if (parsedPort > 65535) throw new ContractError(`${endpointPath}.port`);
    }
    return {
      ip: nullableStringAt(item.ip, `${endpointPath}.ip`),
      port: port === null || port === undefined ? undefined : (port as number),
    };
  };

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
      groups: rule.groups === undefined ? [] : stringsAt(rule.groups, `${path}.rule.groups`),
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
    decoder_name: nullableStringAt(alert.decoder_name, `${path}.decoder_name`),
  };
}

export function parseAlertList(value: unknown): AlertListResponse {
  const response = objectAt(value, "response");
  if (!Array.isArray(response.items)) throw new ContractError("response.items");
  return {
    items: response.items.map((item, index) => parseNormalizedAlert(item, `response.items[${index}]`)),
    page: pageAt(response.page, "response.page"),
  };
}

function incidentStatusAt(value: unknown, path: string): IncidentStatus {
  const status = stringAt(value, path);
  if (!(INCIDENT_STATUSES as readonly string[]).includes(status)) throw new ContractError(path);
  return status as IncidentStatus;
}

function incidentSeverityAt(value: unknown, path: string): IncidentSeverity {
  const severity = stringAt(value, path);
  if (!(INCIDENT_SEVERITIES as readonly string[]).includes(severity)) throw new ContractError(path);
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
    assigned_to: nullableStringAt(incident.assigned_to, `${path}.assigned_to`),
    created_at: dateAt(incident.created_at, `${path}.created_at`),
    updated_at: dateAt(incident.updated_at, `${path}.updated_at`),
    alert_count: integerAt(incident.alert_count, `${path}.alert_count`),
  };
}

export function parseIncidentList(value: unknown): IncidentListResponse {
  const response = objectAt(value, "response");
  if (!Array.isArray(response.items)) throw new ContractError("response.items");
  return {
    items: response.items.map((item, index) => incidentSummaryAt(item, `response.items[${index}]`)),
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

export function parseIncidentDetail(value: unknown): IncidentDetail {
  const incident = objectAt(value, "incident");
  const summary = incidentSummaryAt(incident, "incident");
  if (!Array.isArray(incident.notes)) throw new ContractError("incident.notes");
  if (!Array.isArray(incident.history)) throw new ContractError("incident.history");
  return {
    ...summary,
    alert_ids: stringsAt(incident.alert_ids, "incident.alert_ids"),
    notes: incident.notes.map((note, index) => parseIncidentNote(note, `incident.notes[${index}]`)),
    history: incident.history.map((event, index) => historyAt(event, `incident.history[${index}]`)),
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
  if (!(ANALYST_ROLES as readonly string[]).includes(role)) throw new ContractError(`${path}.role`);
  const permissions = stringsAt(principal.permissions, `${path}.permissions`);
  if (permissions.some((permission) => !(PERMISSIONS as readonly string[]).includes(permission))) {
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

function analysisResultAt(value: unknown, path: string): AIAnalysisResult {
  const result = objectAt(value, path);
  const mitre = result.mitre_context;
  if (!Array.isArray(mitre) || mitre.length > 12) throw new ContractError(`${path}.mitre_context`);
  return {
    summary: boundedStringAt(result.summary, `${path}.summary`, 2000),
    assessment: boundedStringAt(result.assessment, `${path}.assessment`, 4000),
    key_evidence: boundedStringsAt(result.key_evidence, `${path}.key_evidence`, 12, 1200),
    mitre_context: mitre.map((item, index) => {
      const entry = objectAt(item, `${path}.mitre_context[${index}]`);
      const basis = stringAt(entry.basis, `${path}.mitre_context[${index}].basis`);
      if (basis !== "observed" && basis !== "inferred") throw new ContractError(`${path}.mitre_context[${index}].basis`);
      return {
        technique_id: boundedStringAt(entry.technique_id, `${path}.mitre_context[${index}].technique_id`, 32),
        explanation: boundedStringAt(entry.explanation, `${path}.mitre_context[${index}].explanation`, 1200),
        basis,
      };
    }),
    timeline_summary: result.timeline_summary === null ? null : boundedStringAt(result.timeline_summary, `${path}.timeline_summary`, 2400),
    hypotheses: boundedStringsAt(result.hypotheses, `${path}.hypotheses`, 10, 1200),
    investigation_steps: boundedStringsAt(result.investigation_steps, `${path}.investigation_steps`, 12, 1200),
    possible_false_positive_reasons: boundedStringsAt(result.possible_false_positive_reasons, `${path}.possible_false_positive_reasons`, 10, 1200),
    recommended_actions: boundedStringsAt(result.recommended_actions, `${path}.recommended_actions`, 12, 1200),
    containment_considerations: boundedStringsAt(result.containment_considerations, `${path}.containment_considerations`, 10, 1200),
    uncertainties: boundedStringsAt(result.uncertainties, `${path}.uncertainties`, 10, 1200),
  };
}

export function parseAIStatus(value: unknown): AIStatus {
  const status = objectAt(value, "ai_status");
  const state = stringAt(status.state, "ai_status.state");
  if (!(AI_AVAILABILITY as readonly string[]).includes(state)) throw new ContractError("ai_status.state");
  if (status.provider !== "ollama") throw new ContractError("ai_status.provider");
  return {
    state: state as AIAvailability,
    provider: "ollama",
    model: nullableStringAt(status.model, "ai_status.model"),
    diagnostic: nullableStringAt(status.diagnostic, "ai_status.diagnostic"),
    checked_at: dateAt(status.checked_at, "ai_status.checked_at"),
  };
}

export function parseAIAnalysis(value: unknown, path = "analysis"): AIAnalysisRecord {
  const analysis = objectAt(value, path);
  const types: AIAnalysisType[] = ["ALERT_SUMMARY", "INCIDENT_SUMMARY", "ANALYST_QUESTION"];
  const analysisType = stringAt(analysis.analysis_type, `${path}.analysis_type`);
  if (!types.includes(analysisType as AIAnalysisType)) throw new ContractError(`${path}.analysis_type`);
  const targetType = stringAt(analysis.target_type, `${path}.target_type`);
  if (targetType !== "alert" && targetType !== "incident") throw new ContractError(`${path}.target_type`);
  const requester = objectAt(analysis.requested_by, `${path}.requested_by`);
  const context = objectAt(analysis.context, `${path}.context`);
  if (analysis.provider !== "ollama") throw new ContractError(`${path}.provider`);
  if (analysis.policy_version !== "cyberqalqon-ai-policy-v1") throw new ContractError(`${path}.policy_version`);
  if (analysis.schema_version !== "ai-analysis-v1") throw new ContractError(`${path}.schema_version`);
  const fingerprint = stringAt(analysis.context_fingerprint, `${path}.context_fingerprint`);
  if (!/^[0-9a-f]{64}$/.test(fingerprint)) throw new ContractError(`${path}.context_fingerprint`);
  return {
    analysis_id: stringAt(analysis.analysis_id, `${path}.analysis_id`),
    analysis_type: analysisType as AIAnalysisType,
    target_type: targetType as AITargetType,
    target_id: stringAt(analysis.target_id, `${path}.target_id`),
    requested_by: {
      analyst_id: stringAt(requester.analyst_id, `${path}.requested_by.analyst_id`),
      display: stringAt(requester.display, `${path}.requested_by.display`),
    },
    requested_at: dateAt(analysis.requested_at, `${path}.requested_at`),
    completed_at: dateAt(analysis.completed_at, `${path}.completed_at`),
    provider: "ollama",
    model: boundedStringAt(analysis.model, `${path}.model`, 256),
    model_digest: nullableStringAt(analysis.model_digest, `${path}.model_digest`),
    policy_version: "cyberqalqon-ai-policy-v1",
    schema_version: "ai-analysis-v1",
    context_fingerprint: fingerprint,
    context: {
      context_bytes: integerAt(context.context_bytes, `${path}.context.context_bytes`),
      truncated: booleanAt(context.truncated, `${path}.context.truncated`),
      alerts_included: integerAt(context.alerts_included, `${path}.context.alerts_included`),
      alerts_available: integerAt(context.alerts_available, `${path}.context.alerts_available`),
      notes_included: integerAt(context.notes_included, `${path}.context.notes_included`),
      notes_available: integerAt(context.notes_available, `${path}.context.notes_available`),
      history_included: integerAt(context.history_included, `${path}.context.history_included`),
      history_available: integerAt(context.history_available, `${path}.context.history_available`),
      raw_event_included: booleanAt(context.raw_event_included, `${path}.context.raw_event_included`),
      truncation_reasons: boundedStringsAt(context.truncation_reasons, `${path}.context.truncation_reasons`, 20, 256),
    },
    stale: booleanAt(analysis.stale, `${path}.stale`),
    result: analysisResultAt(analysis.result, `${path}.result`),
  };
}

export function parseAIAnalysisHistory(value: unknown): AIAnalysisHistory {
  const history = objectAt(value, "analysis_history");
  if (!Array.isArray(history.items) || history.items.length > 50) throw new ContractError("analysis_history.items");
  return {
    items: history.items.map((item, index) => parseAIAnalysis(item, `analysis_history.items[${index}]`)),
    limit: integerAt(history.limit, "analysis_history.limit", 1),
  };
}
