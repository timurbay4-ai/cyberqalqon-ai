import type { NormalizedAlert, WazuhSeverityLevel } from "../types/alerts";
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

function dateAt(value: unknown, path: string): string {
  const text = stringAt(value, path);
  if (Number.isNaN(Date.parse(text))) throw new ContractError(path);
  return text;
}

function integerAt(value: unknown, path: string, minimum = 0): number {
  if (!Number.isInteger(value) || (value as number) < minimum) throw new ContractError(path);
  return value as number;
}

function nullableStringAt(value: unknown, path: string): string | null {
  if (value === null || value === undefined) return null;
  return stringAt(value, path);
}

function stringsAt(value: unknown, path: string): string[] {
  if (!Array.isArray(value)) throw new ContractError(path);
  return value.map((item, index) => stringAt(item, `${path}[${index}]`));
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
