import { describe, expect, it } from "vitest";

import { ContractError, parseAlertList, parseIncidentDetail, parseNormalizedAlert, parseSession } from "./contracts";
import { ALERT_PAGE, SAMPLE_ALERT, SAMPLE_INCIDENT, SAMPLE_SESSION } from "../test/fixtures";

describe("runtime API contracts", () => {
  it("accepts optional alert fields and empty MITRE arrays", () => {
    const parsed = parseNormalizedAlert(SAMPLE_ALERT);
    expect(parsed.agent.ip).toBeNull();
    expect(parsed.destination).toBeUndefined();
    expect(parsed.mitre).toEqual({ ids: [], tactics: [], techniques: [] });
  });

  it("preserves HTML-looking telemetry as inert strings", () => {
    const parsed = parseAlertList(ALERT_PAGE);
    expect(parsed.items[0].rule.description).toBe("<script>attack()</script>");
    expect((globalThis as { attack?: unknown }).attack).toBeUndefined();
  });

  it("rejects malformed alert responses", () => {
    expect(() => parseAlertList({ items: [{ alert_id: "incomplete" }], page: { limit: 25, next_cursor: null, total: 1 } })).toThrow(ContractError);
  });

  it("rejects unexpected severity values", () => {
    expect(() => parseIncidentDetail({ ...SAMPLE_INCIDENT, severity: "URGENT" })).toThrow(/incident.severity/);
  });

  it("parses the complete incident detail contract", () => {
    const parsed = parseIncidentDetail(SAMPLE_INCIDENT);
    expect(parsed.status).toBe("NEW");
    expect(parsed.notes[0].body).toContain("onerror");
    expect(parsed.history[0].event_type).toBe("CREATED");
  });

  it("validates authenticated roles and permissions", () => {
    expect(parseSession(SAMPLE_SESSION).analyst.role).toBe("ANALYST");
    expect(() => parseSession({ ...SAMPLE_SESSION, analyst: { ...SAMPLE_SESSION.analyst, role: "ROOT" } })).toThrow(/session.analyst.role/);
    expect(() => parseSession({ ...SAMPLE_SESSION, analyst: { ...SAMPLE_SESSION.analyst, permissions: ["everything"] } })).toThrow(/session.analyst.permissions/);
  });
});
