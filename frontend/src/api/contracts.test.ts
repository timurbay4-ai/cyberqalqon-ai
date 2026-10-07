import { describe, expect, it } from "vitest";

import { ContractError, parseAIAnalysis, parseAIAnalysisHistory, parseAIStatus, parseAlertList, parseIncidentDetail, parseNormalizedAlert, parseSession } from "./contracts";
import { AI_STATUS, ALERT_PAGE, SAMPLE_AI_ANALYSIS, SAMPLE_ALERT, SAMPLE_INCIDENT, SAMPLE_SESSION } from "../test/fixtures";

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

  it("validates AI status, provenance, structured output, and history", () => {
    expect(parseAIStatus(AI_STATUS).state).toBe("AVAILABLE");
    const analysis = parseAIAnalysis(SAMPLE_AI_ANALYSIS);
    expect(analysis.schema_version).toBe("ai-analysis-v1");
    expect(analysis.result.mitre_context[0].basis).toBe("observed");
    expect(parseAIAnalysisHistory({ items: [SAMPLE_AI_ANALYSIS], limit: 20 }).items).toHaveLength(1);
  });

  it("rejects malformed AI availability, fingerprints, and result fields", () => {
    expect(() => parseAIStatus({ ...AI_STATUS, state: "READY" })).toThrow(/ai_status.state/);
    expect(() => parseAIAnalysis({ ...SAMPLE_AI_ANALYSIS, context_fingerprint: "short" })).toThrow(/context_fingerprint/);
    expect(() => parseAIAnalysis({ ...SAMPLE_AI_ANALYSIS, result: { ...SAMPLE_AI_ANALYSIS.result, uncertainties: "none" } })).toThrow(/uncertainties/);
    expect(() => parseAIAnalysis({ ...SAMPLE_AI_ANALYSIS, result: { ...SAMPLE_AI_ANALYSIS.result, mitre_context: [{ ...SAMPLE_AI_ANALYSIS.result.mitre_context[0], basis: "trusted" }] } })).toThrow(/basis/);
    expect(() => parseAIAnalysis({ ...SAMPLE_AI_ANALYSIS, result: { ...SAMPLE_AI_ANALYSIS.result, key_evidence: Array(13).fill("x") } })).toThrow(/key_evidence/);
    expect(() => parseAIAnalysis({ ...SAMPLE_AI_ANALYSIS, result: { ...SAMPLE_AI_ANALYSIS.result, summary: "x".repeat(2001) } })).toThrow(/summary/);
  });
});
