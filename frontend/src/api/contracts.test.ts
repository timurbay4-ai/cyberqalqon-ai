import { describe, expect, it } from "vitest";

import { ContractError, parseAIAnalysis, parseAIAnalysisHistory, parseAIStatus, parseAlertList, parseDetectionRules, parseHosts, parseIncidentDetail, parseLogSources, parseNormalizedAlert, parseSecurityActivityReport, parseSecurityEventList, parseSession } from "./contracts";
import { AI_STATUS, ALERT_PAGE, SAMPLE_AI_ANALYSIS, SAMPLE_ALERT, SAMPLE_EVENT, SAMPLE_HOSTS, SAMPLE_INCIDENT, SAMPLE_REPORT, SAMPLE_RULES, SAMPLE_SESSION, SAMPLE_SOURCES } from "../test/fixtures";

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

  it("treats an omitted final-page cursor as null", () => {
    const parsed = parseSecurityEventList({
      items: [SAMPLE_EVENT],
      page: { limit: 50, total: 1, sort: "newest" },
    });
    expect(parsed.page.next_cursor).toBeNull();
  });

  it("rejects unexpected severity values", () => {
    expect(() => parseIncidentDetail({ ...SAMPLE_INCIDENT, severity: "URGENT" })).toThrow(/incident.severity/);
  });

  it("parses the complete incident detail contract", () => {
    const parsed = parseIncidentDetail(SAMPLE_INCIDENT);
    expect(parsed.status).toBe("NEW");
    expect(parsed.notes[0].body).toContain("onerror");
    expect(parsed.history[0].event_type).toBe("CREATED");
    expect(parsed.timeline[0].alert_id).toBe("alert-001");
    expect(parsed.correlation).toBeNull();
  });

  it("parses typed Windows Event Channel identity", () => {
    const parsed = parseNormalizedAlert({
      ...SAMPLE_ALERT,
      user: "cq-m10-synthetic",
      windows: {
        event_id: "4625",
        channel: "Security",
        provider: "Microsoft-Windows-Security-Auditing",
        computer: "WIN-392LNNLLAT3",
      },
    });
    expect(parsed.windows?.event_id).toBe("4625");
    expect(parsed.windows?.provider).toBe("Microsoft-Windows-Security-Auditing");
  });

  it("validates authenticated roles and permissions", () => {
    expect(parseSession(SAMPLE_SESSION).analyst.role).toBe("ANALYST");
    expect(() => parseSession({ ...SAMPLE_SESSION, analyst: { ...SAMPLE_SESSION.analyst, role: "ROOT" } })).toThrow(/session.analyst.role/);
    expect(() => parseSession({ ...SAMPLE_SESSION, analyst: { ...SAMPLE_SESSION.analyst, permissions: ["everything"] } })).toThrow(/session.analyst.permissions/);
  });

  it("validates inventory, read-only rules, and report contracts", () => {
    expect(parseHosts(SAMPLE_HOSTS)[0].agent_status).toBe("UNKNOWN");
    expect(parseLogSources(SAMPLE_SOURCES)[0].source_health).toBe("ACTIVE");
    expect(parseDetectionRules(SAMPLE_RULES)[0].editable).toBe(false);
    expect(parseSecurityActivityReport(SAMPLE_REPORT).total_events).toBe(12);
    expect(() => parseDetectionRules([{ ...SAMPLE_RULES[0], editable: true }])).toThrow(/editable/);
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
