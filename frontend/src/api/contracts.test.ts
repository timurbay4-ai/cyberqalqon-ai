import { describe, expect, it } from "vitest";

import { ContractError, parseAdvancedDetectionRules, parseAgentDetail, parseAgentList, parseAIAnalysis, parseAIAnalysisHistory, parseAIStatus, parseAlertList, parseCanarySafety, parseDetectionConfigurations, parseDetectionDiagnostics, parseDetectionQuality, parseDetectionRuleLifecycle, parseDetectionRules, parseHosts, parseIncidentDetail, parseInvestigationWorkbench, parseLogSources, parseNormalizedAlert, parseOperationalOverview, parseSecurityActivityReport, parseSecurityEventList, parseSession, parseShadowRunDetail, parseTelemetryPrerequisite, parseTuningComparison, parseWazuhIntegrationStatus } from "./contracts";
import { AI_STATUS, ALERT_PAGE, OPERATIONAL_OVERVIEW, SAMPLE_ADVANCED_RULES, SAMPLE_AGENT, SAMPLE_AGENT_LIST, SAMPLE_AI_ANALYSIS, SAMPLE_ALERT, SAMPLE_CANARY_SAFETY, SAMPLE_DETECTION_CONFIGURATION, SAMPLE_DETECTION_DIAGNOSTICS, SAMPLE_DETECTION_LIFECYCLE, SAMPLE_DETECTION_QUALITY, SAMPLE_EVENT, SAMPLE_HOSTS, SAMPLE_INCIDENT, SAMPLE_REPORT, SAMPLE_RULES, SAMPLE_SESSION, SAMPLE_SHADOW_DETAIL, SAMPLE_SOURCES, SAMPLE_TELEMETRY_READINESS, SAMPLE_TUNING_COMPARISON, SAMPLE_WORKBENCH, WAZUH_INTEGRATION_STATUS } from "../test/fixtures";

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
        computer: "WIN-TEST-HOST",
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

  it("validates M11 disabled state and telemetry prerequisites", () => {
    const parsed = parseAdvancedDetectionRules(SAMPLE_ADVANCED_RULES);
    expect(parsed[0].activation_state).toBe("DISABLED_BY_POLICY");
    expect(parsed[0].availability?.status).toBe("RECENTLY_OBSERVED");
    expect(() => parseAdvancedDetectionRules([{ ...SAMPLE_ADVANCED_RULES[0], enabled: true }])).toThrow(/activation_state/);
    expect(() => parseAdvancedDetectionRules([{ ...SAMPLE_ADVANCED_RULES[0], availability: { ...SAMPLE_ADVANCED_RULES[0].availability, status: "ASSUMED" } }])).toThrow(/status/);
  });

  it("validates M14 lifecycle, shadow isolation, tuning, readiness, and diagnostics", () => {
    expect(parseDetectionRuleLifecycle(SAMPLE_DETECTION_LIFECYCLE).runtime_activation_state).toBe("DISABLED_BY_POLICY");
    expect(parseDetectionConfigurations([SAMPLE_DETECTION_CONFIGURATION])[0].state_schema_version).toBe(1);
    expect(parseTelemetryPrerequisite(SAMPLE_TELEMETRY_READINESS).status).toBe("READY");
    expect(parseDetectionDiagnostics(SAMPLE_DETECTION_DIAGNOSTICS).state_recovery_count).toBe(1);
    expect(parseShadowRunDetail(SAMPLE_SHADOW_DETAIL).run.side_effects).toBe(false);
    expect(parseTuningComparison(SAMPLE_TUNING_COMPARISON).results).toHaveLength(2);
    expect(parseCanarySafety(SAMPLE_CANARY_SAFETY).activation_path_enabled).toBe(false);
    expect(() => parseDetectionRuleLifecycle({ ...SAMPLE_DETECTION_LIFECYCLE, runtime_activation_state: "ACTIVE" })).toThrow(/runtime_activation_state/);
    expect(() => parseShadowRunDetail({ ...SAMPLE_SHADOW_DETAIL, run: { ...SAMPLE_SHADOW_DETAIL.run, side_effects: true } })).toThrow(/side_effects/);
    expect(() => parseCanarySafety({ ...SAMPLE_CANARY_SAFETY, activation_path_enabled: true })).toThrow(/activation_boundary/);
  });

  it("validates M15 synthetic-only quality and activation safety", () => {
    expect(parseDetectionQuality(SAMPLE_DETECTION_QUALITY).all_applicable_fixtures_passed).toBe(true);
    expect(() => parseDetectionQuality({ ...SAMPLE_DETECTION_QUALITY, runtime_activation_state: "ACTIVE" })).toThrow(/safety/);
    expect(() => parseDetectionQuality({ ...SAMPLE_DETECTION_QUALITY, fixtures: SAMPLE_DETECTION_QUALITY.fixtures.slice(0, 8) })).toThrow(/fixtures/);
  });

  it("validates authoritative agent and integration contracts", () => {
    expect(parseAgentList(SAMPLE_AGENT_LIST).items[0].connection_status).toBe("ONLINE");
    expect(parseAgentDetail(SAMPLE_AGENT).status_authority).toBe("WAZUH_API");
    expect(parseWazuhIntegrationStatus(WAZUH_INTEGRATION_STATUS).read_only).toBe(true);
    expect(() => parseAgentList({ ...SAMPLE_AGENT_LIST, items: [{ ...SAMPLE_AGENT, connection_status: "FRESH" }] })).toThrow(/connection_status/);
    expect(() => parseWazuhIntegrationStatus({ ...WAZUH_INTEGRATION_STATUS, read_only: false })).toThrow(/security/);
  });

  it("preserves signed forward lag while rejecting non-finite rates", () => {
    const forward = {
      ...OPERATIONAL_OVERVIEW.forward_ingestion!,
      net_lag_bytes_per_second: -7.5,
      net_backlog_trend: "DRAINING",
      rate_measurement_state: "FRESH",
    };
    expect(parseOperationalOverview({ ...OPERATIONAL_OVERVIEW, forward_ingestion: forward }).forward_ingestion?.net_lag_bytes_per_second).toBe(-7.5);
    expect(() => parseOperationalOverview({
      ...OPERATIONAL_OVERVIEW,
      forward_ingestion: { ...forward, net_lag_bytes_per_second: Number.POSITIVE_INFINITY },
    })).toThrow(/net_lag_bytes_per_second/);
  });

  it("validates bounded operational-query measurement evidence", () => {
    const overview = parseOperationalOverview(OPERATIONAL_OVERVIEW);
    expect(overview.measurement.state).toBe("FRESH");
    expect(overview.measurement.execution_model).toBe("BOUNDED_THREADPOOL");
    expect(parseOperationalOverview({
      ...OPERATIONAL_OVERVIEW,
      measurement: { ...OPERATIONAL_OVERVIEW.measurement, state: "STALE" },
    }).measurement.state).toBe("STALE");
    expect(() => parseOperationalOverview({
      ...OPERATIONAL_OVERVIEW,
      measurement: { ...OPERATIONAL_OVERVIEW.measurement, state: "EXPIRED" },
    })).toThrow(/measurement.state/);
    expect(() => parseOperationalOverview({
      ...OPERATIONAL_OVERVIEW,
      measurement: { ...OPERATIONAL_OVERVIEW.measurement, duration_ms: Number.NaN },
    })).toThrow(/measurement.duration_ms/);
  });

  it("keeps the M23 Operations response readable during a backend rollback", () => {
    const {
      stale_ttl_seconds: _staleTtl,
      query_deadline_seconds: _deadline,
      reason_code: _reason,
      cache_hits: _hits,
      cache_misses: _misses,
      singleflight_joins: _joins,
      stale_served: _stale,
      inflight_queries: _inflight,
      pending_waiters: _waiters,
      ...legacyMeasurement
    } = OPERATIONAL_OVERVIEW.measurement;
    const {
      total_events_scope: _totalScope,
      total_events_measurement: _totalMeasurement,
      field_completeness_measurement: _fieldMeasurement,
      field_completeness_reason: _fieldReason,
      duplicate_events_scope: _duplicateScope,
      shipper_counters_scope: _shipperScope,
      ...legacyQuality
    } = OPERATIONAL_OVERVIEW.data_quality;
    const parsed = parseOperationalOverview({
      ...OPERATIONAL_OVERVIEW,
      measurement: legacyMeasurement,
      data_quality: { ...legacyQuality, raw_evidence_records: 2672 },
    });
    expect(parsed.measurement.reason_code).toBe("COMPUTED");
    expect(parsed.data_quality.field_completeness_measurement).toBe("EXACT");
    expect(parsed.data_quality.field_completeness_reason).toBe("LEGACY_LIVE_FULL_SCAN");
  });

  it("keeps approval validity and expiry evidence typed", () => {
    const forward = {
      ...OPERATIONAL_OVERVIEW.forward_ingestion,
      approval_state: "VALID" as const,
      approval_validation_basis: "BOUNDED_SCOPE_TIME_IDENTITY" as const,
      approval_expires_at: "2026-10-21T04:17:44+05:00",
      approval_remaining_seconds: 3600,
      checkpoint_updated_at: "2026-10-20T22:00:00+05:00",
    };
    const parsed = parseOperationalOverview({
      ...OPERATIONAL_OVERVIEW,
      forward_ingestion: forward,
    }).forward_ingestion;
    expect(parsed.approval_state).toBe("VALID");
    expect(parsed.approval_validation_basis).toBe("BOUNDED_SCOPE_TIME_IDENTITY");
    expect(parsed.approval_remaining_seconds).toBe(3600);
    expect(() => parseOperationalOverview({
      ...OPERATIONAL_OVERVIEW,
      forward_ingestion: { ...forward, approval_state: "AUTO_RENEWED" },
    })).toThrow(/approval_state/);
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

  it("validates the bounded read-only investigation workbench contract", () => {
    expect(parseInvestigationWorkbench(SAMPLE_WORKBENCH).primary_event.event_id).toBe(SAMPLE_EVENT.event_id);
    expect(() => parseInvestigationWorkbench({
      ...SAMPLE_WORKBENCH,
      timeline: Array(201).fill({}),
    })).toThrow(/workbench.timeline/);
    expect(() => parseInvestigationWorkbench({
      ...SAMPLE_WORKBENCH,
      detection_context: {
        rule: SAMPLE_ADVANCED_RULES[0],
        finding: {},
        evaluated_event_count: 1,
        execution_budget_ms: 1000,
        side_effects: true,
      },
    })).toThrow(/side_effects/);
  });
});
