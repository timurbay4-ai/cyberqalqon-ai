import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { InvestigationWorkbenchPage } from "./investigation-workbench-page";
import type { InvestigationWorkbench } from "../types/investigation-workbench";
import { createMockApi, SAMPLE_ADVANCED_RULES, SAMPLE_EVENT } from "../test/fixtures";


const WORKBENCH: InvestigationWorkbench = {
  target_type: "M11_FINDING",
  target_label: "DET-001 dry-run finding",
  primary_event: SAMPLE_EVENT,
  summary: {
    observations: ["Observed web evidence at 2026-10-08T14:30:00Z."],
    interpretations: ["These facts support investigation but do not by themselves establish attacker intent or confirmed compromise."],
    missing_fields: ["username"],
  },
  entities: [
    { entity_type: "IPV4", value: "127.0.0.1", label: "Source IP", sensitive: true, pivot_supported: true, evidence_field: "source_ip" },
    { entity_type: "USERNAME", value: "x".repeat(512), label: "Username", sensitive: true, pivot_supported: true, evidence_field: "username" },
  ],
  related_events: [{ event: { ...SAMPLE_EVENT, event_id: "EVT-RELATED", raw_evidence_ref: undefined, structured_payload: undefined, raw_payload: undefined, related_incident_ids: undefined } as never, relationship_types: ["SAME_SOURCE_IP", "SAME_HOST"] }],
  links: [
    { target_type: "ALERT", target_id: "alert-001", title: "Alert alert-001", status: "NEW", severity: "10" },
    { target_type: "INCIDENT", target_id: "INC-001", title: "Investigation incident", status: "INVESTIGATING", severity: "HIGH" },
    { target_type: "CASE", target_id: "CASE-001", title: "SOC case", status: "OPEN", severity: "HIGH" },
  ],
  timeline: [
    { item_id: "event:1", item_type: "SECURITY_EVENT", timestamp: "2026-10-08T14:30:00Z", timestamp_kind: "EVENT_TIME", timestamp_status: "NORMAL", title: "Stored event", source_id: SAMPLE_EVENT.event_id, severity: 8, relationship_types: ["PRIMARY_EVIDENCE"], details: { rule_id: "100120" } },
    { item_id: "note:1", item_type: "ANALYST_NOTE", timestamp: "2026-10-08T14:31:00Z", timestamp_kind: "ANALYST_ACTION_TIME", timestamp_status: "NORMAL", title: "Analyst note", source_id: "INC-001", actor_display: "Analyst One", relationship_types: [], details: {} },
  ],
  ioc_matches: [{ indicator_id: "IOC-1", indicator_type: "IPV4", value: "127.0.0.1", source: "Local review", confidence: 80, evidence_field: "source_ip", caveat: "IOC_MATCH_IS_NOT_PROOF_OF_COMPROMISE" }],
  correlation_groups: [{ group_id: "grp-1", correlation_rule: "CORR-001", classification: "credential activity", confidence: "EXACT_MATCH", grouping_keys: { source_identity: "127.0.0.1", target_identity: "001" }, first_seen: "2026-10-08T14:29:00Z", last_seen: "2026-10-08T14:31:00Z", evidence_count: 2, explanation: "Two alerts shared the exact source and agent.", incident_id: "INC-001" }],
  detection_context: {
    rule: SAMPLE_ADVANCED_RULES[0],
    finding: { finding_id: "FND-1", rule_id: "DET-001", severity: 10, first_event_at: "2026-10-08T14:29:00Z", last_event_at: "2026-10-08T14:30:00Z", group: { hostname: "win-lab", username: "alice" }, matched_event_count: 5, threshold: 5, event_ids: [SAMPLE_EVENT.event_id], explanation: "Five failures for one host, user and source met the threshold.", evidence: [{ event_id: SAMPLE_EVENT.event_id, timestamp: "2026-10-08T14:30:00Z", summary: "4625 failure" }], deduplication_key: "A".repeat(64), mitre_ids: ["T1110.001"] },
    evaluated_event_count: 5,
    execution_budget_ms: 1000,
    source_kind: "HISTORICAL_DRY_RUN",
    side_effects: false,
  },
  query: { start_time: "2026-10-08T00:00:00Z", end_time: "2026-10-09T00:00:00Z", related_limit: 50, related_next_cursor: "opaque-page-2", timeline_limit: 150, sort: "oldest", execution_ms: 2.5, related_truncated: true, schema_version: 17, unavailable_relationships: [] },
};

const target = { target_type: "M11_FINDING" as const, rule_id: "DET-001", finding_key: "A".repeat(64), relative_minutes: 1440 };

function renderPage(overrides: { response?: InvestigationWorkbench; canMutate?: boolean } = {}) {
  const onTargetChange = vi.fn();
  const onOpenEvent = vi.fn();
  const onOpenAlert = vi.fn();
  const onOpenIncident = vi.fn();
  const onOpenCase = vi.fn();
  const api = createMockApi({ getInvestigationWorkbench: vi.fn().mockResolvedValue(overrides.response ?? WORKBENCH) });
  render(<InvestigationWorkbenchPage api={api} target={target} canMutate={overrides.canMutate ?? true} onTargetChange={onTargetChange} onOpenEvent={onOpenEvent} onOpenAlert={onOpenAlert} onOpenIncident={onOpenIncident} onOpenCase={onOpenCase} onOpenRule={vi.fn()} onReturn={vi.fn()} />);
  return { api, onTargetChange, onOpenEvent, onOpenAlert, onOpenIncident, onOpenCase };
}

describe("InvestigationWorkbenchPage", () => {
  it("renders deterministic summary, detection explanation, relationships and context", async () => {
    renderPage();
    expect(await screen.findByRole("heading", { name: "DET-001 dry-run finding" })).toBeInTheDocument();
    expect(screen.getByText(/do not by themselves establish attacker intent/i)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Why this finding matched" })).toBeInTheDocument();
    expect(screen.getByText(/Five failures for one host/i)).toBeInTheDocument();
    expect(screen.getByText("Same source ip")).toBeInTheDocument();
    expect(screen.getByText(/IOC context/i)).toBeInTheDocument();
    expect(screen.getByText(/not proof of compromise/i)).toBeInTheDocument();
    expect(screen.getByText(/CORR-001/)).toBeInTheDocument();
    expect(screen.getByText("Unavailable fields:")).toBeInTheDocument();
    expect(screen.queryByRole("script")).not.toBeInTheDocument();
  });

  it("keeps sensitive entity values in application state and opens related evidence", async () => {
    const { onTargetChange } = renderPage();
    await screen.findByRole("heading", { name: "Evidence-backed pivots" });
    fireEvent.click(screen.getAllByRole("button", { name: /Source IP/i })[0]);
    expect(onTargetChange).toHaveBeenCalledWith(expect.objectContaining({ target_type: "ENTITY", entity_type: "IPV4", entity_value: "127.0.0.1" }));
    expect(window.location.href).not.toContain("127.0.0.1");
    fireEvent.click(screen.getByRole("button", { name: "Investigate" }));
    expect(onTargetChange).toHaveBeenLastCalledWith(expect.objectContaining({ target_type: "EVENT", target_id: "EVT-RELATED" }));
  });

  it("paginates related evidence through history state without URL cursor leakage", async () => {
    const { onTargetChange } = renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Next related page" }));
    expect(onTargetChange).toHaveBeenCalledWith(expect.objectContaining({
      start_time: WORKBENCH.query.start_time,
      end_time: WORKBENCH.query.end_time,
      relative_minutes: null,
      related_cursor: "opaque-page-2",
    }));
    expect(window.location.href).not.toContain("opaque-page-2");
    expect(screen.getByRole("button", { name: "Previous related page" })).toBeDisabled();
  });

  it("filters, expands and sorts the unified timeline without merging equal records", async () => {
    const { api } = renderPage();
    await screen.findByRole("heading", { name: "Evidence and analyst activity" });
    fireEvent.change(screen.getByLabelText("Type"), { target: { value: "ANALYST_NOTE" } });
    expect(screen.queryByText("Stored event")).not.toBeInTheDocument();
    expect(screen.getAllByText("Analyst note").length).toBeGreaterThan(1);
    fireEvent.click(screen.getByRole("button", { name: "Expand all" }));
    expect(screen.getByText(/Analyst action time/i)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Type"), { target: { value: "ALL" } });
    fireEvent.change(screen.getByLabelText("From"), { target: { value: "2026-10-08T23:59" } });
    await waitFor(() => expect(screen.queryByText("Stored event")).not.toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Clear time filter" }));
    expect(screen.getAllByText("Stored event").length).toBeGreaterThan(0);
    fireEvent.change(screen.getByLabelText("Order"), { target: { value: "newest" } });
    await waitFor(() => expect(api.getInvestigationWorkbench).toHaveBeenLastCalledWith(expect.objectContaining({ sort: "newest" }), expect.any(AbortSignal)));
  });

  it("exposes authorized existing evidence pinning and hides it from read-only analysts", async () => {
    const { api } = renderPage();
    const pin = await screen.findByRole("button", { name: "Pin to INC-001" });
    fireEvent.click(pin);
    await waitFor(() => expect(api.pinEvidence).toHaveBeenCalledWith("INC-001", expect.objectContaining({ evidence_type: "EVENT", evidence_id: SAMPLE_EVENT.event_id })));
    fireEvent.change(screen.getByLabelText("Incident note"), { target: { value: "Reviewed in M12." } });
    fireEvent.click(screen.getByRole("button", { name: "Add note to INC-001" }));
    await waitFor(() => expect(api.addIncidentNote).toHaveBeenCalledWith("INC-001", { body: "Reviewed in M12." }));
    await screen.findByRole("heading", { name: "DET-001 dry-run finding" });
    fireEvent.change(screen.getByLabelText("Existing case ID"), { target: { value: "CASE-001" } });
    fireEvent.click(screen.getByRole("button", { name: "Associate event with case" }));
    await waitFor(() => expect(api.linkCaseReference).toHaveBeenCalledWith("CASE-001", "event", SAMPLE_EVENT.event_id, 1));
    document.body.innerHTML = "";
    renderPage({ canMutate: false });
    await screen.findByRole("heading", { name: "DET-001 dry-run finding" });
    expect(screen.queryByRole("button", { name: "Pin to INC-001" })).not.toBeInTheDocument();
  });

  it("renders loading, empty-target and bounded errors honestly", async () => {
    const never = new Promise<InvestigationWorkbench>(() => undefined);
    const api = createMockApi({ getInvestigationWorkbench: vi.fn().mockReturnValue(never) });
    const common = { api, canMutate: false, onTargetChange: vi.fn(), onOpenEvent: vi.fn(), onOpenAlert: vi.fn(), onOpenIncident: vi.fn(), onOpenCase: vi.fn(), onOpenRule: vi.fn(), onReturn: vi.fn() };
    const { rerender } = render(<InvestigationWorkbenchPage {...common} target={target} />);
    expect(screen.getByRole("status")).toHaveTextContent("Building bounded context");
    rerender(<InvestigationWorkbenchPage {...common} target={null} />);
    expect(screen.getByText("No investigation target")).toBeInTheDocument();
    rerender(<InvestigationWorkbenchPage {...common} target={target} api={createMockApi({ getInvestigationWorkbench: vi.fn().mockRejectedValue(new Error("Permission denied")) })} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Permission denied");
  });
});
