import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ApiError } from "../api/client";
import { IncidentsPage } from "./incidents-page";
import { SAMPLE_INCIDENT, createMockApi } from "../test/fixtures";
import type { IncidentDetail } from "../types/incidents";

async function openIncident() {
  fireEvent.click(await screen.findByRole("button", { name: "<script>incidentAttack()</script>" }));
  return screen.findByRole("complementary", { name: "Incident detail" });
}

describe("IncidentsPage", () => {
  it("renders explainable automatic correlation and chronological alert evidence", async () => {
    const correlated: IncidentDetail = {
      ...SAMPLE_INCIDENT,
      auto_correlated: true,
      correlation_rule: "CORR-001",
      classification: "MULTI_STAGE_RECONNAISSANCE",
      correlation: {
        correlation_rule: "CORR-001",
        classification: "MULTI_STAGE_RECONNAISSANCE",
        confidence: "EXACT_MATCH",
        source_identity: "agent:001|source:127.0.0.1",
        target_identity: "agent:001|destination:127.0.0.1",
        explanation: "Three deterministic stages matched; this is not confirmation of compromise.",
        first_seen: "2026-10-06T10:00:00Z",
        last_seen: "2026-10-06T10:02:00Z",
        related_alert_count: 3,
      },
      timeline: [
        { ...SAMPLE_INCIDENT.timeline[0], alert_id: "scan", rule_id: "100111", rule_description: "TCP port scan", source_ip: "127.0.0.1", mitre_ids: ["T1046"] },
        { ...SAMPLE_INCIDENT.timeline[0], alert_id: "enum", rule_id: "100101", rule_description: "Directory enumeration", occurred_at: "2026-10-06T10:01:00Z", source_ip: "127.0.0.1" },
        { ...SAMPLE_INCIDENT.timeline[0], alert_id: "probe", rule_id: "100120", rule_description: "Sensitive path probe", occurred_at: "2026-10-06T10:02:00Z", source_ip: "127.0.0.1" },
      ],
    };
    const api = createMockApi({
      listIncidents: vi.fn().mockResolvedValue({ items: [correlated], page: { limit: 25, next_cursor: null, total: 1 } }),
      getIncident: vi.fn().mockResolvedValue(correlated),
    });
    render(<IncidentsPage api={api} />);
    fireEvent.click(await screen.findByRole("button", { name: correlated.title }));
    const detail = await screen.findByRole("complementary", { name: "Incident detail" });
    expect(within(detail).getByRole("region", { name: "Correlation summary" })).toHaveTextContent("CORR-001");
    expect(within(detail).getByText("MITRE ATT&CK: T1046")).toBeInTheDocument();
    expect(within(detail).getByRole("button", { name: "Open alert scan" })).toBeInTheDocument();
    expect(within(detail).getAllByRole("listitem").map((item) => item.textContent).join(" ")).toContain("TCP port scan");
  });

  it("renders incident content as inert text and exposes only valid next statuses", async () => {
    const api = createMockApi();
    const { container } = render(<IncidentsPage api={api} />);
    const detail = await openIncident();

    expect(within(detail).getByText("<script>incidentAttack()</script>")).toBeInTheDocument();
    expect(within(detail).getByText("<img src=x onerror=attack()>")).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    const transition = within(detail).getByLabelText("Allowed transition");
    expect(within(transition).getByRole("option", { name: "Triaged" })).toBeInTheDocument();
    expect(within(transition).getByRole("option", { name: "False positive" })).toBeInTheDocument();
    expect(within(transition).queryByRole("option", { name: "Resolved" })).not.toBeInTheDocument();
  });

  it("surfaces a backend lifecycle conflict without pretending success", async () => {
    const updateIncidentStatus = vi.fn().mockRejectedValue(new ApiError("Transition rejected", 409, "invalid_status_transition", "status"));
    const api = createMockApi({ updateIncidentStatus });
    const detail = await (async () => { render(<IncidentsPage api={api} />); return openIncident(); })();

    fireEvent.click(within(detail).getByRole("button", { name: "Update status" }));

    expect(await within(detail).findByText("Transition rejected [invalid_status_transition]")).toBeInTheDocument();
    expect(within(detail).queryByText("Status changed to TRIAGED.")).not.toBeInTheDocument();
  });

  it("surfaces a backend authorization failure without pretending success", async () => {
    const updateIncidentStatus = vi.fn().mockRejectedValue(new ApiError("Permission denied", 403, "permission_denied"));
    const api = createMockApi({ updateIncidentStatus });
    render(<IncidentsPage api={api} />);
    const detail = await openIncident();
    fireEvent.click(within(detail).getByRole("button", { name: "Update status" }));
    expect(await within(detail).findByText("Permission denied [permission_denied]")).toBeInTheDocument();
    expect(within(detail).queryByText("Status changed to TRIAGED.")).not.toBeInTheDocument();
  });

  it("does not let a late mutation response replace a newly selected incident", async () => {
    const secondIncident: IncidentDetail = {
      ...SAMPLE_INCIDENT,
      incident_id: "INC-002",
      title: "Second incident",
    };
    let resolveUpdate!: (incident: IncidentDetail) => void;
    const updatePromise = new Promise<IncidentDetail>((resolve) => { resolveUpdate = resolve; });
    const api = createMockApi({
      listIncidents: vi.fn().mockResolvedValue({
        items: [SAMPLE_INCIDENT, secondIncident],
        page: { limit: 25, next_cursor: null, total: 2 },
      }),
      getIncident: vi.fn().mockImplementation((incidentId: string) => Promise.resolve(
        incidentId === secondIncident.incident_id ? secondIncident : SAMPLE_INCIDENT,
      )),
      updateIncidentStatus: vi.fn().mockReturnValue(updatePromise),
    });
    render(<IncidentsPage api={api} />);
    const firstDetail = await openIncident();
    fireEvent.click(within(firstDetail).getByRole("button", { name: "Update status" }));
    await waitFor(() => expect(api.updateIncidentStatus).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: "Second incident" }));
    expect(await screen.findByRole("heading", { name: "Second incident" })).toBeInTheDocument();
    await act(async () => {
      resolveUpdate({ ...SAMPLE_INCIDENT, status: "TRIAGED" });
      await updatePromise;
    });

    const currentDetail = screen.getByRole("complementary", { name: "Incident detail" });
    expect(within(currentDetail).getByRole("heading", { name: "Second incident" })).toBeInTheDocument();
  });

  it("submits notes and assignment through the typed API boundary", async () => {
    const api = createMockApi();
    render(<IncidentsPage api={api} />);
    const detail = await openIncident();
    fireEvent.change(within(detail).getByLabelText("Analyst identifier"), { target: { value: "analyst-2" } });
    fireEvent.click(within(detail).getByRole("button", { name: "Save assignment" }));
    await waitFor(() => expect(api.updateIncidentAssignment).toHaveBeenCalledWith("INC-001", { assigned_to: "analyst-2" }));

    fireEvent.change(within(detail).getByLabelText("New note"), { target: { value: "Containment completed." } });
    fireEvent.click(within(detail).getByRole("button", { name: "Add note" }));
    await waitFor(() => expect(api.addIncidentNote).toHaveBeenCalledWith("INC-001", { body: "Containment completed." }));
  });

  it("creates an incident without a caller-controlled actor field", async () => {
    const createIncident = vi.fn().mockResolvedValue(SAMPLE_INCIDENT);
    const api = createMockApi({ createIncident });
    render(<IncidentsPage api={api} />);
    await screen.findByText("<script>incidentAttack()</script>");

    fireEvent.click(screen.getByRole("button", { name: "Create incident" }));
    const form = screen.getByRole("region", { name: "Create incident" });
    fireEvent.change(within(form).getByLabelText("Title"), { target: { value: "Investigate host" } });
    fireEvent.change(within(form).getByLabelText("Severity"), { target: { value: "CRITICAL" } });
    fireEvent.click(within(form).getByRole("button", { name: "Create incident" }));

    await waitFor(() => expect(createIncident).toHaveBeenCalledWith(expect.objectContaining({ title: "Investigate host", severity: "CRITICAL" })));
    expect(createIncident.mock.calls[0][0]).not.toHaveProperty("actor");
  });

  it("hides every mutation control for viewers", async () => {
    const api = createMockApi();
    render(<IncidentsPage api={api} canMutate={false} />);
    const detail = await openIncident();
    expect(screen.queryByRole("button", { name: "Create incident" })).not.toBeInTheDocument();
    expect(within(detail).getByText("Your Viewer role cannot modify incidents.")).toBeInTheDocument();
    expect(within(detail).queryByRole("button", { name: "Update status" })).not.toBeInTheDocument();
    expect(within(detail).queryByLabelText(/Audit actor/)).not.toBeInTheDocument();
  });

  it("shows an empty incident queue", async () => {
    const api = createMockApi({ listIncidents: vi.fn().mockResolvedValue({ items: [], page: { limit: 25, next_cursor: null, total: 0 } }) });
    render(<IncidentsPage api={api} />);
    expect(await screen.findByText("No matching incidents")).toBeInTheDocument();
  });
});
