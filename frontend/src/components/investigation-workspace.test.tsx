import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { SAMPLE_INVESTIGATION, SAMPLE_INVESTIGATION_TIMELINE, createMockApi } from "../test/fixtures";
import { InvestigationWorkspace } from "./investigation-workspace";


describe("InvestigationWorkspace", () => {
  it("uses persisted checklist versions and pins immutable evidence references", async () => {
    const api = createMockApi();
    render(<InvestigationWorkspace api={api} incidentId="INC-001" canMutate onOpenAlert={() => undefined} onOpenEvent={() => undefined} />);
    expect(await screen.findByText("0 of 1 complete")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("checkbox", { name: "Open" }));
    await waitFor(() => expect(api.updateChecklistItem).toHaveBeenCalledWith(
      "INC-001", "CHK-1", { is_completed: true, expected_version: 1 },
    ));

    fireEvent.change(screen.getByLabelText("Evidence type"), { target: { value: "ALERT" } });
    fireEvent.change(screen.getByLabelText("Immutable evidence ID"), { target: { value: "alert-001" } });
    fireEvent.change(screen.getByLabelText("Annotation"), { target: { value: "Confirm scope" } });
    fireEvent.click(screen.getByRole("button", { name: "Pin evidence" }));
    await waitFor(() => expect(api.pinEvidence).toHaveBeenCalledWith("INC-001", {
      evidence_type: "ALERT", evidence_id: "alert-001", annotation: "Confirm scope",
    }));
  });

  it("shows persisted state read-only to viewers", async () => {
    const api = createMockApi({ getInvestigation: vi.fn().mockResolvedValue(SAMPLE_INVESTIGATION) });
    render(<InvestigationWorkspace api={api} incidentId="INC-001" canMutate={false} onOpenAlert={() => undefined} onOpenEvent={() => undefined} />);
    expect(await screen.findByDisplayValue("Validate the source host")).toHaveAttribute("readonly");
    expect(screen.queryByRole("button", { name: "Add item" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Pin evidence" })).not.toBeInTheDocument();
  });

  it("renders honest empty states and recovers from a backend failure", async () => {
    const empty = {
      ...SAMPLE_INVESTIGATION,
      checklist_items: [], evidence_pins: [], checklist_completed: 0, checklist_total: 0,
    };
    const api = createMockApi({
      getInvestigation: vi.fn().mockRejectedValueOnce(new Error("backend offline")).mockResolvedValue(empty),
      getInvestigationTimeline: vi.fn().mockResolvedValue({
        ...SAMPLE_INVESTIGATION_TIMELINE, items: [], total: 0, next_cursor: null,
      }),
    });
    render(<InvestigationWorkspace api={api} incidentId="INC-001" canMutate onOpenAlert={() => undefined} onOpenEvent={() => undefined} />);

    expect(await screen.findByText("backend offline")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("No checklist items yet.")).toBeInTheDocument();
    expect(screen.getByText("No evidence pinned.")).toBeInTheDocument();
    expect(screen.getByText("No investigation activity.")).toBeInTheDocument();
  });

  it("exposes keyboard-operable reorder controls with current item versions", async () => {
    const second = {
      ...SAMPLE_INVESTIGATION.checklist_items[0],
      checklist_item_id: "CHK-2", body: "Collect volatile evidence", position: 1,
    };
    const workspace = {
      ...SAMPLE_INVESTIGATION,
      checklist_items: [SAMPLE_INVESTIGATION.checklist_items[0], second],
      checklist_total: 2,
    };
    const api = createMockApi({ getInvestigation: vi.fn().mockResolvedValue(workspace) });
    render(<InvestigationWorkspace api={api} incidentId="INC-001" canMutate onOpenAlert={() => undefined} onOpenEvent={() => undefined} />);
    await screen.findByText("0 of 2 complete");

    fireEvent.click(screen.getByRole("button", { name: "Move Collect volatile evidence up" }));
    await waitFor(() => expect(api.reorderChecklist).toHaveBeenCalledWith("INC-001", {
      items: [
        { checklist_item_id: "CHK-2", expected_version: 1 },
        { checklist_item_id: "CHK-1", expected_version: 1 },
      ],
    }));
  });
});
