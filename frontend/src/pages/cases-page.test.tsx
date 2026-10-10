import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { CasesPage } from "./cases-page";
import { CASE_PAGE, SAMPLE_CASE, createMockApi } from "../test/fixtures";


describe("CasesPage", () => {
  it("lists, filters, deep-links, and opens durable case detail", async () => {
    const api = createMockApi();
    const openAlert = vi.fn();
    render(<CasesPage api={api} canMutate openCaseId={null} onOpenAlert={openAlert} onOpenIncident={vi.fn()} onOpenEvent={vi.fn()} />);

    expect(await screen.findByText("Suspicious authentication case")).toBeInTheDocument();
    expect(screen.getByText("Response overdue")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Search cases"), { target: { value: "CASE-001" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply search" }));
    await waitFor(() => expect(api.listCases).toHaveBeenCalledWith(expect.objectContaining({ search: "CASE-001" }), expect.any(AbortSignal)));

    fireEvent.click(screen.getByRole("button", { name: /Suspicious authentication case/ }));
    expect(await screen.findByRole("complementary", { name: "Case CASE-001" })).toBeInTheDocument();
    expect(screen.getByText(/Application-level SHA-256/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Alert alert-001" }));
    expect(openAlert).toHaveBeenCalledWith("alert-001");
    expect(window.location.search).toContain("case=CASE-001");
  });

  it("creates a case only through the explicit create action", async () => {
    const createCase = vi.fn().mockResolvedValue(SAMPLE_CASE);
    const api = createMockApi({ createCase });
    render(<CasesPage api={api} canMutate onOpenAlert={vi.fn()} onOpenIncident={vi.fn()} onOpenEvent={vi.fn()} />);

    await screen.findByText("Suspicious authentication case");
    fireEvent.click(screen.getByRole("button", { name: "Create case" }));
    fireEvent.change(screen.getByLabelText("Title"), { target: { value: "Manual investigation" } });
    fireEvent.click(screen.getAllByRole("button", { name: "Create case" })[1]);
    await waitFor(() => expect(createCase).toHaveBeenCalledWith(expect.objectContaining({ title: "Manual investigation", source_type: "MANUAL", source_id: null })));
  });

  it("renders a read-only workspace without mutation controls", async () => {
    const api = createMockApi({ listCases: vi.fn().mockResolvedValue(CASE_PAGE) });
    render(<CasesPage api={api} canMutate={false} openCaseId="CASE-001" onOpenAlert={vi.fn()} onOpenIncident={vi.fn()} onOpenEvent={vi.fn()} />);

    expect(await screen.findByText("Your role can read cases but cannot change or export them.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create case" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Export PDF" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Add comment" })).not.toBeInTheDocument();
  });
});
