import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { OperationsPage } from "./operations-page";
import { createMockApi, OPERATIONAL_OVERVIEW } from "../test/fixtures";


describe("OperationsPage", () => {
  it("labels unavailable authoritative inventory and opens component evidence", async () => {
    const navigate = vi.fn();
    render(<OperationsPage api={createMockApi()} onNavigate={navigate} />);

    expect(await screen.findByText(/Agent connectivity is authoritative only/)).toBeInTheDocument();
    expect(screen.getByText(OPERATIONAL_OVERVIEW.wazuh_inventory.reason)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Wazuh-manager-runtime/ }));
    const detail = screen.getByRole("complementary", { name: "Component diagnostics" });
    expect(within(detail).getByText("OS_SERVICE_MANAGER")).toBeInTheDocument();
    expect(within(detail).getByRole("button", { name: "Copy component ID" })).toBeEnabled();
  });

  it("links evidence cards to meaningful diagnostics", async () => {
    const navigate = vi.fn();
    render(<OperationsPage api={createMockApi()} onNavigate={navigate} />);
    await screen.findByText(/Agent connectivity is authoritative only/);

    fireEvent.click(screen.getByRole("button", { name: /Wazuh inventory/ }));
    expect(navigate).toHaveBeenCalledWith("hosts");
    fireEvent.click(screen.getByRole("button", { name: /Raw-evidence coverage/ }));
    expect(navigate).toHaveBeenCalledWith("discover");
  });

  it("renders an error state with a working retry", async () => {
    const getOperationalOverview = vi.fn()
      .mockRejectedValueOnce(new Error("snapshot unavailable"))
      .mockResolvedValueOnce(OPERATIONAL_OVERVIEW);
    render(<OperationsPage api={createMockApi({ getOperationalOverview })} onNavigate={() => undefined} />);
    expect(await screen.findByText("snapshot unavailable")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText(/Agent connectivity is authoritative only/)).toBeInTheDocument();
    expect(getOperationalOverview).toHaveBeenCalledTimes(2);
  });
});
