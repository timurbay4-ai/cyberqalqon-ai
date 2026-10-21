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

  it("shows bounded post-start ingestion metrics without inventing history", async () => {
    render(<OperationsPage api={createMockApi()} onNavigate={() => undefined} />);

    expect(await screen.findByRole("heading", { name: "Ingestion performance" })).toBeInTheDocument();
    expect(screen.getByText("DISABLED BY DEFAULT")).toBeInTheDocument();
    expect(screen.getByText(/Pre-M18 unique and duplicate totals remain UNKNOWN/)).toBeInTheDocument();
  });

  it("shows freshness, latency, and event-loop isolation for the bounded query", async () => {
    render(<OperationsPage api={createMockApi()} onNavigate={() => undefined} />);

    expect(await screen.findByText(/Bounded operational query: FRESH/)).toBeInTheDocument();
    expect(screen.getByText(/SQLite reads have a 2\.0 s deadline/)).toBeInTheDocument();
    expect(screen.getByText(/12\.5 ms/)).toBeInTheDocument();
  });

  it("keeps legacy, forward, and historical replay states distinct", async () => {
    render(<OperationsPage api={createMockApi()} onNavigate={() => undefined} />);

    expect(await screen.findByRole("heading", { name: "Legacy shipper diagnostics" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Forward ingestion boundary" })).toBeInTheDocument();
    expect(screen.getByText(/Historical gap: UNPROVEN and not replayed/)).toBeInTheDocument();
    expect(screen.getByText(/no combined completion percentage/)).toBeInTheDocument();
  });

  it("shows approval validity separately from service activity", async () => {
    const getOperationalOverview = vi.fn().mockResolvedValue({
      ...OPERATIONAL_OVERVIEW,
      forward_ingestion: {
        ...OPERATIONAL_OVERVIEW.forward_ingestion,
        service_active: true,
        forward_state: "ACTIVE",
        approval_state: "VALID",
        approval_validation_basis: "BOUNDED_SCOPE_TIME_IDENTITY",
        approval_expires_at: "2026-10-21T04:17:44+05:00",
        approval_remaining_seconds: 3600,
        checkpoint_updated_at: "2026-10-20T22:00:00+05:00",
      },
    });
    render(<OperationsPage api={createMockApi({ getOperationalOverview })} onNavigate={() => undefined} />);

    expect(await screen.findByText("VALID")).toBeInTheDocument();
    expect(screen.getByText("60 minutes")).toBeInTheDocument();
    expect(screen.getByText("Durable checkpoint updated")).toBeInTheDocument();
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

  it("labels stale snapshots and never invents unmaterialized quality totals", async () => {
    const getOperationalOverview = vi.fn().mockResolvedValue({
      ...OPERATIONAL_OVERVIEW,
      measurement: {
        ...OPERATIONAL_OVERVIEW.measurement,
        state: "STALE",
        reason_code: "REFRESH_IN_PROGRESS",
      },
    });
    render(<OperationsPage api={createMockApi({ getOperationalOverview })} onNavigate={() => undefined} />);

    expect(await screen.findByText("Degraded Operations snapshot")).toBeInTheDocument();
    expect(screen.getAllByText("UNKNOWN").length).toBeGreaterThan(0);
    expect(screen.getByText(/Operations never replaces them with an expensive live table scan/)).toBeInTheDocument();
  });
});
