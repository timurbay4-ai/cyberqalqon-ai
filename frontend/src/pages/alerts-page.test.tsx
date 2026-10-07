import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AlertsPage } from "./alerts-page";
import { ALERT_PAGE, createMockApi } from "../test/fixtures";

describe("AlertsPage", () => {
  it("renders optional fields, empty MITRE arrays, and malicious-looking telemetry as text", async () => {
    const api = createMockApi();
    const { container } = render(<AlertsPage api={api} />);

    expect(await screen.findByText("<script>attack()</script>")).toBeInTheDocument();
    expect(screen.getByText("No upstream mapping")).toBeInTheDocument();
    expect(screen.getByText("<img src=x onerror=attack()>")).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: /06 Oct 2026/ }));
    expect(await screen.findByRole("complementary", { name: "Alert detail" })).toBeInTheDocument();
    expect(screen.getAllByText("Not supplied").length).toBeGreaterThan(0);
  });

  it("shows a loading state while the backend request is pending", () => {
    const api = createMockApi({ listAlerts: vi.fn(() => new Promise<typeof ALERT_PAGE>(() => undefined)) });
    render(<AlertsPage api={api} />);
    expect(screen.getByText("Loading alerts")).toBeInTheDocument();
  });

  it("shows an honest empty state", async () => {
    const api = createMockApi({ listAlerts: vi.fn().mockResolvedValue({ items: [], page: { limit: 25, next_cursor: null, total: 0 } }) });
    render(<AlertsPage api={api} />);
    expect(await screen.findByText("No matching alerts")).toBeInTheDocument();
  });

  it("applies search and display-severity filters to the API query", async () => {
    const api = createMockApi();
    render(<AlertsPage api={api} />);
    await screen.findByText("<script>attack()</script>");

    fireEvent.change(screen.getByLabelText("Search"), { target: { value: "credential" } });
    fireEvent.click(screen.getByRole("button", { name: /Critical/ }));
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));

    await waitFor(() => expect(vi.mocked(api.listAlerts)).toHaveBeenLastCalledWith(
      expect.objectContaining({ search: "credential", ruleLevels: [13, 14, 15, 16] }),
      expect.any(AbortSignal),
    ));
  });

  it("shows API errors and retries without substituting demo records", async () => {
    const listAlerts = vi.fn().mockRejectedValueOnce(new Error("backend offline")).mockResolvedValueOnce(ALERT_PAGE);
    const api = createMockApi({ listAlerts });
    render(<AlertsPage api={api} />);

    expect(await screen.findByText("backend offline")).toBeInTheDocument();
    expect(screen.queryByText("<script>attack()</script>")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("<script>attack()</script>")).toBeInTheDocument();
    expect(listAlerts).toHaveBeenCalledTimes(2);
  });
});
