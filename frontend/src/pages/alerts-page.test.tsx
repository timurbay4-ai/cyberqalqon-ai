import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AlertsPage } from "./alerts-page";
import { ALERT_WORKFLOW_PAGE, createMockApi } from "../test/fixtures";

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
    const api = createMockApi({ listAlertWorkflows: vi.fn(() => new Promise<typeof ALERT_WORKFLOW_PAGE>(() => undefined)) });
    render(<AlertsPage api={api} />);
    expect(screen.getByText("Loading alerts")).toBeInTheDocument();
  });

  it("shows an honest empty state", async () => {
    const api = createMockApi({ listAlertWorkflows: vi.fn().mockResolvedValue({ items: [], page: { limit: 25, next_cursor: null, total: 0, sort: "time_desc" }, counts: { total: 0, actionable: 0, unassigned: 0, by_status: { NEW: 0, ACKNOWLEDGED: 0, IN_PROGRESS: 0, RESOLVED: 0, FALSE_POSITIVE: 0 } } }) });
    render(<AlertsPage api={api} />);
    expect(await screen.findByText("No matching alerts")).toBeInTheDocument();
  });

  it("applies exact rule, search, and display-severity filters to the API query", async () => {
    const api = createMockApi();
    render(<AlertsPage api={api} />);
    await screen.findByText("<script>attack()</script>");

    fireEvent.change(screen.getByLabelText("Search"), { target: { value: "credential" } });
    fireEvent.change(screen.getByLabelText("Rule ID"), { target: { value: "100101" } });
    fireEvent.click(screen.getByRole("button", { name: /Critical/ }));
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));

    await waitFor(() => expect(vi.mocked(api.listAlertWorkflows)).toHaveBeenLastCalledWith(
      expect.objectContaining({ search: "credential", ruleId: "100101", ruleLevels: [13, 14, 15, 16] }),
      expect.any(AbortSignal),
    ));
  });

  it("changes the bounded page size and restarts pagination", async () => {
    const api = createMockApi();
    render(<AlertsPage api={api} />);
    await screen.findByText("<script>attack()</script>");

    fireEvent.change(screen.getByLabelText("Rows per page"), { target: { value: "50" } });

    await waitFor(() => expect(vi.mocked(api.listAlertWorkflows)).toHaveBeenLastCalledWith(
      expect.objectContaining({ limit: 50, cursor: undefined }),
      expect.any(AbortSignal),
    ));
  });

  it("shows API errors and retries without substituting demo records", async () => {
    const listAlertWorkflows = vi.fn().mockRejectedValueOnce(new Error("backend offline")).mockResolvedValueOnce(ALERT_WORKFLOW_PAGE);
    const api = createMockApi({ listAlertWorkflows });
    render(<AlertsPage api={api} />);

    expect(await screen.findByText("backend offline")).toBeInTheDocument();
    expect(screen.queryByText("<script>attack()</script>")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("<script>attack()</script>")).toBeInTheDocument();
    expect(listAlertWorkflows).toHaveBeenCalledTimes(2);
  });

  it("applies durable workflow filters", async () => {
    const api = createMockApi();
    render(<AlertsPage api={api} />);
    await screen.findByText("<script>attack()</script>");

    fireEvent.change(screen.getByLabelText("Workflow status"), { target: { value: "ACKNOWLEDGED" } });
    fireEvent.click(screen.getByLabelText("Unassigned only"));
    fireEvent.change(screen.getByLabelText("Sort"), { target: { value: "severity_desc" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));

    await waitFor(() => expect(api.listAlertWorkflows).toHaveBeenLastCalledWith(
      expect.objectContaining({ statuses: ["ACKNOWLEDGED"], unassigned: true, sort: "severity_desc" }),
      expect.any(AbortSignal),
    ));
  });

  it("shows an explicit bounded selection and submits one transactional bulk request", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    const api = createMockApi();
    render(<AlertsPage api={api} canMutate />);
    await screen.findByText("<script>attack()</script>");

    fireEvent.click(screen.getByLabelText("Select alert alert-001"));
    expect(screen.getByText("1 selected")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Apply to selection" }));

    await waitFor(() => expect(api.bulkUpdateAlerts).toHaveBeenCalledWith({
      action: "ACKNOWLEDGE",
      items: [{ alert_id: "alert-001", expected_version: 1 }],
    }));
    expect(confirm).toHaveBeenCalledOnce();
    confirm.mockRestore();
  });

  it("updates alert status with the current optimistic version", async () => {
    const api = createMockApi();
    render(<AlertsPage api={api} canMutate />);
    await screen.findByText("<script>attack()</script>");
    fireEvent.click(screen.getByRole("button", { name: /06 Oct 2026/ }));
    await screen.findByText("Analyst workflow");
    fireEvent.change(screen.getByLabelText("Next status"), { target: { value: "ACKNOWLEDGED" } });
    fireEvent.click(screen.getByRole("button", { name: "Update status" }));
    await waitFor(() => expect(api.updateAlertStatus).toHaveBeenCalledWith("alert-001", "ACKNOWLEDGED", 1));
  });
});
