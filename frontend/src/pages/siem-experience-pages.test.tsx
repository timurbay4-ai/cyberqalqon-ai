import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { DashboardPage } from "./dashboard-page";
import { HostsPage } from "./hosts-page";
import { ReportsPage } from "./reports-page";
import { RulesPage } from "./rules-page";
import { SAMPLE_AGENT, SAMPLE_REPORT, SAMPLE_RULES, SECURITY_OVERVIEW, WAZUH_INTEGRATION_STATUS, createMockApi } from "../test/fixtures";

afterEach(() => vi.restoreAllMocks());

describe("SIEM experience pages", () => {
  it("keeps dashboard metrics actionable and reports a successful manual refresh", async () => {
    const onNavigate = vi.fn();
    const getOverview = vi.fn().mockResolvedValue(SECURITY_OVERVIEW);
    render(<DashboardPage api={createMockApi({ getOverview })} onOpenAlert={() => undefined} onNavigate={onNavigate} />);
    await screen.findByText(/Last successful refresh/);

    fireEvent.click(screen.getByRole("button", { name: /Security events/ }));
    expect(onNavigate).toHaveBeenCalledWith("discover");
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await waitFor(() => expect(getOverview).toHaveBeenCalledTimes(2));
  });

  it("filters the read-only rule catalog and opens a linked detail", async () => {
    const onOpenAlerts = vi.fn();
    render(<RulesPage api={createMockApi()} onOpenAlerts={onOpenAlerts} />);
    fireEvent.change(await screen.findByLabelText("Rule ID or name"), { target: { value: "100111" } });
    fireEvent.click(screen.getByRole("button", { name: "100111" }));
    const detail = await screen.findByRole("complementary", { name: "Rule detail" });
    expect(within(detail).getByText("Wazuh")).toBeInTheDocument();
    expect(within(detail).getByRole("link", { name: "T1046" })).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1046/");
    fireEvent.click(within(detail).getByRole("button", { name: "Open related alerts" }));
    expect(onOpenAlerts).toHaveBeenCalledWith("100111");

    fireEvent.click(within(detail).getByRole("button", { name: "Close rule detail" }));
    fireEvent.change(screen.getByLabelText("Rule ID or name"), { target: { value: "does-not-exist" } });
    expect(screen.getByText("No matching rules")).toBeInTheDocument();
  });

  it("distinguishes authoritative connectivity from telemetry freshness", async () => {
    render(<HostsPage api={createMockApi()} />);
    expect(await screen.findByText(/Authoritative Wazuh connectivity/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: new RegExp(SAMPLE_AGENT.name) }));
    const detail = await screen.findByRole("complementary", { name: "Agent detail" });
    expect(within(detail).getAllByText("ONLINE").length).toBeGreaterThan(0);
    expect(within(detail).getByText(/read-only/)).toBeInTheDocument();
  });

  it("downloads JSON through the authenticated API and reports export errors", async () => {
    vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:report");
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    const download = vi.fn()
      .mockResolvedValueOnce({ blob: new Blob(["{}"]), filename: "cyberqalqon-security-activity.json" })
      .mockRejectedValueOnce(new Error("export unavailable"));
    render(<ReportsPage api={createMockApi({ getSecurityActivityReport: vi.fn().mockResolvedValue(SAMPLE_REPORT), downloadSecurityActivityReport: download })} />);
    await screen.findByText(/Applied filters/);

    fireEvent.click(screen.getByRole("link", { name: "Export JSON" }));
    expect(await screen.findByText("cyberqalqon-security-activity.json downloaded.")).toBeInTheDocument();
    expect(download).toHaveBeenCalledWith(expect.objectContaining({ startTime: expect.any(String), endTime: expect.any(String) }), "json");

    fireEvent.click(screen.getByRole("link", { name: "Export CSV" }));
    expect(await screen.findByText("export unavailable")).toBeInTheDocument();
  });

  it("renders truthful empty rule, host, and report states", async () => {
    const emptyReport = { ...SAMPLE_REPORT, total_events: 0, total_alerts: 0, total_incidents: 0, event_sources: [], alert_severities: [], top_rules: [], host_activity: [] };
    const emptyApi = createMockApi({ listRules: vi.fn().mockResolvedValue([]), listAgents: vi.fn().mockResolvedValue({ items: [], page: { limit: 25, offset: 0, total: 0 }, authoritative_inventory: false, partial: true, observation_timestamp: "2026-10-09T16:49:55Z", cache_age_seconds: 5, message: "Wazuh API unavailable; observed sources are shown with UNKNOWN connection state." }), getWazuhIntegrationStatus: vi.fn().mockResolvedValue({ ...WAZUH_INTEGRATION_STATUS, state: "UNAVAILABLE", configured: false, reason: "Read-only Wazuh API credentials are not configured.", agent_count: null }), listSources: vi.fn().mockResolvedValue([]), getSecurityActivityReport: vi.fn().mockResolvedValue(emptyReport) });
    const { unmount } = render(<RulesPage api={emptyApi} />);
    expect(await screen.findByText("No matching rules")).toBeInTheDocument();
    unmount();
    render(<HostsPage api={emptyApi} />);
    expect(await screen.findByText(/No agent matches the selected filters/)).toBeInTheDocument();
    unmount();
    render(<ReportsPage api={emptyApi} />);
    expect(await screen.findByText(/completed successfully but no matching activity/)).toBeInTheDocument();
  });

  it("rejects an invalid custom report range before another backend query", async () => {
    const getReport = vi.fn().mockResolvedValue(SAMPLE_REPORT);
    render(<ReportsPage api={createMockApi({ getSecurityActivityReport: getReport })} />);
    await screen.findByText(/Applied filters/);
    fireEvent.change(screen.getByLabelText("Range"), { target: { value: "custom" } });
    fireEvent.change(screen.getByLabelText("Start"), { target: { value: "" } });

    expect(await screen.findByText("Choose valid start and end timestamps.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Export CSV" })).toHaveAttribute("aria-disabled", "true");
  });
});
