import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SAMPLE_EVENT, createMockApi } from "../test/fixtures";
import { DiscoverPage } from "./discover-page";
import { DEFAULT_PREFERENCES } from "../types/preferences";

afterEach(() => window.history.replaceState({}, "", "/?view=discover"));

describe("DiscoverPage", () => {
  it("searches server-side, expands redacted JSON, and exposes relationships", async () => {
    const api = createMockApi();
    const openAlert = vi.fn();
    const openIncident = vi.fn();
    const { container } = render(
      <DiscoverPage api={api} onOpenAlert={openAlert} onOpenIncident={openIncident} />,
    );

    expect(await screen.findByText(SAMPLE_EVENT.message)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Source IP"), { target: { value: "127.0.0.1" } });
    fireEvent.change(screen.getByLabelText("Operating system"), { target: { value: "linux" } });
    fireEvent.change(screen.getByLabelText("Event provider"), { target: { value: "sshd" } });
    fireEvent.change(screen.getByLabelText("Event channel"), { target: { value: "auth" } });
    fireEvent.change(screen.getByLabelText("Process name"), { target: { value: "nginx" } });
    fireEvent.change(screen.getByLabelText("Action"), { target: { value: "http_request" } });
    fireEvent.change(screen.getByLabelText("Wazuh rule ID"), { target: { value: "100120" } });
    fireEvent.click(screen.getByRole("button", { name: "Search events" }));
    expect(api.listEvents).toHaveBeenLastCalledWith(
      expect.objectContaining({
        sourceIp: "127.0.0.1",
        operatingSystem: "linux",
        eventProvider: "sshd",
        eventChannel: "auth",
        processName: "nginx",
        eventAction: "http_request",
        ruleId: "100120",
        limit: 25,
      }),
      expect.any(AbortSignal),
    );

    fireEvent.click(screen.getByRole("button", { name: /08 Oct 2026/ }));
    const detail = await screen.findByRole("complementary", { name: "Security event detail" });
    expect(within(detail).getAllByText("EVT-0123456789ABCDEF01234567")).toHaveLength(2);
    expect(within(detail).getByText(/<img src=x onerror=attack/)).toBeInTheDocument();
    expect(within(detail).getAllByText("/usr/sbin/nginx")).toHaveLength(2);
    expect(within(detail).getByText("nginx: worker process")).toBeInTheDocument();
    expect(within(detail).getByText("T1190")).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
    fireEvent.click(within(detail).getByRole("button", { name: /Open alert/ }));
    fireEvent.click(within(detail).getByRole("button", { name: /Open incident/ }));
    expect(openAlert).toHaveBeenCalledWith("alert-001");
    expect(openIncident).toHaveBeenCalledWith("INC-001");
  });

  it("renders a real empty state instead of demo rows", async () => {
    const api = createMockApi({
      listEvents: vi.fn().mockResolvedValue({ items: [], page: { limit: 25, next_cursor: null, total: 0, sort: "newest" } }),
    });
    render(<DiscoverPage api={api} onOpenAlert={() => undefined} onOpenIncident={() => undefined} />);
    expect(await screen.findByText("No matching events")).toBeInTheDocument();
    expect(screen.queryByText(SAMPLE_EVENT.message)).not.toBeInTheDocument();
  });

  it("saves validated category and outcome filters without a cursor", async () => {
    const api = createMockApi();
    render(<DiscoverPage api={api} onOpenAlert={() => undefined} onOpenIncident={() => undefined} />);
    await screen.findByText(SAMPLE_EVENT.message);
    fireEvent.change(screen.getByLabelText("Event category"), { target: { value: "web" } });
    fireEvent.change(screen.getByLabelText("Outcome"), { target: { value: "failure" } });
    fireEvent.change(screen.getByLabelText("Save current filters as"), { target: { value: "Failed web" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(api.saveEventSearch).toHaveBeenCalledWith({
      name: "Failed web",
      query: expect.objectContaining({ eventCategory: "web", outcome: "failure", relativeMinutes: 1440 }),
    }));
  });

  it("runs bounded CQQL without persisting the expression in the URL", async () => {
    window.history.replaceState({}, "", "/?view=discover");
    const api = createMockApi();
    render(<DiscoverPage api={api} onOpenAlert={() => undefined} onOpenIncident={() => undefined} />);
    await screen.findByText(SAMPLE_EVENT.message);
    fireEvent.change(screen.getByLabelText("CQQL query"), {
      target: { value: 'source.ip = "127.0.0.1" AND event.severity >= 8' },
    });
    fireEvent.click(screen.getByRole("button", { name: "Search events" }));

    await waitFor(() => expect(api.searchCQQL).toHaveBeenLastCalledWith(
      expect.objectContaining({
        query: 'source.ip = "127.0.0.1" AND event.severity >= 8',
        sort: "newest",
        limit: 25,
        start_time: expect.any(String),
        end_time: expect.any(String),
      }),
      expect.any(AbortSignal),
    ));
    expect(screen.getByText("Exact total: unknown")).toBeInTheDocument();
    expect(screen.getByText(/Data freshness:/)).toBeInTheDocument();
    expect(await screen.findByText("Search distribution")).toBeInTheDocument();
    expect(screen.getByText(/Exact within the selected bounded range/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Events over time" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Severity" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Source IP" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Host" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Category" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Source type" })).toBeInTheDocument();
    expect(api.getCQQLAnalytics).toHaveBeenCalledTimes(2);
    fireEvent.click(screen.getByRole("button", { name: "Export CSV" }));
    await waitFor(() => expect(api.downloadCQQL).toHaveBeenCalledWith(expect.objectContaining({
      query: 'source.ip = "127.0.0.1" AND event.severity >= 8', limit: 1000,
    })));
    expect(window.location.search).not.toContain("source.ip");
    expect(window.location.search).not.toContain("127.0.0.1");
    expect(
      (window.history.state as { cyberqalqonDiscover?: { cqql?: string } })
        .cyberqalqonDiscover?.cqql,
    ).toBe("");
  });

  it("shows a bounded CQQL analytics failure without hiding search results", async () => {
    const api = createMockApi({
      getCQQLAnalytics: vi.fn().mockRejectedValue(new Error("CQQL query exceeded its execution deadline")),
    });
    render(<DiscoverPage api={api} onOpenAlert={() => undefined} onOpenIncident={() => undefined} />);
    await screen.findByText(SAMPLE_EVENT.message);
    fireEvent.change(screen.getByLabelText("CQQL query"), {
      target: { value: 'event.code = "4625"' },
    });
    fireEvent.click(screen.getByRole("button", { name: "Search events" }));

    expect(await screen.findByText("CQQL analytics unavailable")).toBeInTheDocument();
    expect(screen.getByText("CQQL query exceeded its execution deadline")).toBeInTheDocument();
    expect(screen.getByText(SAMPLE_EVENT.message)).toBeInTheDocument();
  });

  it("stores validated CQQL with an analyst-owned saved search", async () => {
    const api = createMockApi();
    render(<DiscoverPage api={api} onOpenAlert={() => undefined} onOpenIncident={() => undefined} />);
    await screen.findByText(SAMPLE_EVENT.message);
    fireEvent.change(screen.getByLabelText("CQQL query"), {
      target: { value: 'event.code = "4625"' },
    });
    fireEvent.change(screen.getByLabelText("Save current filters as"), {
      target: { value: "Failed logons CQQL" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(api.saveEventSearch).toHaveBeenCalledWith({
      name: "Failed logons CQQL",
      query: expect.objectContaining({ cqql: 'event.code = "4625"', relativeMinutes: 1440 }),
    }));
  });

  it("keeps only non-sensitive filters in the URL and exposes removable active chips", async () => {
    const api = createMockApi();
    render(<DiscoverPage api={api} onOpenAlert={() => undefined} onOpenIncident={() => undefined} />);
    await screen.findByText(SAMPLE_EVENT.message);
    fireEvent.change(screen.getByLabelText("Source IP"), { target: { value: "10.20.30.40" } });
    fireEvent.change(screen.getByLabelText("Wazuh rule ID"), { target: { value: "100120" } });
    fireEvent.click(screen.getByRole("button", { name: "Search events" }));

    expect(window.location.search).toContain("rule_id=100120");
    expect(window.location.search).not.toContain("10.20.30.40");
    expect(screen.getByRole("button", { name: "Remove Rule id filter" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Remove Rule id filter" }));
    await waitFor(() => expect(api.listEvents).toHaveBeenLastCalledWith(
      expect.not.objectContaining({ ruleId: "100120" }),
      expect.any(AbortSignal),
    ));
  });

  it("renames a persisted saved search without replacing its stored query", async () => {
    const saved = { saved_search_id: "SSR-7", name: "Original", query: { relativeMinutes: 60 as const, ruleId: "100101", sort: "newest" as const }, created_at: "2026-10-08T10:00:00Z", updated_at: "2026-10-08T10:00:00Z" };
    const api = createMockApi({ listSavedEventSearches: vi.fn().mockResolvedValue([saved]) });
    render(<DiscoverPage api={api} onOpenAlert={() => undefined} onOpenIncident={() => undefined} />);
    await screen.findByText(SAMPLE_EVENT.message);
    fireEvent.change(screen.getByLabelText("Saved search"), { target: { value: "SSR-7" } });
    fireEvent.change(screen.getByLabelText("Rename selected search"), { target: { value: "Renamed" } });
    fireEvent.click(screen.getByRole("button", { name: "Rename" }));

    await waitFor(() => expect(api.updateSavedEventSearch).toHaveBeenCalledWith("SSR-7", { name: "Renamed", query: saved.query }));
  });

  it("changes the bounded event page size", async () => {
    const api = createMockApi();
    render(<DiscoverPage api={api} onOpenAlert={() => undefined} onOpenIncident={() => undefined} />);
    await screen.findByText(SAMPLE_EVENT.message);
    fireEvent.change(screen.getByLabelText("Rows per page"), { target: { value: "100" } });
    await waitFor(() => expect(api.listEvents).toHaveBeenLastCalledWith(expect.objectContaining({ limit: 100 }), expect.any(AbortSignal)));
  });

  it("restores pagination and filter state after leaving and returning to Discover", async () => {
    window.history.replaceState({}, "", "/?view=discover");
    const api = createMockApi({
      listEvents: vi.fn().mockResolvedValue({
        items: [SAMPLE_EVENT],
        page: { limit: 25, next_cursor: "cursor-page-2", total: 40, sort: "newest" },
      }),
    });
    const rendered = render(<DiscoverPage api={api} onOpenAlert={() => undefined} onOpenIncident={() => undefined} />);
    await screen.findByText(SAMPLE_EVENT.message);
    fireEvent.change(screen.getByLabelText("Wazuh rule ID"), { target: { value: "100120" } });
    fireEvent.click(screen.getByRole("button", { name: "Search events" }));
    fireEvent.click(await screen.findByRole("button", { name: "Next" }));
    await waitFor(() => expect(api.listEvents).toHaveBeenLastCalledWith(
      expect.objectContaining({ cursor: "cursor-page-2", ruleId: "100120" }),
      expect.any(AbortSignal),
    ));
    expect((window.history.state as { cyberqalqonDiscoverCursor?: string }).cyberqalqonDiscoverCursor).toBe("cursor-page-2");

    rendered.unmount();
    render(<DiscoverPage api={api} onOpenAlert={() => undefined} onOpenIncident={() => undefined} />);
    await waitFor(() => expect(api.listEvents).toHaveBeenLastCalledWith(
      expect.objectContaining({ cursor: "cursor-page-2", ruleId: "100120" }),
      expect.any(AbortSignal),
    ));
  });

  it("renders persisted column order and protects essential identification columns", async () => {
    const api = createMockApi();
    const preferences = { ...DEFAULT_PREFERENCES, discover_columns: ["event", "time", "rule"] as const };
    render(<DiscoverPage api={api} preferences={{ ...preferences, discover_columns: [...preferences.discover_columns] }} onOpenAlert={() => undefined} onOpenIncident={() => undefined} />);
    await screen.findByText(SAMPLE_EVENT.message);
    const headers = screen.getAllByRole("columnheader").map((header) => header.textContent);
    expect(headers).toEqual(["Event", "Time", "Rule"]);
    expect(screen.getByRole("checkbox", { name: "Time" })).toBeDisabled();
    expect(screen.getByRole("checkbox", { name: "Event" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Restore defaults" }));
    await waitFor(() => expect(api.updatePreferences).toHaveBeenCalledWith(expect.objectContaining({
      discover_columns: ["time", "source", "host", "identity", "rule", "event"],
      expected_version: 1,
    })));
  });
});
