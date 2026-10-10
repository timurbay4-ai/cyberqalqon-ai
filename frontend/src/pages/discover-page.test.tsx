import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { SAMPLE_EVENT, createMockApi } from "../test/fixtures";
import { DiscoverPage } from "./discover-page";
import { DEFAULT_PREFERENCES } from "../types/preferences";


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
    fireEvent.change(screen.getByLabelText("Wazuh rule ID"), { target: { value: "100120" } });
    fireEvent.click(screen.getByRole("button", { name: "Search events" }));
    expect(api.listEvents).toHaveBeenLastCalledWith(
      expect.objectContaining({ sourceIp: "127.0.0.1", ruleId: "100120", limit: 25 }),
      expect.any(AbortSignal),
    );

    fireEvent.click(screen.getByRole("button", { name: /08 Oct 2026/ }));
    const detail = await screen.findByRole("complementary", { name: "Security event detail" });
    expect(within(detail).getByText("EVT-0123456789ABCDEF01234567")).toBeInTheDocument();
    expect(within(detail).getByText(/<img src=x onerror=attack/)).toBeInTheDocument();
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
