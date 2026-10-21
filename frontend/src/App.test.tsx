import { StrictMode } from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { App } from "./App";
import { ApiError } from "./api/client";
import { SAMPLE_SESSION, createMockApi } from "./test/fixtures";

describe("App", () => {
  it("reports the real backend connection and navigates the SOC workspace", async () => {
    const api = createMockApi();
    render(<App api={api} />);

    expect(await screen.findByText("Live backend")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Discover/ }));
    expect(await screen.findByRole("heading", { name: "Security event explorer" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Alerts/ }));
    expect(await screen.findByRole("heading", { name: "Security alerts" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Incidents/ }));
    expect(await screen.findByRole("heading", { name: "Incidents" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /^Agents$/ }));
    expect(await screen.findByRole("heading", { name: "Agent management" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Detection Rules/ }));
    expect(await screen.findByRole("heading", { name: "Rules, coverage and quality" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Reports/ }));
    expect(await screen.findByRole("heading", { name: "Security reports" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Export CSV" })).toHaveAttribute("href", expect.stringContaining("/api/v1/reports/security-activity.csv"));
    fireEvent.click(screen.getByRole("button", { name: /Administration/ }));
    expect(await screen.findByRole("heading", { name: "Administration" })).toBeInTheDocument();
    expect(await screen.findByText("Session security")).toBeInTheDocument();
  });

  it("shows backend unavailability without substituting demo data", async () => {
    const api = createMockApi({ getSession: vi.fn().mockRejectedValue(new Error("The CyberQalqon backend is unavailable.")) });
    render(<App api={api} />);

    expect(await screen.findByRole("heading", { name: "Analyst sign in" })).toBeInTheDocument();
    expect(screen.getByText("The CyberQalqon backend is unavailable.")).toBeInTheDocument();
    expect(screen.queryByText(/Sanitized demo/)).not.toBeInTheDocument();
  });

  it("keeps the SOC shell protected until login succeeds", async () => {
    const api = createMockApi({
      getSession: vi.fn().mockRejectedValue(new ApiError("A valid analyst session is required", 401, "authentication_required")),
      login: vi.fn().mockResolvedValue(SAMPLE_SESSION),
    });
    render(<App api={api} />);
    expect(await screen.findByRole("heading", { name: "Analyst sign in" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Security overview" })).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "analyst-1" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "secret-value" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("Analyst One")).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Security overview" })).toBeInTheDocument();
  });

  it("shows invalid credentials and handles session expiry centrally", async () => {
    let unauthorized: (() => void) | undefined;
    const api = createMockApi({
      getSession: vi.fn().mockRejectedValue(new ApiError("A valid analyst session is required", 401, "authentication_required")),
      login: vi.fn().mockRejectedValue(new ApiError("Invalid username or password", 401, "invalid_credentials")),
      subscribeUnauthorized: vi.fn((handler: () => void) => { unauthorized = handler; return () => undefined; }),
    });
    const { rerender } = render(<App api={api} />);
    expect(await screen.findByRole("heading", { name: "Analyst sign in" })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "analyst-1" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "wrong" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("Invalid username or password")).toBeInTheDocument();

    api.getSession = vi.fn().mockResolvedValue(SAMPLE_SESSION);
    rerender(<App api={api} />);
    unauthorized?.();
    expect(await screen.findByText("Your analyst session expired. Sign in again.")).toBeInTheDocument();
  });

  it("logs out through the backend and returns to the protected login page", async () => {
    const api = createMockApi();
    render(<App api={api} />);
    expect(await screen.findByText("Analyst One")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    expect(await screen.findByRole("heading", { name: "Analyst sign in" })).toBeInTheDocument();
    expect(api.logout).toHaveBeenCalledOnce();
  }, 10_000);

  it("restores the authenticated shell under React StrictMode", async () => {
    const api = createMockApi();
    render(<StrictMode><App api={api} /></StrictMode>);

    expect(await screen.findByText("Analyst One")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Security overview" })).toBeInTheDocument();
    expect(api.getSession).toHaveBeenCalled();
  });

  it("keeps a valid analyst signed in when dashboard data fails", async () => {
    const api = createMockApi({
      getOverview: vi.fn().mockRejectedValue(new ApiError("Temporary dashboard failure", 500, "backend_failure")),
    });
    render(<App api={api} />);

    expect(await screen.findByText("Analyst One")).toBeInTheDocument();
    expect(await screen.findByText("Temporary dashboard failure")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Analyst sign in" })).not.toBeInTheDocument();
  });

  it("shows persisted per-user notifications and navigates to the related alert", async () => {
    const api = createMockApi({
      listNotifications: vi.fn().mockResolvedValue({
        unread_count: 1,
        limit: 25,
        items: [{
          notification_id: "NTF-1",
          category: "HIGH_ALERT",
          title: "High-severity alert received",
          preview: "Rule 5712 · level 10 · test-host",
          target_type: "alert",
          target_id: "alert-001",
          created_at: "2026-10-08T12:00:00Z",
          read_at: null,
        }],
      }),
      markNotificationRead: vi.fn().mockResolvedValue({
        notification_id: "NTF-1", category: "HIGH_ALERT", title: "High-severity alert received",
        preview: "Rule 5712 · level 10 · test-host", target_type: "alert", target_id: "alert-001",
        created_at: "2026-10-08T12:00:00Z", read_at: "2026-10-08T12:01:00Z",
      }),
    });
    render(<App api={api} />);
    const trigger = await screen.findByRole("button", { name: "Notifications, 1 unread" });
    fireEvent.click(trigger);
    fireEvent.click(await screen.findByRole("button", { name: /High-severity alert received/ }));
    expect(await screen.findByRole("heading", { name: "Security alerts" })).toBeInTheDocument();
    expect(api.markNotificationRead).toHaveBeenCalledWith("NTF-1");
    await waitFor(() => expect(api.getAlertWorkflow).toHaveBeenCalledWith("alert-001", expect.any(AbortSignal)));
  });

  it("supports shareable page deep links and browser history restoration", async () => {
    window.history.replaceState({}, "", "/?view=alerts&alert=alert-001");
    const api = createMockApi();
    render(<App api={api} />);

    expect(await screen.findByRole("heading", { name: "Security alerts" })).toBeInTheDocument();
    await waitFor(() => expect(api.getAlertWorkflow).toHaveBeenCalledWith("alert-001", expect.any(AbortSignal)));
    fireEvent.click(screen.getByRole("button", { name: /^Agents$/ }));
    expect(window.location.search).toBe("?view=hosts");
    window.history.pushState({}, "", "/?view=incidents");
    fireEvent.popState(window);
    expect(await screen.findByRole("heading", { name: "Incidents" })).toBeInTheDocument();
  });

  it("restores sensitive workbench pivots from history state without URL disclosure", async () => {
    const target = {
      target_type: "ENTITY" as const,
      entity_type: "USERNAME" as const,
      entity_value: "sensitive-user@example.test",
      relative_minutes: 1440,
      related_limit: 25,
      timeline_limit: 100,
      sort: "oldest" as const,
    };
    window.history.replaceState({ cyberqalqonWorkbench: target }, "", "/?view=investigate");
    const api = createMockApi();
    render(<App api={api} />);

    expect(await screen.findByRole("heading", { name: /Event EVT-/ })).toBeInTheDocument();
    expect(api.getInvestigationWorkbench).toHaveBeenCalledWith(target, expect.any(AbortSignal));
    expect(window.location.search).toBe("?view=investigate");
    expect(window.location.href).not.toContain("sensitive-user");

    fireEvent.click(screen.getByRole("button", { name: /Alerts/ }));
    expect(await screen.findByRole("heading", { name: "Security alerts" })).toBeInTheDocument();
    window.history.replaceState({ cyberqalqonWorkbench: target }, "", "/?view=investigate");
    fireEvent.popState(window);
    expect(await screen.findByRole("heading", { name: /Event EVT-/ })).toBeInTheDocument();
  });

  it("offers discoverable keyboard shortcuts without hijacking text input", async () => {
    const api = createMockApi();
    render(<App api={api} />);
    await screen.findByRole("heading", { name: "Security overview" });

    fireEvent.keyDown(window, { key: "?" });
    expect(screen.getByRole("dialog", { name: "Shortcuts" })).toBeInTheDocument();
    fireEvent.keyDown(window, { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "Shortcuts" })).not.toBeInTheDocument();

    fireEvent.keyDown(window, { key: "g" });
    fireEvent.keyDown(window, { key: "a" });
    expect(await screen.findByRole("heading", { name: "Security alerts" })).toBeInTheDocument();
    const search = screen.getByLabelText("Search");
    fireEvent.keyDown(search, { key: "?" });
    expect(screen.queryByRole("dialog", { name: "Shortcuts" })).not.toBeInTheDocument();

    fireEvent.keyDown(window, { key: "/" });
    expect(await screen.findByRole("heading", { name: "Security event explorer" })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByLabelText("Keyword")).toHaveFocus());
  });
});
