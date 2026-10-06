import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { App } from "./App";
import { ApiError } from "./api/client";
import { SAMPLE_SESSION, createMockApi } from "./test/fixtures";

describe("App", () => {
  it("reports the real backend connection and navigates the SOC workspace", async () => {
    const api = createMockApi();
    render(<App api={api} />);

    expect(await screen.findByText("Live backend")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Alerts/ }));
    expect(await screen.findByRole("heading", { name: "Security alerts" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Incidents/ }));
    expect(await screen.findByRole("heading", { name: "Incidents" })).toBeInTheDocument();
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
  });
});
