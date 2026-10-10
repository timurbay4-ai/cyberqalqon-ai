import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SAMPLE_SESSION, createMockApi } from "../test/fixtures";
import { AdministrationPage } from "./administration-page";


describe("AdministrationPage", () => {
  it("shows bounded account state and changes the current analyst password", async () => {
    const api = createMockApi();
    const admin = { ...SAMPLE_SESSION.analyst, role: "ADMIN" as const, permissions: ["soc:read", "incident:write", "analyst:manage"] as const };
    render(<AdministrationPage api={api} analyst={{ ...admin, permissions: [...admin.permissions] }} />);
    expect(await screen.findByText("Analyst accounts")).toBeInTheDocument();
    expect(await screen.findByText("Active sessions")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Current password"), { target: { value: "old-password" } });
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "new-password-value" } });
    fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: "new-password-value" } });
    fireEvent.click(screen.getByRole("button", { name: "Change password" }));
    await waitFor(() => expect(api.changePassword).toHaveBeenCalledWith({
      current_password: "old-password",
      new_password: "new-password-value",
    }));
    expect(await screen.findByText("Password changed. Other sessions were revoked.")).toBeInTheDocument();
  });
});
