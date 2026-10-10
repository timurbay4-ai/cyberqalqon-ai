import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { CopyButton } from "./copy-button";

describe("CopyButton", () => {
  it("copies the exact value and announces success", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    render(<CopyButton value={'evidence-<script>'} label="Copy evidence" />);

    fireEvent.click(screen.getByRole("button", { name: "Copy evidence" }));

    await waitFor(() => expect(writeText).toHaveBeenCalledWith('evidence-<script>'));
    expect(await screen.findByRole("button", { name: "Copied" })).toBeInTheDocument();
    expect(screen.getByText("Copy evidence copied to clipboard.")).toBeInTheDocument();
  });

  it("shows an accessible failure when clipboard access is unavailable", async () => {
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined });
    render(<CopyButton value="evidence" label="Copy evidence" />);

    fireEvent.click(screen.getByRole("button", { name: "Copy evidence" }));

    expect(await screen.findByRole("button", { name: "Copy failed" })).toBeInTheDocument();
    expect(screen.getByText(/Clipboard access is unavailable/)).toBeInTheDocument();
  });
});
