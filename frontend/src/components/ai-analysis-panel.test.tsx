import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ApiError } from "../api/client";
import { AIAnalysisPanel } from "./ai-analysis-panel";
import { AI_STATUS, SAMPLE_AI_ANALYSIS, createMockApi } from "../test/fixtures";

describe("AIAnalysisPanel", () => {
  it("distinguishes disabled and unavailable states without a fake result", async () => {
    const api = createMockApi({
      getAIStatus: vi.fn().mockResolvedValue({ ...AI_STATUS, state: "DISABLED", model: null, diagnostic: "ai_disabled" }),
    });
    render(<AIAnalysisPanel api={api} targetType="alert" targetId="alert-001" />);
    expect(await screen.findByText("AI Analyst is disabled by the operator.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Analyze alert with AI" })).toBeDisabled();
    expect(screen.getByText("No AI analysis has been generated for this alert.")).toBeInTheDocument();
  });

  it("rechecks unavailable status and enables analysis when Ollama recovers", async () => {
    const getAIStatus = vi.fn()
      .mockResolvedValueOnce({ ...AI_STATUS, state: "UNAVAILABLE", diagnostic: "provider_unavailable" })
      .mockResolvedValueOnce(AI_STATUS);
    const api = createMockApi({ getAIStatus });
    render(<AIAnalysisPanel api={api} targetType="alert" targetId="alert-001" />);
    expect(await screen.findByText(/Local AI is unavailable/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Retry AI status" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Analyze alert with AI" })).toBeEnabled());
    expect(getAIStatus).toHaveBeenCalledTimes(2);
  });

  it("shows loading then renders validated sections and attacker-influenced output as text", async () => {
    let resolveAnalysis!: (value: typeof SAMPLE_AI_ANALYSIS) => void;
    const analyzeAlert = vi.fn(() => new Promise<typeof SAMPLE_AI_ANALYSIS>((resolve) => { resolveAnalysis = resolve; }));
    const api = createMockApi({ analyzeAlert });
    const { container } = render(<AIAnalysisPanel api={api} targetType="alert" targetId="alert-001" />);
    const button = await screen.findByRole("button", { name: "Analyze alert with AI" });
    await waitFor(() => expect(button).toBeEnabled());
    fireEvent.click(button);
    expect(screen.getByRole("button", { name: "Analyzing…" })).toBeDisabled();
    expect(screen.getByText("Local model analysis is in progress…")).toBeInTheDocument();
    resolveAnalysis(SAMPLE_AI_ANALYSIS);

    const result = await screen.findByRole("article", { name: "AI advisory analysis" });
    expect(within(result).getByText("Summary")).toBeInTheDocument();
    expect(within(result).getByText("Assessment")).toBeInTheDocument();
    expect(within(result).getByText("MITRE context")).toBeInTheDocument();
    expect(within(result).getByText("Uncertainties")).toBeInTheDocument();
    expect(within(result).getByText("Review <script>alert(1)</script> as inert evidence.")).toBeInTheDocument();
    expect(within(result).getByText("Run cmd.exe /c whoami is attacker-controlled text.")).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("a")).toBeNull();
  });

  it("submits a bounded question to the incident endpoint", async () => {
    const api = createMockApi();
    render(<AIAnalysisPanel api={api} targetType="incident" targetId="INC-001" />);
    await waitFor(() => expect(screen.getByRole("button", { name: "Analyze incident with AI" })).toBeEnabled());
    fireEvent.change(screen.getByLabelText("Optional analyst question"), { target: { value: "What evidence should I verify next?" } });
    fireEvent.click(screen.getByRole("button", { name: "Analyze incident with AI" }));
    await waitFor(() => expect(api.analyzeIncident).toHaveBeenCalledWith(
      "INC-001",
      { question: "What evidence should I verify next?" },
      expect.any(AbortSignal),
    ));
    expect(api.analyzeAlert).not.toHaveBeenCalled();
  });

  it("shows persisted provenance, truncation, and staleness without generating", async () => {
    const historical = { ...SAMPLE_AI_ANALYSIS, stale: true, context: { ...SAMPLE_AI_ANALYSIS.context, truncated: true } };
    const api = createMockApi({ listAlertAnalyses: vi.fn().mockResolvedValue({ items: [historical], limit: 20 }) });
    render(<AIAnalysisPanel api={api} targetType="alert" targetId="alert-001" />);
    expect(await screen.findByText(/may be stale/)).toBeInTheDocument();
    expect(screen.getByText(/bounded, truncated context/)).toBeInTheDocument();
    expect(screen.getByText("Requested by Analyst One (analyst-1)")).toBeInTheDocument();
    expect(api.analyzeAlert).not.toHaveBeenCalled();
  });

  it.each([
    ["ai_timeout", "Local AI did not respond before the timeout."],
    ["ai_busy", "Local AI is busy. Retry after the current analysis finishes."],
    ["ai_invalid_response", "The model returned an invalid structured response."],
    ["authentication_required", "Forbidden"],
    ["permission_denied", "Forbidden"],
  ])("surfaces %s safely and allows retry", async (code, message) => {
    const analyzeAlert = vi.fn()
      .mockRejectedValueOnce(new ApiError("Forbidden", code === "permission_denied" ? 403 : 502, code))
      .mockResolvedValueOnce(SAMPLE_AI_ANALYSIS);
    const api = createMockApi({ analyzeAlert });
    render(<AIAnalysisPanel api={api} targetType="alert" targetId="alert-001" />);
    await waitFor(() => expect(screen.getByRole("button", { name: "Analyze alert with AI" })).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: "Analyze alert with AI" }));
    expect(await screen.findByText(message)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Analyze alert with AI" }));
    expect(await screen.findByRole("article", { name: "AI advisory analysis" })).toBeInTheDocument();
    expect(analyzeAlert).toHaveBeenCalledTimes(2);
  });

  it("does not let an old target response overwrite a newly selected target", async () => {
    let resolveOld!: (value: typeof SAMPLE_AI_ANALYSIS) => void;
    const analyzeAlert = vi.fn(() => new Promise<typeof SAMPLE_AI_ANALYSIS>((resolve) => { resolveOld = resolve; }));
    const api = createMockApi({ analyzeAlert });
    const view = render(<AIAnalysisPanel api={api} targetType="alert" targetId="alert-001" />);
    await waitFor(() => expect(screen.getByRole("button", { name: "Analyze alert with AI" })).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: "Analyze alert with AI" }));
    view.rerender(<AIAnalysisPanel api={api} targetType="alert" targetId="alert-002" />);
    resolveOld(SAMPLE_AI_ANALYSIS);
    await waitFor(() => expect(screen.getByText("No AI analysis has been generated for this alert.")).toBeInTheDocument());
    expect(screen.queryByRole("article", { name: "AI advisory analysis" })).not.toBeInTheDocument();
  });
});
