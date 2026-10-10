import {
    fireEvent,
    render,
    screen,
    waitFor,
    within,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createMockApi, SAMPLE_RULE_DRAFT } from "../test/fixtures";
import { DetectionEngineeringPage } from "./detection-engineering-page";
import { ThreatHuntingPage } from "./threat-hunting-page";
import { ThreatIntelligencePage } from "./threat-intelligence-page";

afterEach(() => vi.restoreAllMocks());

describe("CyberQalqon v0.5 analyst pages", () => {
    it("runs a bounded hunt, keeps IP evidence out of the URL, and opens relationships", async () => {
        const api = createMockApi();
        const onOpenEvent = vi.fn();
        const onOpenAlert = vi.fn();
        const onOpenIncident = vi.fn();
        render(
            <ThreatHuntingPage
                api={api}
                canMutate
                onOpenEvent={onOpenEvent}
                onOpenAlert={onOpenAlert}
                onOpenIncident={onOpenIncident}
            />,
        );

        expect(
            await screen.findByText("Authorized local scan evidence"),
        ).toBeInTheDocument();
        fireEvent.change(screen.getByLabelText("Any IP"), {
            target: { value: "127.0.0.1" },
        });
        fireEvent.change(screen.getByLabelText("Rule ID"), {
            target: { value: "100111" },
        });
        fireEvent.click(screen.getByRole("button", { name: "Run hunt" }));

        await waitFor(() =>
            expect(api.runThreatHunt).toHaveBeenLastCalledWith(
                expect.objectContaining({
                    ip: "127.0.0.1",
                    ruleId: "100111",
                    limit: 50,
                }),
                expect.any(AbortSignal),
            ),
        );
        expect(window.location.search).toContain("rule_id=100111");
        expect(window.location.search).not.toContain("127.0.0.1");

        fireEvent.click(
            screen.getByRole("button", { name: /09 Oct 2026|08 Oct 2026/ }),
        );
        fireEvent.click(screen.getByRole("button", { name: "Alert" }));
        fireEvent.click(screen.getByRole("button", { name: "Incident" }));
        expect(onOpenEvent).toHaveBeenCalledWith(
            "EVT-0123456789ABCDEF01234567",
        );
        expect(onOpenAlert).toHaveBeenCalledWith("alert-001");
        expect(onOpenIncident).toHaveBeenCalledWith("INC-001");
    });

    it("creates a validated local IOC and removes mutation controls for read-only access", async () => {
        const api = createMockApi();
        const view = render(
            <ThreatIntelligencePage
                api={api}
                canMutate
                onOpenEvent={() => undefined}
            />,
        );
        expect(
            (await screen.findAllByText("127.0.0.1")).length,
        ).toBeGreaterThan(0);

        const addPanel = screen
            .getByRole("heading", { name: "Add indicator" })
            .closest("section");
        expect(addPanel).not.toBeNull();
        fireEvent.change(within(addPanel!).getByLabelText("Value"), {
            target: { value: "192.0.2.20" },
        });
        fireEvent.change(within(addPanel!).getByLabelText("Description"), {
            target: { value: "Reviewed test IOC" },
        });
        fireEvent.click(
            within(addPanel!).getByRole("button", { name: "Add indicator" }),
        );
        await waitFor(() =>
            expect(api.createIOC).toHaveBeenCalledWith(
                expect.objectContaining({
                    indicator_type: "IPV4",
                    value: "192.0.2.20",
                    confidence: 50,
                }),
            ),
        );

        view.unmount();
        render(
            <ThreatIntelligencePage
                api={createMockApi()}
                canMutate={false}
                onOpenEvent={() => undefined}
            />,
        );
        await screen.findAllByText("127.0.0.1");
        expect(
            screen.queryByRole("heading", { name: "Add indicator" }),
        ).not.toBeInTheDocument();
        expect(
            screen.queryByRole("button", { name: "Deactivate" }),
        ).not.toBeInTheDocument();
    });

    it("keeps mapped, enabled, triggered, and tested coverage facts distinct", async () => {
        render(
            <DetectionEngineeringPage
                api={createMockApi()}
                canMutate
                onOpenAlerts={() => undefined}
                onOpenEvent={() => undefined}
            />,
        );
        await screen.findByText("TCP port scan");
        fireEvent.click(screen.getByRole("button", { name: "Coverage" }));
        const row = await screen.findByRole("row", { name: /T1046/ });
        expect(within(row).getByText("1 · 1 alerts")).toBeInTheDocument();
        expect(within(row).getAllByText("0")).toHaveLength(2);
        expect(
            screen.getByText(/Mapping alone is not proven detection coverage/),
        ).toBeInTheDocument();
    });

    it("dry-runs a validated draft without side effects and requires explicit manual-deployment consent", async () => {
        const testedDraft = {
            ...SAMPLE_RULE_DRAFT,
            status: "TESTED" as const,
            version: 3,
        };
        const api = createMockApi({
            listRuleDraftVersions: vi
                .fn()
                .mockResolvedValue([
                    {
                        version_id: "DRV-1",
                        draft_id: "DRF-1",
                        version_number: 1,
                        snapshot: {},
                        change_summary: "Initial",
                        actor_display: "Analyst One",
                        created_at: "2026-10-09T08:00:00Z",
                    },
                ]),
            dryRunRuleDraft: vi.fn().mockResolvedValue({
                draft: testedDraft,
                start_time: "2026-10-08T00:00:00Z",
                end_time: "2026-10-09T00:00:00Z",
                evaluated_event_count: 12,
                match_count: 1,
                matched_event_ids: ["EVT-0123456789ABCDEF01234567"],
                execution_ms: 1.2,
                result_ids_truncated: false,
                side_effects: false,
            }),
        });
        render(
            <DetectionEngineeringPage
                api={api}
                canMutate
                onOpenAlerts={() => undefined}
                onOpenEvent={() => undefined}
            />,
        );
        await screen.findByText("TCP port scan");
        fireEvent.click(screen.getByRole("button", { name: "Drafts" }));
        fireEvent.click(
            screen.getByRole("button", { name: /Local scan candidate/ }),
        );
        const dryRunButton = await screen.findByRole("button", {
            name: "Dry-run 30 days",
        });
        fireEvent.click(dryRunButton);

        expect(
            await screen.findByText(/1 matches among 12 evaluated events/),
        ).toBeInTheDocument();
        expect(
            screen.getByText(
                /No alerts, incidents, or notifications were generated/,
            ),
        ).toBeInTheDocument();
        const confirmation = screen.getByRole("checkbox", {
            name: /I understand CyberQalqon/,
        });
        const deploy = screen.getByRole("button", {
            name: "Record manual deployment readiness",
        });
        expect(deploy).toBeDisabled();
        fireEvent.click(confirmation);
        fireEvent.change(screen.getByLabelText("Reason"), {
            target: { value: "Approved for separate operator review" },
        });
        expect(deploy).toBeEnabled();
        fireEvent.click(deploy);
        await waitFor(() =>
            expect(api.confirmManualDeployment).toHaveBeenCalledWith(
                "DRF-1",
                3,
                "Approved for separate operator review",
            ),
        );
    });
});
