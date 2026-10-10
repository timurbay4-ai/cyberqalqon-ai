import { describe, expect, it, vi } from "vitest";

import { HttpBackendApi, resolveApiBaseUrl } from "./client";
import {
    ALERT_PAGE,
    SAMPLE_AI_ANALYSIS,
    SAMPLE_HUNT_PAGE,
    SAMPLE_RULE_DRAFT,
    SAMPLE_SESSION,
} from "../test/fixtures";

describe("HttpBackendApi", () => {
    it("defaults to the browser origin so host-only Strict cookies remain same-site", () => {
        expect(resolveApiBaseUrl(undefined)).toBe("");
        expect(resolveApiBaseUrl("  ")).toBe("");
        expect(resolveApiBaseUrl(" http://api.internal:8000 ")).toBe(
            "http://api.internal:8000",
        );
    });

    it("supports the production same-origin boundary without a host override", async () => {
        const fetcher = vi.fn().mockResolvedValue(
            new Response(
                JSON.stringify({
                    status: "ok",
                    service: "cyberqalqon-backend",
                }),
                {
                    status: 200,
                },
            ),
        );
        const client = new HttpBackendApi("", fetcher);

        await client.health();

        expect(fetcher.mock.calls[0][0]).toBe("/health");
    });

    it("does not rebind the browser-native fetch receiver", async () => {
        const nativeLikeFetch = vi.fn(function (this: unknown) {
            if (this instanceof HttpBackendApi)
                throw new TypeError("Illegal invocation");
            return Promise.resolve(
                new Response(
                    JSON.stringify({
                        status: "ok",
                        service: "cyberqalqon-backend",
                    }),
                    { status: 200 },
                ),
            );
        });
        vi.stubGlobal("fetch", nativeLikeFetch);
        try {
            const client = new HttpBackendApi("");
            await expect(client.health()).resolves.toEqual({
                status: "ok",
                service: "cyberqalqon-backend",
            });
            expect(nativeLikeFetch).toHaveBeenCalledOnce();
        } finally {
            vi.unstubAllGlobals();
        }
    });

    it("serializes authoritative alert filters and never adds an ingestion key", async () => {
        const fetcher = vi
            .fn()
            .mockResolvedValue(
                new Response(JSON.stringify(ALERT_PAGE), { status: 200 }),
            );
        const client = new HttpBackendApi("http://backend.test", fetcher);

        await client.listAlerts({
            ruleLevels: [0, 16],
            ruleId: "100101",
            agent: "host-1",
            mitreMapped: false,
            mitreId: "T1110",
            startTime: "2026-10-01T00:00:00Z",
            endTime: "2026-10-07T00:00:00Z",
            search: "authentication",
            limit: 25,
            cursor: "opaque",
        });

        const [url, init] = fetcher.mock.calls[0] as [string, RequestInit];
        const parsed = new URL(url);
        expect(parsed.pathname).toBe("/api/v1/alerts");
        expect(parsed.searchParams.getAll("rule_level")).toEqual(["0", "16"]);
        expect(parsed.searchParams.get("rule_id")).toBe("100101");
        expect(parsed.searchParams.get("mitre_mapped")).toBe("false");
        expect(parsed.searchParams.get("cursor")).toBe("opaque");
        expect(JSON.stringify(init.headers).toLowerCase()).not.toContain(
            "api-key",
        );
        expect(init.credentials).toBe("include");
    });

    it("maps structured backend conflicts into ApiError", async () => {
        const fetcher = vi
            .fn()
            .mockResolvedValue(
                new Response(
                    JSON.stringify({
                        detail: {
                            code: "invalid_status_transition",
                            message: "Transition rejected",
                            field: "status",
                        },
                    }),
                    { status: 409 },
                ),
            );
        const client = new HttpBackendApi("http://backend.test", fetcher);

        await expect(
            client.updateIncidentStatus("INC-1", { status: "TRIAGED" }),
        ).rejects.toMatchObject({
            status: 409,
            code: "invalid_status_transition",
            field: "status",
        });
    });

    it("keeps the session cookie opaque and adds CSRF only to authenticated mutations", async () => {
        const fetcher = vi
            .fn()
            .mockResolvedValueOnce(
                new Response(JSON.stringify(SAMPLE_SESSION), { status: 200 }),
            )
            .mockResolvedValueOnce(
                new Response(
                    JSON.stringify({
                        ...ALERT_PAGE.items[0],
                        incident_id: undefined,
                    }),
                    { status: 500 },
                ),
            )
            .mockResolvedValueOnce(new Response(null, { status: 204 }));
        const client = new HttpBackendApi("http://backend.test", fetcher);

        await client.login({
            username: "analyst-1",
            password: "not-persisted",
        });
        await expect(
            client.createIncident({ title: "Case", severity: "HIGH" }),
        ).rejects.toBeInstanceOf(Error);
        await client.logout();

        const loginInit = fetcher.mock.calls[0][1] as RequestInit;
        const mutationInit = fetcher.mock.calls[1][1] as RequestInit;
        const logoutInit = fetcher.mock.calls[2][1] as RequestInit;
        expect(loginInit.credentials).toBe("include");
        expect(new Headers(loginInit.headers).has("X-CSRF-Token")).toBe(false);
        expect(new Headers(mutationInit.headers).get("X-CSRF-Token")).toBe(
            "csrf-test-token",
        );
        expect(new Headers(logoutInit.headers).get("X-CSRF-Token")).toBe(
            "csrf-test-token",
        );
    });

    it("rejects successful responses containing malformed JSON", async () => {
        const fetcher = vi
            .fn()
            .mockResolvedValue(new Response("not-json", { status: 200 }));
        const client = new HttpBackendApi("http://backend.test", fetcher);
        await expect(client.health()).rejects.toMatchObject({
            code: "invalid_response",
        });
    });

    it("sends only an alert identifier and bounded question through the CSRF-protected backend boundary", async () => {
        const fetcher = vi
            .fn()
            .mockResolvedValueOnce(
                new Response(JSON.stringify(SAMPLE_SESSION), { status: 200 }),
            )
            .mockResolvedValueOnce(
                new Response(JSON.stringify(SAMPLE_AI_ANALYSIS), {
                    status: 200,
                }),
            );
        const client = new HttpBackendApi("http://backend.test", fetcher);
        await client.login({
            username: "analyst-1",
            password: "not-persisted",
        });
        await client.analyzeAlert("alert/with spaces", {
            question: "What next?",
        });

        const [url, init] = fetcher.mock.calls[1] as [string, RequestInit];
        expect(new URL(url).pathname).toBe(
            "/api/v1/ai/alerts/alert%2Fwith%20spaces/analyze",
        );
        expect(JSON.parse(String(init.body))).toEqual({
            question: "What next?",
        });
        expect(new Headers(init.headers).get("X-CSRF-Token")).toBe(
            "csrf-test-token",
        );
        expect(JSON.stringify(init)).not.toContain("X-API-Key");
        expect(url).not.toContain("11434");
    });

    it("notifies the application when an AI request reports session expiry", async () => {
        const fetcher = vi
            .fn()
            .mockResolvedValue(
                new Response(
                    JSON.stringify({
                        detail: {
                            code: "authentication_required",
                            message: "Session expired",
                        },
                    }),
                    { status: 401 },
                ),
            );
        const client = new HttpBackendApi("http://backend.test", fetcher);
        const expired = vi.fn();
        client.subscribeUnauthorized(expired);
        await expect(client.analyzeAlert("alert-1")).rejects.toMatchObject({
            status: 401,
            code: "authentication_required",
        });
        expect(expired).toHaveBeenCalledOnce();
    });

    it("downloads bounded report exports with the server-provided safe filename", async () => {
        const fetcher = vi.fn().mockResolvedValue(
            new Response('{"total_events":0}', {
                status: 200,
                headers: {
                    "Content-Disposition":
                        "attachment; filename=cyberqalqon-security-activity-20261008T120000Z.json",
                    "Content-Type": "application/json",
                },
            }),
        );
        const client = new HttpBackendApi("http://backend.test", fetcher);

        const result = await client.downloadSecurityActivityReport(
            { ruleId: "100101" },
            "json",
        );

        expect(fetcher.mock.calls[0][0]).toContain(
            "/api/v1/reports/security-activity.json?rule_id=100101",
        );
        expect(result.filename).toBe(
            "cyberqalqon-security-activity-20261008T120000Z.json",
        );
        expect(await result.blob.text()).toContain("total_events");
    });

    it("does not clear a valid session for an unrelated API failure", async () => {
        const fetcher = vi
            .fn()
            .mockResolvedValue(
                new Response(
                    JSON.stringify({
                        detail: {
                            code: "backend_failure",
                            message: "Temporary failure",
                        },
                    }),
                    { status: 500 },
                ),
            );
        const client = new HttpBackendApi("", fetcher);
        const expired = vi.fn();
        client.subscribeUnauthorized(expired);

        await expect(client.listAlerts()).rejects.toMatchObject({
            status: 500,
        });

        expect(expired).not.toHaveBeenCalled();
    });

    it("keeps bootstrap session checks from broadcasting an unauthenticated state", async () => {
        const fetcher = vi
            .fn()
            .mockResolvedValue(
                new Response(
                    JSON.stringify({
                        detail: {
                            code: "authentication_required",
                            message: "Sign in",
                        },
                    }),
                    { status: 401 },
                ),
            );
        const client = new HttpBackendApi("", fetcher);
        const expired = vi.fn();
        client.subscribeUnauthorized(expired);

        await expect(client.getSession()).rejects.toMatchObject({
            status: 401,
        });

        expect(expired).not.toHaveBeenCalled();
    });

    it("sends credentials on concurrent dashboard reads", async () => {
        const fetcher = vi
            .fn()
            .mockResolvedValueOnce(
                new Response(JSON.stringify(ALERT_PAGE), { status: 200 }),
            )
            .mockResolvedValueOnce(
                new Response(
                    JSON.stringify({
                        items: [],
                        page: { limit: 25, next_cursor: null, total: 0 },
                    }),
                    { status: 200 },
                ),
            );
        const client = new HttpBackendApi("", fetcher);

        await Promise.all([
            client.listAlerts({ limit: 1 }),
            client.listIncidents({ limit: 1 }),
        ]);

        expect(fetcher).toHaveBeenCalledTimes(2);
        expect(
            fetcher.mock.calls.every(
                ([, init]) => (init as RequestInit).credentials === "include",
            ),
        ).toBe(true);
    });

    it("serializes bounded report ranges without adding secrets", async () => {
        const report = {
            start_time: "2026-10-07T00:00:00Z",
            end_time: "2026-10-08T00:00:00Z",
            generated_at: "2026-10-08T00:00:01Z",
            filters: {
                severity_min: null,
                severity_max: null,
                host: null,
                rule_id: null,
            },
            total_events: 1,
            total_alerts: 0,
            total_incidents: 0,
            event_sources: [],
            alert_severities: [],
            top_rules: [],
            host_activity: [],
            authentication_failures: 0,
            file_integrity_events: 0,
        };
        const fetcher = vi
            .fn()
            .mockResolvedValue(
                new Response(JSON.stringify(report), { status: 200 }),
            );
        const client = new HttpBackendApi("http://backend.test", fetcher);
        await client.getSecurityActivityReport({
            startTime: report.start_time,
            endTime: report.end_time,
        });
        const [url, init] = fetcher.mock.calls[0] as [string, RequestInit];
        const parsed = new URL(url);
        expect(parsed.pathname).toBe("/api/v1/reports/security-activity");
        expect(parsed.searchParams.get("start_time")).toBe(report.start_time);
        expect(JSON.stringify(init)).not.toContain("X-API-Key");
        expect(init.credentials).toBe("include");
    });

    it("serializes bounded hunts and protects detection dry-runs with CSRF", async () => {
        const dryRun = {
            draft: { ...SAMPLE_RULE_DRAFT, status: "TESTED", version: 3 },
            start_time: "2026-10-08T00:00:00Z",
            end_time: "2026-10-09T00:00:00Z",
            evaluated_event_count: 1000,
            match_count: 17,
            matched_event_ids: [],
            execution_ms: 4.2,
            result_ids_truncated: false,
            side_effects: false,
        };
        const fetcher = vi
            .fn()
            .mockResolvedValueOnce(
                new Response(JSON.stringify(SAMPLE_SESSION), { status: 200 }),
            )
            .mockResolvedValueOnce(
                new Response(JSON.stringify(SAMPLE_HUNT_PAGE), { status: 200 }),
            )
            .mockResolvedValueOnce(
                new Response(JSON.stringify(dryRun), { status: 200 }),
            );
        const client = new HttpBackendApi("http://backend.test", fetcher);
        await client.login({
            username: "analyst-1",
            password: "not-persisted",
        });
        await client.runThreatHunt({
            relativeMinutes: 43200,
            ip: "192.0.2.25",
            mitreId: "T1046",
            limit: 100,
        });
        await client.dryRunRuleDraft("DRF/one", {
            expected_version: 2,
            relative_minutes: 43200,
            max_events: 1000,
        });

        const huntUrl = new URL(fetcher.mock.calls[1][0] as string);
        expect(huntUrl.pathname).toBe("/api/v1/threat-hunts");
        expect(huntUrl.searchParams.get("relative_minutes")).toBe("43200");
        expect(huntUrl.searchParams.get("mitre_id")).toBe("T1046");
        expect(huntUrl.searchParams.get("limit")).toBe("100");
        const [dryRunUrl, dryRunInit] = fetcher.mock.calls[2] as [
            string,
            RequestInit,
        ];
        expect(new URL(dryRunUrl).pathname).toBe(
            "/api/v1/detection-engineering/drafts/DRF%2Fone/dry-run",
        );
        expect(new Headers(dryRunInit.headers).get("X-CSRF-Token")).toBe(
            "csrf-test-token",
        );
        expect(JSON.parse(String(dryRunInit.body))).toEqual({
            expected_version: 2,
            relative_minutes: 43200,
            max_events: 1000,
        });
    });
});
