import { describe, expect, it, vi } from "vitest";

import { HttpBackendApi } from "./client";
import { ALERT_PAGE, SAMPLE_SESSION } from "../test/fixtures";

describe("HttpBackendApi", () => {
  it("serializes authoritative alert filters and never adds an ingestion key", async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(ALERT_PAGE), { status: 200 }));
    const client = new HttpBackendApi("http://backend.test", fetcher);

    await client.listAlerts({
      ruleLevels: [0, 16],
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
    expect(parsed.searchParams.get("mitre_mapped")).toBe("false");
    expect(parsed.searchParams.get("cursor")).toBe("opaque");
    expect(JSON.stringify(init.headers).toLowerCase()).not.toContain("api-key");
    expect(init.credentials).toBe("include");
  });

  it("maps structured backend conflicts into ApiError", async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: { code: "invalid_status_transition", message: "Transition rejected", field: "status" } }), { status: 409 }));
    const client = new HttpBackendApi("http://backend.test", fetcher);

    await expect(client.updateIncidentStatus("INC-1", { status: "TRIAGED" })).rejects.toMatchObject({
      status: 409,
      code: "invalid_status_transition",
      field: "status",
    });
  });

  it("keeps the session cookie opaque and adds CSRF only to authenticated mutations", async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(SAMPLE_SESSION), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ...ALERT_PAGE.items[0], incident_id: undefined }), { status: 500 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const client = new HttpBackendApi("http://backend.test", fetcher);

    await client.login({ username: "analyst-1", password: "not-persisted" });
    await expect(client.createIncident({ title: "Case", severity: "HIGH" })).rejects.toBeInstanceOf(Error);
    await client.logout();

    const loginInit = fetcher.mock.calls[0][1] as RequestInit;
    const mutationInit = fetcher.mock.calls[1][1] as RequestInit;
    const logoutInit = fetcher.mock.calls[2][1] as RequestInit;
    expect(loginInit.credentials).toBe("include");
    expect(new Headers(loginInit.headers).has("X-CSRF-Token")).toBe(false);
    expect(new Headers(mutationInit.headers).get("X-CSRF-Token")).toBe("csrf-test-token");
    expect(new Headers(logoutInit.headers).get("X-CSRF-Token")).toBe("csrf-test-token");
  });

  it("rejects successful responses containing malformed JSON", async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response("not-json", { status: 200 }));
    const client = new HttpBackendApi("http://backend.test", fetcher);
    await expect(client.health()).rejects.toMatchObject({ code: "invalid_response" });
  });
});
