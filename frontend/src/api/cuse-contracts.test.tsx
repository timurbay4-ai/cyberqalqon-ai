import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { parseCUSEMetadata, parseSecurityEvent } from "./contracts";
import { EventSourceContext } from "../components/event-source-context";
import { SAMPLE_EVENT } from "../test/fixtures";

const cuse = {
  version: "cuse-v1", adapter_version: "m28-v1", source_family: "SYSMON",
  normalization_status: "NORMALIZED", provenance_status: "PARTIAL",
  historical_continuity: "UNPROVEN", transport_authenticated: true,
  endpoint_identity_verified: false, source_event_time: "2026-10-22T08:00:00Z",
  collector_observation_time: "2026-10-22T08:00:01Z", timestamp_basis: "SOURCE_EVENT_TIME",
  original_event_identity: "928", source_identity_sha256: "a".repeat(64),
  content_fingerprint: "b".repeat(64), idempotency_contract: "LEGACY_RAW_ENVELOPE_SHA256",
  delivery_identity: null, source_generation: null, warnings: ["SOURCE_IDENTITY_CLAIMED"],
  attributes: { process_guid: "SYNTHETIC-GUID", dns_query_name: "synthetic.example.invalid" },
};

describe("CUSE source context", () => {
  it("accepts new metadata and leaves older event detail compatible", () => {
    expect(parseCUSEMetadata(cuse)?.source_family).toBe("SYSMON");
    expect(parseSecurityEvent(SAMPLE_EVENT).cuse).toBeNull();
    expect(parseSecurityEvent({ ...SAMPLE_EVENT, cuse }).cuse?.historical_continuity).toBe("UNPROVEN");
  });

  it.each([
    { provenance_status: "VERIFIED" }, { endpoint_identity_verified: true },
    { source_generation: "claimed-generation" }, { source_family: "UNRECOGNIZED" },
    { content_fingerprint: "bad" }, { source_event_time: "invalid" },
    { source_event_time: "2026-10-22T08:00:00" }, { source_event_time: null },
    { attributes: { nested: { password: "synthetic" } } },
  ])("rejects incompatible or misleading metadata %# %o", (patch) => {
    expect(() => parseCUSEMetadata({ ...cuse, ...patch })).toThrow();
  });

  it("shows source family, partial provenance, and source attributes", () => {
    render(<EventSourceContext event={parseSecurityEvent({ ...SAMPLE_EVENT, cuse })} />);
    expect(screen.getByText("Sysmon")).toBeInTheDocument();
    expect(screen.getByText("PARTIAL")).toBeInTheDocument();
    expect(screen.getByText("Not independently verified")).toBeInTheDocument();
    expect(screen.getByText("synthetic.example.invalid")).toBeInTheDocument();
  });

  it("displays unknown source context on legacy events", () => {
    render(<EventSourceContext event={SAMPLE_EVENT} />);
    expect(screen.getAllByText("UNKNOWN").length).toBeGreaterThan(2);
  });
});
