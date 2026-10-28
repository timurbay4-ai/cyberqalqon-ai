import { describe, expect, it } from "vitest";

import { SAMPLE_EVENT } from "../test/fixtures";
import { ContractError, parseCQQLAnalyticsResponse, parseCQQLFieldCatalog, parseCQQLSearchResponse } from "./contracts";

describe("CQQL runtime contracts", () => {
    it("accepts the bounded search envelope", () => {
        const parsed = parseCQQLSearchResponse({
            items: [SAMPLE_EVENT],
            page: {
                limit: 25,
                next_cursor: "opaque-cursor",
                count_mode: "UNKNOWN",
                sort: "newest",
            },
            metadata: {
                version: "cqql-v1",
                execution_ms: 4.25,
                query_status: "COMPLETE",
                warnings: ["Exact result count is intentionally not computed."],
                truncated: true,
                data_freshness: "2026-10-21T07:00:00Z",
                clause_count: 2,
                ast_depth: 2,
                fts_used: false,
                cost_class: "LOW",
                plan_class: "INDEX_FRIENDLY",
                planner_strategy: "DEFAULT",
                diagnostic_reasons: ["INDEXED_EQUALITY"],
            },
        });
        expect(parsed.page.total).toBeNull();
        expect(parsed.metadata.execution_ms).toBe(4.25);
        expect(parsed.items[0].event_id).toBe(SAMPLE_EVENT.event_id);
    });

    it("rejects fabricated totals and malformed metadata", () => {
        expect(() => parseCQQLSearchResponse({
            items: [],
            page: { limit: 25, total: 999, count_mode: "UNKNOWN", sort: "newest" },
            metadata: {
                version: "cqql-v1",
                execution_ms: -1,
                query_status: "COMPLETE",
                warnings: [],
                truncated: false,
                clause_count: 1,
                ast_depth: 1,
                fts_used: false,
                cost_class: "LOW",
                plan_class: "INDEX_FRIENDLY",
                planner_strategy: "DEFAULT",
                diagnostic_reasons: ["INDEXED_EQUALITY"],
            },
        })).toThrow(ContractError);
    });

    it("validates the server field catalog", () => {
        const catalog = parseCQQLFieldCatalog({
            version: "cqql-v1",
            fields: [{
                name: "source.ip",
                data_type: "ip",
                operators: ["=", "!="],
                indexed: true,
                sensitivity: "network",
                source: "security_events.source_ip",
                derived: false,
                searchable: true,
            }],
            limits: {
                maximum_query_length: 2000,
                maximum_tokens: 256,
                maximum_ast_depth: 8,
                maximum_boolean_clauses: 32,
                maximum_page_size: 100,
                maximum_time_range_days: 31,
                execution_deadline_ms: 1500,
                maximum_concurrent_queries: 4,
            },
        });
        expect(catalog.fields[0]).toMatchObject({ name: "source.ip", indexed: true });
    });

    it.each(["source.ip", "event.provider"])("validates exact bounded analytics for %s", (field) => {
        const analytics = parseCQQLAnalyticsResponse({
            version: "cqql-v1", query_status: "COMPLETE", execution_ms: 3.5,
            completeness: "EXACT_WITHIN_BOUNDED_RANGE", sparse_time_series: true,
            matching_events: 4, clause_count: 1, fts_used: false,
            groups: [{ field, buckets: [{ name: "SYNTHETIC-provider-or-IP", count: 4 }], truncated: false }],
            time_series: [{ timestamp: "2026-10-21T07:00:00Z", count: 4 }],
        });
        expect(analytics.groups[0].buckets[0].count).toBe(4);
        expect(analytics.time_series[0].timestamp).toBe("2026-10-21T07:00:00Z");
    });
});
