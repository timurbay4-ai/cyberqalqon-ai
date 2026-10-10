import { describe, expect, it } from "vitest";

import { formatRelativeTimestamp, formatTimestamp, toApiTimestamp } from "./format";

describe("timestamp formatting", () => {
  it("includes an absolute local timezone label", () => {
    expect(formatTimestamp("2026-10-08T12:00:00Z")).toMatch(/2026/);
    expect(formatTimestamp("2026-10-08T12:00:00Z")).toMatch(/(?:UTC|GMT|[A-Z]{2,5}|GMT[+-]\d+)/);
  });

  it("handles past, future, and malformed timestamps truthfully", () => {
    const now = Date.parse("2026-10-08T12:00:00Z");
    expect(formatRelativeTimestamp("2026-10-08T11:58:00Z", now)).toBe("2 minutes ago");
    expect(formatRelativeTimestamp("2026-10-08T12:02:00Z", now)).toBe("in 2 minutes");
    expect(formatRelativeTimestamp("not-a-date", now)).toBe("not-a-date");
    expect(formatTimestamp("not-a-date")).toBe("not-a-date");
  });

  it("converts offset-aware local input through the browser date model", () => {
    expect(toApiTimestamp("2026-10-08T12:00")).toMatch(/^2026-10-08T\d{2}:00:00\.000Z$/);
    expect(toApiTimestamp("impossible")).toBeUndefined();
  });
});
