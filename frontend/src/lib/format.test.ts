import { describe, expect, it } from "vitest";
import { formatDuration, formatNumber, relativeTime } from "./format";

describe("formatDuration", () => {
  it("renders null as a placeholder rather than 'NaN'", () => {
    // MTTD/MTTR are legitimately null when a tenant has no data yet.
    expect(formatDuration(null)).toBe("--");
    expect(formatDuration(Number.NaN)).toBe("--");
  });

  it("scales the unit to the magnitude", () => {
    expect(formatDuration(45)).toBe("45s");
    expect(formatDuration(600)).toBe("10m");
    expect(formatDuration(5400)).toBe("1.5h");
    expect(formatDuration(172800)).toBe("2.0d");
  });

  it("handles zero", () => {
    expect(formatDuration(0)).toBe("0s");
  });
});

describe("formatNumber", () => {
  it("groups digits using the viewer's locale without altering them", () => {
    // Asserted locale-independently on purpose: grouping differs by locale
    // (en-US "1,234,567" vs en-IN "12,34,567"), and respecting the viewer's
    // locale is the intended behaviour. What must hold is that the digits are
    // unchanged and separators were added.
    const rendered = formatNumber(1234567);
    expect(rendered.replace(/\D/g, "")).toBe("1234567");
    expect(rendered.length).toBeGreaterThan(7);
  });

  it("leaves small numbers alone", () => {
    expect(formatNumber(42)).toBe("42");
    expect(formatNumber(0)).toBe("0");
  });
});

describe("relativeTime", () => {
  const now = new Date("2026-06-15T12:00:00Z").getTime();

  it("collapses very recent times", () => {
    expect(relativeTime("2026-06-15T11:59:40Z", now)).toBe("just now");
  });

  it("renders minutes, hours and days", () => {
    expect(relativeTime("2026-06-15T11:50:00Z", now)).toBe("10 minutes ago");
    expect(relativeTime("2026-06-15T09:00:00Z", now)).toBe("3 hours ago");
    expect(relativeTime("2026-06-12T12:00:00Z", now)).toBe("3 days ago");
  });

  it("singularizes correctly", () => {
    expect(relativeTime("2026-06-15T11:00:00Z", now)).toBe("1 hour ago");
  });

  it("handles a future timestamp", () => {
    // A signed download URL's expiry is in the future.
    expect(relativeTime("2026-06-15T13:00:00Z", now)).toBe("1 hour from now");
  });
});
