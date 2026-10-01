/**
 * Formatting helpers.
 *
 * In their own module rather than alongside the components in `ui.tsx`: a file
 * that mixes component and non-component exports breaks React Fast Refresh, so
 * editing a helper would force a full page reload instead of a hot update.
 */
import type { Severity } from "../api/types";

export function formatDuration(seconds: number | null): string {
  if (seconds === null || Number.isNaN(seconds)) return "--";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`;
  return `${(seconds / 86400).toFixed(1)}d`;
}

export function formatNumber(value: number): string {
  return value.toLocaleString();
}

/** Relative time label, e.g. "3 hours ago". `now` is injectable for tests. */
export function relativeTime(value: string, now: number = Date.now()): string {
  const date = new Date(value);
  const seconds = Math.floor((now - date.getTime()) / 1000);
  if (Math.abs(seconds) < 45) return "just now";

  const units: [number, string][] = [
    [60, "second"],
    [60, "minute"],
    [24, "hour"],
    [7, "day"],
    [4.35, "week"],
    [12, "month"],
  ];
  let amount = Math.abs(seconds);
  let unit = "second";
  for (const [step, name] of units) {
    if (amount < step) {
      unit = name;
      break;
    }
    amount = amount / step;
    unit = name;
  }
  const rounded = Math.floor(amount);
  const suffix = seconds < 0 ? "from now" : "ago";
  return `${rounded} ${unit}${rounded === 1 ? "" : "s"} ${suffix}`;
}

export const SEVERITY_OPTIONS: Severity[] = ["informational", "low", "medium", "high", "critical"];
