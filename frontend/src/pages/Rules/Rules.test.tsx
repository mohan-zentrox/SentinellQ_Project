/**
 * Rule authoring. The dry-run path is the important one: it must not create
 * anything, and an invalid condition must be caught before a save is attempted.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import Rules from "./Rules";
import { mockApi, renderWithRouter, signIn } from "../../test/helpers";

const COVERAGE = {
  totalRules: 1,
  enabledRules: 1,
  rulesWithMatches: 0,
  neverMatchedRules: [
    { ruleId: "rule_1", name: "Silent rule", severity: "high", isEnabled: true, lastEvaluatedAt: null },
  ],
  topRules: [],
};

function rule(overrides: Record<string, unknown> = {}) {
  return {
    id: "rule_1",
    tenantId: "ten_test",
    name: "Failed logins",
    description: "",
    condition: { field: "event_action", op: "eq", value: "login_failed" },
    severity: "high",
    isEnabled: true,
    evaluationWindowMinutes: null,
    lastEvaluatedAt: null,
    lastMatchedAt: null,
    matchCount: 0,
    createdAt: new Date().toISOString(),
    ...overrides,
  };
}

describe("Rules", () => {
  beforeEach(() => {
    signIn("admin");
    vi.stubGlobal("confirm", vi.fn(() => true));
  });

  it("lists rules with their condition and match count", async () => {
    mockApi({
      routes: {
        "GET /detection-rules": [rule({ matchCount: 7 })],
        "GET /analytics/detection-coverage": COVERAGE,
      },
    });
    await renderWithRouter(<Rules />);

    expect(await screen.findByText("Failed logins")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
    expect(screen.getByText(/"event_action"/)).toBeInTheDocument();
  });

  it("surfaces rules that have never matched", async () => {
    mockApi({
      routes: {
        "GET /detection-rules": [rule()],
        "GET /analytics/detection-coverage": COVERAGE,
      },
    });
    await renderWithRouter(<Rules />);

    expect(await screen.findByText(/have never matched/)).toBeInTheDocument();
  });

  it("dry-runs a condition without creating a rule or an alert", async () => {
    const mock = mockApi({
      routes: {
        "GET /detection-rules": [],
        "GET /analytics/detection-coverage": { ...COVERAGE, totalRules: 0, enabledRules: 0 },
        "POST /detection-rules/test": { sampled: 120, matched: 4, matchedEventIds: ["evt_1"] },
      },
    });
    await renderWithRouter(<Rules />);

    await userEvent.click(screen.getByRole("button", { name: /new rule/i }));
    await userEvent.click(screen.getByRole("button", { name: /dry run against recent events/i }));

    expect(await screen.findByText(/Matched/)).toBeInTheDocument();
    expect(screen.getByText("4")).toBeInTheDocument();

    // Nothing was created: only the test endpoint was called.
    expect(mock.calls.filter((call) => call.method === "POST" && call.path === "/detection-rules")).toHaveLength(0);
    expect(mock.callsTo("POST /detection-rules/test")).toHaveLength(1);
  });

  it("rejects malformed condition JSON client-side before calling the API", async () => {
    const mock = mockApi({
      routes: {
        "GET /detection-rules": [],
        "GET /analytics/detection-coverage": { ...COVERAGE, totalRules: 0 },
      },
    });
    await renderWithRouter(<Rules />);

    await userEvent.click(screen.getByRole("button", { name: /new rule/i }));
    const textarea = screen.getByLabelText(/Condition \(JSON\)/);
    await userEvent.clear(textarea);
    await userEvent.type(textarea, "{{not json");
    await userEvent.type(screen.getByLabelText("Name"), "Broken");
    await userEvent.click(screen.getByRole("button", { name: /create rule/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/not valid JSON/);
    expect(mock.calls.filter((call) => call.method === "POST")).toHaveLength(0);
  });

  it("creates a rule with the parsed condition", async () => {
    const mock = mockApi({
      routes: {
        "GET /detection-rules": [],
        "GET /analytics/detection-coverage": { ...COVERAGE, totalRules: 0 },
        "POST /detection-rules": rule({ name: "Criticals" }),
      },
    });
    await renderWithRouter(<Rules />);

    await userEvent.click(screen.getByRole("button", { name: /new rule/i }));
    await userEvent.type(screen.getByLabelText("Name"), "Criticals");
    await userEvent.click(screen.getByRole("button", { name: /create rule/i }));

    await waitFor(() => {
      const posts = mock.calls.filter((call) => call.method === "POST" && call.path === "/detection-rules");
      expect(posts).toHaveLength(1);
      const body = posts[0].body as Record<string, unknown>;
      expect(body.name).toBe("Criticals");
      // The default example condition is pre-filled and parsed to an object.
      expect(body.condition).toEqual({ field: "severity_hint", op: "eq", value: "critical" });
    });
  });

  it("toggles a rule's enabled state", async () => {
    const mock = mockApi({
      routes: {
        "GET /detection-rules": [rule({ isEnabled: true })],
        "GET /analytics/detection-coverage": COVERAGE,
        "PATCH /detection-rules/rule_1": rule({ isEnabled: false }),
      },
    });
    await renderWithRouter(<Rules />);

    await screen.findByText("Failed logins");
    await userEvent.click(screen.getByRole("button", { name: /^disable$/i }));

    await waitFor(() => {
      expect(mock.callsTo("PATCH /detection-rules/rule_1")[0].body).toEqual({ isEnabled: false });
    });
  });

  it("hides destructive controls from an analyst", async () => {
    signIn("analyst");
    mockApi({
      routes: {
        "GET /detection-rules": [rule()],
        "GET /analytics/detection-coverage": COVERAGE,
      },
    });
    await renderWithRouter(<Rules />);

    await screen.findByText("Failed logins");
    // Analysts may author and edit, but deleting is admin+.
    expect(screen.getByRole("button", { name: /^edit$/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^delete$/i })).not.toBeInTheDocument();
  });

  it("warns when no rules exist, since telemetry then produces no alerts", async () => {
    mockApi({
      routes: {
        "GET /detection-rules": [],
        "GET /analytics/detection-coverage": { ...COVERAGE, totalRules: 0, enabledRules: 0, neverMatchedRules: [] },
      },
    });
    await renderWithRouter(<Rules />);

    expect(await screen.findByText(/No detection rules yet/)).toBeInTheDocument();
    expect(screen.getByText(/never produces an alert/)).toBeInTheDocument();
  });
});
