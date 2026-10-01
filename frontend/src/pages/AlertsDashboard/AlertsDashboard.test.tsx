/**
 * The triage flow, which is the behaviour that did not exist before.
 *
 * These assert on the *requests sent*, not just on rendered text: dismissing one
 * alert must PATCH that alert, and dismissing several must use the collection
 * PATCH rather than N individual calls.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import AlertsDashboard from "./AlertsDashboard";
import { fixtures, mockApi, renderWithRouter, signIn } from "../../test/helpers";

const TRENDS = { periodStart: "", periodEnd: "", bucketHours: 24, buckets: [] };

/** The stubbed fetch, typed for assertions on the URLs it was called with. */
function fetchCalls(): string[] {
  const stub = globalThis.fetch as unknown as { mock?: { calls: unknown[][] } };
  return (stub.mock?.calls ?? []).map((call) => String(call[0]));
}


function baseRoutes(alerts: unknown[]) {
  return {
    "GET /alerts": fixtures.paginated(alerts),
    "GET /analytics/kpis": fixtures.kpis(),
    "GET /analytics/alerts/timeseries": TRENDS,
  };
}

describe("AlertsDashboard", () => {
  beforeEach(() => {
    signIn("analyst");
    // window.prompt is how the reason is collected; jsdom does not implement it.
    vi.stubGlobal("prompt", vi.fn(() => "known scanner"));
    vi.stubGlobal("confirm", vi.fn(() => true));
  });

  it("renders the KPI tiles including the false-positive rate", async () => {
    mockApi({ routes: baseRoutes([fixtures.alert()]) });
    await renderWithRouter(<AlertsDashboard />);

    expect(await screen.findByText("False positive rate")).toBeInTheDocument();
    // 1 of 2 alerts dismissed -> 50.0%
    expect(screen.getByText("50.0%")).toBeInTheDocument();
    expect(screen.getByText("MTTD")).toBeInTheDocument();
  });

  it("lists alerts with their severity and detection source", async () => {
    mockApi({
      routes: baseRoutes([
        fixtures.alert({ id: "alrt_1", title: "Brute force detected" }),
        fixtures.alert({ id: "alrt_2", title: "Anomalous activity", detectionSource: "ml", mlScore: 0.93 }),
      ]),
    });
    await renderWithRouter(<AlertsDashboard />);

    expect(await screen.findByText("Brute force detected")).toBeInTheDocument();
    expect(screen.getByText("Anomalous activity")).toBeInTheDocument();
    expect(screen.getByText("ml")).toBeInTheDocument();
    expect(screen.getByText("0.93")).toBeInTheDocument();
  });

  it("dismisses a single selected alert via PATCH /alerts/{id} with a reason", async () => {
    const mock = mockApi({
      routes: {
        ...baseRoutes([fixtures.alert({ id: "alrt_1" })]),
        "PATCH /alerts/alrt_1": fixtures.alert({ id: "alrt_1", status: "dismissed" }),
      },
    });
    await renderWithRouter(<AlertsDashboard />);

    await screen.findByText("Rule triggered: failed logins");
    await userEvent.click(screen.getByLabelText("Select Rule triggered: failed logins"));
    await userEvent.click(screen.getByRole("button", { name: /dismiss as false positive/i }));

    await waitFor(() => {
      const patches = mock.callsTo("PATCH /alerts/alrt_1");
      expect(patches).toHaveLength(1);
      expect(patches[0].body).toEqual({ status: "dismissed", reason: "known scanner" });
    });
  });

  it("uses the bulk endpoint when several alerts are selected", async () => {
    const mock = mockApi({
      routes: {
        ...baseRoutes([
          fixtures.alert({ id: "alrt_1", title: "First" }),
          fixtures.alert({ id: "alrt_2", title: "Second" }),
        ]),
        "PATCH /alerts": { updated: 2, alertIds: ["alrt_1", "alrt_2"] },
      },
    });
    await renderWithRouter(<AlertsDashboard />);

    await screen.findByText("First");
    await userEvent.click(screen.getByLabelText("Select all alerts"));
    await userEvent.click(screen.getByRole("button", { name: /dismiss as false positive/i }));

    await waitFor(() => {
      const bulk = mock.calls.filter((call) => call.method === "PATCH" && call.path === "/alerts");
      expect(bulk).toHaveLength(1);
      expect(bulk[0].body).toEqual({
        alertIds: ["alrt_1", "alrt_2"],
        status: "dismissed",
        reason: "known scanner",
      });
    });
  });

  it("does not offer selection for an already-promoted alert", async () => {
    mockApi({
      routes: baseRoutes([
        fixtures.alert({ id: "alrt_1", title: "Promoted one", status: "promoted", caseId: "case_1" }),
      ]),
    });
    await renderWithRouter(<AlertsDashboard />);

    await screen.findByText("Promoted one");
    expect(screen.queryByLabelText("Select Promoted one")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /view case/i })).toBeInTheDocument();
  });

  it("hides triage controls from a viewer", async () => {
    signIn("viewer");
    mockApi({ routes: baseRoutes([fixtures.alert()]) });
    await renderWithRouter(<AlertsDashboard />);

    await screen.findByText("Rule triggered: failed logins");
    expect(screen.queryByLabelText("Select all alerts")).not.toBeInTheDocument();
  });

  it("offers reopening a dismissed alert", async () => {
    const mock = mockApi({
      routes: {
        ...baseRoutes([
          fixtures.alert({
            id: "alrt_1",
            status: "dismissed",
            dismissReason: "noisy rule",
          }),
        ]),
        "PATCH /alerts/alrt_1": fixtures.alert({ id: "alrt_1", status: "open" }),
      },
    });
    await renderWithRouter(<AlertsDashboard />);

    await screen.findByText(/Dismissed: noisy rule/);
    await userEvent.click(screen.getByRole("button", { name: /reopen/i }));

    await waitFor(() => {
      expect(mock.callsTo("PATCH /alerts/alrt_1")[0].body).toEqual({ status: "open" });
    });
  });

  it("shows an actionable empty state rather than a blank table", async () => {
    mockApi({ routes: baseRoutes([]) });
    await renderWithRouter(<AlertsDashboard />);

    expect(await screen.findByText(/No alerts match these filters/)).toBeInTheDocument();
    expect(screen.getByText(/service token/i)).toBeInTheDocument();
  });

  it("surfaces an API error instead of rendering an empty page", async () => {
    mockApi({
      routes: {
        "GET /alerts": { status: 500, body: { detail: "Database unavailable" } },
        "GET /analytics/kpis": fixtures.kpis(),
        "GET /analytics/alerts/timeseries": TRENDS,
      },
    });
    await renderWithRouter(<AlertsDashboard />);

    expect(await screen.findByRole("alert")).toHaveTextContent("Database unavailable");
  });

  it("sends the status filter to the API", async () => {
    const mock = mockApi({ routes: baseRoutes([fixtures.alert()]) });
    await renderWithRouter(<AlertsDashboard />);

    await screen.findByText("Rule triggered: failed logins");
    await userEvent.selectOptions(screen.getByLabelText("Status"), "dismissed");

    await waitFor(() => {
      expect(fetchCalls().some((url) => url.includes("status=dismissed"))).toBe(true);
    });
    expect(mock.calls.length).toBeGreaterThan(0);
  });
});
