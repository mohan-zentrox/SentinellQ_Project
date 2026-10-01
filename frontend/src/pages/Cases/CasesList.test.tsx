import { beforeEach, describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import CasesList from "./CasesList";
import { fixtures, mockApi, renderWithRouter, signIn } from "../../test/helpers";

function caseRow(overrides: Record<string, unknown> = {}) {
  const created = new Date(Date.now() - 7200_000).toISOString();
  return {
    id: "case_1",
    tenantId: "ten_test",
    title: "Suspicious logins",
    description: "",
    status: "investigating",
    severity: "high",
    assigneeUserId: null,
    alertIds: ["alrt_1"],
    createdAt: created,
    updatedAt: created,
    resolvedAt: null,
    ...overrides,
  };
}

describe("CasesList", () => {
  beforeEach(() => signIn("analyst"));

  it("lists cases, which previously had no entry point in the UI", async () => {
    mockApi({ routes: { "GET /cases": fixtures.paginated([caseRow()]) } });
    await renderWithRouter(<CasesList />);

    expect(await screen.findByText("Suspicious logins")).toBeInTheDocument();
    expect(screen.getByText("investigating")).toBeInTheDocument();
    expect(screen.getByText("unassigned")).toBeInTheDocument();
  });

  it("computes resolution time for a resolved case", async () => {
    const createdAt = new Date("2026-06-01T10:00:00Z").toISOString();
    const resolvedAt = new Date("2026-06-01T13:00:00Z").toISOString();
    mockApi({
      routes: {
        "GET /cases": fixtures.paginated([
          caseRow({ status: "resolved", createdAt, updatedAt: resolvedAt, resolvedAt }),
        ]),
      },
    });
    await renderWithRouter(<CasesList />);

    // 3 hours between creation and resolution.
    expect(await screen.findByText("3.0h")).toBeInTheDocument();
  });

  it("does not request the user roster as an analyst", async () => {
    // Listing users is admin-only; requesting it would 403 and surface a
    // spurious error for something purely cosmetic.
    const mock = mockApi({ routes: { "GET /cases": fixtures.paginated([caseRow()]) } });
    await renderWithRouter(<CasesList />);

    await screen.findByText("Suspicious logins");
    expect(mock.callsTo("GET /tenants/me/users")).toHaveLength(0);
  });

  it("resolves assignee ids to emails for an admin", async () => {
    signIn("admin");
    mockApi({
      routes: {
        "GET /cases": fixtures.paginated([caseRow({ assigneeUserId: "usr_2" })]),
        "GET /tenants/me/users": [
          {
            id: "usr_2",
            tenantId: "ten_test",
            email: "analyst@acme.test",
            fullName: "A",
            role: "analyst",
            isActive: true,
            provisionedBy: "local",
            lastLoginAt: null,
            createdAt: null,
          },
        ],
      },
    });
    await renderWithRouter(<CasesList />);

    expect(await screen.findByText("analyst@acme.test")).toBeInTheDocument();
  });

  it("sends the assignment scope filter", async () => {
    const mock = mockApi({ routes: { "GET /cases": fixtures.paginated([caseRow()]) } });
    await renderWithRouter(<CasesList />);

    await screen.findByText("Suspicious logins");
    await userEvent.selectOptions(screen.getByLabelText("Assignment"), "unassigned");

    const stub = globalThis.fetch as unknown as { mock?: { calls: unknown[][] } };
    const urls = (stub.mock?.calls ?? []).map((call) => String(call[0]));
    expect(urls.some((url) => url.includes("unassigned=true"))).toBe(true);
    expect(mock.calls.length).toBeGreaterThan(1);
  });

  it("shows an empty state pointing at the promote flow", async () => {
    mockApi({ routes: { "GET /cases": fixtures.paginated([]) } });
    await renderWithRouter(<CasesList />);

    expect(await screen.findByText(/No cases match these filters/)).toBeInTheDocument();
    expect(screen.getByText(/Promote one or more alerts/)).toBeInTheDocument();
  });
});
