/**
 * Test helpers: a tiny request-matching fetch stub and a render wrapper.
 *
 * Deliberately not MSW. The component tests need to assert *which* endpoint was
 * called with what body (that triage sends `status: "dismissed"`, that bulk
 * triage uses the collection PATCH), and a map from "METHOD /path" to a response
 * makes that directly inspectable without a service-worker layer.
 */
import type { ReactElement } from "react";
import { act, render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import { useAuthStore } from "../store/authStore";
import type { Role } from "../api/types";

export interface RecordedCall {
  method: string;
  path: string;
  body: unknown;
}

export interface MockApiOptions {
  /** Map of "GET /alerts" (path without the /v1 prefix) to a response body, or
   *  to a {status, body} pair for error cases. */
  routes: Record<string, unknown>;
}

export interface MockApi {
  calls: RecordedCall[];
  /** Calls matching a "METHOD /path-prefix" key. */
  callsTo: (key: string) => RecordedCall[];
}

function normalize(url: string): string {
  // The client prefixes /v1; strip it plus any query string so route keys stay
  // readable.
  const withoutOrigin = url.replace(/^https?:\/\/[^/]+/, "");
  return withoutOrigin.replace(/^\/v1/, "").split("?")[0] || "/";
}

export function mockApi({ routes }: MockApiOptions): MockApi {
  const calls: RecordedCall[] = [];

  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();
      const method = (init?.method ?? "GET").toUpperCase();
      const path = normalize(url);
      const body = init?.body ? JSON.parse(init.body as string) : undefined;
      calls.push({ method, path, body });

      const exact = routes[`${method} ${path}`];
      // Fall back to the longest matching prefix so a test can stub
      // "GET /alerts" and serve "/alerts/alrt_1" too.
      const prefixKey = Object.keys(routes)
        .filter((key) => key.startsWith(`${method} `))
        .filter((key) => path.startsWith(key.slice(method.length + 1)))
        .sort((a, b) => b.length - a.length)[0];
      const entry = exact ?? (prefixKey ? routes[prefixKey] : undefined);

      if (entry === undefined) {
        return new Response(JSON.stringify({ detail: `No stub for ${method} ${path}` }), {
          status: 404,
          headers: { "Content-Type": "application/json" },
        });
      }

      const shaped = entry as { status?: number; body?: unknown };
      const isShaped =
        shaped !== null && typeof shaped === "object" && ("status" in shaped || "body" in shaped);
      const status = isShaped ? shaped.status ?? 200 : 200;
      const payload = isShaped ? shaped.body : entry;

      if (status === 204) {
        return new Response(null, { status: 204 });
      }
      return new Response(JSON.stringify(payload ?? null), {
        status,
        headers: { "Content-Type": "application/json" },
      });
    }),
  );

  return {
    calls,
    callsTo: (key: string) => {
      const [method, ...rest] = key.split(" ");
      const prefix = rest.join(" ");
      return calls.filter((call) => call.method === method.toUpperCase() && call.path.startsWith(prefix));
    },
  };
}

export function signIn(role: Role = "analyst") {
  useAuthStore.getState().setSession({
    accessToken: "test-access-token",
    refreshToken: "test-refresh-token",
    tenantId: "ten_test",
    userId: "usr_test",
    role,
  });
}

/**
 * Render inside a MemoryRouter, letting the mount-time fetches settle inside `act`.
 *
 * Pages here fire several independent queries on mount; draining them here means
 * the first assertion sees loaded state rather than a spinner. See
 * `src/test/setup.ts` for why some act warnings remain regardless.
 */
export async function renderWithRouter(ui: ReactElement, { route = "/" }: { route?: string } = {}) {
  let result!: ReturnType<typeof render>;
  await act(async () => {
    result = render(<MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter>);
    // A stubbed fetch settles across several turns (the Response, then
    // response.json(), then the hook's then/finally), so a macrotask yield is
    // needed to drain the whole chain rather than a single microtask.
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
  return result;
}

/** Minimal valid fixtures, so a test only states what it cares about. */
export const fixtures = {
  alert: (overrides: Record<string, unknown> = {}) => ({
    id: "alrt_1",
    tenantId: "ten_test",
    ruleId: "rule_1",
    title: "Rule triggered: failed logins",
    description: "5 failures",
    severity: "high",
    status: "open",
    eventIds: ["evt_1"],
    caseId: null,
    detectionSource: "rule",
    mlScore: null,
    mlModelVersion: null,
    dismissedAt: null,
    dismissedByUserId: null,
    dismissReason: null,
    notifiedAt: null,
    createdAt: new Date().toISOString(),
    ...overrides,
  }),
  kpis: (overrides: Record<string, unknown> = {}) => ({
    periodStart: new Date(Date.now() - 86400000 * 30).toISOString(),
    periodEnd: new Date().toISOString(),
    alertVolume: 2,
    dismissedAlerts: 1,
    falsePositiveRate: 0.5,
    mttdSeconds: 120,
    mttrSeconds: 3600,
    openCases: 1,
    resolvedCases: 0,
    alertsBySeverity: { high: 2 },
    alertsByDetectionSource: { rule: 2 },
    ...overrides,
  }),
  paginated: (items: unknown[]) => ({
    total: items.length,
    page: 1,
    pageSize: 25,
    items,
  }),
};
