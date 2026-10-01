/**
 * The API client's transparent-refresh behaviour.
 *
 * This is the riskiest logic in the frontend: refresh rotation is single-use
 * server-side, so firing one refresh per concurrent 401 would look like a token
 * replay and get the whole session family revoked as suspected theft. These tests
 * pin that exactly one refresh happens.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, queryString } from "./client";
import { useAuthStore } from "../store/authStore";

function signedIn() {
  useAuthStore.getState().setSession({
    accessToken: "stale-access",
    refreshToken: "refresh-1",
    tenantId: "ten_a",
    userId: "usr_a",
    role: "analyst",
  });
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("queryString", () => {
  it("omits undefined, null and empty values", () => {
    expect(queryString({ page: 1, status: "open", severity: "", actor: undefined, x: null })).toBe(
      "?page=1&status=open",
    );
  });

  it("returns an empty string when nothing is set", () => {
    expect(queryString({ a: undefined })).toBe("");
  });
});

describe("api error mapping", () => {
  beforeEach(signedIn);

  it("surfaces a FastAPI string detail", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json({ detail: "Alert not found" }, 404)));
    await expect(api.get("/alerts/missing")).rejects.toMatchObject({
      status: 404,
      message: "Alert not found",
    });
  });

  it("flattens a 422 validation detail list into a readable message", async () => {
    // Without this, the user is shown "[object Object]".
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        json(
          {
            detail: [
              { loc: ["body", "severity"], msg: "String should match pattern" },
              { loc: ["body", "name"], msg: "Field required" },
            ],
          },
          422,
        ),
      ),
    );
    await expect(api.post("/detection-rules", {})).rejects.toThrowError(
      /severity: String should match pattern; name: Field required/,
    );
  });

  it("returns undefined for a 204", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 204 })));
    await expect(api.delete("/detection-rules/rule_1")).resolves.toBeUndefined();
  });
});

describe("transparent refresh", () => {
  beforeEach(signedIn);

  it("refreshes once on a 401 and replays the original request", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/auth/refresh")) {
        return json({
          accessToken: "fresh-access",
          tokenType: "bearer",
          tenantId: "ten_a",
          userId: "usr_a",
          role: "analyst",
          refreshToken: "refresh-2",
          expiresIn: 3600,
        });
      }
      const token = (init?.headers as Record<string, string>)?.Authorization;
      if (token === "Bearer stale-access") {
        return json({ detail: "Invalid or expired token" }, 401);
      }
      return json({ ok: true });
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(api.get("/auth/me")).resolves.toEqual({ ok: true });

    // The rotated token replaced the old one, so the next request uses it.
    expect(useAuthStore.getState().accessToken).toBe("fresh-access");
    expect(useAuthStore.getState().refreshToken).toBe("refresh-2");

    const refreshCalls = fetchMock.mock.calls.filter((call) =>
      String(call[0]).includes("/auth/refresh"),
    );
    expect(refreshCalls).toHaveLength(1);
  });

  it("shares one refresh across concurrent 401s", async () => {
    let refreshCount = 0;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/auth/refresh")) {
        refreshCount += 1;
        return json({
          accessToken: "fresh-access",
          tokenType: "bearer",
          tenantId: "ten_a",
          userId: "usr_a",
          role: "analyst",
          refreshToken: `refresh-${refreshCount + 1}`,
          expiresIn: 3600,
        });
      }
      const token = (init?.headers as Record<string, string>)?.Authorization;
      if (token === "Bearer stale-access") {
        return json({ detail: "expired" }, 401);
      }
      return json({ ok: url });
    });
    vi.stubGlobal("fetch", fetchMock);

    await Promise.all([api.get("/alerts"), api.get("/cases"), api.get("/events")]);

    // Three concurrent 401s, one refresh. More than one would be treated by the
    // backend as refresh-token reuse and revoke the session family.
    expect(refreshCount).toBe(1);
  });

  it("logs out when the refresh itself fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) =>
        String(input).includes("/auth/refresh")
          ? json({ detail: "Refresh token has been revoked" }, 401)
          : json({ detail: "expired" }, 401),
      ),
    );

    await expect(api.get("/alerts")).rejects.toBeInstanceOf(ApiError);
    expect(useAuthStore.getState().accessToken).toBeNull();
    expect(useAuthStore.getState().role).toBeNull();
  });

  it("does not attempt a refresh when there is no refresh token", async () => {
    useAuthStore.getState().setSession({
      accessToken: "only-access",
      refreshToken: null,
      tenantId: "ten_a",
      userId: "usr_a",
      role: "viewer",
    });
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      json({ detail: "expired" }, 401),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(api.get("/alerts")).rejects.toBeInstanceOf(ApiError);
    expect(
      fetchMock.mock.calls.filter((call) => String(call[0]).includes("/auth/refresh")),
    ).toHaveLength(0);
    expect(useAuthStore.getState().accessToken).toBeNull();
  });
});
