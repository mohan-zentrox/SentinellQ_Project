import { beforeEach, describe, expect, it } from "vitest";
import { useAuthStore } from "./authStore";

describe("authStore", () => {
  beforeEach(() => {
    useAuthStore.getState().logout();
  });

  it("stores the refresh token alongside the access token", () => {
    useAuthStore.getState().setSession({
      accessToken: "a",
      refreshToken: "r",
      tenantId: "ten_1",
      userId: "usr_1",
      role: "admin",
    });
    const state = useAuthStore.getState();
    expect(state.accessToken).toBe("a");
    expect(state.refreshToken).toBe("r");
    expect(state.role).toBe("admin");
  });

  it("clears every field on logout", () => {
    useAuthStore.getState().setSession({
      accessToken: "a",
      refreshToken: "r",
      tenantId: "ten_1",
      userId: "usr_1",
      role: "owner",
    });
    useAuthStore.getState().logout();
    const state = useAuthStore.getState();
    expect(state.accessToken).toBeNull();
    expect(state.refreshToken).toBeNull();
    expect(state.tenantId).toBeNull();
    expect(state.userId).toBeNull();
    expect(state.role).toBeNull();
  });

  describe("hasRole", () => {
    function withRole(role: "owner" | "admin" | "analyst" | "viewer") {
      useAuthStore.getState().setSession({
        accessToken: "a",
        refreshToken: null,
        tenantId: "ten_1",
        userId: "usr_1",
        role,
      });
      return useAuthStore.getState().hasRole;
    }

    it("treats privilege as ordered, matching the backend hierarchy", () => {
      // An owner satisfies an "admin or above" check.
      expect(withRole("owner")("admin")).toBe(true);
      expect(withRole("admin")("admin")).toBe(true);
      expect(withRole("analyst")("admin")).toBe(false);
      expect(withRole("viewer")("analyst")).toBe(false);
      expect(withRole("analyst")("analyst")).toBe(true);
      expect(withRole("viewer")("viewer")).toBe(true);
    });

    it("is false when signed out", () => {
      useAuthStore.getState().logout();
      expect(useAuthStore.getState().hasRole("viewer")).toBe(false);
    });
  });
});
