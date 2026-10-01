import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { Role } from "../api/types";
import { ROLE_RANK } from "../api/types";

interface Session {
  accessToken: string;
  refreshToken: string | null;
  tenantId: string;
  userId: string;
  role: Role;
}

interface AuthState {
  accessToken: string | null;
  refreshToken: string | null;
  tenantId: string | null;
  userId: string | null;
  role: Role | null;
  setSession: (session: Session) => void;
  logout: () => void;
  /** True when the signed-in role is at least `minimum` by privilege. */
  hasRole: (minimum: Role) => boolean;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      accessToken: null,
      refreshToken: null,
      tenantId: null,
      userId: null,
      role: null,
      setSession: ({ accessToken, refreshToken, tenantId, userId, role }) =>
        set({ accessToken, refreshToken, tenantId, userId, role }),
      logout: () =>
        set({ accessToken: null, refreshToken: null, tenantId: null, userId: null, role: null }),
      // Mirrors the backend's require_role: privilege is ordered, so an owner
      // satisfies an "admin or above" check. Used only to hide controls the API
      // would reject anyway -- the server remains the authority.
      hasRole: (minimum) => {
        const role = get().role;
        return role !== null && ROLE_RANK[role] >= ROLE_RANK[minimum];
      },
    }),
    {
      name: "sentineliq-auth",
      partialize: (state) => ({
        accessToken: state.accessToken,
        refreshToken: state.refreshToken,
        tenantId: state.tenantId,
        userId: state.userId,
        role: state.role,
      }),
    },
  ),
);
