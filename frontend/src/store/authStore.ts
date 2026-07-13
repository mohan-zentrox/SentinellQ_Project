import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { Role } from "../api/types";

interface AuthState {
  accessToken: string | null;
  tenantId: string | null;
  userId: string | null;
  role: Role | null;
  setSession: (session: { accessToken: string; tenantId: string; userId: string; role: Role }) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      accessToken: null,
      tenantId: null,
      userId: null,
      role: null,
      setSession: ({ accessToken, tenantId, userId, role }) =>
        set({ accessToken, tenantId, userId, role }),
      logout: () => set({ accessToken: null, tenantId: null, userId: null, role: null }),
    }),
    { name: "sentineliq-auth" },
  ),
);
